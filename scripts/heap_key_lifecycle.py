#!/usr/bin/env python3
"""Run a Windows heap-dump probe without writing recovered key material."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import subprocess
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SIDECAR_MAGIC = b"JSBK"
SIDECAR_TEXT_PREFIX = b"JSBK1."
SIDECAR_SIZE = 118
BOOT_MAGIC = b"JSBM"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_sidecar(path: Path) -> tuple[bytes, bytes]:
    raw = path.read_bytes()
    if raw.startswith(SIDECAR_TEXT_PREFIX):
        binary = base64.urlsafe_b64decode(raw[len(SIDECAR_TEXT_PREFIX) :] + b"=" * (-len(raw[len(SIDECAR_TEXT_PREFIX) :]) % 4))
    else:
        binary = raw
    if len(binary) != SIDECAR_SIZE or not binary.startswith(SIDECAR_MAGIC):
        raise ValueError("unsupported JSBK sidecar")
    binding = binary[10:42]
    wrapping_key_bytes = hmac.new(
        binding,
        b"JavaShroud/BootKekSidecar/v1/key" + binary[42:58],
        hashlib.sha256,
    ).digest()
    aad = binary[:70]
    kek = AESGCM(wrapping_key_bytes).decrypt(binary[58:70], binary[70:], aad)
    if len(kek) != 32:
        raise ValueError("decoded JSBK KEK length is invalid")
    return binary, kek


def find_boot_material(jar: Path) -> tuple[str, bytes]:
    with zipfile.ZipFile(jar) as archive:
        candidates = []
        for info in archive.infolist():
            if info.is_dir():
                continue
            data = archive.read(info)
            if data.startswith(BOOT_MAGIC):
                candidates.append((info.filename, data))
        if len(candidates) != 1:
            raise ValueError(f"expected one JSBM resource, found {len(candidates)}")
        return candidates[0]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", required=True, type=Path)
    parser.add_argument("--sidecar", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--java", default=os.environ.get("JAVA", "java"))
    parser.add_argument("--jcmd", default=os.environ.get("JCMD", "jcmd"))
    parser.add_argument("--observe-seconds", type=float, default=8.0)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    sidecar_binary, kek = decode_sidecar(args.sidecar)
    boot_path, boot_material = find_boot_material(args.jar)
    heap_path = args.output_dir / "heap.hprof"
    stdout_path = args.output_dir / "stdout.log"
    stderr_path = args.output_dir / "stderr.log"
    report_path = args.output_dir / "key-lifecycle-report.json"
    environment = os.environ.copy()
    environment["JAVASHROUD_BOOT_SECRET_FILE_V1"] = str(args.sidecar.resolve())
    environment.pop("JAVASHROUD_BOOT_SECRET_V1", None)
    process = None
    jcmd_result: dict[str, object]
    started = utc_now()
    try:
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            process = subprocess.Popen(
                [args.java, "-Xverify:all", "-jar", str(args.jar.resolve())],
                cwd=str(args.output_dir),
                env=environment,
                stdout=stdout,
                stderr=stderr,
            )
            time.sleep(max(0.5, args.observe_seconds))
            command = [args.jcmd, str(process.pid), "GC.heap_dump", str(heap_path.resolve())]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
            jcmd_result = {
                "command": command,
                "exit_code": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            }
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=15)

    heap_bytes = heap_path.read_bytes() if heap_path.is_file() else b""
    raw_kek_occurrences = heap_bytes.count(kek) if heap_bytes else None
    stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.is_file() else ""
    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.is_file() else ""
    report = {
        "schema_version": 1,
        "generated_at_utc": utc_now(),
        "started_at_utc": started,
        "jar": {"path": str(args.jar.resolve()), "sha256": sha256(args.jar.read_bytes())},
        "sidecar": {
            "path": str(args.sidecar.resolve()),
            "format": "JSBK1 text" if args.sidecar.read_bytes().startswith(SIDECAR_TEXT_PREFIX) else "JSBK binary",
            "size": args.sidecar.stat().st_size,
            "sha256": sha256(args.sidecar.read_bytes()),
            "binding_sha256": sha256(sidecar_binary[10:42]),
            "raw_kek_occurrences_in_sidecar": sidecar_binary.count(kek),
        },
        "boot_material": {"entry": boot_path, "size": len(boot_material), "sha256": sha256(boot_material)},
        "process": {"pid": process.pid if process is not None else None, "exit_code": process.returncode if process is not None else None},
        "jcmd": jcmd_result,
        "heap": {
            "path": str(heap_path),
            "size": len(heap_bytes),
            "raw_kek_occurrences": raw_kek_occurrences,
            "status": "pass" if raw_kek_occurrences == 0 else "fail",
        },
        "logs": {
            "verify_error_present": "VerifyError" in stdout_text or "VerifyError" in stderr_text,
            "native_alignment_panic_present": "misaligned address" in stdout_text or "misaligned address" in stderr_text,
        },
        "contract": "The report never stores the decoded KEK; it records only hashes and occurrence counts.",
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["heap"]["status"] == "pass" and not report["logs"]["verify_error_present"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
