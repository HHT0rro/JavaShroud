#!/usr/bin/env python3
"""Collect Linux Java 17 runtime evidence for the one frozen protected JAR.

The process layout is intentional:

* ``wsl.exe`` only launches ``bash`` and its host-side stdout/stderr are stored
  as *host launcher* diagnostics.
* The Linux shell redirects the Java process's stdout, stderr, and exit code
  to files on the mounted project drive.
* Python reads those Linux-created files.  Consequently ``cases[*].stderr``
  is application/JVM stderr only; it never contains WSL launcher diagnostics.

The collector fails closed when the exact Java 17 path, mounted JAR SHA-256,
case exit codes, or byte-level Windows/Linux stdout agreement no longer hold.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "local-evidence" / "artifact" / "demo-protected-final.jar"
OUT = ROOT / "local-evidence" / "runtime" / "linux"
DISTRO = "Ubuntu-24.04"
JAVA = "/usr/lib/jvm/java-17-openjdk-amd64/bin/java"
ARTIFACT_WSL = "/mnt/e/XiangMu/JavaShroud-public/promo-video-v2/local-evidence/artifact/demo-protected-final.jar"
OUT_WSL = "/mnt/e/XiangMu/JavaShroud-public/promo-video-v2/local-evidence/runtime/linux"
CASES = ("approved", "step-up", "denied")


class EvidenceError(RuntimeError):
    """Raised when evidence capture or evidence linkage is incomplete."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def decode_bytes(value: bytes) -> str:
    """Decode diagnostics for JSON while raw bytes remain fingerprinted/base64 encoded."""
    return value.decode("utf-8", errors="replace")


def encode_host_diagnostic(value: bytes) -> dict[str, Any]:
    return {
        "text": decode_bytes(value),
        "utf8ReplacementBytes": len(value),
        "sha256": hashlib.sha256(value).hexdigest(),
        "base64": base64.b64encode(value).decode("ascii"),
    }


def command_string(argv: list[str]) -> str:
    return shlex.join(argv)


def read_required(path: Path, label: str) -> bytes:
    if not path.is_file():
        raise EvidenceError(f"Linux shell did not create {label}: {path}")
    return path.read_bytes()


def run_linux_redirected(label: str, argv: list[str]) -> dict[str, Any]:
    """Run an argv in Linux and collect *in-shell* stdout/stderr/exit code.

    ``wsl.exe`` diagnostics are deliberately captured by the Windows parent,
    while Java's streams are redirected by Bash inside WSL.  This prevents a
    host launcher warning from being mistakenly represented as Java stderr.
    """
    capture_id = uuid.uuid4().hex
    stdout_wsl = f"{OUT_WSL}/.{label}.{capture_id}.stdout"
    stderr_wsl = f"{OUT_WSL}/.{label}.{capture_id}.stderr"
    exit_wsl = f"{OUT_WSL}/.{label}.{capture_id}.exit"
    stdout_path = OUT / f".{label}.{capture_id}.stdout"
    stderr_path = OUT / f".{label}.{capture_id}.stderr"
    exit_path = OUT / f".{label}.{capture_id}.exit"

    linux_command = command_string(argv)
    bash_script = "\n".join(
        (
            "set +e",
            f"{linux_command} > {shlex.quote(stdout_wsl)} 2> {shlex.quote(stderr_wsl)}",
            "process_rc=$?",
            f"printf '%s\\n' \"$process_rc\" > {shlex.quote(exit_wsl)}",
            "exit 0",
        )
    )

    try:
        # Feed the script over stdin.  Passing it through ``bash -lc`` from a
        # Windows process can make ``$?`` expand before Bash sees it; stdin
        # preserves the Linux shell's actual Java exit code.
        launcher = subprocess.run(
            ["wsl.exe", "-d", DISTRO, "--", "/bin/bash", "-s"],
            input=bash_script.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        stdout = read_required(stdout_path, f"{label} stdout")
        stderr = read_required(stderr_path, f"{label} stderr")
        exit_text = read_required(exit_path, f"{label} exit code").decode("ascii", errors="strict").strip()
        try:
            process_returncode = int(exit_text)
        except ValueError as exc:
            raise EvidenceError(f"invalid Linux process exit code for {label}: {exit_text!r}") from exc

        return {
            "command": linux_command,
            "returncode": process_returncode,
            "stdout": decode_bytes(stdout),
            "stderr": decode_bytes(stderr),
            "stdoutUtf8Sha256": hashlib.sha256(stdout).hexdigest(),
            "stderrUtf8Sha256": hashlib.sha256(stderr).hexdigest(),
            "stdoutUtf8Bytes": len(stdout),
            "stderrUtf8Bytes": len(stderr),
            "capture": {
                "method": "linux-shell-redirection-to-mounted-project-directory",
                "stdoutPathWsl": stdout_wsl,
                "stderrPathWsl": stderr_wsl,
                "exitCodePathWsl": exit_wsl,
            },
            "hostLauncherReturncode": launcher.returncode,
            "hostLauncherStdout": encode_host_diagnostic(launcher.stdout),
            "hostLauncherStderr": encode_host_diagnostic(launcher.stderr),
        }
    finally:
        for path in (stdout_path, stderr_path, exit_path):
            path.unlink(missing_ok=True)


def write_record(path: Path, result: dict[str, Any]) -> None:
    """Write an auditable text record without collapsing host and Java stderr."""
    host_stdout = result["hostLauncherStdout"]
    host_stderr = result["hostLauncherStderr"]
    sections = (
        ("COMMAND", str(result["command"])),
        ("JAVA PROCESS EXIT CODE", str(result["returncode"])),
        ("JAVA STDOUT", str(result["stdout"])),
        ("JAVA STDERR", str(result["stderr"])),
        ("HOST LAUNCHER EXIT CODE", str(result["hostLauncherReturncode"])),
        ("HOST LAUNCHER STDOUT", str(host_stdout["text"])),
        ("HOST LAUNCHER STDERR", str(host_stderr["text"])),
        ("HOST LAUNCHER STDERR SHA256", str(host_stderr["sha256"])),
        ("HOST LAUNCHER STDERR BASE64", str(host_stderr["base64"])),
    )
    content = "\n\n".join(f"{heading}\n{value}" for heading, value in sections) + "\n"
    path.write_text(content, encoding="utf-8", newline="\n")


def case_map(runtime: dict[str, Any]) -> dict[str, dict[str, Any]]:
    entries = runtime.get("cases")
    if not isinstance(entries, list):
        raise EvidenceError("Windows runtime cases is not a list")
    mapped: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("case"), str):
            raise EvidenceError("invalid Windows runtime case entry")
        mapped[entry["case"]] = entry
    return mapped


def compare_to_windows(windows: dict[str, Any], linux_cases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    windows_cases = case_map(windows)
    rows: list[dict[str, Any]] = []
    for linux_case in linux_cases:
        case_name = str(linux_case["case"])
        win = windows_cases.get(case_name)
        if win is None:
            raise EvidenceError(f"Windows evidence has no case: {case_name}")
        windows_stdout = str(win.get("stdout", "")).encode("utf-8")
        linux_stdout = str(linux_case["stdout"]).encode("utf-8")
        rows.append(
            {
                "case": case_name,
                "windowsReturncode": win.get("returncode"),
                "linuxReturncode": linux_case["returncode"],
                "stdoutByteForByteMatch": windows_stdout == linux_stdout,
                "windowsStdoutUtf8Bytes": len(windows_stdout),
                "linuxStdoutUtf8Bytes": len(linux_stdout),
                "windowsStdoutUtf8Sha256": hashlib.sha256(windows_stdout).hexdigest(),
                "linuxStdoutUtf8Sha256": hashlib.sha256(linux_stdout).hexdigest(),
                "windowsStdout": str(win.get("stdout", "")),
                "linuxStdout": str(linux_case["stdout"]),
                "windowsApplicationStderr": str(win.get("stderr", "")),
                "linuxApplicationStderr": str(linux_case["stderr"]),
            }
        )
    return rows


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    if not ARTIFACT.is_file():
        raise EvidenceError(f"frozen artifact not found: {ARTIFACT}")

    windows_runtime_path = ROOT / "local-evidence" / "runtime" / "windows" / "runtime.json"
    if not windows_runtime_path.is_file():
        raise EvidenceError(f"Windows runtime evidence not found: {windows_runtime_path}")
    windows = json.loads(windows_runtime_path.read_text(encoding="utf-8"))
    if not isinstance(windows, dict):
        raise EvidenceError("Windows runtime evidence is not a JSON object")

    windows_sha = sha256(ARTIFACT)
    recorded_windows_sha = str(windows.get("artifactSha256", "")).lower()

    java_probe = run_linux_redirected("java-version", [JAVA, "-version"])
    write_record(OUT / "java-version.txt", java_probe)

    platform_probe = run_linux_redirected("platform", ["/usr/bin/uname", "-a"])
    write_record(OUT / "platform.txt", platform_probe)

    hash_probe = run_linux_redirected("sha256", ["/usr/bin/sha256sum", ARTIFACT_WSL])
    write_record(OUT / "sha256.txt", hash_probe)
    hash_tokens = str(hash_probe["stdout"]).strip().split(maxsplit=1)
    linux_sha = hash_tokens[0].lower() if hash_tokens else ""

    cases: list[dict[str, Any]] = []
    for case_name in CASES:
        result = run_linux_redirected(
            f"run-{case_name}",
            [JAVA, "-Xverify:all", "-jar", ARTIFACT_WSL, "--case", case_name],
        )
        case = {"case": case_name, **result}
        write_record(OUT / f"run-{case_name}.txt", case)
        cases.append(case)

    comparison = compare_to_windows(windows, cases)

    java_text = str(java_probe["stdout"]) + str(java_probe["stderr"])
    valid_java = java_probe["returncode"] == 0 and 'openjdk version "17.' in java_text
    required_host_launches = [java_probe, platform_probe, hash_probe, *cases]
    host_launches_pass = all(int(item["hostLauncherReturncode"]) == 0 for item in required_host_launches)
    artifact_match = (
        bool(linux_sha)
        and bool(recorded_windows_sha)
        and windows_sha == linux_sha == recorded_windows_sha
        and int(windows.get("artifactBytes", -1)) == ARTIFACT.stat().st_size
    )
    all_cases_exit_zero = all(int(item["returncode"]) == 0 for item in cases)
    all_application_stderr_empty = all(str(item["stderr"]) == "" for item in cases)
    all_stdout_match = bool(comparison) and all(bool(row["stdoutByteForByteMatch"]) for row in comparison)
    all_windows_stderr_empty = all(str(row["windowsApplicationStderr"]) == "" for row in comparison)
    host_warning_present = any(bool(str(item["hostLauncherStderr"]["text"])) for item in required_host_launches)

    verification = {
        "java17ExactPathPassed": valid_java,
        "hostLauncherCommandsExitZero": host_launches_pass,
        "sameMountedArtifactSha256Passed": artifact_match,
        "allLinuxCasesExitZero": all_cases_exit_zero,
        "allLinuxApplicationStderrEmpty": all_application_stderr_empty,
        "allWindowsApplicationStderrEmpty": all_windows_stderr_empty,
        "allStdoutByteForByteMatchesWindows": all_stdout_match,
        "hostLauncherDiagnosticPresent": host_warning_present,
        "hostLauncherDiagnosticScope": (
            "hostLauncherStderr is emitted by wsl.exe on the Windows host. "
            "Java stdout/stderr and Java exit code are captured independently by Linux shell redirection."
        ),
        "applicationStderrScope": (
            "cases[*].stderr contains only the Java process stderr file created inside the Linux shell; "
            "it excludes all WSL launcher diagnostics."
        ),
    }
    verification["universalArtifactEvidencePassed"] = all(
        bool(verification[key])
        for key in (
            "java17ExactPathPassed",
            "hostLauncherCommandsExitZero",
            "sameMountedArtifactSha256Passed",
            "allLinuxCasesExitZero",
            "allLinuxApplicationStderrEmpty",
            "allWindowsApplicationStderrEmpty",
            "allStdoutByteForByteMatchesWindows",
        )
    )

    result: dict[str, Any] = {
        "schemaVersion": 2,
        "generatedAtUtc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "platform": {
            "distribution": DISTRO,
            "execution": "WSL2",
            "command": platform_probe["command"],
            "returncode": platform_probe["returncode"],
            "stdout": platform_probe["stdout"],
            "stderr": platform_probe["stderr"],
            "hostLauncherReturncode": platform_probe["hostLauncherReturncode"],
            "hostLauncherStderr": platform_probe["hostLauncherStderr"],
        },
        "java": {
            "path": JAVA,
            "versionCommand": java_probe["command"],
            "versionReturncode": java_probe["returncode"],
            "versionStdout": java_probe["stdout"],
            "versionStderr": java_probe["stderr"],
            "hostLauncherReturncode": java_probe["hostLauncherReturncode"],
            "hostLauncherStderr": java_probe["hostLauncherStderr"],
            "isJava17": valid_java,
        },
        "artifact": {
            "windowsPath": str(ARTIFACT),
            "wslPath": ARTIFACT_WSL,
            "bytes": ARTIFACT.stat().st_size,
            "windowsSha256": windows_sha,
            "recordedWindowsRuntimeSha256": recorded_windows_sha,
            "linuxSha256Command": hash_probe["command"],
            "linuxSha256Returncode": hash_probe["returncode"],
            "linuxSha256": linux_sha,
            "sameSha256": artifact_match,
            "sha256CheckNote": "Windows direct hash, Windows runtime manifest hash, and Linux sha256sum hash must all match.",
            "hostLauncherReturncode": hash_probe["hostLauncherReturncode"],
            "hostLauncherStderr": hash_probe["hostLauncherStderr"],
        },
        "cases": cases,
        "windowsComparison": comparison,
        "verification": verification,
        "recordFiles": {
            "javaVersion": "java-version.txt",
            "platform": "platform.txt",
            "sha256": "sha256.txt",
            "approved": "run-approved.txt",
            "stepUp": "run-step-up.txt",
            "denied": "run-denied.txt",
        },
    }
    (OUT / "runtime.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    summary = [
        "CROSS-PLATFORM LINUX RUNTIME EVIDENCE",
        f"artifact.windows.path={ARTIFACT}",
        f"artifact.wsl.path={ARTIFACT_WSL}",
        f"artifact.sha256={windows_sha}",
        f"platform.uname={str(platform_probe['stdout']).strip()}",
        f"java.path={JAVA}",
        f"java17.exact_path_passed={str(valid_java).lower()}",
        f"same_mounted_artifact_sha256_passed={str(artifact_match).lower()}",
        "capture=linux-shell-redirection (Java streams) + host-launcher diagnostics (wsl.exe)",
    ]
    for item in cases:
        summary.extend(
            (
                f"case.{item['case']}.exit_code={item['returncode']}",
                f"case.{item['case']}.stdout={str(item['stdout']).rstrip()}",
                f"case.{item['case']}.java_stderr_empty={str(str(item['stderr']) == '').lower()}",
                f"case.{item['case']}.host_launcher_stderr_present={str(bool(str(item['hostLauncherStderr']['text']))).lower()}",
            )
        )
    summary.extend(
        (
            f"all_application_stderr_empty={str(all_application_stderr_empty).lower()}",
            f"all_stdout_byte_for_byte_matches_windows={str(all_stdout_match).lower()}",
            f"universal_artifact_evidence_passed={str(verification['universalArtifactEvidencePassed']).lower()}",
        )
    )
    (OUT / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8", newline="\n")

    return 0 if verification["universalArtifactEvidencePassed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"linux runtime evidence rejected: {exc}", file=sys.stderr)
        raise SystemExit(1)
