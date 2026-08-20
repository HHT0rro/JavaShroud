#!/usr/bin/env python3
"""Build and verify the deterministic Java 17 promotional baseline artifact.

The script deliberately has no Gradle/Maven dependency. It accepts an optional
--java-home and otherwise uses JAVA_HOME; for this repository it defaults to
E:\\java\\jdk-17 when available. Every command, output, SHA-256, javap
signature, and case result is written under demo-artifacts/local-evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEMO_ROOT = ROOT / "demo-artifacts"
SOURCE_ROOT = DEMO_ROOT / "src"
BUILD_ROOT = DEMO_ROOT / "build"
CLASS_ROOT = BUILD_ROOT / "classes"
DIST_ROOT = BUILD_ROOT / "dist"
EVIDENCE_ROOT = DEMO_ROOT / "local-evidence" / "baseline"
JAR_PATH = DIST_ROOT / "demo-baseline.jar"

CASES = ("approved", "step-up", "denied")
EXPECTED_PREFIXES = {
    "approved": "APPROVED · digest=",
    "step-up": "STEP_UP · digest=",
    "denied": "DENIED · digest=",
}
EXPECTED_SCORES = {
    "approved": 18,
    "step-up": 52,
    "denied": 88,
}


def resolve_tool(java_home: Path, name: str) -> Path:
    suffix = ".exe" if os.name == "nt" else ""
    candidate = java_home / "bin" / f"{name}{suffix}"
    if candidate.exists():
        return candidate
    fallback = shutil.which(f"{name}{suffix}") or shutil.which(name)
    if fallback:
        return Path(fallback)
    raise FileNotFoundError(f"Could not find {name} under {java_home / 'bin'} or PATH")


def resolve_java_home(argument: str | None) -> Path:
    candidates: list[Path] = []
    if argument:
        candidates.append(Path(argument))
    if os.environ.get("JAVA_HOME"):
        candidates.append(Path(os.environ["JAVA_HOME"]))
    candidates.append(Path(r"E:\java\jdk-17"))
    for candidate in candidates:
        if (candidate / "bin" / ("javac.exe" if os.name == "nt" else "javac")).exists():
            return candidate.resolve()
    joined = ", ".join(str(path) for path in candidates)
    raise FileNotFoundError(f"No usable Java home found. Checked: {joined}")


def decode_output(value: bytes, preferred_encoding: str | None = None) -> str:
    if not value:
        return ""
    encodings = ([preferred_encoding] if preferred_encoding else []) + [
        "utf-8", "utf-8-sig", "mbcs" if os.name == "nt" else "utf-8"
    ]
    for encoding in encodings:
        if encoding is None:
            continue
        try:
            return value.decode(encoding)
        except UnicodeDecodeError:
            continue
    return value.decode(preferred_encoding or "utf-8", errors="replace")


def run(command: list[str], cwd: Path, stdout_encoding: str | None = None) -> dict[str, Any]:
    completed = subprocess.run(command, cwd=cwd, capture_output=True)
    return {
        "command": command,
        "returncode": completed.returncode,
        "stdout": decode_output(completed.stdout, stdout_encoding),
        "stderr": decode_output(completed.stderr),
    }


def write_command_record(destination: Path, label: str, record: dict[str, Any]) -> None:
    command = subprocess.list2cmdline(record["command"])
    destination.write_text(
        "COMMAND\n"
        + command
        + "\n\nEXIT CODE\n"
        + str(record["returncode"])
        + "\n\nSTDOUT\n"
        + record["stdout"]
        + "\n\nSTDERR\n"
        + record["stderr"],
        encoding="utf-8",
    )


def ensure_success(record: dict[str, Any], label: str) -> None:
    if record["returncode"] != 0:
        raise RuntimeError(
            f"{label} failed with exit code {record['returncode']}.\n"
            f"stdout:\n{record['stdout']}\nstderr:\n{record['stderr']}"
        )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_expected_case(case: str, record: dict[str, Any]) -> str:
    ensure_success(record, f"case {case}")
    output = record["stdout"].strip()
    prefix = EXPECTED_PREFIXES[case]
    if not output.startswith(prefix):
        raise RuntimeError(f"case {case} output did not start with {prefix!r}: {output!r}")
    if record["stderr"]:
        raise RuntimeError(f"case {case} produced stderr: {record['stderr']!r}")
    digest = output.removeprefix(prefix)
    if not re.fullmatch(r"[0-9a-f]{16}", digest):
        raise RuntimeError(f"case {case} did not emit a 16-character lowercase hex digest: {output!r}")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--java-home", help="Java 17 home; defaults to JAVA_HOME or E:\\java\\jdk-17")
    args = parser.parse_args()

    java_home = resolve_java_home(args.java_home)
    java = resolve_tool(java_home, "java")
    javac = resolve_tool(java_home, "javac")
    jar = resolve_tool(java_home, "jar")
    javap = resolve_tool(java_home, "javap")

    if not SOURCE_ROOT.exists():
        raise FileNotFoundError(f"Source root does not exist: {SOURCE_ROOT}")

    shutil.rmtree(CLASS_ROOT, ignore_errors=True)
    shutil.rmtree(DIST_ROOT, ignore_errors=True)
    shutil.rmtree(EVIDENCE_ROOT, ignore_errors=True)
    CLASS_ROOT.mkdir(parents=True, exist_ok=True)
    DIST_ROOT.mkdir(parents=True, exist_ok=True)
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)

    sources = sorted(str(path) for path in SOURCE_ROOT.rglob("*.java"))
    if len(sources) != 5:
        raise RuntimeError(f"Expected exactly five Java sample sources, found {len(sources)}: {sources}")

    version_record = run([str(java), "-version"], ROOT)
    write_command_record(EVIDENCE_ROOT / "java-version.txt", "java-version", version_record)
    if version_record["returncode"] != 0:
        ensure_success(version_record, "java -version")

    compile_record = run([
        str(javac),
        "--release", "17",
        "-encoding", "UTF-8",
        "-d", str(CLASS_ROOT),
        *sources,
    ], ROOT)
    write_command_record(EVIDENCE_ROOT / "compile.txt", "compile", compile_record)
    ensure_success(compile_record, "javac --release 17")

    manifest_path = BUILD_ROOT / "manifest.mf"
    manifest_path.write_text("Manifest-Version: 1.0\nMain-Class: demo.Main\n\n", encoding="utf-8", newline="\n")
    jar_record = run([
        str(jar),
        "--create",
        "--file", str(JAR_PATH),
        "--manifest", str(manifest_path),
        "-C", str(CLASS_ROOT), ".",
    ], ROOT)
    write_command_record(EVIDENCE_ROOT / "package.txt", "package", jar_record)
    ensure_success(jar_record, "jar --create")

    descriptor_record = run([
        str(javap),
        "-s", "-p", "-classpath", str(JAR_PATH), "demo.ProtectedOperation",
    ], ROOT)
    write_command_record(EVIDENCE_ROOT / "protected-operation-descriptor.txt", "javap descriptor", descriptor_record)
    ensure_success(descriptor_record, "javap descriptor")
    expected_descriptor = "descriptor: (II)J"
    if expected_descriptor not in descriptor_record["stdout"]:
        raise RuntimeError(f"Expected {expected_descriptor!r} in javap output\n{descriptor_record['stdout']}")

    policy_javap_record = run([
        str(javap),
        "-c", "-p", "-s", "-classpath", str(JAR_PATH), "demo.AccessPolicy",
    ], ROOT)
    write_command_record(EVIDENCE_ROOT / "access-policy-javap.txt", "javap AccessPolicy", policy_javap_record)
    ensure_success(policy_javap_record, "javap AccessPolicy")

    case_outputs: dict[str, str] = {}
    case_records: dict[str, dict[str, Any]] = {}
    for case in CASES:
        record = run([str(java), "-jar", str(JAR_PATH), "--case", case], ROOT, stdout_encoding="utf-8")
        write_command_record(EVIDENCE_ROOT / f"run-{case}.txt", f"run {case}", record)
        case_outputs[case] = require_expected_case(case, record)
        case_records[case] = {
            "command": record["command"],
            "returncode": record["returncode"],
            "stdout": record["stdout"],
            "stderr": record["stderr"],
        }

    manifest = {
        "artifact": {
            "path": str(JAR_PATH.resolve()),
            "sha256": sha256_file(JAR_PATH),
            "sizeBytes": JAR_PATH.stat().st_size,
            "javaRelease": 17,
            "mainClass": "demo.Main",
        },
        "java": {
            "home": str(java_home),
            "java": str(java),
            "javac": str(javac),
            "jar": str(jar),
            "javap": str(javap),
            "versionStdout": version_record["stdout"],
            "versionStderr": version_record["stderr"],
        },
        "sourceFiles": [str(Path(source).resolve()) for source in sources],
        "protectedOperation": {
            "method": "demo.ProtectedOperation.execute",
            "descriptor": "(II)J",
            "descriptorEvidence": str((EVIDENCE_ROOT / "protected-operation-descriptor.txt").resolve()),
        },
        "cases": case_records,
        "caseOutputs": case_outputs,
        "expectedScores": EXPECTED_SCORES,
        "reproducibility": {
            "sourceDateEpoch": os.environ.get("SOURCE_DATE_EPOCH"),
            "archiveNote": "JDK 17 jar does not expose a reproducible --date option; artifact SHA is recorded per build.",
        },
    }
    (EVIDENCE_ROOT / "baseline-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    for case in CASES:
        print(case_outputs[case])
    print(f"BASELINE_JAR={JAR_PATH}")
    print(f"SHA256={manifest['artifact']['sha256']}")
    print("PROTECTED_OPERATION_DESCRIPTOR=(II)J")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exception:
        print(f"build_baseline.py: {exception}", file=sys.stderr)
        raise SystemExit(1)
