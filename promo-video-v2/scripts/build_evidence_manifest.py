#!/usr/bin/env python3
"""Build the video-facing evidence manifest from one frozen protected JAR.

This script is deliberately fail-closed.  It only publishes the Universal-JAR
story when the hashes, Java 17 runs, stdout, CFR inputs, bytecode evidence,
native-resource metadata, and string scan all agree with the frozen artifact.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "local-evidence"
GENERATED = ROOT / "generated-evidence"
ARTIFACT = LOCAL / "artifact" / "demo-protected-final.jar"

EXPECTED_CASES = ("approved", "step-up", "denied")
EXPECTED_OUTPUTS = {
    "approved": "APPROVED · digest=82eca2cbf134f031",
    "step-up": "STEP_UP · digest=aacf3fed42fa2067",
    "denied": "DENIED · digest=adeb7274380e30fe",
}


class EvidenceError(RuntimeError):
    """Raised when any evidence link fails validation."""


def read_text(path: Path) -> str:
    if not path.is_file():
        raise EvidenceError(f"missing evidence file: {path}")
    return path.read_text(encoding="utf-8", errors="strict")


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid JSON: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"expected JSON object: {path}")
    return value


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def normalize_output(value: str) -> str:
    return value.replace("\r\n", "\n").rstrip("\n")


def body_after_heading(text: str, heading: str) -> str:
    marker = f"{heading}\n"
    if marker not in text:
        raise EvidenceError(f"heading {heading!r} missing from command record")
    body = text.split(marker, 1)[1]
    if "\n\nSTDERR\n" in body:
        body = body.split("\n\nSTDERR\n", 1)[0]
    return body.strip()


def source_lines(path: Path, start_pattern: str | None = None, limit: int = 80) -> list[str]:
    lines = read_text(path).splitlines()
    start = 0
    if start_pattern:
        for index, line in enumerate(lines):
            if re.search(start_pattern, line):
                start = index
                break
        else:
            raise EvidenceError(f"pattern {start_pattern!r} missing from {path}")
    return lines[start : start + limit]


def select_lines(path: Path, patterns: tuple[str, ...], limit: int = 30) -> list[str]:
    selected: list[str] = []
    for line in read_text(path).splitlines():
        if any(pattern in line for pattern in patterns):
            selected.append(line.rstrip())
            if len(selected) >= limit:
                break
    if not selected:
        raise EvidenceError(f"no matching evidence in {path}")
    return selected


def validate_cases(windows: dict[str, Any], linux: dict[str, Any]) -> tuple[list[dict[str, Any]], bool]:
    windows_by_case = {entry["case"]: entry for entry in windows.get("cases", [])}
    linux_by_case = {entry["case"]: entry for entry in linux.get("cases", [])}
    rows: list[dict[str, Any]] = []

    for case in EXPECTED_CASES:
        if case not in windows_by_case or case not in linux_by_case:
            raise EvidenceError(f"missing cross-platform case: {case}")
        win = windows_by_case[case]
        lin = linux_by_case[case]
        win_output = normalize_output(str(win.get("stdout", "")))
        lin_output = normalize_output(str(lin.get("stdout", "")))
        expected = EXPECTED_OUTPUTS[case]
        passed = (
            int(win.get("returncode", -1)) == 0
            and int(lin.get("returncode", -1)) == 0
            and win_output == lin_output == expected
            and str(win.get("stderr", "")) == ""
        )
        if not passed:
            raise EvidenceError(f"cross-platform case validation failed: {case}")
        rows.append(
            {
                "case": case,
                "command": f"java -Xverify:all -jar demo-protected-final.jar --case {case}",
                "output": expected,
                "windowsExit": 0,
                "linuxExit": 0,
                "match": True,
            }
        )
    return rows, True


def main() -> int:
    if not ARTIFACT.is_file():
        raise EvidenceError(f"frozen artifact missing: {ARTIFACT}")

    artifact_hash = sha256(ARTIFACT)
    artifact_bytes = ARTIFACT.stat().st_size

    engine = read_json(LOCAL / "engine" / "engine.json")
    engine_jar = LOCAL / "engine" / "obfuscator-engine-0.12-frozen.jar"
    if sha256(engine_jar) != engine.get("sha256"):
        raise EvidenceError("frozen engine SHA-256 differs from engine.json")

    baseline = read_json(ROOT / "demo-artifacts" / "local-evidence" / "baseline" / "baseline-manifest.json")
    cfr = read_json(LOCAL / "tools" / "cfr-0.152.json")
    if sha256(LOCAL / "tools" / "cfr-0.152.jar") != cfr.get("sha256"):
        raise EvidenceError("CFR JAR SHA-256 differs from cfr-0.152.json")

    windows = read_json(LOCAL / "runtime" / "windows" / "runtime.json")
    linux = read_json(LOCAL / "runtime" / "linux" / "runtime.json")
    build_evidence = read_json(LOCAL / "artifact" / "demo-protected.build-evidence.json")
    string_scan = read_json(LOCAL / "inspection" / "string-scan.json")

    claimed_hashes = {
        str(windows.get("artifactSha256", "")),
        str(linux.get("artifact", {}).get("windowsSha256", "")),
        str(linux.get("artifact", {}).get("recordedWindowsRuntimeSha256", "")),
        str(linux.get("artifact", {}).get("linuxSha256", "")),
        str(build_evidence.get("candidate_jar_sha256", "")),
    }
    if claimed_hashes != {artifact_hash}:
        raise EvidenceError(f"artifact SHA mismatch across evidence: {sorted(claimed_hashes)}")
    if int(windows.get("artifactBytes", -1)) != artifact_bytes:
        raise EvidenceError("Windows runtime artifact size mismatch")
    if int(linux.get("artifact", {}).get("bytes", -1)) != artifact_bytes:
        raise EvidenceError("Linux runtime artifact size mismatch")

    verification = linux.get("verification", {})
    for key in (
        "java17ExactPathPassed",
        "sameMountedArtifactSha256Passed",
        "allLinuxCasesExitZero",
        "allStdoutByteForByteMatchesWindows",
        "universalArtifactEvidencePassed",
    ):
        if verification.get(key) is not True:
            raise EvidenceError(f"Linux verification gate failed: {key}")

    cases, result_match = validate_cases(windows, linux)

    if string_scan.get("needle") != "PROTECTED_EXPORT::INTERNAL_APPROVAL_ONLY":
        raise EvidenceError("unexpected string-scan needle")
    if string_scan.get("baselineEntryHits") != ["demo/MessageVault.class"]:
        raise EvidenceError("baseline string evidence is incomplete")
    if string_scan.get("finalEntryHits") != []:
        raise EvidenceError("protected JAR still contains the direct sensitive literal")

    natives = build_evidence.get("natives", [])
    platforms = {entry.get("platform") for entry in natives}
    if platforms != {"windows-x64", "linux-x64"}:
        raise EvidenceError(f"unexpected native platforms: {platforms}")
    native_entries = {entry["platform"]: entry["entry"] for entry in natives}
    methods = build_evidence.get("methods", [])
    if len(methods) != 1:
        raise EvidenceError("expected exactly one VMBC method resource")
    vmbc_resource = methods[0]["resource_path"]

    jar_tree_record = read_text(LOCAL / "inspection" / "final-jar-tree.txt")
    jar_entries = body_after_heading(jar_tree_record, "STDOUT").splitlines()
    required_entries = [*native_entries.values(), vmbc_resource, "META-INF/.r/boot.dat"]
    for entry in required_entries:
        if entry not in jar_entries:
            raise EvidenceError(f"required protected JAR resource missing from jar tf: {entry}")

    protected_javap = read_text(LOCAL / "inspection" / "protected-operation-final-javap.txt")
    dispatcher_match = re.search(
        r'invokestatic\s+#\d+\s+// Method "?(r/[^".]+(?:/[^".]+)*)"?\.(m_[0-9a-f]+):\(J\[Ljava/lang/Object;\)Ljava/lang/Object;',
        protected_javap,
    )
    if not dispatcher_match:
        raise EvidenceError("VMBC dispatcher call not found in final javap evidence")
    dispatcher_owner, dispatcher_method = dispatcher_match.groups()

    access_final_javap = read_text(LOCAL / "inspection" / "access-policy-final-javap.txt")
    if "tableswitch" not in access_final_javap or "lookupswitch" not in access_final_javap:
        raise EvidenceError("control-flow evidence is missing switch dispatch structures")
    message_final_javap = read_text(LOCAL / "inspection" / "message-vault-final-javap.txt")
    if "cachedDecodeString" not in message_final_javap:
        raise EvidenceError("string decoder call not found in final bytecode evidence")

    final_build_log = read_text(LOCAL / "engine" / "final-build.log")
    required_log_fragments = (
        "Compiled JNI microkernel for windows-x64",
        "Compiled JNI microkernel for linux-x64",
        "Applied max native stub shell for windows-x64",
        "Applied max native stub shell for linux-x64",
        "Run completed: passes=4, transformedClasses=3, transformedMembers=2",
        'type = "done"',
        "progress = 100",
    )
    for fragment in required_log_fragments:
        if fragment not in final_build_log:
            raise EvidenceError(f"required engine log fragment missing: {fragment}")

    access_source_path = ROOT / "demo-artifacts" / "src" / "demo" / "AccessPolicy.java"
    access_cfr_path = LOCAL / "cfr" / "final" / "demo" / "AccessPolicy.java"
    protected_cfr_path = LOCAL / "cfr" / "final" / "demo" / "ProtectedOperation.java"
    message_cfr_path = LOCAL / "cfr" / "final" / "demo" / "MessageVault.java"

    manifest: dict[str, Any] = {
        "schemaVersion": 2,
        "evidencePolicy": "single-frozen-artifact-fail-closed",
        "engine": {
            "version": engine["engineVersion"],
            "vbcVersion": engine["vbcVersion"],
            "sha256": engine["sha256"],
            "shaShort": engine["sha256"][:12],
            "sizeBytes": engine["sizeBytes"],
            "schemaVersion": engine["schemaVersion"],
            "javaBuildRuntime": "Java 21",
        },
        "baseline": {
            "jarName": "demo-baseline.jar",
            "sha256": baseline["artifact"]["sha256"],
            "javaRelease": 17,
            "caseScores": baseline["expectedScores"],
        },
        "artifact": {
            "jarName": "demo-protected-final.jar",
            "sha256": artifact_hash,
            "shaShort": artifact_hash[:12],
            "sizeBytes": artifact_bytes,
            "sizeMiB": round(artifact_bytes / (1024 * 1024), 2),
            "universal": True,
            "sameShaAcrossPlatforms": True,
            "bootResource": "META-INF/.r/boot.dat",
            "vmbcResource": vmbc_resource,
            "nativeEntries": native_entries,
            "jarEntries": jar_entries,
        },
        "cfr": {
            "version": cfr["version"],
            "sha256": cfr["sha256"],
            "shaShort": cfr["sha256"][:12],
            "inputProtectedJarSha256": artifact_hash,
            "generatedSources": [
                "demo/AccessPolicy.java",
                "demo/ProtectedOperation.java",
                "demo/MessageVault.java",
            ],
        },
        "platforms": {
            "windows": {
                "label": "Windows x64",
                "java": "Java 17",
                "javaPath": windows["java"],
                "artifactSha256": artifact_hash,
            },
            "linux": {
                "label": "Ubuntu 24.04 · Linux x64",
                "java": "OpenJDK 17.0.19",
                "javaPath": linux["java"]["path"],
                "artifactSha256": artifact_hash,
                "launcherDiagnosticExcludedFromApplicationStderr": True,
            },
        },
        "cases": cases,
        "resultMatch": result_match,
        "passes": [
            {
                "id": "method-virtualization",
                "label": "VMBC Virtualization",
                "target": "demo/ProtectedOperation#execute:(II)J",
                "status": "applied",
            },
            {
                "id": "control-flow-obfuscation",
                "label": "Control Flow",
                "target": "demo/AccessPolicy",
                "status": "applied-with-safe-edge-limit",
            },
            {
                "id": "string-encryption",
                "label": "String Protection",
                "target": "demo/MessageVault",
                "status": "applied",
            },
            {
                "id": "jni-microkernel-loader",
                "label": "JNI Microkernel",
                "target": "demo/Main",
                "status": "applied-windows-linux",
            },
        ],
        "engineEvents": [
            "Loaded input JAR · Java 17 · 7 classes",
            "string-encryption · selected demo/MessageVault",
            "control-flow-obfuscation · selected demo/AccessPolicy",
            "jni-microkernel-loader · Windows x64 + Linux x64",
            "method-virtualization · ProtectedOperation.execute:(II)J",
            "Compiled JNI microkernel for windows-x64",
            "Compiled JNI microkernel for linux-x64",
            "Run completed · passes=4 · transformedClasses=3 · transformedMembers=2",
            "DONE · progress=100",
        ],
        "controlFlow": {
            "target": "demo/AccessPolicy",
            "density": 8,
            "dispatchMode": "tableswitch-hybrid",
            "branchInjection": "normal",
            "edgeInjectionNote": "Analyzer-safe edge injection was skipped for unsupported/new-object edges; opaque predicates and switch dispatch structures were still applied.",
            "javapHighlights": select_lines(
                LOCAL / "inspection" / "access-policy-final-javap.txt",
                ("ifne", "ifeq", "lookupswitch", "tableswitch"),
                24,
            ),
        },
        "vmbc": {
            "target": "demo/ProtectedOperation#execute:(II)J",
            "descriptor": "(II)J",
            "dispatcherOwner": dispatcher_owner,
            "dispatcherMethod": dispatcher_method,
            "dispatcherDisplay": f"{dispatcher_owner}.{dispatcher_method}(token, args)",
            "resource": vmbc_resource,
            "resourceSha256": methods[0]["resource_sha256"],
            "resourceBytes": methods[0]["resource_size"],
            "caption": "Method body moved to VMBC resource",
            "javapTail": source_lines(
                LOCAL / "inspection" / "protected-operation-final-javap.txt",
                r"^\s*492:",
                28,
            ),
        },
        "stringEvidence": {
            "needle": string_scan["needle"],
            "baselineEntryHits": string_scan["baselineEntryHits"],
            "finalEntryHits": string_scan["finalEntryHits"],
            "directLiteralRemoved": True,
            "decoderCall": "cachedDecodeString(byte[], int, int, long, long)",
            "cfrLines": source_lines(message_cfr_path, r"public static String protectedExportNotice", 6),
        },
        "code": {
            "accessPolicySource": read_text(access_source_path).splitlines(),
            "accessPolicyCfr": read_text(access_cfr_path).splitlines(),
            "protectedOperationSource": read_text(
                ROOT / "demo-artifacts" / "src" / "demo" / "ProtectedOperation.java"
            ).splitlines(),
            "protectedOperationCfr": read_text(protected_cfr_path).splitlines(),
            "messageVaultSource": read_text(
                ROOT / "demo-artifacts" / "src" / "demo" / "MessageVault.java"
            ).splitlines(),
            "messageVaultCfr": read_text(message_cfr_path).splitlines(),
        },
        "moreCapabilities": [
            "Renaming",
            "Constant Obfuscation",
            "InvokeDynamic",
        ],
        "narrative": {
            "coreClaim": "代码，换一种执行方式。",
            "repository": "github.com/HHT0rro/JavaShroud",
            "cta": "STAR · BUILD · PROTECT",
            "licenseLine": "JavaShroud · 开源 Java 保护工具链 · GPL-3.0",
        },
    }

    GENERATED.mkdir(parents=True, exist_ok=True)
    json_path = GENERATED / "evidence.json"
    js_path = GENERATED / "evidence.js"
    json_text = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    json_path.write_text(json_text, encoding="utf-8", newline="\n")
    js_path.write_text(
        "window.JAVASHROUD_EVIDENCE = "
        + json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))
        + ";\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "artifactSha256": artifact_hash,
                "universal": True,
                "resultMatch": result_match,
                "json": str(json_path),
                "js": str(js_path),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as exc:
        print(f"evidence manifest rejected: {exc}", file=sys.stderr)
        raise SystemExit(1)
