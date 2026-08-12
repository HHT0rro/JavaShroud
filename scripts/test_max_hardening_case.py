#!/usr/bin/env python3
"""Focused self-test for scripts/max_hardening_case.py (no CASE fixture mutation)."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("max_hardening_case.py")
SPEC = importlib.util.spec_from_file_location("max_hardening_case", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class MaxHardeningCaseRunnerTest(unittest.TestCase):
    def make_case(self, root: Path) -> tuple[Path, Path, Path]:
        case = root / "CASE"
        (case / "originals").mkdir(parents=True)
        (case / "recovered" / "ir2").mkdir(parents=True)
        (case / "recovered" / "vbc4").mkdir(parents=True)
        (case / "report").mkdir(parents=True)

        baseline = case / "originals" / "baseline.jar"
        with zipfile.ZipFile(baseline, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")

        vbc4_index = {"0000000000000001": {}, "0000000000000002": {}}
        token_map = {
            "0000000000000001": {"class": "sample/One", "method": "first()"},
            "0000000000000002": {"class": "sample/Two", "method": "second()"},
        }
        (case / "recovered" / "vbc4_index.json").write_text(json.dumps(vbc4_index), encoding="utf-8")
        (case / "recovered" / "token_to_method.json").write_text(json.dumps(token_map), encoding="utf-8")
        (case / "recovered" / "ir2" / "0000000000000001.json").write_text("{}", encoding="utf-8")
        (case / "recovered" / "ir2" / "0000000000000001.ir").write_text("i 0 00", encoding="utf-8")
        (case / "recovered" / "ir2" / "0000000000000002.json").write_text("{}", encoding="utf-8")
        (case / "report" / "rebuild_report.txt").write_text("methods devirtualized: 1\n", encoding="utf-8")

        artifact = root / "target.jar"
        with zipfile.ZipFile(artifact, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
            archive.writestr("META-INF/.r/0.dat", b"JSBI\x00VBC4S|1|\x00catalog\x00originalOwner")
            archive.writestr("native/kernel.dll", b"MZ\x00JSRP\x00js_vm_")
        evidence = {
            "candidate_jar_sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            "methods": [
                {"semantic_id": "01" * 32},
                {"semantic_id": "02" * 32},
            ],
        }
        artifact.with_name(f"{artifact.stem}.build-evidence.json").write_text(json.dumps(evidence), encoding="utf-8")
        sidecar = root / "target.boot-kek.jsbk"
        sidecar.write_bytes(b"JSBK1.SlNCSwE")
        return case, artifact, sidecar

    def test_report_is_outside_case_and_contains_required_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, artifact, sidecar = self.make_case(root)
            before = sorted(path.relative_to(case).as_posix() for path in case.rglob("*") if path.is_file())
            report_dir = root / "reports"

            result = RUNNER.main(
                [
                    "--case-root",
                    str(case),
                    "--artifact",
                    str(artifact),
                    "--sidecar",
                    str(sidecar),
                    "--report-dir",
                    str(report_dir),
                ]
            )

            self.assertEqual(0, result)
            after = sorted(path.relative_to(case).as_posix() for path in case.rglob("*") if path.is_file())
            self.assertEqual(before, after, "default run must not write CASE")
            report = json.loads((report_dir / "max-hardening-case.json").read_text(encoding="utf-8"))
            self.assertFalse(report["command_failure"])
            self.assertEqual("fail", report["static_scans"]["W1"]["status"])
            self.assertEqual("fail", report["static_scans"]["W2"]["status"])
            self.assertEqual("fail", report["static_scans"]["W3"]["status"])
            self.assertEqual("fail", report["static_scans"]["W5"]["status"])
            self.assertEqual("authenticated_envelope", report["static_scans"]["W6"]["status"])
            matrix = report["case_recovery_matrix"]
            self.assertEqual(2, matrix["high_value_target_count"])
            self.assertEqual(1, matrix["complete_recovery_evidence_count"])
            method_evidence = report["artifact_method_evidence"]
            self.assertEqual("valid", method_evidence["status"])
            self.assertEqual(2, method_evidence["protected_method_count"])
            self.assertTrue(method_evidence["protected_method_count_meets_target"])
            self.assertTrue((report_dir / "max-hardening-case.md").is_file())

    def test_rejects_report_directory_inside_case(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, artifact, _ = self.make_case(root)
            with self.assertRaises(SystemExit) as raised:
                RUNNER.resolve_arguments(
                    RUNNER.build_parser(),
                    [
                        "--case-root",
                        str(case),
                        "--artifact",
                        str(artifact),
                        "--report-dir",
                        str(case / "reports"),
                    ],
                )
            self.assertEqual(2, raised.exception.code)

    def test_case_root_defaults_from_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, artifact, _ = self.make_case(root)
            with patch.dict(os.environ, {"CASE_ROOT": str(case)}):
                _, resolved_case, resolved_artifact, _, report_dir = RUNNER.resolve_arguments(
                    RUNNER.build_parser(),
                    ["--artifact", str(artifact), "--report-dir", str(root / "reports")],
                )
            self.assertEqual(case.resolve(), resolved_case)
            self.assertEqual(artifact.resolve(), resolved_artifact)
            self.assertTrue(report_dir.is_relative_to(root))

    def test_pipeline_fixture_does_not_reuse_source_recovery_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, _, _ = self.make_case(root)
            (case / "scripts").mkdir()
            (case / "scripts" / "placeholder.py").write_text("", encoding="utf-8")
            (case / "deps").mkdir()
            (case / "deps" / "placeholder.jar").write_bytes(b"")
            workspace = root / "workspace"
            workspace.mkdir()

            stage = RUNNER.copy_pipeline_fixture(case, workspace)

            self.assertEqual([], list((stage / "recovered").rglob("*")))
            targets = {
                "0000000000000001": {"class": "sample/One", "method": "first()"},
                "0000000000000002": {"class": "sample/Two", "method": "second()"},
            }
            matrix = RUNNER.high_value_recovery_matrix(stage, [], target_methods=targets)
            self.assertEqual("not_available", matrix["status"])
            self.assertEqual(2, matrix["high_value_target_count"])
            self.assertEqual("not_measured", matrix["recovery_measurement"])
            self.assertIsNone(matrix["complete_recovery_evidence_count"])
            self.assertTrue(all(not row["file_evidence_complete"] for row in matrix["matrix"]))

    def test_pipeline_extracts_artifact_and_marks_legacy_protocol_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, artifact, _ = self.make_case(root)
            (case / "scripts").mkdir()
            (case / "scripts" / "placeholder.py").write_text("", encoding="utf-8")
            (case / "deps").mkdir()
            (case / "deps" / "placeholder.jar").write_bytes(b"")
            report_dir = root / "reports"
            before = sorted(path.relative_to(case).as_posix() for path in case.rglob("*") if path.is_file())

            result = RUNNER.main(
                [
                    "--case-root",
                    str(case),
                    "--artifact",
                    str(artifact),
                    "--report-dir",
                    str(report_dir),
                    "--run-case-pipeline",
                ]
            )

            self.assertEqual(0, result)
            report = json.loads((report_dir / "max-hardening-case.json").read_text(encoding="utf-8"))
            pipeline = report["commands"]["pipeline"]
            self.assertEqual("blocked", pipeline["status"])
            steps = {step["label"]: step for step in pipeline["commands"]}
            self.assertEqual("passed", steps["extract-jar"]["status"])
            self.assertEqual("passed", steps["discover-native-payloads"]["status"])
            self.assertEqual("blocked", steps["legacy-key-helper-javap"]["status"])
            self.assertEqual("blocked", steps["stage1-parse-legacy-native-header"]["status"])
            self.assertEqual("blocked", steps["decode-legacy-ir"]["status"])
            self.assertFalse(any(step["status"] == "failed" for step in pipeline["commands"]))
            recovery = pipeline["recovery_matrix"]
            self.assertEqual("not_available", recovery["status"])
            self.assertEqual("not_measured", recovery["recovery_measurement"])
            self.assertIsNone(recovery["complete_recovery_evidence_count"])
            after = sorted(path.relative_to(case).as_posix() for path in case.rglob("*") if path.is_file())
            self.assertEqual(before, after)

    def test_verify_defaults_to_non_gui_diagnostics_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, artifact, sidecar = self.make_case(root)
            args, _, _, _, _ = RUNNER.resolve_arguments(
                RUNNER.build_parser(),
                [
                    "--case-root",
                    str(case),
                    "--artifact",
                    str(artifact),
                    "--sidecar",
                    str(sidecar),
                    "--report-dir",
                    str(root / "reports"),
                    "--run-verify",
                ],
            )
            self.assertFalse(args.verify_raw)

    def test_pipeline_marks_attempted_key_helper_command_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, artifact, _ = self.make_case(root)
            (case / "scripts").mkdir()
            (case / "scripts" / "extract_keys.py").write_text("", encoding="utf-8")
            (case / "deps").mkdir()
            (case / "deps" / "placeholder.jar").write_bytes(b"")
            with zipfile.ZipFile(artifact, "a") as archive:
                archive.writestr("sample/Legacy.class", b"\xca\xfe\xba\xbejsRrkS")

            with patch.object(
                RUNNER,
                "run_command_to_file",
                return_value={"label": "legacy-key-helper-javap", "status": "failed", "error": "missing javap"},
            ):
                result = RUNNER.main(
                    [
                        "--case-root",
                        str(case),
                        "--artifact",
                        str(artifact),
                        "--report-dir",
                        str(root / "reports"),
                        "--run-case-pipeline",
                    ]
                )

            self.assertEqual(2, result)
            report = json.loads((root / "reports" / "max-hardening-case.json").read_text(encoding="utf-8"))
            pipeline = report["commands"]["pipeline"]
            self.assertEqual("failed", pipeline["status"])
            steps = {step["label"]: step for step in pipeline["commands"]}
            self.assertEqual("failed", steps["legacy-key-helper-javap"]["status"])
            self.assertEqual("blocked", steps["extract-legacy-jsrp-keys"]["status"])
            self.assertTrue(report["command_failure"])

    def test_pipeline_marks_newer_native_header_as_blocked_not_failed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, artifact, _ = self.make_case(root)
            (case / "scripts").mkdir()
            (case / "scripts" / "stage1_parse_header.py").write_text("", encoding="utf-8")
            (case / "deps").mkdir()
            (case / "deps" / "placeholder.jar").write_bytes(b"")
            version_five_artifact = root / "target-v5.jar"
            with zipfile.ZipFile(artifact) as source, zipfile.ZipFile(version_five_artifact, "w") as archive:
                for info in source.infolist():
                    payload = source.read(info)
                    if info.filename == "native/kernel.dll":
                        payload = b"MZ" + b"\x00" * 12 + RUNNER.LEGACY_NATIVE_HEADER_MARKER + (5).to_bytes(4, "little")
                    archive.writestr(info, payload)

            result = RUNNER.main(
                [
                    "--case-root",
                    str(case),
                    "--artifact",
                    str(version_five_artifact),
                    "--report-dir",
                    str(root / "reports"),
                    "--run-case-pipeline",
                ]
            )

            self.assertEqual(0, result)
            report = json.loads((root / "reports" / "max-hardening-case.json").read_text(encoding="utf-8"))
            pipeline = report["commands"]["pipeline"]
            steps = {step["label"]: step for step in pipeline["commands"]}
            header = steps["stage1-parse-legacy-native-header"]
            self.assertEqual("blocked", header["status"])
            self.assertEqual([5], header["observed_versions"])
            self.assertFalse(any(step["status"] == "failed" for step in pipeline["commands"]))

    def test_reference_jar_resolves_semantic_method_identity(self) -> None:
        def u2(value: int) -> bytes:
            return value.to_bytes(2, "big")

        def utf8(value: str) -> bytes:
            encoded = value.encode("utf-8")
            return b"\x01" + u2(len(encoded)) + encoded

        class_bytes = b"".join(
            [
                bytes.fromhex("cafebabe00000034"),
                u2(5),
                utf8("sample/Root"),
                b"\x07" + u2(1),
                utf8("run"),
                utf8("()I"),
                u2(0x0021),
                u2(2),
                u2(0),
                u2(0),
                u2(0),
                u2(1),
                u2(0x0009),
                u2(3),
                u2(4),
                u2(0),
                u2(0),
            ]
        )
        with tempfile.TemporaryDirectory() as temp:
            jar = Path(temp) / "reference.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr("sample/Root.class", class_bytes)

            identities = RUNNER.reference_method_identities(jar, [])

            semantic_id = hashlib.sha256(b"sample/Root\0run\0()I").hexdigest()
            self.assertEqual(
                {"owner": "sample/Root", "name": "run", "descriptor": "()I", "access": 0x0009},
                identities[semantic_id],
            )

    def test_requested_command_failure_is_reported_from_isolated_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            case, _, _ = self.make_case(root)
            artifact = case / "originals" / "baseline.jar"
            report_dir = root / "reports"
            before = sorted(path.relative_to(case).as_posix() for path in case.rglob("*") if path.is_file())

            result = RUNNER.main(
                [
                    "--case-root",
                    str(case),
                    "--artifact",
                    str(artifact),
                    "--report-dir",
                    str(report_dir),
                    "--run-verify",
                    "--java",
                    str(root / "missing-java"),
                ]
            )

            self.assertEqual(2, result)
            report = json.loads((report_dir / "max-hardening-case.json").read_text(encoding="utf-8"))
            verify = report["commands"]["verify"]
            self.assertEqual("failed", verify["status"])
            self.assertFalse(verify["source_case_mutated"])
            self.assertTrue(Path(verify["workspace"]).is_relative_to(report_dir))
            self.assertNotEqual(str(artifact), verify["argv"][-1])
            after = sorted(path.relative_to(case).as_posix() for path in case.rglob("*") if path.is_file())
            self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main(verbosity=2)
