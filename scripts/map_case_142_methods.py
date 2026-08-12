#!/usr/bin/env python3
"""Build a repeatable CASE-to-reference method identity report.

The old CASE has 142 VBC4 tokens, but the rebuilt clean JAR intentionally
removes some build-time helpers. This tool keeps that distinction explicit:
only a bytecode-backed mapping may enter the protected semantic-ID intersection.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime


DEFAULT_CASE_ROOT = Path(r"E:\javashroud-reTest\CASE")
DEFAULT_REFERENCE_JAR = Path(r"E:\javashroud-product-video\SimpleFiveInARow.jar")
DEFAULT_RELEASE_ROOT = Path(
    r"C:\Users\xbeng\Documents\JavaShroud-acceptance-evidence-20260803\release-r3"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def method_identity(owner: str, name: str, descriptor: str) -> str:
    return "\0".join((owner, name, descriptor))


def semantic_id(owner: str, name: str, descriptor: str) -> str:
    return hashlib.sha256(method_identity(owner, name, descriptor).encode("utf-8")).hexdigest()


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))


def find_java_tool(name: str) -> str:
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / f"{name}.exe"
        if candidate.is_file():
            return str(candidate)
    resolved = shutil.which(name)
    if resolved:
        return resolved
    raise FileNotFoundError(f"Unable to locate {name}; set JAVA_HOME or add it to PATH")


def write_targets(case_root: Path, target_path: Path) -> list[dict[str, str]]:
    recovered = case_root / "recovered"
    token_map = read_json(recovered / "token_to_method.json")
    if not isinstance(token_map, dict):
        raise ValueError("CASE token_to_method.json must be an object")

    rows: list[dict[str, str]] = []
    for token in sorted(token_map):
        ir_path = recovered / "ir2" / f"{token}.json"
        ir = read_json(ir_path)
        metadata = ir.get("metadata") if isinstance(ir, dict) else None
        if not isinstance(metadata, dict):
            raise ValueError(f"Missing metadata in {ir_path}")
        if metadata.get("entryToken") != token:
            raise ValueError(f"Token mismatch in {ir_path}")
        row = {
            "token": token,
            "case_owner": str(metadata["originalOwner"]),
            "case_name": str(metadata["originalName"]),
            "case_descriptor": str(metadata["originalDesc"]),
        }
        rows.append(row)

    target_path.parent.mkdir(parents=True, exist_ok=True)
    with target_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        for row in rows:
            writer.writerow((row["token"], row["case_owner"], row["case_name"], row["case_descriptor"]))
    return rows


def compile_and_map(
    source: Path,
    asm_dir: Path,
    clean_jar: Path,
    reference_jar: Path,
    targets_path: Path,
    tsv_path: Path,
    classes_dir: Path,
) -> None:
    asm = asm_dir / "asm-9.8.jar"
    asm_tree = asm_dir / "asm-tree-9.8.jar"
    missing = [str(path) for path in (asm, asm_tree) if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing ASM dependency: " + ", ".join(missing))

    javac = find_java_tool("javac")
    java = find_java_tool("java")
    classes_dir.mkdir(parents=True, exist_ok=True)
    compile_cp = os.pathsep.join((str(asm), str(asm_tree)))
    run_cp = os.pathsep.join((str(classes_dir), str(asm), str(asm_tree)))
    subprocess.run(
        [javac, "-encoding", "UTF-8", "-cp", compile_cp, "-d", str(classes_dir), str(source)],
        check=True,
    )
    subprocess.run(
        [
            java,
            "-cp",
            run_cp,
            "CaseMethodIdentityMapper",
            str(clean_jar),
            str(reference_jar),
            str(targets_path),
            str(tsv_path),
        ],
        check=True,
    )


def tsv_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def evidence_identity_map(build_evidence: Path, case_report: Path) -> tuple[dict[str, str], set[str]]:
    build = read_json(build_evidence)
    report = read_json(case_report)
    if not isinstance(build, dict) or not isinstance(report, dict):
        raise ValueError("Build evidence and CASE report must be JSON objects")
    build_ids = {str(item["semantic_id"]) for item in build.get("methods", [])}
    artifact = report.get("artifact_method_evidence")
    if not isinstance(artifact, dict) or artifact.get("identity_mapping_status") != "complete":
        raise ValueError("CASE report lacks complete artifact method identity evidence")

    identities: dict[str, str] = {}
    for item in artifact.get("methods", []):
        owner = str(item["owner"])
        name = str(item["name"])
        descriptor = str(item["descriptor"])
        identity = method_identity(owner, name, descriptor)
        expected = semantic_id(owner, name, descriptor)
        actual = str(item["semantic_id"])
        if actual != expected:
            raise ValueError(f"Semantic ID mismatch for {owner}.{name}{descriptor}")
        if actual not in build_ids:
            raise ValueError(f"Semantic ID absent from build evidence: {actual}")
        if identities.setdefault(identity, actual) != actual:
            raise ValueError(f"Conflicting semantic IDs for {owner}.{name}{descriptor}")
    if len(identities) != len(build_ids):
        raise ValueError("Artifact identity map and build evidence method set differ")
    return identities, build_ids


def report_mapping(
    rows: list[dict[str, str]],
    inputs: dict[str, Path],
    identity_to_semantic_id: dict[str, str],
    protected_semantic_ids: set[str],
) -> dict[str, object]:
    mapping_rows: list[dict[str, object]] = []
    matched_reference_identities: list[str] = []
    mapped_semantic_ids: list[str] = []

    for row in rows:
        status = row["status"]
        reference_identity = None
        semantic = None
        protected = False
        if status == "matched":
            reference_identity = method_identity(
                row["reference_owner"], row["reference_name"], row["reference_descriptor"]
            )
            semantic = identity_to_semantic_id.get(reference_identity)
            protected = semantic in protected_semantic_ids if semantic else False
            if semantic:
                mapped_semantic_ids.append(semantic)
            matched_reference_identities.append(reference_identity)

        case_category = "reference-backed" if status == "matched" else classify_unmapped_case_method(row)
        mapping_rows.append(
            {
                "token": row["token"],
                "case_method": {
                    "owner": row["case_owner"],
                    "name": row["case_name"],
                    "descriptor": row["case_descriptor"],
                    "source_file": row["case_source_file"] or None,
                },
                "status": status,
                "case_identity_category": case_category,
                "match_tier": row["match_tier"] or None,
                "candidate_count": int(row["candidate_count"]),
                "candidate_identities": row["candidate_identities"].split("|") if row["candidate_identities"] else [],
                "candidate_scores": row["candidate_scores"].split("|") if row["candidate_scores"] else [],
                "reference_method": (
                    {
                        "owner": row["reference_owner"],
                        "name": row["reference_name"],
                        "descriptor": row["reference_descriptor"],
                        "source_file": row["reference_source_file"] or None,
                    }
                    if reference_identity
                    else None
                ),
                "r3_semantic_id": semantic,
                "r3_protected": protected,
                "case_strict_fingerprint": row["strict_fingerprint"] or None,
                "case_structural_fingerprint": row["structural_fingerprint"] or None,
            }
        )

    status_counts = Counter(row["status"] for row in rows)
    tier_counts = Counter(row["match_tier"] or "unmatched" for row in rows)
    category_counts = Counter(row["case_identity_category"] for row in mapping_rows)
    duplicate_reference_identities = sorted(
        identity for identity, count in Counter(matched_reference_identities).items() if count > 1
    )
    all_mapped_are_protected = bool(mapping_rows) and all(
        row["r3_protected"] for row in mapping_rows if row["status"] == "matched"
    )
    complete = (
        len(rows) == 142
        and status_counts == {"matched": 142}
        and len(duplicate_reference_identities) == 0
        and len(set(mapped_semantic_ids)) == 142
        and all_mapped_are_protected
    )

    return {
        "schema_version": 1,
        "kind": "case-fixed-142-reference-identity-mapping",
        "generated_at_utc": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "algorithm": {
            "engine": "ASM 9.8",
            "class_identity": "unique shared LDC string anchors, then high-margin method anchors",
            "method_identity": "normalized descriptor plus bytecode feature coverage; strict and structural fingerprints are retained per row",
            "acceptance": "only mapper status=matched participates in the protected semantic-ID intersection",
        },
        "inputs": {
            name: {"path": str(path), "sha256": sha256_file(path)} for name, path in inputs.items()
        },
        "fixed_case_set": {
            "token_count": len(rows),
            "status_counts": dict(sorted(status_counts.items())),
            "match_tier_counts": dict(sorted(tier_counts.items())),
            "identity_category_counts": dict(sorted(category_counts.items())),
            "matched_reference_method_count": len(matched_reference_identities),
            "matched_reference_unique_method_count": len(set(matched_reference_identities)),
            "duplicate_reference_identities": duplicate_reference_identities,
        },
        "r3_intersection": {
            "protected_semantic_id_count": len(protected_semantic_ids),
            "mapped_semantic_id_count": len(mapped_semantic_ids),
            "mapped_unique_semantic_id_count": len(set(mapped_semantic_ids)),
            "all_mapped_methods_protected": all_mapped_are_protected,
        },
        "release_gate": {
            "fixed_142_identity_mapping_complete": complete,
            "status": "pass" if complete else "blocked",
            "reason": (
                "All 142 fixed CASE tokens map one-to-one to protected reference identities."
                if complete
                else (
                    f"{status_counts.get('missing-case-method', 0)} CASE tokens are build-time helpers absent "
                    f"from the clean/reference JARs; only {len(set(mapped_semantic_ids))} reference-backed identities map to the protected set."
                )
            ),
        },
        "mappings": mapping_rows,
    }


def classify_unmapped_case_method(row: dict[str, str]) -> str:
    if row["status"] != "missing-case-method":
        return "unresolved-reference-identity"
    if row["case_name"].startswith("a_px"):
        return "removed-build-time-string-helper"
    if "Ljava/lang/invoke/MethodHandles$Lookup;" in row["case_descriptor"]:
        return "removed-build-time-invokedynamic-bootstrap"
    return "removed-case-method-unclassified"


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-root", type=Path, default=DEFAULT_CASE_ROOT)
    parser.add_argument("--reference-jar", type=Path, default=DEFAULT_REFERENCE_JAR)
    parser.add_argument("--release-root", type=Path, default=DEFAULT_RELEASE_ROOT)
    parser.add_argument("--clean-jar", type=Path)
    parser.add_argument("--build-evidence", type=Path)
    parser.add_argument("--case-report", type=Path)
    parser.add_argument("--asm-dir", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--require-complete", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    case_root = args.case_root.resolve()
    release_root = args.release_root.resolve()
    clean_jar = (args.clean_jar or case_root / "patches" / "SimpleFiveInARow-clean.jar").resolve()
    reference_jar = args.reference_jar.resolve()
    build_evidence = (
        args.build_evidence
        or release_root / "SimpleFiveInARow-max-hardening.build-evidence.json"
    ).resolve()
    case_report = (args.case_report or release_root / "case-report" / "max-hardening-case.json").resolve()
    output = (args.output or release_root / "case-report" / "case-fixed-142-method-mapping.json").resolve()
    work_dir = (args.work_dir or output.parent / "case-method-identity-mapper-work").resolve()
    asm_dir = (args.asm_dir or case_root / "deps").resolve()
    mapper_source = Path(__file__).with_name("CaseMethodIdentityMapper.java").resolve()

    required = (clean_jar, reference_jar, build_evidence, case_report, mapper_source)
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError("Missing required input: " + ", ".join(missing))

    targets_path = work_dir / "fixed-case-142-targets.tsv"
    mapper_tsv = work_dir / "case-fixed-142-method-mapping.tsv"
    target_rows = write_targets(case_root, targets_path)
    if len(target_rows) != 142:
        raise ValueError(f"Expected 142 CASE tokens, found {len(target_rows)}")
    compile_and_map(
        mapper_source,
        asm_dir,
        clean_jar,
        reference_jar,
        targets_path,
        mapper_tsv,
        work_dir / "classes",
    )
    rows = tsv_rows(mapper_tsv)
    if len(rows) != len(target_rows):
        raise ValueError(f"Mapper produced {len(rows)} rows for {len(target_rows)} targets")
    identity_to_semantic_id, protected_semantic_ids = evidence_identity_map(build_evidence, case_report)
    report = report_mapping(
        rows,
        {
            "case_clean_jar": clean_jar,
            "reference_jar": reference_jar,
            "r3_build_evidence": build_evidence,
            "r3_case_report": case_report,
            "mapper_source": mapper_source,
            "generated_case_targets": targets_path,
            "mapper_tsv": mapper_tsv,
        },
        identity_to_semantic_id,
        protected_semantic_ids,
    )
    write_json(output, report)
    print(
        json.dumps(
            {
                "report": str(output),
                "status": report["release_gate"]["status"],
                "status_counts": report["fixed_case_set"]["status_counts"],
                "mapped_unique_semantic_id_count": report["r3_intersection"]["mapped_unique_semantic_id_count"],
            },
            ensure_ascii=False,
        )
    )
    return 0 if not args.require_complete or report["release_gate"]["fixed_142_identity_mapping_complete"] else 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FileNotFoundError, ValueError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(2)
