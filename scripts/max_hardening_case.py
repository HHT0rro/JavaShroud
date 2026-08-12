#!/usr/bin/env python3
"""Read-only CASE acceptance runner for JavaShroud ``max-hardening`` artifacts.

The runner deliberately keeps all generated material outside ``CASE_ROOT``.  It
can inspect a supplied artifact and sidecar without changing the CASE fixture;
the optional legacy pipeline/RebuildJar executions use an isolated copy beneath
the report directory instead of invoking the CASE scripts in place.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT_DIR = REPOSITORY_ROOT / "build" / "reports" / "max-hardening-case"
REPORT_JSON_NAME = "max-hardening-case.json"
REPORT_MARKDOWN_NAME = "max-hardening-case.md"
ENTRY_SCAN_LIMIT = 4 * 1024 * 1024
TOTAL_SCAN_LIMIT = 64 * 1024 * 1024
MAX_SAMPLES = 64
COMMAND_OUTPUT_LIMIT = 16 * 1024
LEGACY_NATIVE_HEADER_MARKER = b"JS_NATIVE_MAX_PAYLOAD_V1\x00"
LEGACY_KEY_HELPER_MARKER = b"jsRrkS"
LEGACY_RESOURCE_MARKER = b"JSRP"


class RunnerError(RuntimeError):
    """An input/configuration error for which a CASE report cannot be trusted."""


MARKER_SPECS: tuple[tuple[str, bytes, bool], ...] = (
    ("legacy_jsbi", b"JSBI", False),
    ("fixed_bootstrap_path", b"META-INF/.r/0.dat", False),
    ("legacy_vbc4_manifest", b"VBC4S|1|", False),
    ("legacy_vbc4_family", b"VBC4S|", False),
    ("catalog_literal", b"catalog", True),
    ("manifest_literal", b"manifest", True),
    ("original_owner", b"originalOwner", False),
    ("original_name", b"originalName", False),
    ("original_descriptor", b"originalDesc", False),
    ("original_access", b"originalAccess", False),
    ("native_jsrp", b"JSRP", False),
    ("native_vm_symbol", b"js_vm_", True),
    ("sidecar_marker", b"JSBK", False),
)
NATIVE_MARKERS = {"legacy_jsbi", "legacy_vbc4_manifest", "native_jsrp", "native_vm_symbol", "sidecar_marker"}
NATIVE_SUFFIXES = {".dll", ".so", ".dylib", ".jnilib", ".exe"}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resolve_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve(strict=False)


def is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
    except ValueError:
        return False
    return True


def relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def append_error(errors: list[dict[str, Any]], scope: str, message: str, **details: Any) -> None:
    error: dict[str, Any] = {"scope": scope, "message": message}
    error.update(details)
    errors.append(error)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def describe_file(path: Path | None, errors: list[dict[str, Any]], scope: str) -> dict[str, Any]:
    if path is None:
        return {"status": "not_provided"}
    record: dict[str, Any] = {"path": str(path)}
    if not path.is_file():
        record["status"] = "missing"
        append_error(errors, scope, "File does not exist or is not a regular file.", path=str(path))
        return record
    try:
        stat = path.stat()
        record.update({"status": "present", "size": stat.st_size, "sha256": sha256_file(path)})
    except OSError as exc:
        record["status"] = "error"
        append_error(errors, scope, "Unable to read file metadata or SHA-256.", path=str(path), error=str(exc))
    return record


def sample_paths(case_root: Path) -> list[Path]:
    originals = case_root / "originals"
    if not originals.is_dir():
        return []
    return sorted((path for path in originals.rglob("*.jar") if path.is_file()), key=lambda path: path.as_posix().lower())


def read_prefix(path: Path, limit: int) -> bytes:
    with path.open("rb") as handle:
        return handle.read(limit)


def marker_stats() -> dict[str, dict[str, Any]]:
    return {name: {"count": 0, "samples": []} for name, _, _ in MARKER_SPECS}


def record_marker(
    stats: dict[str, dict[str, Any]],
    marker_name: str,
    entry: str,
    offset: int,
    count: int,
) -> None:
    stat = stats[marker_name]
    stat["count"] += count
    if len(stat["samples"]) < MAX_SAMPLES:
        stat["samples"].append({"entry": entry, "offset": offset})


def inspect_markers(stats: dict[str, dict[str, Any]], entry: str, data: bytes) -> None:
    lower_data: bytes | None = None
    for marker_name, marker, casefold in MARKER_SPECS:
        haystack = data
        needle = marker
        if casefold:
            if lower_data is None:
                lower_data = data.lower()
            haystack = lower_data
            needle = marker.lower()
        count = haystack.count(needle)
        if count:
            record_marker(stats, marker_name, entry, haystack.find(needle), count)


def looks_like_native(name: str, data: bytes) -> bool:
    lower_name = name.lower()
    return (
        Path(lower_name).suffix in NATIVE_SUFFIXES
        or lower_name.startswith("native/")
        or "/native/" in lower_name
        or data.startswith(b"MZ")
        or data.startswith(b"\x7fELF")
        or data[:4] in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"}
    )


def scan_artifact(artifact: Path | None, errors: list[dict[str, Any]]) -> dict[str, Any]:
    """Collect bounded static evidence from a JAR/ZIP or a standalone binary."""

    result: dict[str, Any] = {
        "artifact": describe_file(artifact, errors, "artifact"),
        "status": "not_provided" if artifact is None else "not_scanned",
        "markers": marker_stats(),
        "native_markers": marker_stats(),
        "entry_name_hits": {
            "fixed_bootstrap_path": {"count": 0, "samples": []},
            "jsbi": {"count": 0, "samples": []},
            "manifest_catalog": {"count": 0, "samples": []},
            "ordinary_manifest": {"count": 0, "samples": []},
        },
        "native_entry_count": 0,
        "native_entries": [],
        "scan_limits": {"per_entry_bytes": ENTRY_SCAN_LIMIT, "total_bytes": TOTAL_SCAN_LIMIT},
        "truncated_entries": [],
        "entry_errors": [],
    }
    if artifact is None or result["artifact"]["status"] != "present":
        result["status"] = "not_available"
        return result

    def add_name_hit(kind: str, name: str) -> None:
        stat = result["entry_name_hits"][kind]
        stat["count"] += 1
        if len(stat["samples"]) < MAX_SAMPLES:
            stat["samples"].append(name)

    def inspect_entry(name: str, data: bytes, size: int) -> None:
        inspect_markers(result["markers"], name, data)
        if looks_like_native(name, data):
            result["native_entry_count"] += 1
            if len(result["native_entries"]) < MAX_SAMPLES:
                result["native_entries"].append(
                    {"entry": name, "size": size, "magic": data[:4].hex()}
                )
            native_stats = marker_stats()
            inspect_markers(native_stats, name, data)
            for marker_name in NATIVE_MARKERS:
                source = native_stats[marker_name]
                if source["count"]:
                    destination = result["native_markers"][marker_name]
                    destination["count"] += source["count"]
                    remaining = MAX_SAMPLES - len(destination["samples"])
                    destination["samples"].extend(source["samples"][:remaining])

    if zipfile.is_zipfile(artifact):
        result["format"] = "zip"
        total_scanned = 0
        try:
            with zipfile.ZipFile(artifact) as archive:
                infos = archive.infolist()
                result["entry_count"] = len(infos)
                for info in infos:
                    if info.is_dir():
                        continue
                    name = info.filename
                    lower_name = name.lower()
                    if lower_name == "meta-inf/.r/0.dat":
                        add_name_hit("fixed_bootstrap_path", name)
                    if "jsbi" in lower_name:
                        add_name_hit("jsbi", name)
                    if lower_name == "meta-inf/manifest.mf":
                        add_name_hit("ordinary_manifest", name)
                    if any(token in lower_name for token in ("manifest", "catalog", "bootstrap", "index")):
                        add_name_hit("manifest_catalog", name)

                    remaining = TOTAL_SCAN_LIMIT - total_scanned
                    if remaining <= 0:
                        if len(result["truncated_entries"]) < MAX_SAMPLES:
                            result["truncated_entries"].append({"entry": name, "reason": "total_scan_limit"})
                        continue
                    limit = min(info.file_size, ENTRY_SCAN_LIMIT, remaining)
                    if info.file_size > limit and len(result["truncated_entries"]) < MAX_SAMPLES:
                        result["truncated_entries"].append(
                            {"entry": name, "size": info.file_size, "scanned_bytes": limit}
                        )
                    try:
                        with archive.open(info) as handle:
                            data = handle.read(limit)
                    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                        if len(result["entry_errors"]) < MAX_SAMPLES:
                            result["entry_errors"].append({"entry": name, "error": str(exc)})
                        continue
                    total_scanned += len(data)
                    inspect_entry(name, data, info.file_size)
        except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
            result["status"] = "error"
            append_error(errors, "artifact", "Unable to inspect ZIP/JAR entries.", path=str(artifact), error=str(exc))
            return result
    else:
        result["format"] = "binary"
        try:
            stat = artifact.stat()
            data = read_prefix(artifact, min(stat.st_size, TOTAL_SCAN_LIMIT))
            if stat.st_size > len(data):
                result["truncated_entries"].append(
                    {"entry": artifact.name, "size": stat.st_size, "scanned_bytes": len(data)}
                )
            inspect_entry(artifact.name, data, stat.st_size)
        except OSError as exc:
            result["status"] = "error"
            append_error(errors, "artifact", "Unable to inspect binary artifact.", path=str(artifact), error=str(exc))
            return result

    result["status"] = "scanned"
    return result


def scan_sidecar(sidecar: Path | None, errors: list[dict[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {"file": describe_file(sidecar, errors, "sidecar"), "status": "not_provided"}
    if sidecar is None:
        return result
    if result["file"]["status"] != "present":
        result["status"] = "error"
        return result
    try:
        data = read_prefix(sidecar, 64 * 1024)
    except OSError as exc:
        result["status"] = "error"
        append_error(errors, "sidecar", "Unable to inspect sidecar prefix.", path=str(sidecar), error=str(exc))
        return result

    stripped = data.strip()
    result["prefix_hex"] = data[:8].hex()
    if data.startswith(b"JSBK1."):
        result.update({"status": "authenticated_envelope", "format": "JSBK1 text envelope"})
        encoded = data[len(b"JSBK1.") :].strip()
        try:
            decoded = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
            result["base64url_valid"] = True
            result["inner_magic"] = decoded[:4].decode("ascii", "replace")
        except (ValueError, UnicodeError) as exc:
            result.update({"status": "malformed", "base64url_valid": False, "error": str(exc)})
    elif data.startswith(b"JSBK"):
        result.update({"status": "authenticated_envelope", "format": "JSBK binary envelope"})
        if len(data) >= 5:
            result["version_byte"] = data[4]
    elif len(stripped) == 64 and re.fullmatch(rb"[0-9a-fA-F]{64}", stripped):
        result.update({"status": "legacy_raw_material", "format": "bare 64-hex secret"})
    elif len(stripped) == 32:
        result.update({"status": "legacy_raw_material", "format": "raw 32-byte secret"})
    else:
        result.update({"status": "unknown", "format": "unrecognized sidecar"})
    result["artifact_binding"] = "not decrypted or disclosed by the runner"
    return result


def count_marker(scan: Mapping[str, Any], marker_name: str) -> int:
    return int(scan["markers"][marker_name]["count"])


def build_static_scans(artifact_scan: Mapping[str, Any], sidecar: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    if artifact_scan.get("status") != "scanned":
        unavailable = {
            "status": "not_run",
            "reason": "A readable --artifact is required for artifact static scanning.",
        }
        scans = {f"W{number}": dict(unavailable) for number in range(1, 6)}
    else:
        fixed_path_names = artifact_scan["entry_name_hits"]["fixed_bootstrap_path"]
        fixed_path_count = count_marker(artifact_scan, "fixed_bootstrap_path") + int(fixed_path_names["count"])
        jsbi_count = count_marker(artifact_scan, "legacy_jsbi") + int(artifact_scan["entry_name_hits"]["jsbi"]["count"])
        legacy_manifest_count = count_marker(artifact_scan, "legacy_vbc4_manifest")
        legacy_family_count = count_marker(artifact_scan, "legacy_vbc4_family")
        identity_count = sum(
            count_marker(artifact_scan, marker)
            for marker in ("original_owner", "original_name", "original_descriptor", "original_access")
        )
        catalog_count = count_marker(artifact_scan, "catalog_literal")
        manifest_count = count_marker(artifact_scan, "manifest_literal")
        native_markers = artifact_scan["native_markers"]
        native_legacy_count = sum(int(native_markers[name]["count"]) for name in ("legacy_jsbi", "legacy_vbc4_manifest", "native_jsrp"))

        scans = {
            "W1": {
                "name": "Legacy JSBI bootstrap index",
                "status": "fail" if jsbi_count else "pass",
                "count": jsbi_count,
                "content_hits": artifact_scan["markers"]["legacy_jsbi"],
                "entry_name_hits": artifact_scan["entry_name_hits"]["jsbi"],
            },
            "W2": {
                "name": "Fixed META-INF/.r/0.dat resource path",
                "status": "fail" if fixed_path_count else "pass",
                "count": fixed_path_count,
                "content_hits": artifact_scan["markers"]["fixed_bootstrap_path"],
                "entry_name_hits": fixed_path_names,
            },
            "W3": {
                "name": "Legacy VBC4S|1| manifest protocol",
                "status": "fail" if legacy_manifest_count else "pass",
                "count": legacy_manifest_count,
                "content_hits": artifact_scan["markers"]["legacy_vbc4_manifest"],
            },
            "W4": {
                "name": "Manifest/catalog and method-identity exposure",
                "status": "fail" if legacy_family_count or identity_count else ("observed" if catalog_count or manifest_count else "clear"),
                "count": legacy_family_count + identity_count,
                "legacy_vbc4_family": artifact_scan["markers"]["legacy_vbc4_family"],
                "identity_field_count": identity_count,
                "catalog_literal": artifact_scan["markers"]["catalog_literal"],
                "manifest_literal": artifact_scan["markers"]["manifest_literal"],
                "resource_name_hits": artifact_scan["entry_name_hits"]["manifest_catalog"],
                "ordinary_jar_manifest_entries": artifact_scan["entry_name_hits"]["ordinary_manifest"],
            },
            "W5": {
                "name": "Native payload marker exposure",
                "status": "fail" if native_legacy_count else ("observed" if artifact_scan["native_entry_count"] else "not_found"),
                "count": native_legacy_count,
                "native_entry_count": artifact_scan["native_entry_count"],
                "native_entries": artifact_scan["native_entries"],
                "native_markers": {name: native_markers[name] for name in sorted(NATIVE_MARKERS)},
            },
        }

    sidecar_status = str(sidecar.get("status", "not_provided"))
    scans["W6"] = {
        "name": "Boot sidecar format",
        "status": "fail" if sidecar_status == "legacy_raw_material" else sidecar_status,
        "count": 1 if sidecar_status not in {"not_provided", "error"} else 0,
        "sidecar": dict(sidecar),
    }
    return scans


def read_json(path: Path, errors: list[dict[str, Any]], scope: str) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        append_error(errors, scope, "Unable to parse JSON evidence.", path=str(path), error=str(exc))
        return None


class ClassFileError(ValueError):
    pass


class ClassFileCursor:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def take(self, size: int) -> bytes:
        if size < 0 or self.offset > len(self.data) - size:
            raise ClassFileError("truncated classfile")
        value = self.data[self.offset : self.offset + size]
        self.offset += size
        return value

    def u1(self) -> int:
        return self.take(1)[0]

    def u2(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u4(self) -> int:
        return int.from_bytes(self.take(4), "big")


def skip_class_attributes(cursor: ClassFileCursor) -> None:
    for _ in range(cursor.u2()):
        cursor.take(2)
        cursor.take(cursor.u4())


def parse_class_methods(data: bytes) -> list[dict[str, Any]]:
    cursor = ClassFileCursor(data)
    if cursor.u4() != 0xCAFEBABE:
        raise ClassFileError("invalid classfile magic")
    cursor.take(4)  # minor + major
    constant_pool_count = cursor.u2()
    constant_pool: list[Any] = [None] * constant_pool_count
    index = 1
    while index < constant_pool_count:
        tag = cursor.u1()
        if tag == 1:
            constant_pool[index] = cursor.take(cursor.u2()).decode("utf-8", errors="replace")
        elif tag in (3, 4):
            cursor.take(4)
        elif tag in (5, 6):
            cursor.take(8)
            index += 1
        elif tag == 7:
            constant_pool[index] = ("class", cursor.u2())
        elif tag in (8, 16, 19, 20):
            cursor.take(2)
        elif tag in (9, 10, 11, 12, 17, 18):
            cursor.take(4)
        elif tag == 15:
            cursor.take(3)
        else:
            raise ClassFileError(f"unsupported constant-pool tag {tag}")
        index += 1

    cursor.take(2)  # class access
    this_class = cursor.u2()
    cursor.take(2)  # super class
    class_entry = constant_pool[this_class] if 0 < this_class < len(constant_pool) else None
    if not isinstance(class_entry, tuple) or class_entry[0] != "class":
        raise ClassFileError("invalid this_class entry")
    owner = constant_pool[class_entry[1]] if 0 < class_entry[1] < len(constant_pool) else None
    if not isinstance(owner, str):
        raise ClassFileError("invalid class name entry")

    cursor.take(cursor.u2() * 2)  # interfaces
    for _ in range(cursor.u2()):
        cursor.take(6)
        skip_class_attributes(cursor)

    methods: list[dict[str, Any]] = []
    for _ in range(cursor.u2()):
        access = cursor.u2()
        name_index = cursor.u2()
        descriptor_index = cursor.u2()
        name = constant_pool[name_index] if 0 < name_index < len(constant_pool) else None
        descriptor = constant_pool[descriptor_index] if 0 < descriptor_index < len(constant_pool) else None
        if not isinstance(name, str) or not isinstance(descriptor, str):
            raise ClassFileError("invalid method identity entry")
        methods.append({"owner": owner, "name": name, "descriptor": descriptor, "access": access})
        skip_class_attributes(cursor)
    return methods


def reference_method_identities(reference_jar: Path | None, errors: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if reference_jar is None or not reference_jar.is_file():
        return {}
    identities: dict[str, dict[str, Any]] = {}
    try:
        with zipfile.ZipFile(reference_jar) as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.endswith(".class"):
                    continue
                try:
                    methods = parse_class_methods(archive.read(info))
                except (ClassFileError, OSError, RuntimeError) as exc:
                    append_error(
                        errors,
                        "reference_jar",
                        "Unable to parse a reference classfile.",
                        path=str(reference_jar),
                        entry=info.filename,
                        error=str(exc),
                    )
                    continue
                for method in methods:
                    semantic_id = hashlib.sha256(
                        f"{method['owner']}\0{method['name']}\0{method['descriptor']}".encode("utf-8")
                    ).hexdigest()
                    identities[semantic_id] = method
    except (OSError, zipfile.BadZipFile) as exc:
        append_error(errors, "reference_jar", "Unable to inspect reference JAR.", path=str(reference_jar), error=str(exc))
    return identities


def parse_rebuild_count(report_path: Path) -> int | None:
    if not report_path.is_file():
        return None
    try:
        match = re.search(
            r"^methods devirtualized:\s*(\d+)\s*$",
            report_path.read_text(encoding="utf-8", errors="replace"),
            flags=re.MULTILINE,
        )
    except OSError:
        return None
    return int(match.group(1)) if match else None


def high_value_recovery_matrix(
    case_root: Path,
    errors: list[dict[str, Any]],
    scope: str = "case_recovery",
    target_methods: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a matrix from the CASE's VBC4 catalog and IR material if present."""

    recovered = case_root / "recovered"
    vbc4_index_path = recovered / "vbc4_index.json"
    token_map_path = recovered / "token_to_method.json"
    source = "fixed CASE high-value target manifest" if target_methods else None
    tokens: list[str] = sorted(str(token) for token in target_methods) if target_methods else []
    vbc4_index: Mapping[str, Any] = {}
    if vbc4_index_path.is_file():
        value = read_json(vbc4_index_path, errors, scope)
        if isinstance(value, dict):
            vbc4_index = value
            if not tokens:
                tokens = sorted(str(token) for token in value)
                source = relative_path(vbc4_index_path, case_root)
        elif value is not None:
            append_error(errors, scope, "VBC4 index is not a JSON object.", path=str(vbc4_index_path))

    token_map: Mapping[str, Any] = {}
    if token_map_path.is_file():
        value = read_json(token_map_path, errors, scope)
        if isinstance(value, dict):
            token_map = value
            if not tokens:
                tokens = sorted(str(token) for token in value)
                source = relative_path(token_map_path, case_root)
        elif value is not None:
            append_error(errors, scope, "Token map is not a JSON object.", path=str(token_map_path))

    vbc4_dir = recovered / "vbc4"
    ir_dir = recovered / "ir2"
    recovered_vbc4_files = sorted(vbc4_dir.glob("*.vbc4")) if vbc4_dir.is_dir() else []
    recovered_ir_files = sorted(ir_dir.glob("*.json")) if ir_dir.is_dir() else []

    if not tokens:
        if recovered_vbc4_files:
            tokens = sorted(path.stem for path in recovered_vbc4_files)
            if tokens:
                source = relative_path(vbc4_dir, case_root)
    if not tokens:
        if recovered_ir_files:
            tokens = sorted(path.stem for path in recovered_ir_files)
            if tokens:
                source = relative_path(ir_dir, case_root)

    has_recovery_material = bool(vbc4_index or recovered_vbc4_files or recovered_ir_files)
    if not tokens or not has_recovery_material:
        matrix: list[dict[str, Any]] = []
        if tokens:
            for token in tokens:
                target_info = (target_methods or {}).get(token, {})
                if not isinstance(target_info, Mapping):
                    target_info = {}
                matrix.append(
                    {
                        "token": token,
                        "class": target_info.get("class"),
                        "method": target_info.get("method"),
                        "vbc4_present": False,
                        "ir_json_present": False,
                        "ir_json_valid": None,
                        "ir_text_present": False,
                        "file_evidence_complete": False,
                        "catalog_resource": None,
                    }
                )
        return {
            "status": "not_available",
            "reason": "No recovered VBC4 container or IR JSON was produced; recovery count is not measured.",
            "expected_count": len(tokens),
            "high_value_target_count": len(tokens),
            "recovery_measurement": "not_measured",
            "complete_recovery_evidence_count": None,
            "matrix": matrix,
        }

    matrix: list[dict[str, Any]] = []
    invalid_ir_json: list[str] = []
    for token in tokens:
        ir_json_path = ir_dir / f"{token}.json"
        ir_text_path = ir_dir / f"{token}.ir"
        vbc4_path = vbc4_dir / f"{token}.vbc4"
        ir_json_valid: bool | None = None
        if ir_json_path.is_file():
            try:
                json.loads(ir_json_path.read_text(encoding="utf-8"))
                ir_json_valid = True
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                ir_json_valid = False
                if len(invalid_ir_json) < MAX_SAMPLES:
                    invalid_ir_json.append(token)
        token_info = token_map.get(token, {}) if isinstance(token_map.get(token, {}), dict) else {}
        if not token_info and target_methods is not None and isinstance(target_methods.get(token, {}), dict):
            token_info = target_methods[token]
        catalog_info = vbc4_index.get(token, {}) if isinstance(vbc4_index.get(token, {}), dict) else {}
        complete = bool(ir_json_valid and ir_text_path.is_file() and ir_text_path.stat().st_size > 0)
        matrix.append(
            {
                "token": token,
                "class": token_info.get("class"),
                "method": token_info.get("method"),
                "vbc4_present": vbc4_path.is_file(),
                "ir_json_present": ir_json_path.is_file(),
                "ir_json_valid": ir_json_valid,
                "ir_text_present": ir_text_path.is_file(),
                "file_evidence_complete": complete,
                "catalog_resource": catalog_info.get("resource"),
            }
        )

    complete_count = sum(1 for row in matrix if row["file_evidence_complete"])
    rebuild_report = case_root / "report" / "rebuild_report.txt"
    rebuilt_artifacts = [
        describe_file(path, errors, scope)
        for path in sorted((case_root / "patches").glob("*.jar"))
        if path.is_file()
    ] if (case_root / "patches").is_dir() else []
    return {
        "status": "available",
        "source": source,
        "expected_count": len(tokens),
        "high_value_target_count": len(tokens),
        "recovery_measurement": "file_evidence",
        "complete_recovery_evidence_count": complete_count,
        "ir_json_count": sum(1 for row in matrix if row["ir_json_present"]),
        "ir_text_count": sum(1 for row in matrix if row["ir_text_present"]),
        "invalid_ir_json_tokens": invalid_ir_json,
        "reported_methods_devirtualized": parse_rebuild_count(rebuild_report),
        "rebuilt_artifacts": rebuilt_artifacts,
        "matrix": matrix,
    }


def default_build_evidence_path(artifact: Path | None) -> Path | None:
    if artifact is None:
        return None
    return artifact.with_name(f"{artifact.stem}.build-evidence.json")


def artifact_method_evidence(
    artifact: Path | None,
    evidence_path: Path | None,
    reference_jar: Path | None,
    high_value_target_count: int,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    """Validate the external production-build evidence paired with an artifact.

    The evidence intentionally contains semantic hashes rather than plaintext
    owner/name/descriptor tuples.  It proves which build-local method records
    reached the final authenticated catalog without weakening the artifact's
    identity-confidentiality contract.
    """

    if artifact is None:
        return {"status": "not_available", "reason": "No artifact was supplied."}
    if evidence_path is None or not evidence_path.is_file():
        return {
            "status": "missing",
            "path": str(evidence_path) if evidence_path is not None else None,
            "high_value_target_count": high_value_target_count,
            "protected_method_count": 0,
            "protected_method_count_meets_target": False,
        }
    value = read_json(evidence_path, errors, "build_evidence")
    if not isinstance(value, dict):
        return {"status": "invalid", "path": str(evidence_path)}

    candidate_hash = value.get("candidate_jar_sha256")
    artifact_hash = sha256_file(artifact) if artifact.is_file() else None
    raw_methods = value.get("methods")
    methods = raw_methods if isinstance(raw_methods, list) else []
    semantic_ids: list[str] = []
    invalid_rows = 0
    for method in methods:
        semantic_id = method.get("semantic_id") if isinstance(method, dict) else None
        if isinstance(semantic_id, str) and re.fullmatch(r"[0-9a-f]{64}", semantic_id):
            semantic_ids.append(semantic_id)
        else:
            invalid_rows += 1
    unique_ids = sorted(set(semantic_ids))
    hash_matches = isinstance(candidate_hash, str) and artifact_hash == candidate_hash.lower()
    status = "valid" if hash_matches and invalid_rows == 0 and len(unique_ids) == len(methods) else "invalid"
    if not hash_matches:
        append_error(
            errors,
            "build_evidence",
            "Candidate build evidence does not match the supplied artifact hash.",
            path=str(evidence_path),
            expected=artifact_hash,
            actual=candidate_hash,
        )
    if invalid_rows or len(unique_ids) != len(methods):
        append_error(
            errors,
            "build_evidence",
            "Candidate build evidence contains invalid or duplicate method rows.",
            path=str(evidence_path),
            method_rows=len(methods),
            unique_semantic_ids=len(unique_ids),
            invalid_rows=invalid_rows,
        )
    protected_count = len(unique_ids)
    reference_identities = reference_method_identities(reference_jar, errors)
    identified_methods = [
        {"semantic_id": semantic_id, **reference_identities[semantic_id]}
        for semantic_id in unique_ids
        if semantic_id in reference_identities
    ]
    unmatched_ids = [semantic_id for semantic_id in unique_ids if semantic_id not in reference_identities]
    return {
        "status": status,
        "file": describe_file(evidence_path, errors, "build_evidence"),
        "candidate_jar_sha256": candidate_hash,
        "artifact_sha256": artifact_hash,
        "artifact_hash_matches": hash_matches,
        "identity_format": "sha256(owner\\0name\\0descriptor)",
        "reference_jar": describe_file(reference_jar, errors, "reference_jar") if reference_jar is not None else None,
        "identity_mapping_status": "complete" if reference_identities and not unmatched_ids else ("partial" if identified_methods else "not_available"),
        "identified_method_count": len(identified_methods),
        "unmatched_semantic_ids": unmatched_ids,
        "methods": identified_methods,
        "high_value_target_count": high_value_target_count,
        "protected_method_count": protected_count,
        "protected_method_count_meets_target": protected_count >= high_value_target_count > 0,
        "semantic_ids": unique_ids,
    }


def truncate_output(data: bytes) -> str:
    if len(data) > COMMAND_OUTPUT_LIMIT:
        data = data[:COMMAND_OUTPUT_LIMIT] + b"\n... output truncated by runner ...\n"
    return data.decode("utf-8", errors="replace")


def run_command(label: str, argv: Sequence[str], cwd: Path, timeout: int, env: Mapping[str, str] | None = None) -> dict[str, Any]:
    started_at = utc_now()
    started = time.monotonic()
    result: dict[str, Any] = {
        "label": label,
        "argv": list(argv),
        "cwd": str(cwd),
        "started_at_utc": started_at,
    }
    try:
        completed = subprocess.run(
            list(argv),
            cwd=str(cwd),
            env=dict(env) if env is not None else None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        result.update(
            {
                "status": "failed",
                "error": f"Timed out after {timeout} seconds.",
                "stdout": truncate_output(exc.stdout or b""),
                "stderr": truncate_output(exc.stderr or b""),
            }
        )
    except OSError as exc:
        result.update({"status": "failed", "error": str(exc)})
    else:
        result.update(
            {
                "status": "passed" if completed.returncode == 0 else "failed",
                "exit_code": completed.returncode,
                "stdout": truncate_output(completed.stdout),
                "stderr": truncate_output(completed.stderr),
            }
        )
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    return result


def make_workspace(report_dir: Path, prefix: str) -> Path:
    runs = report_dir / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    base = f"{prefix}-{datetime.now().strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"
    for suffix in range(1000):
        candidate = runs / (base if suffix == 0 else f"{base}-{suffix}")
        try:
            candidate.mkdir()
            return candidate
        except FileExistsError:
            continue
    raise RunnerError("Unable to create a unique run workspace under the report directory.")


def copy_tree(source: Path, destination: Path) -> None:
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def pipeline_step(label: str, status: str, phase: str, **details: Any) -> dict[str, Any]:
    result: dict[str, Any] = {"label": label, "status": status, "phase": phase}
    result.update(details)
    return result


def pipeline_blocked(label: str, phase: str, reason: str, **details: Any) -> dict[str, Any]:
    return pipeline_step(label, "blocked", phase, reason=reason, **details)


def extract_pipeline_jar(artifact: Path, destination: Path) -> dict[str, Any]:
    """Extract the staged JAR without allowing member paths to leave the workspace."""

    try:
        with zipfile.ZipFile(artifact) as archive:
            extracted_files = 0
            uncompressed_size = 0
            for info in archive.infolist():
                if info.is_dir():
                    continue
                member = PurePosixPath(info.filename.replace("\\", "/"))
                if member.is_absolute() or ".." in member.parts or not member.parts:
                    raise RunnerError(f"Unsafe archive member path: {info.filename}")
                target = destination.joinpath(*member.parts)
                if not is_within(target.resolve(strict=False), destination.resolve(strict=False)):
                    raise RunnerError(f"Archive member escapes extraction directory: {info.filename}")
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)
                extracted_files += 1
                uncompressed_size += info.file_size
    except (OSError, RunnerError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        return pipeline_step("extract-jar", "failed", "pre-extraction", error=str(exc))
    return pipeline_step(
        "extract-jar",
        "passed",
        "pre-extraction",
        extraction_root=str(destination),
        extracted_file_count=extracted_files,
        uncompressed_size=uncompressed_size,
    )


def discover_pipeline_native_payloads(extracted_root: Path, recovered: Path) -> dict[str, Any]:
    native_entries: list[dict[str, Any]] = []
    legacy_header_paths: list[Path] = []
    legacy_header_versions: list[int | None] = []
    for path in sorted(path for path in extracted_root.rglob("*") if path.is_file()):
        try:
            prefix = read_prefix(path, 8)
        except OSError:
            continue
        entry = relative_path(path, extracted_root)
        if not looks_like_native(entry, prefix):
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        native_entries.append({"entry": entry, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        marker_offset = data.find(LEGACY_NATIVE_HEADER_MARKER)
        if marker_offset >= 0:
            legacy_header_paths.append(path)
            version_offset = marker_offset + len(LEGACY_NATIVE_HEADER_MARKER)
            version = int.from_bytes(data[version_offset : version_offset + 4], "little")
            legacy_header_versions.append(version if len(data) >= version_offset + 4 else None)

    selected_header = None
    if len(legacy_header_paths) == 1:
        selected_header = recovered / "outer_stub.dll"
        shutil.copy2(legacy_header_paths[0], selected_header)
    return pipeline_step(
        "discover-native-payloads",
        "passed",
        "pre-extraction",
        native_entry_count=len(native_entries),
        native_entries=native_entries[:MAX_SAMPLES],
        legacy_native_header_count=len(legacy_header_paths),
        legacy_native_header_versions=legacy_header_versions,
        legacy_outer_stub=str(selected_header) if selected_header is not None else None,
    )


def discover_legacy_key_helpers(extracted_root: Path) -> list[str]:
    helpers: list[str] = []
    for path in sorted(extracted_root.rglob("*.class")):
        try:
            if LEGACY_KEY_HELPER_MARKER not in path.read_bytes():
                continue
        except OSError:
            continue
        helpers.append(relative_path(path, extracted_root)[:-len(".class")])
    return helpers


def read_pipeline_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def has_nonempty_mapping(path: Path) -> bool:
    value = read_pipeline_json(path)
    return isinstance(value, dict) and bool(value)


def has_legacy_partition_keys(path: Path) -> bool:
    value = read_pipeline_json(path)
    if not isinstance(value, dict):
        return False
    slots = value.get("slots")
    anchor_slot = value.get("anchorSlot")
    return isinstance(slots, dict) and bool(slots) and anchor_slot is not None and str(anchor_slot) in slots


def has_legacy_native_secrets(path: Path) -> bool:
    value = read_pipeline_json(path)
    return (
        isinstance(value, dict)
        and isinstance(value.get("masterKey"), str)
        and isinstance(value.get("layoutDigest"), str)
    )


def has_nonempty_list(path: Path) -> bool:
    value = read_pipeline_json(path)
    return isinstance(value, list) and bool(value)


def has_legacy_jsrp_resources(extracted_root: Path) -> int:
    count = 0
    for path in extracted_root.rglob("*"):
        if not path.is_file() or path.suffix == ".class":
            continue
        try:
            if read_prefix(path, len(LEGACY_RESOURCE_MARKER)) == LEGACY_RESOURCE_MARKER:
                count += 1
        except OSError:
            continue
    return count


def rebase_copied_legacy_case_paths(scripts: Path, stage: Path) -> int:
    """Keep the copied legacy scripts inside the isolated report workspace."""

    source_root = r"E:\javashroud-reTest\CASE"
    destination_root = str(stage)
    replacements = (
        (source_root, destination_root),
        (source_root.replace("\\", "\\\\"), destination_root.replace("\\", "\\\\")),
    )
    changed = 0
    for path in scripts.glob("*.py"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        updated = text
        for source, destination in replacements:
            updated = updated.replace(source, destination)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed += 1
    return changed


def run_command_to_file(
    label: str,
    argv: Sequence[str],
    cwd: Path,
    timeout: int,
    stdout_path: Path,
) -> dict[str, Any]:
    started_at = utc_now()
    started = time.monotonic()
    result: dict[str, Any] = {
        "label": label,
        "argv": list(argv),
        "cwd": str(cwd),
        "started_at_utc": started_at,
        "stdout_file": str(stdout_path),
    }
    try:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        with stdout_path.open("wb") as output:
            completed = subprocess.run(
                list(argv),
                cwd=str(cwd),
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.PIPE,
                check=False,
                timeout=timeout,
            )
    except subprocess.TimeoutExpired as exc:
        result.update(
            {
                "status": "failed",
                "error": f"Timed out after {timeout} seconds.",
                "stderr": truncate_output(exc.stderr or b""),
            }
        )
    except OSError as exc:
        result.update({"status": "failed", "error": str(exc)})
    else:
        result.update(
            {
                "status": "passed" if completed.returncode == 0 else "failed",
                "exit_code": completed.returncode,
                "stderr": truncate_output(completed.stderr),
            }
        )
    if stdout_path.is_file():
        result["stdout_file_size"] = stdout_path.stat().st_size
    result["duration_seconds"] = round(time.monotonic() - started, 3)
    return result


def run_verify(
    args: argparse.Namespace,
    artifact: Path | None,
    sidecar: Path | None,
    report_dir: Path,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    if not args.run_verify:
        return {"status": "not_requested"}
    if artifact is None or not artifact.is_file():
        return {"status": "failed", "error": "--run-verify requires a readable --artifact."}
    try:
        workspace = make_workspace(report_dir, "verify")
        staged_artifact = workspace / artifact.name
        shutil.copy2(artifact, staged_artifact)
        staged_sidecar = None
        if sidecar is not None and sidecar.is_file():
            staged_sidecar = workspace / sidecar.name
            shutil.copy2(sidecar, staged_sidecar)
    except (OSError, RunnerError) as exc:
        append_error(errors, "verify", "Unable to create isolated verification workspace.", error=str(exc))
        return {"status": "failed", "error": str(exc)}
    environment = os.environ.copy()
    sidecar_env = None
    if staged_sidecar is not None:
        sidecar_env = "JAVASHROUD_BOOT_SECRET_FILE_V1"
        environment[sidecar_env] = str(staged_sidecar)
    result = run_command(
        "java -Xverify:all",
        [
            args.java,
            "-Xverify:all",
            "-jar",
            str(staged_artifact),
            *([] if args.verify_raw else ["--diagnostics-only"]),
        ],
        workspace,
        args.command_timeout,
        environment,
    )
    result["sidecar_environment_variable"] = sidecar_env
    result["workspace"] = str(workspace)
    result["source_case_mutated"] = False
    return result


def run_rebuild(
    args: argparse.Namespace,
    case_root: Path,
    artifact: Path | None,
    report_dir: Path,
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    if not args.run_rebuild:
        return {"status": "not_requested"}
    if artifact is None or not artifact.is_file():
        return {"status": "failed", "error": "--run-rebuild requires a readable --artifact."}
    class_file = case_root / "build" / "RebuildJar.class"
    recovered = case_root / "recovered"
    dependencies = sorted((case_root / "deps").glob("*.jar")) if (case_root / "deps").is_dir() else []
    if not class_file.is_file() or not recovered.is_dir() or not dependencies:
        return {
            "status": "failed",
            "error": "CASE RebuildJar.class, recovered/, or deps/*.jar is missing.",
            "class_file": str(class_file),
            "recovered": str(recovered),
            "dependency_count": len(dependencies),
        }
    try:
        workspace = make_workspace(report_dir, "rebuild")
        staged_artifact = workspace / artifact.name
        shutil.copy2(artifact, staged_artifact)
        copied_recovered = workspace / "recovered"
        copy_tree(recovered, copied_recovered)
    except (OSError, RunnerError) as exc:
        append_error(errors, "rebuild", "Unable to create isolated RebuildJar workspace.", error=str(exc))
        return {"status": "failed", "error": str(exc)}

    output_jar = workspace / "patched.jar"
    rebuild_report = workspace / "rebuild_report.txt"
    classpath = os.pathsep.join([str(class_file.parent), *(str(path) for path in dependencies)])
    command = run_command(
        "CASE RebuildJar (isolated)",
        [
            args.java,
            "-cp",
            classpath,
            "RebuildJar",
            str(staged_artifact),
            str(output_jar),
            str(copied_recovered),
            str(rebuild_report),
        ],
        workspace,
        args.command_timeout,
    )
    result: dict[str, Any] = {
        "status": command["status"],
        "workspace": str(workspace),
        "command": command,
        "source_case_mutated": False,
        "output_artifact": describe_file(output_jar, errors, "rebuild_output"),
        "reported_methods_devirtualized": parse_rebuild_count(rebuild_report),
    }
    return result


def copy_pipeline_fixture(case_root: Path, workspace: Path) -> Path:
    stage = workspace / "CASE"
    stage.mkdir()
    for name in ("scripts", "deps"):
        source = case_root / name
        if not source.is_dir():
            raise RunnerError(f"CASE pipeline prerequisite is missing: {source}")
        copy_tree(source, stage / name)
    for name in ("recovered", "static", "originals", "patches", "report"):
        (stage / name).mkdir()
    return stage


def run_case_pipeline(
    args: argparse.Namespace,
    case_root: Path,
    artifact: Path | None,
    report_dir: Path,
    errors: list[dict[str, Any]],
    target_methods: Mapping[str, Any],
) -> dict[str, Any]:
    """Run the legacy chain in a copied workspace without reusing CASE recovery data."""

    if not args.run_case_pipeline:
        return {"status": "not_requested"}
    try:
        workspace = make_workspace(report_dir, "pipeline")
        stage = copy_pipeline_fixture(case_root, workspace)
        rebased_script_count = rebase_copied_legacy_case_paths(stage / "scripts", stage)
    except (OSError, RunnerError) as exc:
        append_error(errors, "pipeline", "Unable to create isolated CASE pipeline workspace.", error=str(exc))
        return {"status": "failed", "error": str(exc)}

    originals = sorted((stage / "originals").glob("*.jar"))
    if artifact is not None:
        if not artifact.is_file():
            return {"status": "failed", "workspace": str(workspace), "error": "Artifact is not readable."}
        staged_artifact = (stage / "originals" / (originals[0].name if originals else artifact.name))
        shutil.copy2(artifact, staged_artifact)
    elif originals:
        staged_artifact = originals[0]
    else:
        return {"status": "failed", "workspace": str(workspace), "error": "No JAR is available for the copied pipeline."}

    scripts = stage / "scripts"
    recovered = stage / "recovered"
    extracted_root = stage / "static" / "jar"
    dependencies = sorted((stage / "deps").glob("*.jar"))
    classpath = os.pathsep.join([*(str(path) for path in dependencies)])
    rebuild_classpath = os.pathsep.join([str(scripts), *(str(path) for path in dependencies)])
    output_jar = stage / "patches" / "rebuilt.jar"
    rebuild_report = stage / "report" / "rebuild_report.txt"
    command_results: list[dict[str, Any]] = []
    extraction = extract_pipeline_jar(staged_artifact, extracted_root)
    command_results.append(extraction)

    if extraction["status"] == "passed":
        native_discovery = discover_pipeline_native_payloads(extracted_root, recovered)
        command_results.append(native_discovery)
        key_helpers = discover_legacy_key_helpers(extracted_root)
        command_results.append(
            pipeline_step(
                "discover-legacy-key-helper",
                "passed",
                "pre-extraction",
                legacy_key_helper_count=len(key_helpers),
                legacy_key_helpers=key_helpers[:MAX_SAMPLES],
                legacy_jsrp_resource_count=has_legacy_jsrp_resources(extracted_root),
            )
        )
    else:
        native_discovery = pipeline_blocked(
            "discover-native-payloads",
            "pre-extraction",
            "JAR extraction did not complete.",
        )
        key_helpers = []
        command_results.extend(
            [
                native_discovery,
                pipeline_blocked(
                    "discover-legacy-key-helper",
                    "pre-extraction",
                    "JAR extraction did not complete.",
                ),
            ]
        )

    keys_path = recovered / "keys.json"
    keys_ready = False
    if extraction["status"] != "passed":
        command_results.extend(
            [
                pipeline_blocked("legacy-key-helper-javap", "legacy-key", "JAR extraction did not complete."),
                pipeline_blocked("extract-legacy-jsrp-keys", "legacy-key", "JAR extraction did not complete."),
            ]
        )
    elif len(key_helpers) != 1:
        command_results.extend(
            [
                pipeline_blocked(
                    "legacy-key-helper-javap",
                    "legacy-key",
                    "The legacy jsRrkS partition-key helper was not uniquely present in the extracted classes.",
                    candidate_count=len(key_helpers),
                ),
                pipeline_blocked(
                    "extract-legacy-jsrp-keys",
                    "legacy-key",
                    "No uniquely identified legacy key helper is available for javap extraction.",
                ),
            ]
        )
    elif not (scripts / "extract_keys.py").is_file():
        command_results.append(
            pipeline_step(
                "legacy-key-helper-javap",
                "failed",
                "legacy-key",
                error="CASE extract_keys.py is missing from the copied fixture.",
            )
        )
        command_results.append(
            pipeline_blocked("extract-legacy-jsrp-keys", "legacy-key", "CASE extract_keys.py is unavailable.")
        )
    else:
        helper_class = key_helpers[0].replace("/", ".")
        javap_output = stage / "static" / "legacy-key-helper.javap.txt"
        javap_result = run_command_to_file(
            "legacy-key-helper-javap",
            [args.javap, "-classpath", str(staged_artifact), "-p", "-c", helper_class],
            stage,
            args.pipeline_timeout,
            javap_output,
        )
        javap_result["phase"] = "legacy-key"
        command_results.append(javap_result)
        if javap_result["status"] != "passed":
            command_results.append(
                pipeline_blocked(
                    "extract-legacy-jsrp-keys",
                    "legacy-key",
                    "javap did not produce the legacy key-helper disassembly.",
                )
            )
        else:
            key_result = run_command(
                "extract-legacy-jsrp-keys",
                [sys.executable, str(scripts / "extract_keys.py"), str(javap_output), str(keys_path)],
                stage,
                args.pipeline_timeout,
            )
            key_result["phase"] = "legacy-key"
            if key_result["status"] == "passed" and not has_legacy_partition_keys(keys_path):
                command_results.append(
                    pipeline_blocked(
                        "extract-legacy-jsrp-keys",
                        "legacy-key",
                        "The legacy extractor completed without producing usable partition keys.",
                        command=key_result,
                    )
                )
            else:
                command_results.append(key_result)
                keys_ready = key_result["status"] == "passed"

    legacy_jsrp_count = has_legacy_jsrp_resources(extracted_root) if extraction["status"] == "passed" else 0
    jsrp_index_path = recovered / "jsrp_index.json"
    jsrp_ready = False
    if not keys_ready:
        command_results.append(
            pipeline_blocked(
                "decode-legacy-jsrp",
                "legacy-resource",
                "Legacy JSRP decoding requires keys.json from the legacy key-helper extraction stage.",
                legacy_jsrp_resource_count=legacy_jsrp_count,
            )
        )
    elif not legacy_jsrp_count:
        command_results.append(
            pipeline_blocked(
                "decode-legacy-jsrp",
                "legacy-resource",
                "No legacy JSRP resource header was found in the extracted artifact.",
            )
        )
    elif not (scripts / "decode_jsrp.py").is_file():
        command_results.append(
            pipeline_step("decode-legacy-jsrp", "failed", "legacy-resource", error="CASE decode_jsrp.py is missing.")
        )
    else:
        jsrp_result = run_command(
            "decode-legacy-jsrp",
            [sys.executable, str(scripts / "decode_jsrp.py"), str(staged_artifact)],
            stage,
            args.pipeline_timeout,
        )
        jsrp_result["phase"] = "legacy-resource"
        if jsrp_result["status"] == "passed" and not has_nonempty_list(jsrp_index_path):
            command_results.append(
                pipeline_blocked(
                    "decode-legacy-jsrp",
                    "legacy-resource",
                    "The legacy decoder completed without recovering any authenticated JSRP resource.",
                    command=jsrp_result,
                )
            )
        else:
            command_results.append(jsrp_result)
            jsrp_ready = jsrp_result["status"] == "passed"

    legacy_catalog_count = 0
    jsrp_plain_dir = recovered / "jsrp"
    if jsrp_ready and jsrp_plain_dir.is_dir():
        for path in jsrp_plain_dir.rglob("*"):
            if not path.is_file():
                continue
            try:
                if read_prefix(path, 4) == b"JSD1":
                    legacy_catalog_count += 1
            except OSError:
                continue
    vbc4_index_path = recovered / "vbc4_index.json"
    vbc4_ready = False
    if not jsrp_ready:
        command_results.append(
            pipeline_blocked("parse-legacy-catalog", "legacy-resource", "No authenticated legacy JSRP plaintext is available.")
        )
    elif not legacy_catalog_count:
        command_results.append(
            pipeline_blocked(
                "parse-legacy-catalog",
                "legacy-resource",
                "Recovered resources do not contain the legacy JSD1 catalog format.",
            )
        )
    elif not (scripts / "parse_catalog.py").is_file():
        command_results.append(
            pipeline_step("parse-legacy-catalog", "failed", "legacy-resource", error="CASE parse_catalog.py is missing.")
        )
    else:
        catalog_result = run_command(
            "parse-legacy-catalog",
            [sys.executable, str(scripts / "parse_catalog.py")],
            stage,
            args.pipeline_timeout,
        )
        catalog_result["phase"] = "legacy-resource"
        if catalog_result["status"] == "passed" and not has_nonempty_mapping(vbc4_index_path):
            command_results.append(
                pipeline_blocked(
                    "parse-legacy-catalog",
                    "legacy-resource",
                    "The legacy catalog parser completed without reconstructing any VBC4 container.",
                    command=catalog_result,
                )
            )
        else:
            command_results.append(catalog_result)
            vbc4_ready = catalog_result["status"] == "passed"

    legacy_header_count = int(native_discovery.get("legacy_native_header_count", 0))
    legacy_header_versions = native_discovery.get("legacy_native_header_versions", [])
    header_path = recovered / "payload_header.json"
    header_ready = False
    if legacy_header_count != 1:
        command_results.append(
            pipeline_blocked(
                "stage1-parse-legacy-native-header",
                "legacy-native",
                "The extracted native payload does not expose exactly one JS_NATIVE_MAX_PAYLOAD_V1 header.",
                candidate_count=legacy_header_count,
            )
        )
    elif legacy_header_versions != [3]:
        command_results.append(
            pipeline_blocked(
                "stage1-parse-legacy-native-header",
                "legacy-native",
                "The copied CASE stage1 parser only supports legacy native-header version 3.",
                observed_versions=legacy_header_versions,
            )
        )
    elif not (scripts / "stage1_parse_header.py").is_file():
        command_results.append(
            pipeline_step(
                "stage1-parse-legacy-native-header",
                "failed",
                "legacy-native",
                error="CASE stage1_parse_header.py is missing.",
            )
        )
    else:
        header_result = run_command(
            "stage1-parse-legacy-native-header",
            [sys.executable, str(scripts / "stage1_parse_header.py")],
            stage,
            args.pipeline_timeout,
        )
        header_result["phase"] = "legacy-native"
        if header_result["status"] == "passed" and not header_path.is_file():
            command_results.append(
                pipeline_blocked(
                    "stage1-parse-legacy-native-header",
                    "legacy-native",
                    "The legacy native-header parser did not produce payload_header.json.",
                    command=header_result,
                )
            )
        else:
            command_results.append(header_result)
            header_ready = header_result["status"] == "passed"

    if header_ready:
        command_results.append(
            pipeline_blocked(
                "stage2-unpack-legacy-native-payload",
                "legacy-native",
                "The CASE stage2 script performs an unbounded 2^32 seed search and is not run by the bounded Windows acceptance runner.",
            )
        )
    else:
        command_results.append(
            pipeline_blocked(
                "stage2-unpack-legacy-native-payload",
                "legacy-native",
                "A parsed legacy native header is required before the stage2 seed search.",
            )
        )
    command_results.append(
        pipeline_blocked(
            "stage2b-joint-search-legacy-native-payload",
            "legacy-native",
            (
                "The CASE stage2b alternative also performs an unbounded 2^32 seed search and is not run by the bounded Windows acceptance runner."
                if header_ready
                else "A parsed legacy native header is required before the stage2b joint seed/offset search."
            ),
        )
    )
    command_results.append(
        pipeline_blocked(
            "stage3-emulate-legacy-native-key",
            "dynamic-only",
            "The CASE stage3 script requires a Kali/Unicorn dynamic-emulation environment and profile-specific addresses; it is not a Windows static extraction step.",
        )
    )
    command_results.append(
        pipeline_blocked(
            "stage5-dump-legacy-jsx",
            "dynamic-only",
            "The CASE stage5 script requires a Kali/Unicorn dynamic-emulation environment and a decrypted legacy inner DLL; no dynamic dump is synthesized here.",
        )
    )

    native_secrets_path = recovered / "native_secrets.json"
    native_secrets_ready = False
    if not (recovered / "inner.dll").is_file() or not vbc4_ready:
        command_results.append(
            pipeline_blocked(
                "stage4-find-legacy-native-secrets",
                "legacy-native",
                "The legacy native-secret scan requires both inner.dll and a reconstructed legacy VBC4 catalog.",
            )
        )
    elif not (scripts / "stage4_find_secrets.py").is_file():
        command_results.append(
            pipeline_step(
                "stage4-find-legacy-native-secrets",
                "failed",
                "legacy-native",
                error="CASE stage4_find_secrets.py is missing.",
            )
        )
    else:
        secret_result = run_command(
            "stage4-find-legacy-native-secrets",
            [sys.executable, str(scripts / "stage4_find_secrets.py")],
            stage,
            args.pipeline_timeout,
        )
        secret_result["phase"] = "legacy-native"
        if secret_result["status"] == "passed" and not has_legacy_native_secrets(native_secrets_path):
            command_results.append(
                pipeline_blocked(
                    "stage4-find-legacy-native-secrets",
                    "legacy-native",
                    "The legacy native-secret scan completed without producing native_secrets.json.",
                    command=secret_result,
                )
            )
        else:
            command_results.append(secret_result)
            native_secrets_ready = secret_result["status"] == "passed"

    ir_dir = recovered / "ir2"
    ir_ready = False
    if not (vbc4_ready and native_secrets_ready):
        command_results.append(
            pipeline_blocked(
                "decode-legacy-ir",
                "lowering",
                "Legacy IR decoding requires both reconstructed VBC4 containers and native_secrets.json.",
            )
        )
    elif not (scripts / "decode_ir.py").is_file():
        command_results.append(
            pipeline_step("decode-legacy-ir", "failed", "lowering", error="CASE decode_ir.py is missing.")
        )
    else:
        ir_result = run_command(
            "decode-legacy-ir",
            [sys.executable, str(scripts / "decode_ir.py")],
            stage,
            args.pipeline_timeout,
        )
        ir_result["phase"] = "lowering"
        if ir_result["status"] == "passed" and not any(ir_dir.glob("*.json")):
            command_results.append(
                pipeline_blocked(
                    "decode-legacy-ir",
                    "lowering",
                    "The legacy decoder completed without producing any IR JSON file.",
                    command=ir_result,
                )
            )
        else:
            command_results.append(ir_result)
            ir_ready = ir_result["status"] == "passed"

    token_map_path = recovered / "token_to_method.json"
    if not vbc4_ready:
        command_results.append(
            pipeline_blocked("map-legacy-tokens", "lowering", "A reconstructed legacy VBC4 catalog is required.")
        )
    elif not (scripts / "map_tokens.py").is_file():
        command_results.append(pipeline_step("map-legacy-tokens", "failed", "lowering", error="CASE map_tokens.py is missing."))
    else:
        token_result = run_command(
            "map-legacy-tokens",
            [sys.executable, str(scripts / "map_tokens.py")],
            stage,
            args.pipeline_timeout,
        )
        token_result["phase"] = "lowering"
        if token_result["status"] == "passed" and not has_nonempty_mapping(token_map_path):
            command_results.append(
                pipeline_blocked(
                    "map-legacy-tokens",
                    "lowering",
                    "The legacy token mapper completed without producing token_to_method.json.",
                    command=token_result,
                )
            )
        else:
            command_results.append(token_result)

    string_callsites_path = recovered / "string_callsites.json"
    if not ir_ready:
        command_results.extend(
            [
                pipeline_blocked("extract-legacy-string-callsites", "lowering", "Legacy IR decoding did not complete."),
                pipeline_blocked("decrypt-legacy-strings", "lowering", "Legacy IR decoding did not complete."),
            ]
        )
    elif not (scripts / "extract_strings.py").is_file() or not (scripts / "decrypt_strings.py").is_file():
        command_results.extend(
            [
                pipeline_step(
                    "extract-legacy-string-callsites",
                    "failed",
                    "lowering",
                    error="CASE string extraction scripts are missing.",
                ),
                pipeline_blocked("decrypt-legacy-strings", "lowering", "CASE string extraction scripts are unavailable."),
            ]
        )
    else:
        extract_strings_result = run_command(
            "extract-legacy-string-callsites",
            [sys.executable, str(scripts / "extract_strings.py")],
            stage,
            args.pipeline_timeout,
        )
        extract_strings_result["phase"] = "lowering"
        command_results.append(extract_strings_result)
        if extract_strings_result["status"] != "passed" or not string_callsites_path.is_file():
            command_results.append(
                pipeline_blocked("decrypt-legacy-strings", "lowering", "No legacy string callsite material was produced.")
            )
        else:
            decrypt_strings_result = run_command(
                "decrypt-legacy-strings",
                [sys.executable, str(scripts / "decrypt_strings.py")],
                stage,
                args.pipeline_timeout,
            )
            decrypt_strings_result["phase"] = "lowering"
            command_results.append(decrypt_strings_result)

    if not ir_ready:
        command_results.extend(
            [
                pipeline_blocked("compile-rebuildjar", "rebuild", "No recovered legacy IR is available for a rebuild attempt."),
                pipeline_blocked("rebuild-jar", "rebuild", "No recovered legacy IR is available for a rebuild attempt."),
            ]
        )
    elif not (scripts / "RebuildJar.java").is_file():
        command_results.extend(
            [
                pipeline_step("compile-rebuildjar", "failed", "rebuild", error="CASE RebuildJar.java is missing."),
                pipeline_blocked("rebuild-jar", "rebuild", "CASE RebuildJar.java is unavailable."),
            ]
        )
    else:
        compile_result = run_command(
            "compile-rebuildjar",
            [args.javac, "-cp", classpath, str(scripts / "RebuildJar.java")],
            stage,
            args.pipeline_timeout,
        )
        compile_result["phase"] = "rebuild"
        command_results.append(compile_result)
        if compile_result["status"] != "passed":
            command_results.append(pipeline_blocked("rebuild-jar", "rebuild", "RebuildJar compilation did not complete."))
        else:
            rebuild_result = run_command(
                "rebuild-jar",
                [
                    args.java,
                    "-cp",
                    rebuild_classpath,
                    "RebuildJar",
                    str(staged_artifact),
                    str(output_jar),
                    str(recovered),
                    str(rebuild_report),
                ],
                stage,
                args.pipeline_timeout,
            )
            rebuild_result["phase"] = "rebuild"
            command_results.append(rebuild_result)

    pipeline_errors: list[dict[str, Any]] = []
    pipeline_matrix = high_value_recovery_matrix(
        stage,
        pipeline_errors,
        "pipeline_recovery",
        target_methods=target_methods,
    )
    for error in pipeline_errors:
        errors.append(error)
    failed_steps = [result for result in command_results if result.get("status") == "failed"]
    blocked_steps = [result for result in command_results if result.get("status") == "blocked"]
    status = "failed" if failed_steps else ("blocked" if blocked_steps else "passed")
    first_blocker = blocked_steps[0] if blocked_steps else None
    return {
        "status": status,
        "workspace": str(workspace),
        "staged_artifact": describe_file(staged_artifact, errors, "pipeline_artifact"),
        "rebased_legacy_script_count": rebased_script_count,
        "commands": command_results,
        "source_case_mutated": False,
        "reused_source_recovery_evidence": False,
        "recovery_matrix": pipeline_matrix,
        "recovery_count_interpretation": "not_measured" if pipeline_matrix.get("recovery_measurement") == "not_measured" else "file_evidence_only",
        "first_blocker": first_blocker,
        "output_artifact": (
            describe_file(output_jar, errors, "pipeline_output")
            if output_jar.is_file()
            else {"status": "not_produced", "reason": "The isolated pipeline did not reach a rebuild output."}
        ),
        "reported_methods_devirtualized": parse_rebuild_count(rebuild_report),
    }


def requested_command_failed(commands: Mapping[str, Any]) -> bool:
    def failed(value: Any) -> bool:
        if isinstance(value, dict):
            if value.get("status") == "failed":
                return True
            return any(failed(child) for child in value.values())
        if isinstance(value, list):
            return any(failed(child) for child in value)
        return False

    return failed(commands)


def build_report(args: argparse.Namespace, case_root: Path, artifact: Path | None, sidecar: Path | None, report_dir: Path) -> dict[str, Any]:
    errors: list[dict[str, Any]] = []
    requested_commands = [
        name
        for name, requested in (
            ("verify", args.run_verify),
            ("rebuild", args.run_rebuild),
            ("pipeline", args.run_case_pipeline),
        )
        if requested
    ]
    samples = [describe_file(path, errors, "sample") for path in sample_paths(case_root)]
    artifact_scan = scan_artifact(artifact, errors)
    sidecar_scan = scan_sidecar(sidecar, errors)
    case_recovery_matrix = high_value_recovery_matrix(case_root, errors)
    target_methods = {
        row["token"]: {"class": row.get("class"), "method": row.get("method")}
        for row in case_recovery_matrix.get("matrix", [])
    }
    evidence_path = resolve_path(args.build_evidence) if args.build_evidence else default_build_evidence_path(artifact)
    reference_jar = resolve_path(args.reference_jar) if args.reference_jar else None
    method_evidence = artifact_method_evidence(
        artifact,
        evidence_path,
        reference_jar,
        int(case_recovery_matrix.get("high_value_target_count", 0)),
        errors,
    )
    commands = {
        "verify": run_verify(args, artifact, sidecar, report_dir, errors),
        "rebuild": run_rebuild(args, case_root, artifact, report_dir, errors),
        "pipeline": run_case_pipeline(args, case_root, artifact, report_dir, errors, target_methods),
    }
    report: dict[str, Any] = {
        "schema_version": 1,
        "generated_at_utc": utc_now(),
        "runner": {
            "path": str(Path(__file__).resolve()),
            "python": sys.version.split()[0],
            "repository_root": str(REPOSITORY_ROOT),
        },
        "read_only_contract": {
            "case_root": str(case_root),
            "report_dir": str(report_dir),
            "report_dir_is_outside_case_root": not is_within(report_dir, case_root),
            "optional_commands_requested": requested_commands,
            "optional_execution_workspace": "report_dir/runs only",
        },
        "inputs": {
            "samples": samples,
            "artifact": artifact_scan["artifact"],
            "sidecar": sidecar_scan["file"],
            "reference_jar": describe_file(reference_jar, errors, "reference_jar") if reference_jar is not None else None,
        },
        "artifact_scan": artifact_scan,
        "static_scans": build_static_scans(artifact_scan, sidecar_scan),
        "artifact_method_evidence": method_evidence,
        "case_recovery_matrix": case_recovery_matrix,
        "commands": commands,
        "errors": errors,
    }
    report["command_failure"] = requested_command_failed(commands)
    return report


def markdown_escape(value: Any) -> str:
    if value is None:
        return ""
    return str(value).replace("|", "\\|").replace("\n", " ")


def static_scan_summary(scan: Mapping[str, Any]) -> str:
    if scan.get("status") == "not_run":
        return str(scan.get("reason", "not run"))
    if "count" in scan:
        return f"count={scan['count']}"
    return ""


def render_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# JavaShroud max-hardening CASE report",
        "",
        f"Generated: `{report['generated_at_utc']}`",
        "",
        "## Read-only boundary",
        "",
        f"- CASE root: `{report['read_only_contract']['case_root']}`",
        f"- Report directory: `{report['read_only_contract']['report_dir']}`",
        f"- Report directory outside CASE: `{report['read_only_contract']['report_dir_is_outside_case_root']}`",
        "- Optional pipeline/RebuildJar workspaces are created under the report directory; the source CASE is not used as an output location.",
        "",
        "## Inputs and SHA-256",
        "",
        "| Kind | Path | Size | SHA-256 |",
        "|---|---|---:|---|",
    ]
    for sample in report["inputs"]["samples"]:
        lines.append(
            f"| sample | {markdown_escape(sample.get('path'))} | {markdown_escape(sample.get('size'))} | {markdown_escape(sample.get('sha256'))} |"
        )
    for kind in ("artifact", "sidecar"):
        value = report["inputs"][kind]
        lines.append(
            f"| {kind} ({markdown_escape(value.get('status'))}) | {markdown_escape(value.get('path'))} | {markdown_escape(value.get('size'))} | {markdown_escape(value.get('sha256'))} |"
        )

    lines.extend(["", "## W1-W6 static scans", "", "| Check | Status | Summary |", "|---|---|---|"])
    for name, scan in report["static_scans"].items():
        lines.append(
            f"| {name}: {markdown_escape(scan.get('name'))} | {markdown_escape(scan.get('status'))} | {markdown_escape(static_scan_summary(scan))} |"
        )

    method_evidence = report.get("artifact_method_evidence", {})
    lines.extend(
        [
            "",
            "## Candidate build method evidence",
            "",
            f"- Status: **{markdown_escape(method_evidence.get('status'))}**",
            f"- Evidence file: `{markdown_escape((method_evidence.get('file') or {}).get('path'))}`",
            f"- Artifact hash matches evidence: **{markdown_escape(method_evidence.get('artifact_hash_matches'))}**",
            f"- Protected method records: **{markdown_escape(method_evidence.get('protected_method_count'))}**",
            f"- Meets CASE high-value target: **{markdown_escape(method_evidence.get('protected_method_count_meets_target'))}**",
        ]
    )

    matrix = report["case_recovery_matrix"]
    lines.extend(["", "## High-value method recovery matrix", ""])
    if matrix.get("status") != "available":
        lines.append(f"Unavailable: {markdown_escape(matrix.get('reason'))}")
    else:
        lines.extend(
            [
                f"- Evidence source: `{markdown_escape(matrix.get('source'))}`",
                f"- High-value target count: **{matrix['high_value_target_count']}**",
                f"- Complete file-evidence recoveries (`.json` + valid JSON and non-empty `.ir`): **{matrix['complete_recovery_evidence_count']}**",
                f"- CASE RebuildJar reported methods devirtualized: **{markdown_escape(matrix.get('reported_methods_devirtualized'))}**",
                "",
                "| Token | Class | Method | VBC4 | IR JSON | IR text | Complete evidence |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for row in matrix["matrix"]:
            lines.append(
                "| {token} | {class_name} | {method} | {vbc4} | {ir_json} | {ir_text} | {complete} |".format(
                    token=markdown_escape(row["token"]),
                    class_name=markdown_escape(row.get("class")),
                    method=markdown_escape(row.get("method")),
                    vbc4="yes" if row["vbc4_present"] else "no",
                    ir_json="valid" if row["ir_json_valid"] else ("invalid" if row["ir_json_valid"] is False else "missing"),
                    ir_text="yes" if row["ir_text_present"] else "no",
                    complete="yes" if row["file_evidence_complete"] else "no",
                )
            )

    lines.extend(["", "## Optional command results", "", "| Command | Status | Exit code | Duration (s) |", "|---|---|---:|---:|"])
    for name, result in report["commands"].items():
        command = result.get("command", result)
        if name == "pipeline":
            lines.append(f"| {name} (aggregate) | {markdown_escape(result.get('status'))} |  |  |")
            for step in result.get("commands", []):
                lines.append(
                    f"| pipeline/{markdown_escape(step.get('label'))} | {markdown_escape(step.get('status'))} | {markdown_escape(step.get('exit_code'))} | {markdown_escape(step.get('duration_seconds'))} |"
                )
            recovery = result.get("recovery_matrix", {})
            if recovery:
                lines.append(
                    f"| pipeline/recovery-measurement | {markdown_escape(recovery.get('recovery_measurement'))} |  | {markdown_escape(recovery.get('complete_recovery_evidence_count'))} |"
                )
            if not result.get("commands"):
                lines.append(f"| {name} | {markdown_escape(result.get('status'))} |  |  |")
            continue
        lines.append(
            f"| {name} | {markdown_escape(result.get('status'))} | {markdown_escape(command.get('exit_code'))} | {markdown_escape(command.get('duration_seconds'))} |"
        )

    if report["errors"]:
        lines.extend(["", "## Reported errors", ""])
        for error in report["errors"]:
            lines.append(f"- **{markdown_escape(error.get('scope'))}**: {markdown_escape(error.get('message'))}")
    return "\n".join(lines) + "\n"


def write_reports(report: Mapping[str, Any], report_dir: Path) -> tuple[Path, Path]:
    report_dir.mkdir(parents=True, exist_ok=True)
    json_path = report_dir / REPORT_JSON_NAME
    markdown_path = report_dir / REPORT_MARKDOWN_NAME
    json_temp = json_path.with_suffix(json_path.suffix + ".tmp")
    markdown_temp = markdown_path.with_suffix(markdown_path.suffix + ".tmp")
    json_temp.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_temp.write_text(render_markdown(report), encoding="utf-8")
    json_temp.replace(json_path)
    markdown_temp.replace(markdown_path)
    return json_path, markdown_path


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-root", help="CASE fixture root. Defaults to CASE_ROOT.")
    parser.add_argument("--artifact", help="JAR or binary artifact to scan (optional for CASE-only evidence).")
    parser.add_argument("--sidecar", help="Boot KEK sidecar paired with --artifact.")
    parser.add_argument(
        "--build-evidence",
        help="External candidate build evidence. Defaults to ARTIFACT with .build-evidence.json suffix.",
    )
    parser.add_argument("--reference-jar", help="Build input JAR used to resolve external semantic method IDs.")
    parser.add_argument(
        "--report-dir",
        default=str(DEFAULT_REPORT_DIR),
        help="Report output directory; it must be outside CASE_ROOT.",
    )
    parser.add_argument("--run-verify", "--verify", action="store_true", help="Run java -Xverify:all -jar ARTIFACT.")
    parser.add_argument("--run-rebuild", action="store_true", help="Run CASE RebuildJar in an isolated report workspace.")
    parser.add_argument(
        "--run-case-pipeline",
        "--run-pipeline",
        action="store_true",
        help="Run a copied CASE pipeline in an isolated report workspace.",
    )
    parser.add_argument("--java", default=os.environ.get("JAVA", "java"), help="Java executable for optional commands.")
    parser.add_argument("--javac", default=os.environ.get("JAVAC", "javac"), help="javac executable for the copied CASE pipeline.")
    parser.add_argument("--javap", default=os.environ.get("JAVAP", "javap"), help="javap executable for legacy key-helper extraction.")
    parser.add_argument(
        "--verify-raw",
        action="store_true",
        help="Run the artifact entrypoint without --diagnostics-only; the caller must close GUI applications.",
    )
    parser.add_argument("--command-timeout", type=positive_int, default=60, help="Timeout per verification/RebuildJar command.")
    parser.add_argument("--pipeline-timeout", type=positive_int, default=180, help="Timeout per copied pipeline step.")
    return parser


def resolve_arguments(parser: argparse.ArgumentParser, argv: Sequence[str] | None) -> tuple[argparse.Namespace, Path, Path | None, Path | None, Path]:
    args = parser.parse_args(argv)
    if sys.version_info < (3, 11):
        parser.error("Python 3.11 or newer is required.")
    raw_case_root = args.case_root or os.environ.get("CASE_ROOT")
    if not raw_case_root:
        parser.error("--case-root is required unless CASE_ROOT is set.")
    case_root = resolve_path(raw_case_root)
    if not case_root.is_dir():
        parser.error(f"CASE root does not exist or is not a directory: {case_root}")
    report_dir = resolve_path(args.report_dir)
    if is_within(report_dir, case_root):
        parser.error("--report-dir must be outside CASE_ROOT to preserve the read-only fixture boundary.")
    artifact = resolve_path(args.artifact) if args.artifact else None
    sidecar = resolve_path(args.sidecar) if args.sidecar else None
    return args, case_root, artifact, sidecar, report_dir


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args, case_root, artifact, sidecar, report_dir = resolve_arguments(parser, argv)
        report = build_report(args, case_root, artifact, sidecar, report_dir)
        json_path, markdown_path = write_reports(report, report_dir)
    except RunnerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")
    if report["command_failure"]:
        print("One or more requested commands failed; see the report for captured output.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
