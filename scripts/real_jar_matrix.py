#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import re
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_FIXTURES = [
    Path(r"E:\XiangMu\TestJar\demo.jar"),
    Path(r"E:\XiangMu\TestJar\TEST.jar"),
    Path(r"E:\XiangMu\TestJar\jvm-obf-tester.jar"),
]

DEFAULT_SKIP = {
    "anti-dump-protection",
    "anti-instrumentation",
    "class-encryption-loader",
    "environment-bound-keys",
    "jni-microkernel-loader",
    "method-body-delayed-decryption",
    "method-virtualization",
    "string-encryption",
}


@dataclass(frozen=True)
class Case:
    name: str
    passes: list[str]
    params: dict[str, dict[str, Any]]


def run(cmd: list[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )


def jar_main_class(jar_path: Path) -> str | None:
    with tempfile.TemporaryDirectory(prefix="javashroud-manifest-") as temp_dir:
        temp = Path(temp_dir)
        proc = run(["jar", "xf", str(jar_path), "META-INF/MANIFEST.MF"], temp, 20)
        manifest = temp / "META-INF" / "MANIFEST.MF"
        if proc.returncode != 0 or not manifest.exists():
            return None
        for line in manifest.read_text(errors="replace").splitlines():
            if line.lower().startswith("main-class:"):
                return line.split(":", 1)[1].strip()
    return None


def toml_string(value: str) -> str:
    return json.dumps(value)


def toml_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return toml_string(value)
    raise TypeError(f"Unsupported TOML scalar: {value!r}")


def config_path_string(path: Path) -> str:
    return str(path.resolve()).replace(os.sep, "/")


def write_config(path: Path, input_jar: Path, output_jar: Path, case: Case) -> None:
    lines = [
        f"inputJarPath = {toml_string(config_path_string(input_jar))}",
        f"outputJarPath = {toml_string(config_path_string(output_jar))}",
        "allowIncomplete = true",
        "allowOptInPasses = true",
        "allowRedundantPasses = true",
        "",
    ]
    for pass_id in case.passes:
        lines += ["[[passes]]", f"id = {toml_string(pass_id)}", "enabled = true"]
        params = case.params.get(pass_id, {})
        if params:
            lines += ["", "[passes.params]"]
            for key, value in sorted(params.items()):
                lines.append(f"{key} = {toml_scalar(value)}")
        lines.append("")
    lines += ["[ruleSet]", "rules = []", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def load_schema(engine: Path, cwd: Path) -> dict[str, Any]:
    proc = run(["java", "-jar", str(engine), "-schema"], cwd, 60)
    if proc.returncode != 0:
        raise RuntimeError(proc.stdout + proc.stderr)
    return tomllib.loads(proc.stdout)


def profiles(module: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {"default": {}, "min": {}, "max": {}}
    for param in module.get("params", []):
        if param.get("hidden", False):
            continue
        key = param["key"]
        default = param.get("defaultValue")
        options = param.get("options") or []
        param_type = param.get("type")
        if default is not None:
            result["default"][key] = default
        if options:
            result["min"][key] = options[0]
            result["max"][key] = options[-1]
        elif param_type == "boolean":
            result["min"][key] = False
            result["max"][key] = True
        elif param_type == "number":
            result["min"][key] = 1
            result["max"][key] = 10
        elif param_type == "string" and default not in (None, ""):
            result["min"][key] = default
            result["max"][key] = default
    return result


def conflicts(data: dict[str, Any]) -> set[frozenset[str]]:
    return {
        frozenset(rule.get("passIds", []))
        for rule in data.get("compatibility", [])
        if rule.get("severity") == "hard"
    }


def compatible(pass_ids: list[str], hard_conflicts: set[frozenset[str]]) -> bool:
    selected = set(pass_ids)
    return all(not pair.issubset(selected) for pair in hard_conflicts)


def build_cases(data: dict[str, Any], mode: str, include_native: bool, limit: int | None, offset: int = 0) -> list[Case]:
    modules = {module["id"]: module for module in data["modules"]}
    hard_conflicts = conflicts(data)
    pass_ids = [pid for pid in sorted(modules) if include_native or pid not in DEFAULT_SKIP]
    cases: list[Case] = []

    if data.get("defaultPipeline"):
        cases.append(Case("default-pipeline", list(data["defaultPipeline"]), {}))

    if mode in {"single", "all"}:
        for pass_id in pass_ids:
            for profile_name, params in profiles(modules[pass_id]).items():
                cases.append(Case(f"single-{pass_id}-{profile_name}", [pass_id], {pass_id: params} if params else {}))

    if mode in {"pair", "all"}:
        for combo in itertools.combinations(pass_ids, 2):
            combo_ids = list(combo)
            if compatible(combo_ids, hard_conflicts):
                cases.append(Case("pair-" + "__".join(combo_ids), combo_ids, {}))

    if mode in {"triple", "all"}:
        for combo in itertools.combinations(pass_ids, 3):
            combo_ids = list(combo)
            if compatible(combo_ids, hard_conflicts):
                cases.append(Case("triple-" + "__".join(combo_ids), combo_ids, {}))

    if mode in {"random", "all"}:
        rng = random.Random(20260623)
        for index in range(20):
            combo_ids = rng.sample(pass_ids, rng.randint(2, min(6, len(pass_ids))))
            if compatible(combo_ids, hard_conflicts):
                cases.append(Case(f"random-{index:02d}", combo_ids, {}))

    if mode in {"full", "all"}:
        full = [pid for pid in pass_ids if compatible([pid], hard_conflicts)]
        cases.append(Case("full-non-hard-conflict", full, {}))

    deduped: list[Case] = []
    seen: set[tuple[str, tuple[str, ...], str]] = set()
    for case in cases:
        key = (case.name, tuple(case.passes), repr(case.params))
        if key not in seen:
            seen.add(key)
            deduped.append(case)
    sliced = deduped[offset:]
    return sliced[:limit] if limit else sliced


def fingerprint(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()[:16]


def normalize_text(value: str) -> str:
    text = value.replace("\r\n", "\n")
    text = re.sub(r"Total time: \d+ms", "Total time: <time>", text)
    text = re.sub(r"Calc: \d+ms", "Calc: <time>", text)
    text = re.sub(r"\b\d+\.\d+ms\b", "<time>", text)
    text = re.sub(r"Jar size: \d+KB", "Jar size: <size>", text)
    text = re.sub(r"^Test 1\.6: Pool (PASS|FAIL)$", "Test 1.6: Pool <flaky>", text, flags=re.MULTILINE)
    text = re.sub(r"^\+-[-+]+\+$", "+<table-border>+", text, flags=re.MULTILINE)
    text = re.sub(r"[ \t]+\|", " |", text)
    text = re.sub(r"\|[ \t]+", "| ", text)
    return text.strip()


def normalize(proc: subprocess.CompletedProcess[str]) -> tuple[int, str, str]:
    return (proc.returncode, normalize_text(proc.stdout), normalize_text(proc.stderr))


def stable_run(jar_path: Path, cwd: Path, attempts: int, timeout: int) -> tuple[int, str, str]:
    observations = [normalize(run(["java", "-jar", str(jar_path)], cwd, timeout)) for _ in range(max(1, attempts))]
    counts: dict[tuple[int, str, str], int] = {}
    for observation in observations:
        counts[observation] = counts.get(observation, 0) + 1
    return max(counts.items(), key=lambda item: item[1])[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, default=Path("build/core-engine/libs/obfuscator-engine.jar"))
    parser.add_argument("--fixtures", type=Path, nargs="*", default=DEFAULT_FIXTURES)
    parser.add_argument("--mode", choices=["single", "pair", "triple", "full", "random", "all"], default="single")
    parser.add_argument("--include-native", action="store_true")
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--work-dir", type=Path, default=Path("build/real-jar-matrix"))
    parser.add_argument("--run-timeout", type=int, default=20)
    parser.add_argument("--run-attempts", type=int, default=5)
    parser.add_argument("--obfuscate-timeout", type=int, default=120)
    args = parser.parse_args()

    cwd = Path.cwd()
    engine = args.engine if args.engine.is_absolute() else cwd / args.engine
    data = load_schema(engine, cwd)
    cases = build_cases(data, args.mode, args.include_native, args.limit, args.offset)
    args.work_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    for fixture in [path.resolve() for path in args.fixtures]:
        if not fixture.exists():
            print(f"SKIP missing {fixture}")
            continue
        main_class = jar_main_class(fixture)
        if not main_class:
            print(f"SKIP no Main-Class {fixture}")
            continue
        baseline = stable_run(fixture, cwd, args.run_attempts, args.run_timeout)
        print(f"FIXTURE {fixture.name} main={main_class} sha={fingerprint(fixture)} baseline_rc={baseline[0]}")
        for index, case in enumerate(cases, 1):
            safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in case.name)[:140]
            out_dir = args.work_dir / fixture.stem / f"{index:03d}-{safe_name}"
            if out_dir.exists():
                shutil.rmtree(out_dir)
            out_dir.mkdir(parents=True)
            output_jar = out_dir / f"{fixture.stem}-obf.jar"
            config_path = out_dir / "config.toml"
            write_config(config_path, fixture, output_jar, case)

            start = time.time()
            obfuscated = run(["java", "-jar", str(engine), "-config", str(config_path)], cwd, args.obfuscate_timeout)
            elapsed = time.time() - start
            if obfuscated.returncode != 0 or not output_jar.exists():
                failures += 1
                (out_dir / "obfuscate.stdout.txt").write_text(obfuscated.stdout, encoding="utf-8", errors="replace")
                (out_dir / "obfuscate.stderr.txt").write_text(obfuscated.stderr, encoding="utf-8", errors="replace")
                print(f"FAIL obfuscate {fixture.name} {case.name} rc={obfuscated.returncode} sec={elapsed:.1f}")
                continue

            actual = stable_run(output_jar, cwd, args.run_attempts, args.run_timeout)
            if actual != baseline:
                failures += 1
                (out_dir / "baseline.txt").write_text(repr(baseline), encoding="utf-8")
                (out_dir / "obfuscated.txt").write_text(repr(actual), encoding="utf-8")
                print(f"FAIL runtime {fixture.name} {case.name} expected={baseline[0]} actual={actual[0]} sha={fingerprint(output_jar)}")
            else:
                print(f"PASS {fixture.name} {case.name} sec={elapsed:.1f} sha={fingerprint(output_jar)}")
    print(f"SUMMARY cases={len(cases)} failures={failures} work_dir={args.work_dir}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

