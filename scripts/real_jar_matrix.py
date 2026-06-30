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
import queue
import threading
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
    try:
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
    except subprocess.TimeoutExpired as error:
        stdout = error.stdout.decode("utf-8", errors="replace") if isinstance(error.stdout, bytes) else error.stdout
        stderr = error.stderr.decode("utf-8", errors="replace") if isinstance(error.stderr, bytes) else error.stderr
        return subprocess.CompletedProcess(
            cmd,
            124,
            stdout or "",
            (stderr or "") + f"\n<TIMEOUT after {timeout}s>",
        )


def run_jar(jar_path: Path, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    proc = subprocess.Popen(
        ["java", "-jar", str(jar_path)],
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output_queue: queue.Queue[tuple[str, str | None]] = queue.Queue()

    def drain(name: str, stream: Any) -> None:
        try:
            for line in stream:
                output_queue.put((name, line))
        finally:
            output_queue.put((name, None))

    assert proc.stdout is not None
    assert proc.stderr is not None
    threading.Thread(target=drain, args=("stdout", proc.stdout), daemon=True).start()
    threading.Thread(target=drain, args=("stderr", proc.stderr), daemon=True).start()

    stdout: list[str] = []
    stderr: list[str] = []
    completed_streams: set[str] = set()
    deadline = time.monotonic() + timeout
    early_success_patterns = [
        re.compile(r"Tests .* Finished"),
        re.compile(r"skipStartupDiagnostics=false"),
    ]

    while len(completed_streams) < 2:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            proc.kill()
            stderr.append(f"\n<TIMEOUT after {timeout}s>")
            break
        try:
            name, chunk = output_queue.get(timeout=min(0.2, remaining))
        except queue.Empty:
            if proc.poll() is not None:
                continue
            continue
        if chunk is None:
            completed_streams.add(name)
            continue
        target = stdout if name == "stdout" else stderr
        target.append(chunk)
        combined_stdout = "".join(stdout)
        if any(pattern.search(combined_stdout) for pattern in early_success_patterns):
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            return subprocess.CompletedProcess(["java", "-jar", str(jar_path)], 0, combined_stdout, "".join(stderr))

    return subprocess.CompletedProcess(["java", "-jar", str(jar_path)], proc.poll() or 0, "".join(stdout), "".join(stderr))


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


def expand_fixtures(paths: list[Path]) -> list[Path]:
    fixtures: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        expanded = sorted(path.glob("*.jar")) if path.is_dir() else [path]
        for fixture in expanded:
            resolved = fixture.resolve()
            if resolved not in seen:
                seen.add(resolved)
                fixtures.append(resolved)
    return fixtures


def jar_entries(jar_path: Path, cwd: Path, timeout: int) -> list[str] | None:
    proc = run(["jar", "tf", str(jar_path)], cwd, timeout)
    if proc.returncode != 0:
        return None
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def validate_library_jar(jar_path: Path, cwd: Path, timeout: int) -> tuple[bool, str]:
    entries = jar_entries(jar_path, cwd, timeout)
    if entries is None:
        return False, "jar tool could not list entries"
    class_count = sum(1 for entry in entries if entry.endswith(".class"))
    if class_count == 0:
        return False, "no .class entries found"
    return True, f"entries={len(entries)} classes={class_count}"


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
        if key == "targetPlatform":
            result["default"][key] = "auto"
            result["min"][key] = "auto"
            result["max"][key] = "auto"
            continue
        if key == "maxInstructions":
            if default is not None:
                result["default"][key] = default
            result["min"][key] = 1
            result["max"][key] = 2_147_483_647
            continue
        if key == "maxBroadVirtualizedMethods":
            if default is not None:
                result["default"][key] = default
            result["min"][key] = 1
            result["max"][key] = 0
            continue
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


def combo_case(name: str, pass_ids: list[str], modules: dict[str, Any], profile_name: str) -> Case:
    params = {
        pass_id: profile_params
        for pass_id in pass_ids
        if (profile_params := profiles(modules[pass_id]).get(profile_name, {}))
    }
    suffix = "" if profile_name == "default" else f"-params-{profile_name}"
    return Case(name + suffix, pass_ids, params)


def build_cases(
    data: dict[str, Any],
    mode: str,
    include_native: bool,
    limit: int | None,
    offset: int = 0,
    combo_param_profiles: list[str] | None = None,
) -> list[Case]:
    modules = {module["id"]: module for module in data["modules"]}
    hard_conflicts = conflicts(data)
    pass_ids = [pid for pid in sorted(modules) if include_native or pid not in DEFAULT_SKIP]
    combo_profiles = combo_param_profiles or ["default"]
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
                for profile_name in combo_profiles:
                    cases.append(combo_case("pair-" + "__".join(combo_ids), combo_ids, modules, profile_name))

    if mode in {"triple", "all"}:
        for combo in itertools.combinations(pass_ids, 3):
            combo_ids = list(combo)
            if compatible(combo_ids, hard_conflicts):
                for profile_name in combo_profiles:
                    cases.append(combo_case("triple-" + "__".join(combo_ids), combo_ids, modules, profile_name))

    if mode in {"random", "all"}:
        rng = random.Random(20260623)
        for index in range(20):
            combo_ids = rng.sample(pass_ids, rng.randint(2, min(6, len(pass_ids))))
            if compatible(combo_ids, hard_conflicts):
                for profile_name in combo_profiles:
                    cases.append(combo_case(f"random-{index:02d}", combo_ids, modules, profile_name))

    if mode in {"full", "all"}:
        full: list[str] = []
        for pid in pass_ids:
            if compatible(full + [pid], hard_conflicts):
                full.append(pid)
        for profile_name in combo_profiles:
            cases.append(combo_case("full-non-hard-conflict", full, modules, profile_name))

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


def normalize_text(value: str, ignore_pool: bool = False) -> str:
    text = value.replace("\r\n", "\n")
    text = re.sub(r"\[\d{2}:\d{2}:\d{2}\.\d{3}\]", "[<clock>]", text)
    text = re.sub(r"\[\+\d+ms\]", "[+<time>]", text)
    text = re.sub(r"Total time: \d+ms", "Total time: <time>", text)
    text = re.sub(r"Calc: \d+ms", "Calc: <time>", text)
    text = re.sub(r"耗时=\d+ms", "耗时=<time>", text)
    text = re.sub(r"用时=\d+ms", "用时=<time>", text)
    text = re.sub(r"启动耗时=\d+ms", "启动耗时=<time>", text)
    text = re.sub(r"\b\d+\.\d+ms\b", "<time>", text)
    text = re.sub(r"\b\d+ms\b", "<time>", text)
    text = re.sub(r"\b\d+\.<time>(?=\s|\|)", "<time>", text)
    text = re.sub(r"Jar size: \d+KB", "Jar size: <size>", text)
    if ignore_pool:
        text = re.sub(r"^Test 1\.6: Pool (PASS|FAIL|ERROR)$", "Test 1.6: Pool <ignored>", text, flags=re.MULTILINE)
    text = re.sub(r"^\+-[-+]+\+$", "+<table-border>+", text, flags=re.MULTILINE)
    text = re.sub(r"[ \t]+\|", " |", text)
    text = re.sub(r"\|[ \t]+", "| ", text)
    lines = [line.rstrip() for line in text.strip().splitlines() if line.strip()]
    return "\n".join(sorted(lines))


def normalize(proc: subprocess.CompletedProcess[str], ignore_pool: bool = False) -> tuple[int, str, str]:
    return (proc.returncode, normalize_text(proc.stdout, ignore_pool), normalize_text(proc.stderr, ignore_pool))


def run_observations(jar_path: Path, cwd: Path, attempts: int, timeout: int, ignore_pool: bool) -> list[tuple[int, str, str]]:
    return [normalize(run_jar(jar_path, cwd, timeout), ignore_pool) for _ in range(max(1, attempts))]


def majority_observation(observations: list[tuple[int, str, str]]) -> tuple[int, str, str]:
    counts: dict[tuple[int, str, str], int] = {}
    for observation in observations:
        counts[observation] = counts.get(observation, 0) + 1
    return max(counts.items(), key=lambda item: item[1])[0]


def observation_counts(observations: list[tuple[int, str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for observation in observations:
        key = repr(observation)
        counts[key] = counts.get(key, 0) + 1
    return counts


def expected_config_validation_rejection(proc: subprocess.CompletedProcess[str]) -> bool:
    text = proc.stdout + "\n" + proc.stderr
    if "Config validation failed:" not in text:
        return False
    expected_fragments = [
        "missing companion passes:",
        "incompatible passes",
        "cannot be enabled together",
    ]
    return any(fragment in text for fragment in expected_fragments)


def first_validation_line(proc: subprocess.CompletedProcess[str]) -> str:
    for line in (proc.stdout + "\n" + proc.stderr).splitlines():
        if "Config validation failed:" in line:
            return line.strip()
    return "Config validation failed"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engine", type=Path, default=Path("build/core-engine/libs/obfuscator-engine.jar"))
    parser.add_argument("--fixtures", type=Path, nargs="*", default=DEFAULT_FIXTURES)
    parser.add_argument("--mode", choices=["single", "pair", "triple", "full", "random", "all"], default="single")
    parser.add_argument("--include-native", action="store_true")
    parser.add_argument(
        "--combo-param-profiles",
        nargs="+",
        choices=["default", "min", "max"],
        default=["default"],
        help="Parameter profiles to apply to pair/triple/random/full cases.",
    )
    parser.add_argument("--limit", type=int, default=12)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--work-dir", type=Path, default=Path("build/real-jar-matrix"))
    parser.add_argument("--run-timeout", type=int, default=20)
    parser.add_argument("--run-attempts", type=int, default=5)
    parser.add_argument("--obfuscate-timeout", type=int, default=120)
    parser.add_argument("--ignore-testjar-pool-flake", action="store_true", help="Ignore only the known nondeterministic TEST.jar Pool line while preserving all other output checks.")
    args = parser.parse_args()

    cwd = Path.cwd()
    engine = args.engine if args.engine.is_absolute() else cwd / args.engine
    data = load_schema(engine, cwd)
    cases = build_cases(data, args.mode, args.include_native, args.limit, args.offset, args.combo_param_profiles)
    args.work_dir.mkdir(parents=True, exist_ok=True)

    failures = 0
    expected_validation_rejections = 0
    for fixture in expand_fixtures(args.fixtures):
        if not fixture.exists():
            print(f"SKIP missing {fixture}")
            continue
        main_class = jar_main_class(fixture)
        ignore_pool = args.ignore_testjar_pool_flake and fixture.name.lower().startswith("test")
        baseline_observations: list[tuple[int, str, str]] = []
        baseline: tuple[int, str, str] | None = None
        library_validation = ""
        if main_class:
            baseline_observations = run_observations(fixture, cwd, args.run_attempts, args.run_timeout, ignore_pool)
            baseline = majority_observation(baseline_observations)
            print(f"FIXTURE {fixture.name} main={main_class} sha={fingerprint(fixture)} baseline_rc={baseline[0]}")
            if len(set(baseline_observations)) > 1:
                print(f"FLAKY baseline {fixture.name} variants={len(set(baseline_observations))}")
        else:
            ok, library_validation = validate_library_jar(fixture, cwd, args.run_timeout)
            print(f"FIXTURE {fixture.name} main=<none> sha={fingerprint(fixture)} library_check={library_validation}")
            if not ok:
                failures += 1
                continue
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
                if expected_config_validation_rejection(obfuscated):
                    expected_validation_rejections += 1
                    (out_dir / "obfuscate.stdout.txt").write_text(obfuscated.stdout, encoding="utf-8", errors="replace")
                    (out_dir / "obfuscate.stderr.txt").write_text(obfuscated.stderr, encoding="utf-8", errors="replace")
                    print(f"XFAIL validation {fixture.name} {case.name} rc={obfuscated.returncode} reason={first_validation_line(obfuscated)}")
                    continue
                failures += 1
                (out_dir / "obfuscate.stdout.txt").write_text(obfuscated.stdout, encoding="utf-8", errors="replace")
                (out_dir / "obfuscate.stderr.txt").write_text(obfuscated.stderr, encoding="utf-8", errors="replace")
                print(f"FAIL obfuscate {fixture.name} {case.name} rc={obfuscated.returncode} sec={elapsed:.1f}")
                continue

            if main_class and baseline is not None:
                actual_observations = run_observations(output_jar, cwd, args.run_attempts, args.run_timeout, ignore_pool)
                actual = majority_observation(actual_observations)
                if len(set(actual_observations)) > 1:
                    failures += 1
                    (out_dir / "baseline.txt").write_text(repr(baseline), encoding="utf-8")
                    (out_dir / "baseline-observations.json").write_text(json.dumps(observation_counts(baseline_observations), ensure_ascii=False, indent=2), encoding="utf-8")
                    (out_dir / "obfuscated.txt").write_text(repr(actual), encoding="utf-8")
                    (out_dir / "obfuscated-observations.json").write_text(json.dumps(observation_counts(actual_observations), ensure_ascii=False, indent=2), encoding="utf-8")
                    print(f"FLAKY runtime {fixture.name} {case.name} variants={len(set(actual_observations))} sha={fingerprint(output_jar)}")
                elif actual != baseline:
                    failures += 1
                    (out_dir / "baseline.txt").write_text(repr(baseline), encoding="utf-8")
                    (out_dir / "baseline-observations.json").write_text(json.dumps(observation_counts(baseline_observations), ensure_ascii=False, indent=2), encoding="utf-8")
                    (out_dir / "obfuscated.txt").write_text(repr(actual), encoding="utf-8")
                    (out_dir / "obfuscated-observations.json").write_text(json.dumps(observation_counts(actual_observations), ensure_ascii=False, indent=2), encoding="utf-8")
                    print(f"FAIL runtime {fixture.name} {case.name} expected={baseline[0]} actual={actual[0]} sha={fingerprint(output_jar)}")
                else:
                    print(f"PASS {fixture.name} {case.name} sec={elapsed:.1f} sha={fingerprint(output_jar)}")
            else:
                ok, detail = validate_library_jar(output_jar, cwd, args.run_timeout)
                if not ok:
                    failures += 1
                    (out_dir / "library-validation.txt").write_text(detail, encoding="utf-8")
                    print(f"FAIL library {fixture.name} {case.name} reason={detail} sha={fingerprint(output_jar)}")
                else:
                    print(f"PASS library {fixture.name} {case.name} sec={elapsed:.1f} {detail} sha={fingerprint(output_jar)}")
    print(f"SUMMARY cases={len(cases)} failures={failures} xfail_validation={expected_validation_rejections} work_dir={args.work_dir}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
