"""Drive the owned packaged desktop using Windows UIAutomation."""

import ctypes
from _ctypes import COMError
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import tomllib
import traceback
import zipfile

import psutil
from pywinauto import Desktop

ROOT = Path(os.environ["RUNNER_TEMP"]) / "rc2-desktop-smoke"
EVIDENCE = ROOT / "evidence"
PACKAGE = ROOT / "package"
PRIVATE = ROOT / "private"
REPO = Path(os.environ["GITHUB_WORKSPACE"])
RESULT = {}
RUNS = []
ACTIONS = []
OWNED = set()
OWNED_BIRTHS = {}
USER32 = ctypes.WinDLL("user32", use_last_error=True)
USER32.IsWindowVisible.argtypes = [wintypes.HWND]
USER32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
USER32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
USER32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
USER32.SendMessageTimeoutW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM, wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)]


def checkpoint(page, desktop, name):
    records = windows(desktop)
    save_json(f"{name}.windows.json", records)
    if any(item["pid"] == desktop.pid and item["responsive"] for item in records):
        RESULT["window_responsive"] = True
    uia_window(desktop).capture_as_image().save(str(EVIDENCE / f"{name}.desktop.png"))
    save_json("acceptance.json", RESULT)


def save_json(name, value):
    (EVIDENCE / name).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def action(name, **details):
    ACTIONS.append({"action": name, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **details})
    save_json("ui-actions.json", ACTIONS)
    print(name, json.dumps(details, ensure_ascii=True), flush=True)


def recorded(name, command, timeout=60, env=None):
    start = time.monotonic()
    timed_out = False
    with (EVIDENCE / f"{name}.stdout.log").open("wb") as stdout, (EVIDENCE / f"{name}.stderr.log").open("wb") as stderr:
        process = subprocess.Popen([str(part) for part in command], stdout=stdout, stderr=stderr, env=env, cwd=PACKAGE)
        try:
            code = process.wait(timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            for child in psutil.Process(process.pid).children(recursive=True):
                child.kill()
            process.kill()
            code = process.wait(10)
    entry = {"name": name, "command": [str(part) for part in command], "exit_code": code,
             "timed_out": timed_out, "elapsed_ms": round((time.monotonic() - start) * 1000)}
    RUNS.append(entry)
    save_json("runs.json", RUNS)
    if timed_out or code != 0:
        raise RuntimeError(f"{name} exit={code} timed_out={timed_out}")
    return (EVIDENCE / f"{name}.stdout.log").read_text(encoding="utf-8", errors="replace")


def track_processes(desktop):
    OWNED.add(desktop.pid)
    try:
        children = psutil.Process(desktop.pid).children(recursive=True)
    except psutil.NoSuchProcess:
        children = []
    OWNED.update(child.pid for child in children)
    records = []
    for process_id in sorted(OWNED):
        try:
            process = psutil.Process(process_id)
            OWNED_BIRTHS.setdefault(process_id, process.create_time())
            if process.create_time() != OWNED_BIRTHS[process_id]:
                continue
            records.append({"pid": process_id, "ppid": process.ppid(), "exe": process.exe(), "command": process.cmdline()})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    save_json("owned-processes.json", records)
    return records


def windows(desktop):
    track_processes(desktop)
    records = []
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def capture(handle, _):
        process_id = wintypes.DWORD()
        USER32.GetWindowThreadProcessId(handle, ctypes.byref(process_id))
        if process_id.value in OWNED and USER32.IsWindowVisible(handle):
            title = ctypes.create_unicode_buffer(1024)
            USER32.GetWindowTextW(handle, title, len(title))
            rect = wintypes.RECT()
            USER32.GetWindowRect(handle, ctypes.byref(rect))
            response = ctypes.c_size_t()
            responsive = bool(USER32.SendMessageTimeoutW(handle, 0, 0, 0, 2, 2000, ctypes.byref(response)))
            records.append({"handle": int(handle), "pid": process_id.value, "title": title.value,
                            "responsive": responsive, "rect": [rect.left, rect.top, rect.right, rect.bottom]})
        return True

    USER32.EnumWindows(callback_type(capture), 0)
    return records


def native_file_dialog(desktop, value, name):
    deadline = time.monotonic() + 15
    dialog = None
    while time.monotonic() < deadline:
        candidates = [item for item in windows(desktop) if re.search(r"选择输入|选择导入配置|选择输出|Open|Save", item["title"])]
        if len(candidates) == 1:
            dialog = Desktop(backend="uia").window(handle=candidates[0]["handle"]).wrapper_object()
        if dialog is not None:
            break
        time.sleep(0.3)
    if dialog is None:
        raise RuntimeError(f"{name}: owned Windows file dialog was not accessible through UIAutomation")
    controls = dialog.descendants()
    save_json(f"{name}.dialog-controls.json", [
        {"name": control.window_text(), "type": control.element_info.control_type,
         "automation_id": control.element_info.automation_id}
        for control in controls[:250]
    ])
    dialog.capture_as_image().save(str(EVIDENCE / f"{name}.dialog.png"))
    edits = [control for control in controls if control.element_info.control_type == "Edit"]
    file_edit = next((control for control in edits if control.element_info.automation_id == "1148"), None)
    if file_edit is None:
        file_edit = next((control for control in edits if re.search("file name|文件名", control.window_text(), re.I)), None)
    if file_edit is None:
        raise RuntimeError(f"{name}: file-name edit was absent in the observed native dialog")
    file_edit.set_edit_text(str(value))
    buttons = [control for control in controls if control.element_info.control_type == "Button"]
    confirm = next((control for control in buttons if control.element_info.automation_id == "1"), None)
    if confirm is None:
        raise RuntimeError(f"{name}: native dialog confirm button was absent")
    action(name, dialog=dialog.window_text(), file=str(value), interaction="UIAutomation ValuePattern + InvokePattern")
    confirm.invoke()


def uia_window(desktop):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        own_windows = windows(desktop)
        window = next((item for item in own_windows if item["pid"] == desktop.pid and item["title"] == "JavaShroud"), None)
        if window is not None:
            return Desktop(backend="uia").window(handle=window["handle"]).wrapper_object()
        if desktop.poll() is not None:
            break
        time.sleep(0.3)
    raise RuntimeError("The owned desktop window was not visible after the startup readiness deadline")


def uia_snapshot(desktop, name):
    window = uia_window(desktop)
    controls = window.descendants()
    records = []
    for control in controls:
        try:
            entry = {"name": control.window_text(), "type": control.element_info.control_type,
                     "automation_id": control.element_info.automation_id,
                     "enabled": control.is_enabled(), "visible": control.is_visible()}
        except COMError:
            continue
        try:
            entry["value"] = control.iface_value.CurrentValue
        except Exception:
            pass
        records.append(entry)
    save_json(f"{name}.uia.json", records)
    checkpoint(None, desktop, name)
    return records


def uia_find(desktop, pattern, control_type="Button", timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        matches = [control for control in uia_window(desktop).descendants(control_type=control_type)
                   if re.search(pattern, control.window_text()) and control.is_enabled()]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            visible = [control for control in matches if control.is_visible()]
            if len(visible) == 1:
                return visible[0]
        time.sleep(0.3)
    raise RuntimeError(f"UIAutomation could not uniquely resolve {control_type} matching {pattern}")


def uia_invoke(desktop, pattern, name):
    button = uia_find(desktop, pattern)
    action(name, accessible_name=button.window_text(), interaction="UIAutomation InvokePattern")
    button.invoke()


def uia_flow(desktop, input_jar, output_jar, config):
    RESULT["interaction_backend"] = "Windows UIAutomation"
    records = uia_snapshot(desktop, "uia-01-initial")
    if not records:
        raise RuntimeError("The hosted session exposed no UIAutomation descendants")
    uia_invoke(desktop, r"^(选择 JAR 文件|Choose JAR file)$", "uia-select-input")
    native_file_dialog(desktop, input_jar, "uia-02-select-input")
    time.sleep(1)
    records = uia_snapshot(desktop, "uia-03-input")
    if not any(str(input_jar).replace("\\", "/") in entry.get("value", "").replace("\\", "/") for entry in records):
        raise RuntimeError("Selected input was not reflected in the real path editor")
    RESULT["gui_input_selected"] = True
    uia_invoke(desktop, r"^(导入配置|Import config|导入|Import)$", "uia-import-config")
    native_file_dialog(desktop, config, "uia-04-import-config")
    deadline = time.monotonic() + 60
    records = []
    while time.monotonic() < deadline:
        records = uia_snapshot(desktop, "uia-05-imported")
        if any(output_jar.as_posix() in entry.get("value", "").replace("\\", "/") for entry in records):
            break
        time.sleep(0.3)
    if not any(output_jar.as_posix() in entry.get("value", "").replace("\\", "/") for entry in records):
        raise RuntimeError("Imported output path did not appear in the real UI")
    RESULT["gui_config_imported"] = True
    RESULT["gui_output_selected"] = True
    uia_invoke(desktop, r"^流水线$|^Pipeline$", "uia-open-pipeline")
    time.sleep(0.5)
    records = uia_snapshot(desktop, "uia-06-pipeline")
    checkboxes = uia_window(desktop).descendants(control_type="CheckBox")
    if not any("编译" in item.window_text() or "Debug" in item.window_text() for item in checkboxes):
        raise RuntimeError("The actual module catalog did not expose the strip pass")
    checked = [{"name": item.window_text(), "toggle": item.get_toggle_state()} for item in checkboxes]
    save_json("uia-pipeline-toggles.json", checked)
    if sum(item["toggle"] == 1 for item in checked) != 1:
        raise RuntimeError("Imported strip-only configuration did not select exactly one pass")
    RESULT["schema_loaded_in_gui"] = True
    RESULT["gui_schema_module_count"] = len(checkboxes)
    uia_invoke(desktop, r"^工作台$|^Workbench$", "uia-return-home")
    uia_snapshot(desktop, "uia-07-ready")
    uia_invoke(desktop, r"^(开始混淆|Start run)$", "uia-start-run")
    RESULT["gui_start_clicked"] = True
    deadline = time.monotonic() + 90
    observed = []
    while time.monotonic() < deadline:
        track_processes(desktop)
        observed = [item.window_text() for item in uia_window(desktop).descendants()]
        if any(text in ("任务未完成", "Task not completed") for text in observed):
            uia_snapshot(desktop, "uia-08-failed")
            raise RuntimeError("The real GUI displayed a failed task")
        if output_jar.exists() and any("Engine completed analysis and wrote output jar=" in text for text in observed):
            RESULT["gui_completion_log_visible"] = True
            break
        time.sleep(0.3)
    save_json("uia-final-text.json", observed)
    uia_snapshot(desktop, "uia-08-result")
    if not RESULT.get("gui_completion_log_visible"):
        raise RuntimeError("The real GUI did not confirm a generated output within 90 seconds")
    uia_invoke(desktop, r"^工作台$|^Workbench$", "uia-view-completed-result")
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        result_text = [item.window_text() for item in uia_window(desktop).descendants()]
        if any(text in ("产物已生成", "Output generated") for text in result_text):
            RESULT["gui_result_visible"] = True
            break
        time.sleep(0.3)
    uia_snapshot(desktop, "uia-09-home-result")
    if not RESULT["gui_result_visible"]:
        raise RuntimeError("The completed file was not reflected in the workbench result panel")
    log_path = Path(str(output_jar) + ".log")
    if log_path.exists():
        shutil.copy2(log_path, EVIDENCE / "gui-engine.log")
        text = log_path.read_text(encoding="utf-8", errors="replace")
        RESULT["gui_done_event"] = bool(re.search(r'type\s*=\s*"done"', text))
    action("uia-output-visible", output=str(output_jar), done_in_retained_log=RESULT["gui_done_event"])


def retain_generated_configs(stop):
    while not stop.is_set():
        for config_path in (PRIVATE / "temp").glob("javashroud-config-*/obfuscation-config.toml"):
            try:
                content = config_path.read_text(encoding="utf-8")
                parsed = tomllib.loads(content)
                if parsed.get("inputJarPath") and parsed.get("passes"):
                    (EVIDENCE / "desktop-generated-config.toml").write_text(content, encoding="utf-8")
            except (OSError, tomllib.TOMLDecodeError):
                pass
        stop.wait(0.005)


def fixture():
    source = EVIDENCE / "source"
    classes = EVIDENCE / "classes"
    source.mkdir()
    classes.mkdir()
    original = REPO / "core-engine/src/test/resources/official-test-jar/pack/tests/bench/Calc.java"
    shutil.copy2(original, source / "Calc.java")
    (source / "OwnedCalcMain.java").write_text(
        'import pack.tests.bench.Calc;\npublic final class OwnedCalcMain {\n'
        '    public static void main(String[] args) {\n'
        '        Calc.runAll();\n        System.out.println("COUNT=" + Calc.count);\n    }\n}\n', encoding="utf-8")
    bin_path = Path(os.environ["VERIFY_JDK_21"]) / "bin"
    recorded("javac-java8", [bin_path / "javac.exe", "--release", "8", "-g", "-d", classes,
                             source / "Calc.java", source / "OwnedCalcMain.java"])
    input_jar = EVIDENCE / "owned-calc-original.jar"
    output_jar = EVIDENCE / "output/owned-calc-gui-strip.jar"
    output_jar.parent.mkdir()
    recorded("jar-create", [bin_path / "jar.exe", "--create", "--file", input_jar,
                            "--main-class", "OwnedCalcMain", "-C", classes, "."])
    config = EVIDENCE / "gui-import-minimal.toml"
    config.write_text(
        '[meta]\nformat = "javashroud-workbench"\nversion = 3\nartifactFormat = "jar"\n'
        'protectionProfile = "minimal"\n\n[input]\n'
        f'inputJarPath = {json.dumps(input_jar.as_posix())}\n'
        f'outputJarPath = {json.dumps(output_jar.as_posix())}\n\n'
        '[[passes]]\nid = "strip-compile-debug-info"\nenabled = true\n', encoding="utf-8")
    for relative in ["desktop-app/engine_config_support.go", "desktop-app/app.go",
                     "desktop-app/frontend/src/modules/obfuscation/config-toml.ts",
                     "desktop-app/frontend/src/components/DropZonePanel.vue"]:
        shutil.copy2(REPO / relative, source / Path(relative).name)
    return input_jar, output_jar, config


def verify_jar(path):
    with zipfile.ZipFile(path) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("JAR CRC validation failed")
        classes = {name: int.from_bytes(archive.read(name)[6:8], "big")
                   for name in archive.namelist() if name.endswith(".class")}
        required = {"OwnedCalcMain.class", "pack/tests/bench/Calc.class"}
        if not required.issubset(classes) or any(major != 52 for major in classes.values()):
            raise RuntimeError(f"Unexpected classfile identities or major values: {classes}")
        signatures = [name for name in archive.namelist() if re.match(r"META-INF/.*\.(SF|RSA|DSA|EC)$", name, re.I)]
    return {"sha256": digest(path), "classes": classes, "signature_entries": signatures,
            "fixture_signature_status": "unsigned owned fixture", "zip_crc_verified": True}


def verify_execution(input_jar, output_jar, before):
    hashes = {"original": verify_jar(input_jar), "gui_output": verify_jar(output_jar)}
    if hashes["original"]["sha256"] != before:
        raise RuntimeError("GUI processing changed the original fixture")
    save_json("fixture-identities.json", hashes)
    for jdk in ("17", "21"):
        java_bin = Path(os.environ[f"VERIFY_JDK_{jdk}"]) / "bin"
        recorded(f"jdk{jdk}-version", [java_bin / "java.exe", "-version"])
        for label, jar_path in (("original", input_jar), ("gui-output", output_jar)):
            name = f"jdk{jdk}-{label}"
            stdout = recorded(name, [java_bin / "java.exe", "-jar", jar_path])
            stderr = (EVIDENCE / f"{name}.stderr.log").read_text(encoding="utf-8")
            normalized = re.sub(r"(?m)^Calc:\d+ms\r?\n?", "", stdout).strip()
            if normalized != "COUNT=30000" or stderr.strip():
                raise RuntimeError(f"{name} failed owned Calc semantics")
    java_bin = Path(os.environ["VERIFY_JDK_21"]) / "bin"
    for label, jar_path in (("original", input_jar), ("gui-output", output_jar)):
        recorded(f"jarsigner-{label}", [java_bin / "jarsigner.exe", "-verify", jar_path])
    RESULT["fixture_execution_passed"] = True


def prepare_package(pins):
    run = json.loads(recorded("verify-only-run", ["gh", "api", f"repos/HHT0rro/JavaShroud/actions/runs/{pins['release_run_id']}"]))
    if run["head_sha"] != pins["source_sha"] or run["status"] != "completed" or run["conclusion"] != "success":
        raise RuntimeError("The pinned verify-only run did not succeed at the expected source")
    metadata = json.loads(recorded("verify-only-artifact", ["gh", "api", f"repos/HHT0rro/JavaShroud/actions/artifacts/{pins['artifact_id']}"]))
    if metadata["workflow_run"]["id"] != pins["release_run_id"] or metadata["workflow_run"]["head_sha"] != pins["source_sha"]:
        raise RuntimeError("The pinned artifact belongs to a different run or source")
    if metadata["digest"] != "sha256:" + pins["artifact_sha256"]:
        raise RuntimeError("The artifact API digest differs from the independently retained pin")
    archive_path = ROOT / "verify-only-artifact.zip"
    start = time.monotonic()
    with archive_path.open("wb") as stdout, (EVIDENCE / "artifact-download.stderr.log").open("wb") as stderr:
        result = subprocess.run(["gh", "api", f"repos/HHT0rro/JavaShroud/actions/artifacts/{pins['artifact_id']}/zip"],
                                stdout=stdout, stderr=stderr, timeout=120)
    RUNS.append({"name": "artifact-download", "exit_code": result.returncode,
                 "elapsed_ms": round((time.monotonic() - start) * 1000)})
    save_json("runs.json", RUNS)
    if result.returncode != 0 or digest(archive_path) != pins["artifact_sha256"]:
        raise RuntimeError("The verify-only artifact download or digest check failed")
    with zipfile.ZipFile(archive_path) as archive:
        matches = [name for name in archive.namelist() if Path(name).name == "javashroud-windows-amd64.zip"]
        if len(matches) != 1 or archive.testzip() is not None:
            raise RuntimeError("The verify-only artifact did not contain one valid Windows package")
        package_zip = ROOT / "javashroud-windows-amd64.zip"
        package_zip.write_bytes(archive.read(matches[0]))
    if digest(package_zip) != pins["package_sha256"]:
        raise RuntimeError("The Windows package digest differed from its pin")
    with zipfile.ZipFile(package_zip) as archive:
        if archive.testzip() is not None:
            raise RuntimeError("The Windows package failed CRC validation")
        archive.extractall(PACKAGE)
    paths = {"desktop": PACKAGE / "javashroud.exe", "engine": PACKAGE / "engine/obfuscator-engine.exe",
             "xenolith": PACKAGE / "tools/xenolith.exe"}
    for name, path in paths.items():
        if digest(path) != pins[f"{name}_sha256"]:
            raise RuntimeError(f"The extracted {name} digest differed from its pin")
    save_json("pins.json", pins)
    return paths


def run_gui_profile(profile, paths, pins):
    global EVIDENCE, PRIVATE, RESULT
    EVIDENCE = ROOT / "evidence" / profile
    PRIVATE = ROOT / "private" / profile
    EVIDENCE.mkdir(parents=True)
    for name in ("temp", "appdata", "localappdata", "webview"):
        (PRIVATE / name).mkdir(parents=True, exist_ok=True)
    RESULT = {"profile_requested": profile, "source_sha": pins["source_sha"],
              "workflow_sha": os.environ["GITHUB_SHA"], "run_id": os.environ["GITHUB_RUN_ID"],
              "desktop_sha256": pins["desktop_sha256"], "engine_sha256": pins["engine_sha256"],
              "engine_mode": "packaged NativeImage", "status": "running",
              "gui_done_event": False, "gui_result_visible": False}
    RUNS.clear()
    ACTIONS.clear()
    OWNED.clear()
    OWNED_BIRTHS.clear()
    input_jar, output_jar, config = fixture()
    config.write_text(config.read_text(encoding="utf-8").replace('protectionProfile = "minimal"',
                      f'protectionProfile = "{profile}"'), encoding="utf-8")
    before = digest(input_jar)
    environment = os.environ.copy()
    environment.update({"APPDATA": str(PRIVATE / "appdata"), "LOCALAPPDATA": str(PRIVATE / "localappdata"),
                        "TEMP": str(PRIVATE / "temp"), "TMP": str(PRIVATE / "temp"),
                        "WEBVIEW2_USER_DATA_FOLDER": str(PRIVATE / "webview")})
    save_json("isolated-environment.json", {name: environment[name] for name in
              ("APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "WEBVIEW2_USER_DATA_FOLDER")})
    stop = threading.Event()
    watcher = threading.Thread(target=retain_generated_configs, args=(stop,), daemon=True)
    watcher.start()
    desktop = None
    stdout = (EVIDENCE / "desktop.stdout.log").open("wb")
    stderr = (EVIDENCE / "desktop.stderr.log").open("wb")
    try:
        desktop = subprocess.Popen([str(paths["desktop"])], cwd=PACKAGE, env=environment,
                                   stdout=stdout, stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW)
        action("packaged-desktop-started", pid=desktop.pid, profile=profile)
        uia_flow(desktop, input_jar, output_jar, config)
        actual = tomllib.loads((EVIDENCE / "desktop-generated-config.toml").read_text(encoding="utf-8"))
        selected = [item["id"] for item in actual.get("passes", []) if item.get("enabled", True)]
        if actual.get("protectionProfile") != profile or selected != ["strip-compile-debug-info"]:
            raise RuntimeError("The actual GUI CLI configuration lost its profile or strip-only selection")
        RESULT["actual_cli_profile"] = actual["protectionProfile"]
        RESULT["actual_gui_passes"] = selected
        RESULT["profile_preserved"] = True
        scan = output_jar.with_name(output_jar.stem + ".release-scan.txt")
        scan_text = scan.read_text(encoding="utf-8")
        if f"profile={profile}\n" not in scan_text or "RESULT=PASS" not in scan_text:
            raise RuntimeError("The actual GUI output release scan did not confirm the requested profile")
        RESULT["release_scan_profile"] = profile
        RESULT["release_scan_passed"] = True
        verify_execution(input_jar, output_jar, before)
        RESULT["full_gui_file_flow"] = True
        RESULT["status"] = "passed"
    except Exception as error:
        RESULT["status"] = "failed"
        RESULT["error"] = str(error)
        (EVIDENCE / "failure.traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
        if desktop is not None:
            try:
                uia_snapshot(desktop, "failure")
            except Exception:
                pass
    finally:
        stop.set()
        watcher.join(timeout=5)
        killed = []
        if desktop is not None:
            track_processes(desktop)
            for pid in sorted(OWNED, reverse=True):
                try:
                    process = psutil.Process(pid)
                    if process.create_time() == OWNED_BIRTHS.get(pid):
                        process.kill()
                        killed.append(process)
                except psutil.NoSuchProcess:
                    pass
            _, alive = psutil.wait_procs(killed, timeout=10)
            RESULT["owned_processes_alive_after_cleanup"] = [process.pid for process in alive]
            RESULT["desktop_cleanup_exit"] = desktop.poll()
            if alive:
                RESULT["status"] = "failed-cleanup"
        stdout.close()
        stderr.close()
        listeners = [{"pid": item.pid, "address": item.laddr.ip, "port": item.laddr.port}
                     for item in psutil.net_connections(kind="tcp")
                     if item.status == psutil.CONN_LISTEN and item.pid in OWNED]
        save_json("cleanup-listeners.json", listeners)
        if listeners:
            RESULT["status"] = "failed-cleanup"
        save_json("acceptance.json", RESULT)
    return dict(RESULT)


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    PACKAGE.mkdir(parents=True, exist_ok=True)
    pins = json.loads((REPO / ".github/diagnostics/rc2-package-pins.json").read_text(encoding="utf-8"))
    paths = prepare_package(pins)
    schema = tomllib.loads(recorded("package-engine-schema", [paths["engine"], "-schema"]))
    if str(schema["schemaVersion"]) != "2" or schema["engineVersion"] != "0.31.2-rc.2":
        raise RuntimeError("The real packaged NativeImage schema identity differed from the candidate")
    results = []
    for profile in ("minimal", "release-hardened"):
        result = run_gui_profile(profile, paths, pins)
        results.append(result)
        if result["status"] != "passed":
            break
    (ROOT / "evidence/summary.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2), flush=True)
    return 0 if len(results) == 2 and all(item["status"] == "passed" for item in results) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        (EVIDENCE / "fatal.traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
        raise

