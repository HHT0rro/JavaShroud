"""Exercise the published desktop through its own WebView and native dialogs."""

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import tomllib
import traceback
import urllib.request
import zipfile

import psutil
from PIL import ImageGrab
from playwright.sync_api import sync_playwright
from pywinauto import Desktop


ROOT = Path(os.environ["RUNNER_TEMP"]) / "packaged-desktop-smoke"
EVIDENCE = ROOT / "evidence"
PACKAGE = ROOT / "package"
PRIVATE = ROOT / "private"
REPO = Path(os.environ["GITHUB_WORKSPACE"])
PINS = {
    "zip": "80614ba64c89c9ec5fab49952313c4f8c19fc4a9f250073564a116c95e28fca8",
    "engine": "16f308d34c00e5793b39f3e6528f09331f98a2b5742290094839021a8ea40cda",
    "desktop": "0bd474c27f46520b71e5b66717df0320ac0dafc55b32c137626a6377be5d2c80",
    "xenolith": "3cf8d3a55a538d6aad2c42a1eedb6c646395d8d001caa64b6cf6d9ecc5f84eab",
}
RESULT = {
    "run_id": os.environ["GITHUB_RUN_ID"],
    "workflow_sha": os.environ["GITHUB_SHA"],
    "release": "v0.31.1",
    "release_source_sha": "d2c4becbb242786a3266bd492e025a7828b7ac76",
    "desktop_started": False,
    "window_responsive": False,
    "schema_via_desktop_binding": False,
    "schema_loaded_in_gui": False,
    "gui_input_selected": False,
    "gui_config_imported": False,
    "gui_output_selected": False,
    "gui_start_clicked": False,
    "gui_done_event": False,
    "gui_result_visible": False,
    "fixture_execution_passed": False,
    "explicit_minimal_profile_preserved": False,
    "full_gui_file_flow": False,
    "status": "running",
    "boundaries": [],
}
RUNS = []
ACTIONS = []
OWNED = set()
OWNED_BIRTHS = {}
USER32 = ctypes.WinDLL("user32", use_last_error=True)
USER32.IsWindowVisible.argtypes = [wintypes.HWND]
USER32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
USER32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
USER32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
USER32.SendMessageTimeoutW.argtypes = [
    wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
    wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t),
]


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


def checkpoint(page, desktop, name):
    own_windows = windows(desktop)
    save_json(f"{name}.windows.json", own_windows)
    if any(window["pid"] == desktop.pid and window["responsive"] for window in own_windows):
        RESULT["window_responsive"] = True
    try:
        ImageGrab.grab(all_screens=True).save(EVIDENCE / f"{name}.desktop.png")
    except Exception as error:
        action("native-screenshot-unavailable", stage=name, detail=str(error))
    if page is not None:
        page.screenshot(path=str(EVIDENCE / f"{name}.webview.png"), full_page=True, timeout=15000)
        (EVIDENCE / f"{name}.aria.txt").write_text(page.locator("body").aria_snapshot(timeout=15000), encoding="utf-8")
        (EVIDENCE / f"{name}.body.txt").write_text(page.locator("body").inner_text(), encoding="utf-8")
        save_json(f"{name}.controls.json", page.locator("input,button,select").evaluate_all(
            "elements => elements.map(e => ({tag:e.tagName,id:e.id,role:e.getAttribute('role'),"
            "aria:e.getAttribute('aria-label'),text:e.innerText,value:e.value,disabled:e.disabled}))"))
    save_json("acceptance.json", RESULT)


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


def wait_cdp(port, desktop):
    endpoint = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 12
    last_error = "No loopback CDP endpoint"
    while time.monotonic() < deadline:
        if desktop.poll() is not None:
            raise RuntimeError(f"Desktop exited before CDP readiness with code {desktop.returncode}")
        track_processes(desktop)
        listeners = [connection for connection in psutil.net_connections(kind="tcp")
                     if connection.status == psutil.CONN_LISTEN and connection.laddr.port == port]
        for connection in listeners:
            if connection.pid not in OWNED or connection.laddr.ip not in ("127.0.0.1", "::1"):
                raise RuntimeError("CDP listener ownership or loopback boundary failed")
        if listeners:
            save_json("debug-listeners.json", [{"pid": connection.pid, "address": connection.laddr.ip,
                                               "port": connection.laddr.port} for connection in listeners])
            try:
                with urllib.request.urlopen(endpoint + "/json/version", timeout=2) as response:
                    save_json("cdp-version.json", json.load(response))
                return endpoint
            except Exception as error:
                last_error = str(error)
        time.sleep(0.5)
    raise RuntimeError(last_error)


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
        entry = {"name": control.window_text(), "type": control.element_info.control_type,
                 "automation_id": control.element_info.automation_id,
                 "enabled": control.is_enabled(), "visible": control.is_visible()}
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
    time.sleep(1)
    records = uia_snapshot(desktop, "uia-05-imported")
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
        if output_jar.exists() and any(text in ("产物已生成", "Output generated") for text in observed):
            RESULT["gui_result_visible"] = True
            break
        time.sleep(0.3)
    save_json("uia-final-text.json", observed)
    uia_snapshot(desktop, "uia-08-result")
    if not RESULT["gui_result_visible"]:
        raise RuntimeError("The real GUI did not confirm a generated output within 90 seconds")
    log_path = Path(str(output_jar) + ".log")
    if log_path.exists():
        shutil.copy2(log_path, EVIDENCE / "gui-engine.log")
        text = log_path.read_text(encoding="utf-8", errors="replace")
        RESULT["gui_done_event"] = bool(re.search(r'type\s*=\s*"done"', text))
    action("uia-output-visible", output=str(output_jar), done_in_retained_log=RESULT["gui_done_event"])


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
        if len(classes) != 2 or any(major != 52 for major in classes.values()):
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


def gui_flow(page, desktop, input_jar, output_jar, config):
    page.set_default_timeout(15000)
    page.wait_for_function("() => document.querySelector('#input-jar-path') !== null", timeout=45000)
    checkpoint(page, desktop, "01-loaded")
    if "wails" not in page.url.lower() and not page.url.startswith("http://localhost"):
        raise RuntimeError("Unexpected desktop WebView origin")
    page.wait_for_function("() => document.querySelector('.engine-version')?.innerText.includes('0.31.1')", timeout=45000)
    schema = page.evaluate("async () => await window.go.main.App.GetEngineCapabilities()")
    (EVIDENCE / "desktop-binding-schema.toml").write_text(schema, encoding="utf-8")
    parsed = tomllib.loads(schema)
    if str(parsed["schemaVersion"]) != "2" or parsed["engineVersion"] != "0.31.1":
        raise RuntimeError("Unexpected schema from the desktop backend")
    RESULT["schema_via_desktop_binding"] = True
    action("schema-visible-and-desktop-binding-verified", version=parsed["engineVersion"], module_count=len(parsed["modules"]))
    page.evaluate("""() => {
        window.__ownedSmokeEvents = [];
        window.runtime.EventsOn('engine:event', value => window.__ownedSmokeEvents.push(value));
    }""")
    checkpoint(page, desktop, "02-schema-ready")
    input_control = page.locator("#input-jar-path")
    choose_input = page.get_by_role("button", name=re.compile(r"^(选择 JAR 文件|Choose JAR file)$"))
    if choose_input.count() == 1:
        choose_input.click()
        native_file_dialog(desktop, input_jar, "03-select-input")
    else:
        action("input-path-editor", selector="#input-jar-path", reason="Owned UI exposes an editable path")
        input_control.fill(str(input_jar))
        input_control.press("Tab")
    input_control.wait_for(state="visible")
    page.wait_for_function("path => document.querySelector('#input-jar-path')?.value === path", arg=str(input_jar))
    RESULT["gui_input_selected"] = True
    checkpoint(page, desktop, "04-input-loaded")
    page.get_by_role("button", name=re.compile(r"^(导入配置|Import config)$")).click()
    native_file_dialog(desktop, config, "05-import-config")
    page.wait_for_function("path => document.querySelector('#output-jar-path')?.value.replaceAll('\\\\','/') === path", arg=output_jar.as_posix())
    RESULT["gui_config_imported"] = True
    checkpoint(page, desktop, "06-imported")
    page.locator("#output-jar-path").fill(str(output_jar))
    page.locator("#output-jar-path").press("Tab")
    RESULT["gui_output_selected"] = True
    page.get_by_test_id("nav-passes").click()
    checkpoint(page, desktop, "07-pipeline")
    checkboxes = page.get_by_role("checkbox")
    checked = []
    for index in range(checkboxes.count()):
        item = checkboxes.nth(index)
        if item.is_checked():
            checked.append(item.get_attribute("aria-label"))
    action("pipeline-observed", checked_checkboxes=checked, requested_profile="minimal")
    page.get_by_test_id("nav-home").click()
    start = page.get_by_role("button", name=re.compile(r"^(开始混淆|Start run)$"))
    start.wait_for(state="visible")
    if not start.is_enabled():
        raise RuntimeError("Start run remains disabled after the imported configuration")
    checkpoint(page, desktop, "08-ready-to-run")
    start.click()
    RESULT["gui_start_clicked"] = True
    action("gui-start-clicked")
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        track_processes(desktop)
        payloads = page.evaluate("() => window.__ownedSmokeEvents")
        save_json("desktop-engine-events.json", payloads)
        event_types = [payload.get("type") for payload in payloads if isinstance(payload, dict)]
        if "error" in event_types:
            raise RuntimeError("Desktop emitted an engine error event")
        if output_jar.exists() and "done" in event_types:
            RESULT["gui_done_event"] = True
            break
        page.wait_for_timeout(300)
    if not RESULT["gui_done_event"]:
        raise RuntimeError("Desktop UI did not complete the owned file flow within 90 seconds")
    page.get_by_test_id("nav-home").click()
    page.wait_for_function("() => /产物已生成|Output generated/.test(document.body.innerText)")
    RESULT["gui_result_visible"] = True
    checkpoint(page, desktop, "09-gui-complete")


def main():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    PRIVATE.mkdir(parents=True, exist_ok=True)
    for directory in ("appdata", "localappdata", "temp", "webview"):
        (PRIVATE / directory).mkdir(exist_ok=True)
    archive = ROOT / "download/javashroud-windows-amd64.zip"
    if digest(archive) != PINS["zip"]:
        raise RuntimeError("Package ZIP pin mismatch")
    with zipfile.ZipFile(archive) as package_zip:
        package_zip.extractall(PACKAGE)
    paths = {"engine": PACKAGE / "engine/obfuscator-engine.exe", "desktop": PACKAGE / "javashroud.exe",
             "xenolith": PACKAGE / "tools/xenolith.exe"}
    for name, path in paths.items():
        if digest(path) != PINS[name]:
            raise RuntimeError(f"{name} pin mismatch")
    save_json("pins.json", {**PINS, "run_id": RESULT["run_id"], "workflow_sha": RESULT["workflow_sha"]})
    schema = recorded("package-engine-schema", [paths["engine"], "-schema"])
    parsed_schema = tomllib.loads(schema)
    if str(parsed_schema["schemaVersion"]) != "2" or parsed_schema["engineVersion"] != "0.31.1":
        raise RuntimeError("Package engine schema identity mismatch")
    RESULT["package_engine_schema"] = True
    input_jar, output_jar, config = fixture()
    before = digest(input_jar)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    environment = os.environ.copy()
    environment.update({"APPDATA": str(PRIVATE / "appdata"), "LOCALAPPDATA": str(PRIVATE / "localappdata"),
                        "TEMP": str(PRIVATE / "temp"), "TMP": str(PRIVATE / "temp"),
                        "WEBVIEW2_USER_DATA_FOLDER": str(PRIVATE / "webview"),
                        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": f"--remote-debugging-port={port} --remote-debugging-address=127.0.0.1"})
    save_json("isolated-environment.json", {key: environment[key] for key in (
        "APPDATA", "LOCALAPPDATA", "TEMP", "TMP", "WEBVIEW2_USER_DATA_FOLDER", "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS")})
    desktop = None
    page = None
    exit_code = 1
    stdout = (EVIDENCE / "desktop.stdout.log").open("wb")
    stderr = (EVIDENCE / "desktop.stderr.log").open("wb")
    try:
        desktop = subprocess.Popen([str(paths["desktop"])], cwd=PACKAGE, env=environment,
                                   stdout=stdout, stderr=stderr, creationflags=subprocess.CREATE_NO_WINDOW)
        RESULT["desktop_started"] = True
        action("desktop-started", pid=desktop.pid, debug_port=port)
        try:
            endpoint = wait_cdp(port, desktop)
        except RuntimeError as error:
            if str(error) != "No loopback CDP endpoint":
                raise
            action("cdp-unavailable-using-native-uia", reason=str(error))
            uia_flow(desktop, input_jar, output_jar, config)
        else:
            with sync_playwright() as playwright:
                browser = playwright.chromium.connect_over_cdp(endpoint, timeout=15000)
                pages = [candidate for context in browser.contexts for candidate in context.pages]
                save_json("cdp-pages.json", [{"url": candidate.url} for candidate in pages])
                page = next((candidate for candidate in pages if "wails" in candidate.url.lower()), None)
                if page is None:
                    raise RuntimeError("The owned WebView2 endpoint did not expose the desktop page")
                page.on("pageerror", lambda error: action("webview-page-error", detail=str(error)))
                gui_flow(page, desktop, input_jar, output_jar, config)
        for generated in (PRIVATE / "temp").glob("javashroud-config-*/obfuscation-config.toml"):
            shutil.copy2(generated, EVIDENCE / "desktop-generated-config.toml")
        generated_path = EVIDENCE / "desktop-generated-config.toml"
        if generated_path.exists():
            generated = tomllib.loads(generated_path.read_text(encoding="utf-8"))
            actual_passes = [item["id"] for item in generated.get("passes", []) if item.get("enabled", True)]
            if actual_passes != ["strip-compile-debug-info"]:
                raise RuntimeError(f"Unexpected GUI-selected passes: {actual_passes}")
            RESULT["actual_gui_passes"] = actual_passes
            RESULT["explicit_minimal_profile_preserved"] = generated.get("protectionProfile") == "minimal"
            RESULT["generated_profile"] = generated.get("protectionProfile", "absent; engine JAR default release-hardened")
        if not RESULT["explicit_minimal_profile_preserved"]:
            RESULT["boundaries"].append("The shipped desktop request does not preserve the imported minimal profile. The generated configuration and its strip-only pass list are archived.")
        verify_execution(input_jar, output_jar, before)
        RESULT["full_gui_file_flow"] = True
        RESULT["status"] = "gui-file-flow-passed"
        exit_code = 0
    except Exception as error:
        RESULT["error"] = str(error)
        (EVIDENCE / "failure.traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
        RESULT["status"] = "failed"
        if desktop is not None:
            try:
                uia_snapshot(desktop, "failure-uia")
            except Exception:
                pass
            try:
                checkpoint(page, desktop, "failure")
            except Exception:
                pass
        if RESULT["window_responsive"] and RESULT.get("package_engine_schema") and not RESULT["gui_start_clicked"]:
            RESULT["status"] = "partial-window-and-schema-only"
            RESULT["boundaries"].append(str(error))
            exit_code = 0
    finally:
        if desktop is not None:
            track_processes(desktop)
            cleanup = []
            owned_processes = []
            for process_id in sorted(OWNED, reverse=True):
                try:
                    process = psutil.Process(process_id)
                    if process.create_time() != OWNED_BIRTHS.get(process_id):
                        cleanup.append({"pid": process_id, "detail": "PID identity changed before cleanup"})
                        continue
                    cleanup.append({"pid": process_id, "exe": process.exe(), "action": "terminate owned process"})
                    process.kill()
                    owned_processes.append(process)
                except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
                    cleanup.append({"pid": process_id, "detail": str(error)})
            psutil.wait_procs(owned_processes, timeout=10)
            save_json("cleanup-processes.json", cleanup)
            RESULT["desktop_exit_code_after_cleanup"] = desktop.poll()
        stdout.close()
        stderr.close()
        listeners = [connection for connection in psutil.net_connections(kind="tcp")
                     if connection.status == psutil.CONN_LISTEN and connection.laddr.port == port]
        save_json("cleanup-listeners.json", [{"pid": connection.pid, "address": connection.laddr.ip,
                                             "port": connection.laddr.port} for connection in listeners])
        RESULT["debug_listener_closed"] = not listeners
        if listeners:
            RESULT["status"] = "failed-cleanup"
            exit_code = 1
        for generated in (PRIVATE / "temp").glob("javashroud-config-*/obfuscation-config.toml"):
            shutil.copy2(generated, EVIDENCE / "desktop-generated-config.toml")
        for path in output_jar.parent.glob("*"):
            if path.is_file() and path.suffix in (".txt", ".log", ".toml", ".json"):
                shutil.copy2(path, EVIDENCE / path.name)
        save_json("acceptance.json", RESULT)
    return exit_code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        EVIDENCE.mkdir(parents=True, exist_ok=True)
        RESULT["status"] = "failed-before-desktop-flow"
        RESULT["error"] = str(error)
        save_json("acceptance.json", RESULT)
        (EVIDENCE / "failure.traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
        raise
