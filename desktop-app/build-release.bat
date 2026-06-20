@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~-1%"=="\" set "SCRIPT_DIR=%SCRIPT_DIR:~0,-1%"
set "CORE_DIR=%SCRIPT_DIR%\.."
for %%I in ("%CORE_DIR%") do set "CORE_DIR=%%~fI"
set "FRONTEND_DIR=%SCRIPT_DIR%\frontend"
set "CORE_BUILD_FRONTEND_DIST=%CORE_DIR%\build\frontend\dist"
set "FRONTEND_SOURCE_DIST=%FRONTEND_DIR%\dist"
set "BUILD_ROOT=%CORE_DIR%\build"
set "BUILD_LOG_DIR=%BUILD_ROOT%\logs"
set "FRONTEND_BUILD_LOG=%BUILD_LOG_DIR%\desktop-app-release-frontend-build.log"
if not defined GOEXE set "GOEXE=go"
if not defined WAILS_EXE set "WAILS_EXE=wails"
where "%GOEXE%" >nul 2>nul
if errorlevel 1 (
  echo Missing Go compiler executable. Set GOEXE or make go available on PATH.
  exit /b 1
)
where "%WAILS_EXE%" >nul 2>nul
if errorlevel 1 (
  echo Missing Wails CLI executable. Set WAILS_EXE or make wails available on PATH.
  exit /b 1
)
set "PATH=%SCRIPT_DIR%;%PATH%"
set "ENGINE_EMBED_DIR=%SCRIPT_DIR%\embedded"
set "ENGINE_EMBED_PATH=%ENGINE_EMBED_DIR%\obfuscator-engine.exe"
set "RSRC_SYSO=%SCRIPT_DIR%\rsrc_windows_amd64.syso"
set "RSRC_SYSO_DISABLED=%SCRIPT_DIR%\rsrc_windows_amd64.syso.codex-disabled"
if not exist "%ENGINE_EMBED_DIR%" mkdir "%ENGINE_EMBED_DIR%"
if not exist "%FRONTEND_DIR%\package.json" (
  echo Missing frontend package.json: %FRONTEND_DIR%\package.json
  exit /b 1
)
if not exist "%SCRIPT_DIR%\wails.json" (
  echo Missing Wails config: %SCRIPT_DIR%\wails.json
  exit /b 1
)
if not exist "%BUILD_ROOT%" mkdir "%BUILD_ROOT%" || exit /b 1
if not exist "%BUILD_LOG_DIR%" mkdir "%BUILD_LOG_DIR%" || exit /b 1
where corepack >nul 2>nul
if errorlevel 1 (
  echo Missing corepack. Install Node.js with Corepack enabled, or make corepack available on PATH.
  exit /b 1
)

call "%SCRIPT_DIR%\..\core-engine\build-native.bat"
if errorlevel 1 exit /b %errorlevel%
copy /y "%SCRIPT_DIR%\..\build\core-engine\native\manual-native-image\obfuscator-engine.exe" "%ENGINE_EMBED_PATH%" >nul
if errorlevel 1 exit /b %errorlevel%

if exist "%FRONTEND_BUILD_LOG%" del /f /q "%FRONTEND_BUILD_LOG%" >nul 2>nul
cmd /d /c "corepack yarn --cwd ""%FRONTEND_DIR%"" build > ""%FRONTEND_BUILD_LOG%"" 2>&1"
set "FRONTEND_EXIT=%ERRORLEVEL%"
type "%FRONTEND_BUILD_LOG%"
if not "%FRONTEND_EXIT%"=="0" exit /b %FRONTEND_EXIT%
if exist "%CORE_BUILD_FRONTEND_DIST%" rmdir /s /q "%CORE_BUILD_FRONTEND_DIST%" || exit /b 1
xcopy "%FRONTEND_SOURCE_DIST%" "%CORE_BUILD_FRONTEND_DIST%\" /e /i /y >nul || exit /b 1

call :sync_app_icon || exit /b 1
if exist "%RSRC_SYSO_DISABLED%" (
  echo Disabled resource file already exists: %RSRC_SYSO_DISABLED%
  exit /b 1
)
if exist "%RSRC_SYSO%" move /y "%RSRC_SYSO%" "%RSRC_SYSO_DISABLED%" >nul
if errorlevel 1 exit /b %ERRORLEVEL%
pushd "%SCRIPT_DIR%" || exit /b 1
call "%WAILS_EXE%" build -compiler "%GOEXE%" -tags javashroud_embed_engine -s %*
set "WAILS_EXIT=%ERRORLEVEL%"
popd
if exist "%RSRC_SYSO_DISABLED%" move /y "%RSRC_SYSO_DISABLED%" "%RSRC_SYSO%" >nul
exit /b %WAILS_EXIT%

:sync_app_icon
set "PYTHON_EXE="
for %%P in (python py) do (
  if not defined PYTHON_EXE (
    where %%P >nul 2>nul && set "PYTHON_EXE=%%P"
  )
)
if defined PYTHON_EXE (
  %PYTHON_EXE% "%SCRIPT_DIR%\scripts\sync_app_icon.py"
  exit /b %ERRORLEVEL%
)
if exist "%FRONTEND_DIR%\public\brand\appicon.png" if exist "%FRONTEND_DIR%\public\brand\appicon.ico" (
  echo Python not found; using existing app icon assets.
  exit /b 0
)
echo Python not found and app icon assets are incomplete.
exit /b 1
