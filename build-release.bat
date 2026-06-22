@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "CORE_DIR=%~dp0"
if "%CORE_DIR:~-1%"=="\" set "CORE_DIR=%CORE_DIR:~0,-1%"
set "DESKTOP_DIR=%CORE_DIR%\desktop-app"
set "FRONTEND_DIR=%DESKTOP_DIR%\frontend"
set "DESKTOP_EMBEDDED_DIR=%DESKTOP_DIR%\embedded"
set "BUILD_ROOT=%CORE_DIR%\build"
if /I not "%BUILD_ROOT%"=="%CORE_DIR%\build" (
  echo Refusing to delete unexpected build directory: %BUILD_ROOT%
  exit /b 1
)
if exist "%BUILD_ROOT%" (
  echo Removing build directory: %BUILD_ROOT%
  rmdir /s /q "%BUILD_ROOT%" || exit /b 1
)
set "DESKTOP_BUILD_DIR=%BUILD_ROOT%\desktop-app"
set "DESKTOP_BIN_DIR=%DESKTOP_BUILD_DIR%\bin"
set "DESKTOP_ENGINE_DIR=%DESKTOP_BIN_DIR%\engine"
set "FRONTEND_BUILD_DIR=%BUILD_ROOT%\frontend\dist"
set "WAILS_FRONTEND_DIST=%FRONTEND_DIR%\dist"
set "FRONTEND_SOURCE_DIST=%FRONTEND_DIR%\dist"
set "WAILS_APPICON_SOURCE=%FRONTEND_DIR%\public\brand\appicon.png"
set "WAILS_APPICON_TARGET=%DESKTOP_DIR%\build\appicon.png"
set "WAILS_ICON_SOURCE=%FRONTEND_DIR%\public\brand\appicon.ico"
set "WAILS_ICON_RESOURCE=%DESKTOP_DIR%\rsrc_windows_amd64.syso"
set "RELEASE_ROOT=%BUILD_ROOT%\release"
set "RELEASE_DIR=%RELEASE_ROOT%\javashroud-windows-amd64"
set "ENGINE_BUILD_DIR=%BUILD_ROOT%\core-engine"
set "ENGINE_JAR=%ENGINE_BUILD_DIR%\libs\obfuscator-engine.jar"
set "ENGINE_RESOURCE_CONFIG=%ENGINE_BUILD_DIR%\native\generated\generateResourcesConfigFile\resource-config.json"
set "ENGINE_NATIVE_DIR=%ENGINE_BUILD_DIR%\native\manual-native-image"
set "ENGINE_EXE=%ENGINE_NATIVE_DIR%\obfuscator-engine.exe"
set "ENGINE_NATIVE_STAMP=%ENGINE_NATIVE_DIR%\obfuscator-engine.sha256"
set "ENGINE_MAIN_CLASS=io.github.hht0rro.javashroud.MainKt"
set "APP_EXE=%DESKTOP_BIN_DIR%\javashroud.exe"
set "WAILS_OUTPUT_RELATIVE=..\build\desktop-app\bin\javashroud.exe"
set "WAILS_ACTUAL_EXE=%DESKTOP_DIR%\build\build\desktop-app\bin\javashroud.exe"
set "FRONTEND_BUILD_LOG=%BUILD_ROOT%\logs\frontend-build.log"
rem ---- Build optimization toggles ----
rem Supported switches: --strict-heap | --pgo <profile>
set "ENABLE_PGO="
set "PGO_PROFILE="

:parse_switches
if "%~1"=="" goto :switches_done
if /I "%~1"=="--strict-heap" ( set "ENABLE_STRICT_HEAP=1" & shift & goto :parse_switches )
if /I "%~1"=="--pgo" ( set "ENABLE_PGO=1" & set "PGO_PROFILE=%~2" & shift & shift & goto :parse_switches )
shift
goto :parse_switches
:switches_done
if not defined GOEXE set "GOEXE=go"
if not defined WAILS_EXE set "WAILS_EXE=wails"
if defined GRAALVM_HOME if exist "%GRAALVM_HOME%\bin\native-image.cmd" (
  set "JAVA_HOME=%GRAALVM_HOME%"
  set "PATH=%GRAALVM_HOME%\bin;%PATH%"
)

if not exist "%BUILD_ROOT%" mkdir "%BUILD_ROOT%" || exit /b 1
if not exist "%BUILD_ROOT%\logs" mkdir "%BUILD_ROOT%\logs" || exit /b 1
if not exist "%DESKTOP_BIN_DIR%" mkdir "%DESKTOP_BIN_DIR%" || exit /b 1
if not exist "%DESKTOP_ENGINE_DIR%" mkdir "%DESKTOP_ENGINE_DIR%" || exit /b 1

if not exist "%CORE_DIR%\gradlew.bat" (
  echo Missing Gradle wrapper: %CORE_DIR%\gradlew.bat
  exit /b 1
)
if not exist "%DESKTOP_DIR%\wails.json" (
  echo Missing Wails config: %DESKTOP_DIR%\wails.json
  exit /b 1
)
if not exist "%DESKTOP_EMBEDDED_DIR%" mkdir "%DESKTOP_EMBEDDED_DIR%" || exit /b 1
if not exist "%FRONTEND_DIR%\package.json" (
  echo Missing frontend package.json: %FRONTEND_DIR%\package.json
  exit /b 1
)
if not exist "%WAILS_APPICON_SOURCE%" (
  echo Missing Wails app icon source: %WAILS_APPICON_SOURCE%
  exit /b 1
)
if not exist "%WAILS_ICON_SOURCE%" (
  echo Missing Wails icon resource source: %WAILS_ICON_SOURCE%
  exit /b 1
)

where native-image >nul 2>nul
if errorlevel 1 (
  if not defined GRAALVM_HOME (
    echo Missing GraalVM Native Image. Install a GraalVM JDK and ensure native-image is available on PATH, or set GRAALVM_HOME to a GraalVM installation with native-image installed.
    exit /b 1
  )
  if not exist "%GRAALVM_HOME%\bin\native-image.cmd" (
    echo Missing GraalVM Native Image. Install a GraalVM JDK and ensure native-image is available on PATH, or set GRAALVM_HOME to a GraalVM installation with native-image installed.
    exit /b 1
  )
)

if not defined VCVARSALL (
  echo Missing Visual Studio C++ build tools environment. Set VCVARSALL to vcvarsall.bat from Visual Studio Build Tools.
  exit /b 1
)
if not exist "%VCVARSALL%" (
  echo Missing Visual Studio C++ build tools environment. Set VCVARSALL to vcvarsall.bat from Visual Studio Build Tools.
  exit /b 1
)

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
for /f "usebackq delims=" %%I in (`"%GOEXE%" env GOROOT`) do set "GOROOT=%%I"
if not exist "%GOROOT%\pkg\tool\windows_amd64\compile.exe" (
  echo Go toolchain is incomplete for windows_amd64: %GOROOT%\pkg\tool\windows_amd64\compile.exe
  exit /b 1
)
set "GOTOOLDIR=%GOROOT%\pkg\tool\windows_amd64"
set "PATH=%GOROOT%\bin;%PATH%"
set "GOMAXPROCS=%NUMBER_OF_PROCESSORS%"
set "GOTELEMETRY=off"
set "GOWORK=off"
set "GOFLAGS=-trimpath"

for /f "usebackq delims=" %%I in (`"%GOEXE%" env GOARCH`) do set "GOARCH=%%I"
if /I not "%GOARCH%"=="amd64" (
  echo Unsupported Go architecture for release build: %GOARCH%. Expected amd64.
  exit /b 1
)

if not exist "%FRONTEND_DIR%\node_modules\.yarn-state.yml" (
  echo [1/10] Installing frontend dependencies...
  call corepack yarn --cwd "%FRONTEND_DIR%" install --immutable || exit /b 1
) else (
  echo [1/10] Frontend dependencies already installed.
)

set "GRADLE_OPTS=-Dorg.gradle.parallel=true -Dorg.gradle.caching=true -Dorg.gradle.configuration-cache=true"
set "GRADLE_ENGINE_TASK=:core-engine:jar :core-engine:generateResourcesConfigFile"
if defined ENABLE_SKIP_ENGINE_TESTS (
  echo Skipping engine tests for faster build: ENABLE_SKIP_ENGINE_TESTS is enabled.
  set "GRADLE_ENGINE_TASK=%GRADLE_ENGINE_TASK% -x :core-engine:test"
)
echo [2/10] Building engine jar and native resources...
pushd "%CORE_DIR%" || exit /b 1
call gradlew.bat --no-build-cache --no-configuration-cache --rerun-tasks :core-engine:jar :core-engine:generateResourcesConfigFile || (popd & exit /b 1)
popd
if not exist "%ENGINE_JAR%" (
  echo Engine jar build did not produce obfuscator-engine.jar: %ENGINE_JAR%
  exit /b 1
)
if not exist "%ENGINE_RESOURCE_CONFIG%" (
  echo Engine resource config was not generated: %ENGINE_RESOURCE_CONFIG%
  exit /b 1
)

echo [3/10] Building native engine executable...
set "ENGINE_NATIVE_CACHE_ENABLED=1"
set "ENGINE_NATIVE_STAMP_FILE=%ENGINE_NATIVE_DIR%\.release-stamp.txt"
set "ENGINE_NATIVE_CACHE_OK="
call :sha256_file "%ENGINE_JAR%" ENGINE_JAR_SHA256 || exit /b 1
set "ENGINE_NATIVE_CACHE_KEY=args=%NATIVE_IMAGE_BUILD_ARGS%;jar=%ENGINE_JAR_SHA256%"
if defined ENABLE_QUICK_BUILD set "ENGINE_NATIVE_CACHE_ENABLED=0"
if defined ENABLE_PGO set "ENGINE_NATIVE_CACHE_ENABLED=0"
if "%ENGINE_NATIVE_CACHE_ENABLED%"=="1" if exist "%ENGINE_EXE%" if exist "%ENGINE_NATIVE_STAMP_FILE%" (
  set /p ENGINE_NATIVE_PREV_KEY= < "%ENGINE_NATIVE_STAMP_FILE%"
  if "!ENGINE_NATIVE_PREV_KEY!"=="!ENGINE_NATIVE_CACHE_KEY!" set "ENGINE_NATIVE_CACHE_OK=1"
)
if "%ENGINE_NATIVE_CACHE_OK%"=="1" (
  echo Reusing cached native engine build: %ENGINE_EXE%
) else (
  call "%CORE_DIR%\core-engine\build-native.bat" || exit /b 1
)
if exist "%ENGINE_NATIVE_DIR%" mkdir "%ENGINE_NATIVE_DIR%" >nul 2>nul
> "%ENGINE_NATIVE_STAMP_FILE%" echo !ENGINE_NATIVE_CACHE_KEY!
if not exist "%ENGINE_EXE%" (
  echo Native engine build did not produce obfuscator-engine.exe: %ENGINE_EXE%
  exit /b 1
)
copy /y "%ENGINE_EXE%" "%DESKTOP_EMBEDDED_DIR%\obfuscator-engine.exe" >nul || exit /b 1
if not exist "%DESKTOP_EMBEDDED_DIR%\obfuscator-engine.exe" (
  echo Embedded engine input is missing for Wails build: %DESKTOP_EMBEDDED_DIR%\obfuscator-engine.exe
  exit /b 1
)
call :verify_same_file_hash "%ENGINE_EXE%" "%DESKTOP_EMBEDDED_DIR%\obfuscator-engine.exe" "embedded native engine" || exit /b 1

echo [4/10] Building frontend bundle...
if exist "%FRONTEND_BUILD_LOG%" del /f /q "%FRONTEND_BUILD_LOG%" >nul 2>nul
cmd /d /c "corepack yarn --cwd ""%FRONTEND_DIR%"" build > ""%FRONTEND_BUILD_LOG%"" 2>&1"
set "FRONTEND_EXIT=%ERRORLEVEL%"
type "%FRONTEND_BUILD_LOG%"
if not "%FRONTEND_EXIT%"=="0" exit /b %FRONTEND_EXIT%
call :verify_frontend_bundle "%FRONTEND_SOURCE_DIST%" || exit /b 1
if exist "%FRONTEND_BUILD_DIR%" rmdir /s /q "%FRONTEND_BUILD_DIR%" || exit /b 1
xcopy "%FRONTEND_SOURCE_DIST%" "%FRONTEND_BUILD_DIR%\" /e /i /y >nul || exit /b 1
call :verify_frontend_bundle "%FRONTEND_BUILD_DIR%" || exit /b 1
call :verify_frontend_bundle "%WAILS_FRONTEND_DIST%" || exit /b 1
call :verify_synced_frontend "%FRONTEND_BUILD_DIR%" "%WAILS_FRONTEND_DIST%" || exit /b 1

echo [5/10] Building desktop executable for relocation into repository build output...
if not exist "%DESKTOP_DIR%\build" mkdir "%DESKTOP_DIR%\build" || exit /b 1
copy /y "%WAILS_APPICON_SOURCE%" "%WAILS_APPICON_TARGET%" >nul || exit /b 1
set "RSRC_CACHE_OK="
if exist "%WAILS_ICON_RESOURCE%" if exist "%WAILS_ICON_SOURCE%" (
  for %%A in ("%WAILS_ICON_SOURCE%") do set "ICON_TS=%%~tA"
  for %%B in ("%WAILS_ICON_RESOURCE%") do set "RESOURCE_TS=%%~tB"
  if "!RESOURCE_TS!" geq "!ICON_TS!" set "RSRC_CACHE_OK=1"
)
if "%RSRC_CACHE_OK%"=="1" (
  echo Reusing cached Windows resource object: %WAILS_ICON_RESOURCE%
) else (
  pushd "%DESKTOP_DIR%" || exit /b 1
  "%GOEXE%" run github.com/akavel/rsrc@v0.10.2 -ico "%WAILS_ICON_SOURCE%" -o "%WAILS_ICON_RESOURCE%" || (popd & exit /b 1)
  popd
)
if exist "%APP_EXE%" del /f /q "%APP_EXE%" >nul 2>nul
if exist "%WAILS_ACTUAL_EXE%" del /f /q "%WAILS_ACTUAL_EXE%" >nul 2>nul
pushd "%DESKTOP_DIR%" || exit /b 1
"%WAILS_EXE%" build -compiler "%GOEXE%" -tags javashroud_embed_engine -s -m -nopackage -platform windows/amd64 -o "%WAILS_OUTPUT_RELATIVE%" || (popd & exit /b 1)
popd
if not exist "%WAILS_ACTUAL_EXE%" (
  echo Desktop build did not produce the expected Wails output: %WAILS_ACTUAL_EXE%
  exit /b 1
)
move /y "%WAILS_ACTUAL_EXE%" "%APP_EXE%" >nul || exit /b 1
if not exist "%APP_EXE%" (
  echo Desktop build did not relocate javashroud.exe under build output: %APP_EXE%
  exit /b 1
)
copy /y "%ENGINE_EXE%" "%DESKTOP_ENGINE_DIR%\obfuscator-engine.exe" >nul || exit /b 1
if not exist "%DESKTOP_ENGINE_DIR%\obfuscator-engine.exe" (
  echo Desktop runtime engine is missing from build output: %DESKTOP_ENGINE_DIR%\obfuscator-engine.exe
  exit /b 1
)
call :verify_same_file_hash "%ENGINE_EXE%" "%DESKTOP_ENGINE_DIR%\obfuscator-engine.exe" "desktop runtime native engine" || exit /b 1

echo [6/10] Preparing release directory...
if exist "%RELEASE_DIR%" rmdir /s /q "%RELEASE_DIR%"
mkdir "%RELEASE_DIR%" || exit /b 1
copy /y "%APP_EXE%" "%RELEASE_DIR%\javashroud.exe" >nul || exit /b 1

echo [7/10] Writing release metadata...
(
  echo JavaShroud Windows AMD64 Release
  echo.
  echo Files:
  echo - javashroud.exe
  echo.
  echo Build root: %BUILD_ROOT%
) > "%RELEASE_DIR%\README.txt"

echo [8/10] Verifying release package...
if not exist "%RELEASE_DIR%\javashroud.exe" exit /b 1

echo [9/10] Release contents:
dir /b "%RELEASE_DIR%"

echo [10/10] Release package ready: %RELEASE_DIR%
exit /b 0

:sha256_file
set "SHA_FILE=%~1"
set "SHA_VAR=%~2"
set "POWERSHELL_EXE=powershell"
where pwsh >nul 2>nul && set "POWERSHELL_EXE=pwsh"
for /f "delims=" %%H in ('%POWERSHELL_EXE% -NoProfile -Command "(Get-FileHash -Algorithm SHA256 -LiteralPath $env:SHA_FILE).Hash"') do set "%SHA_VAR%=%%H"
if not defined %SHA_VAR% exit /b 1
exit /b 0

:verify_same_file_hash
call :sha256_file "%~1" HASH_A || exit /b 1
call :sha256_file "%~2" HASH_B || exit /b 1
if /I not "%HASH_A%"=="%HASH_B%" (
  echo Hash mismatch for %~3
  exit /b 1
)
exit /b 0

:verify_frontend_bundle
set "VERIFY_DIR=%~1"
if not exist "%VERIFY_DIR%\index.html" exit /b 1
if not exist "%VERIFY_DIR%\assets" exit /b 1
exit /b 0

:verify_synced_frontend
if not exist "%~1\index.html" exit /b 1
if not exist "%~2\index.html" exit /b 1
fc /b "%~1\index.html" "%~2\index.html" >nul
if errorlevel 1 exit /b 1
exit /b 0
