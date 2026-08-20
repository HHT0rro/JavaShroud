@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "CORE_DIR=%%~fI"
set "ENGINE_BUILD_DIR=%CORE_DIR%\build\core-engine"
set "ENGINE_LIBS_DIR=%ENGINE_BUILD_DIR%\libs"
set "ENGINE_JAR=%ENGINE_LIBS_DIR%\obfuscator-engine.jar"
set "ENGINE_RESOURCE_CONFIG=%ENGINE_BUILD_DIR%\native\generated\generateResourcesConfigFile\resource-config.json"
set "ENGINE_NATIVE_DIR=%ENGINE_BUILD_DIR%\native\manual-native-image"
set "ENGINE_EXE=%ENGINE_NATIVE_DIR%\obfuscator-engine.exe"
set "ENGINE_MAIN_CLASS=io.github.hht0rro.javashroud.MainKt"
set "HELPER_CLASS_RESOURCES_1=META-INF/javashroud-helpers/.*\.class"
set "HELPER_CLASS_RESOURCES_2=META-INF/javashroud-helpers/.*\.bin"
set "HELPER_CLASS_RESOURCES_3=io/github/hht0rro/javashroud/transforms/protection/.*\.class"
set "META_INF_RESOURCES=META-INF/.*"

if defined GRAALVM_HOME if exist "%GRAALVM_HOME%\bin\native-image.cmd" (
  set "JAVA_HOME=%GRAALVM_HOME%"
  set "PATH=%GRAALVM_HOME%\bin;%PATH%"
)

call :require_file "%CORE_DIR%\gradlew.bat" "Missing Gradle wrapper" || exit /b 1
call :resolve_native_image || exit /b 1
call :resolve_vcvarsall || exit /b 1

echo [1/3] Building engine jar and native resources...
pushd "%CORE_DIR%" || exit /b 1
call gradlew.bat --build-cache --no-configuration-cache --rerun-tasks :core-engine:jar :core-engine:generateResourcesConfigFile || (popd & exit /b 1)
popd
call :resolve_engine_jar || exit /b 1
call :require_file "%ENGINE_RESOURCE_CONFIG%" "Engine resource config was not generated" || exit /b 1

echo [2/3] Building native engine executable...
if not exist "%ENGINE_NATIVE_DIR%" mkdir "%ENGINE_NATIVE_DIR%" || exit /b 1
set "NATIVE_IMAGE_TUNING_ARGS= --no-fallback --enable-url-protocols=https -H:+ReportExceptionStackTraces"
call "%VCVARSALL%" x64 >nul || exit /b 1
call "%NATIVE_IMAGE_CMD%" -cp "%ENGINE_JAR%" -H:Name=obfuscator-engine "-H:Path=%ENGINE_NATIVE_DIR%" %NATIVE_IMAGE_TUNING_ARGS% "-H:IncludeResources=%HELPER_CLASS_RESOURCES_1%" "-H:IncludeResources=%HELPER_CLASS_RESOURCES_2%" "-H:IncludeResources=%HELPER_CLASS_RESOURCES_3%" "-H:IncludeResources=%META_INF_RESOURCES%" "-H:ResourceConfigurationFiles=%ENGINE_RESOURCE_CONFIG%" %ENGINE_MAIN_CLASS% || exit /b 1
call :require_file "%ENGINE_EXE%" "Native engine build did not produce obfuscator-engine.exe" || exit /b 1

echo [3/3] Native engine ready: %ENGINE_EXE%
exit /b 0

:require_file
if exist %~1 exit /b 0
echo %~2: %~1
exit /b 1

:resolve_engine_jar
set "ENGINE_VERSIONED_JAR="
for /f "delims=" %%J in ('dir /b /a-d /o-d "%ENGINE_LIBS_DIR%\obfuscator-engine-*.jar" 2^>nul') do (
  if not defined ENGINE_VERSIONED_JAR set "ENGINE_VERSIONED_JAR=%ENGINE_LIBS_DIR%\%%J"
)
if not defined ENGINE_VERSIONED_JAR (
  if exist "%ENGINE_JAR%" (
    echo Using existing engine jar alias: %ENGINE_JAR%
    exit /b 0
  )
  echo Engine jar build did not produce obfuscator-engine.jar or obfuscator-engine-*.jar under %ENGINE_LIBS_DIR%
  exit /b 1
)
copy /y "%ENGINE_VERSIONED_JAR%" "%ENGINE_JAR%" >nul || exit /b 1
echo Engine jar alias ready: %ENGINE_JAR% from %ENGINE_VERSIONED_JAR%
exit /b 0

:resolve_native_image
set "NATIVE_IMAGE_CMD="
if defined GRAALVM_HOME if exist "%GRAALVM_HOME%\bin\native-image.cmd" set "NATIVE_IMAGE_CMD=%GRAALVM_HOME%\bin\native-image.cmd"
if not defined NATIVE_IMAGE_CMD if defined GRAALVM_HOME if exist "%GRAALVM_HOME%\bin\native-image.exe" set "NATIVE_IMAGE_CMD=%GRAALVM_HOME%\bin\native-image.exe"
if not defined NATIVE_IMAGE_CMD (
  for /f "delims=" %%I in ('where native-image 2^>nul') do (
    if not defined NATIVE_IMAGE_CMD set "NATIVE_IMAGE_CMD=%%~fI"
  )
)
if defined NATIVE_IMAGE_CMD exit /b 0
echo Missing GraalVM Native Image. Install a GraalVM JDK and ensure native-image is available on PATH, or set GRAALVM_HOME to a GraalVM installation with native-image installed.
exit /b 1

:resolve_vcvarsall
set "VCVARSALL_CMD="
if defined VCVARSALL if exist "%VCVARSALL%" set "VCVARSALL_CMD=%VCVARSALL%"
if not defined VCVARSALL_CMD if defined VSINSTALLDIR if exist "%VSINSTALLDIR%\VC\Auxiliary\Build\vcvarsall.bat" set "VCVARSALL_CMD=%VSINSTALLDIR%\VC\Auxiliary\Build\vcvarsall.bat"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not defined VCVARSALL_CMD if exist "!VSWHERE!" (
  for /f "usebackq delims=" %%I in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find VC\Auxiliary\Build\vcvarsall.bat`) do (
    if not defined VCVARSALL_CMD set "VCVARSALL_CMD=%%~fI"
  )
)
if not defined VCVARSALL_CMD (
  echo Missing Visual Studio C++ build tools environment. Set VCVARSALL to vcvarsall.bat from Visual Studio Build Tools.
  exit /b 1
)
set "VCVARSALL=%VCVARSALL_CMD%"
exit /b 0
