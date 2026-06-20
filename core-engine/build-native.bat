@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "CORE_DIR=%%~fI"
set "ENGINE_BUILD_DIR=%CORE_DIR%\build\core-engine"
set "ENGINE_JAR=%ENGINE_BUILD_DIR%\libs\obfuscator-engine.jar"
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
call :require_native_image
call :require_vcvarsall

echo [1/3] Building engine jar and native resources...
pushd "%CORE_DIR%" || exit /b 1
call gradlew.bat --build-cache --no-configuration-cache --rerun-tasks :core-engine:jar :core-engine:generateResourcesConfigFile || (popd & exit /b 1)
popd
call :require_file "%ENGINE_JAR%" "Engine jar build did not produce obfuscator-engine.jar" || exit /b 1
call :require_file "%ENGINE_RESOURCE_CONFIG%" "Engine resource config was not generated" || exit /b 1

echo [2/3] Building native engine executable...
if not exist "%ENGINE_NATIVE_DIR%" mkdir "%ENGINE_NATIVE_DIR%" || exit /b 1
set "NATIVE_IMAGE_CMD=%GRAALVM_HOME%\bin\native-image.cmd"
set "NATIVE_IMAGE_TUNING_ARGS= --no-fallback -H:+ReportExceptionStackTraces"
cmd /v:on /c "call "%VCVARSALL%" x64 >nul && "%NATIVE_IMAGE_CMD%" -cp "%ENGINE_JAR%" -H:Name=obfuscator-engine -H:Path="%ENGINE_NATIVE_DIR%" %NATIVE_IMAGE_TUNING_ARGS% -H:IncludeResources="%HELPER_CLASS_RESOURCES_1%" -H:IncludeResources="%HELPER_CLASS_RESOURCES_2%" -H:IncludeResources="%HELPER_CLASS_RESOURCES_3%" -H:IncludeResources="%META_INF_RESOURCES%" -H:ResourceConfigurationFiles="%ENGINE_RESOURCE_CONFIG%" %ENGINE_MAIN_CLASS%" || exit /b 1
call :require_file "%ENGINE_EXE%" "Native engine build did not produce obfuscator-engine.exe" || exit /b 1

echo [3/3] Native engine ready: %ENGINE_EXE%
exit /b 0

:require_file
if exist %~1 exit /b 0
echo %~2: %~1
exit /b 1

:require_native_image
where native-image >nul 2>nul
if %errorlevel%==0 exit /b 0
if defined GRAALVM_HOME if exist "%GRAALVM_HOME%\bin\native-image.cmd" exit /b 0
echo Missing GraalVM Native Image. Install a GraalVM JDK and ensure native-image is available on PATH, or set GRAALVM_HOME to a GraalVM installation with native-image installed.
exit /b 1

:require_vcvarsall
if defined VCVARSALL if exist "%VCVARSALL%" exit /b 0
echo Missing Visual Studio C++ build tools environment. Set VCVARSALL to vcvarsall.bat from Visual Studio Build Tools.
exit /b 1
