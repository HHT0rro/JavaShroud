@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: build-native-kernel.bat
:: Compiles the JavaShroud modular native microkernel for the current platform.
:: Requires: MSVC build tools (vcvarsall.bat) and GraalVM/JDK JNI headers.

set "SCRIPT_DIR=%~dp0"
set "SRC1=%SCRIPT_DIR%js_kernel.c"
set "SRC2=%SCRIPT_DIR%js_helpers.c"
set "SRC3=%SCRIPT_DIR%js_native_common.c"
set "SRC4=%SCRIPT_DIR%js_crypto.c"
set "SRC5=%SCRIPT_DIR%js_antidebug.c"
set "SRC6=%SCRIPT_DIR%js_protected_section.c"
set "SRC7=%SCRIPT_DIR%js_vm_core.c"
set "SRC8=%SCRIPT_DIR%js_vm_resource.c"
set "SRC9=%SCRIPT_DIR%js_vm_symbol.c"
set "SRC10=%SCRIPT_DIR%js_jni_runtime.c"
set "BUILD_DIR=%SCRIPT_DIR%build"
set "ZSTD_DIR=%SCRIPT_DIR%zstd"

if not defined JAVA_HOME if defined GRAALVM_HOME set "JAVA_HOME=%GRAALVM_HOME%"

if not exist "%SRC1%" (
  echo Missing source: %SRC1%
  exit /b 1
)
if not exist "%SRC2%" (
  echo Missing source: %SRC2%
  exit /b 1
)
if not defined VCVARSALL (
  echo Missing VCVARSALL. Set VCVARSALL to vcvarsall.bat from Visual Studio Build Tools.
  exit /b 1
)
if not defined JAVA_HOME (
  echo Missing JAVA_HOME or GRAALVM_HOME with JNI headers.
  exit /b 1
)
if not exist "%JAVA_HOME%\include\jni.h" (
  echo Missing JNI header: %JAVA_HOME%\include\jni.h
  exit /b 1
)
if not exist "%JAVA_HOME%\include\win32\jni_md.h" (
  echo Missing JNI platform header: %JAVA_HOME%\include\win32\jni_md.h
  exit /b 1
)

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo [1/2] Compiling modular native kernel for Windows x64...
call "%VCVARSALL%" x64 >nul
cl /nologo /O2 /LD /DZSTDLIB_VISIBLE= /DZSTDERRORLIB_VISIBLE= /DXXH_PUBLIC_API= /Fe:"%BUILD_DIR%\js_kernel_windows-x64.dll" "%SRC1%" "%SRC2%" "%SRC3%" "%SRC4%" "%SRC5%" "%SRC6%" "%SRC7%" "%SRC8%" "%SRC9%" "%SRC10%" "%ZSTD_DIR%\common\debug.c" "%ZSTD_DIR%\common\entropy_common.c" "%ZSTD_DIR%\common\error_private.c" "%ZSTD_DIR%\common\fse_decompress.c" "%ZSTD_DIR%\common\xxhash.c" "%ZSTD_DIR%\common\zstd_common.c" "%ZSTD_DIR%\decompress\huf_decompress.c" "%ZSTD_DIR%\decompress\zstd_ddict.c" "%ZSTD_DIR%\decompress\zstd_decompress.c" "%ZSTD_DIR%\decompress\zstd_decompress_block.c" /I"%JAVA_HOME%\include" /I"%JAVA_HOME%\include\win32" /I"%ZSTD_DIR%" /I"%ZSTD_DIR%\common" /I"%ZSTD_DIR%\decompress" /link /INCREMENTAL:NO /EXPORT:JNI_OnLoad /EXPORT:JNI_OnUnload
if errorlevel 1 (
  echo Compilation failed.
  exit /b 1
)

echo [2/2] Native kernel ready: %BUILD_DIR%\js_kernel_windows-x64.dll
exit /b 0
