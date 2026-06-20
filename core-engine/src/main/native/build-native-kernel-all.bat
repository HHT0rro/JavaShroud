@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: build-native-kernel-all.bat
:: Cross-compiles the JavaShroud native microkernel for all declared platforms using Zig.
:: Requires: Zig 0.13+ and JDK/GraalVM JNI headers.

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
set "CROSS_COMPILE_DIR=%SCRIPT_DIR%cross-compile"
set "ZSTD_DIR=%SCRIPT_DIR%zstd"

if not defined JAVA_HOME if defined GRAALVM_HOME set "JAVA_HOME=%GRAALVM_HOME%"
if not defined JAVA_HOME (
    echo Missing JAVA_HOME or GraalVM/JDK JNI headers.
    exit /b 1
)
if not exist "%JAVA_HOME%\include\jni.h" (
    echo Missing JNI header: %JAVA_HOME%\include\jni.h
    exit /b 1
)
set "JNI_INCLUDE=-I""%CROSS_COMPILE_DIR%"" -I""%ZSTD_DIR%"" -I""%ZSTD_DIR%\common"" -I""%ZSTD_DIR%\decompress"""
set "ZSTD_HIDE=-DZSTDLIB_VISIBLE= -DZSTDERRORLIB_VISIBLE= -DXXH_PUBLIC_API="
set "ZSTD_SRC=""%ZSTD_DIR%\common\debug.c"" ""%ZSTD_DIR%\common\entropy_common.c"" ""%ZSTD_DIR%\common\error_private.c"" ""%ZSTD_DIR%\common\fse_decompress.c"" ""%ZSTD_DIR%\common\xxhash.c"" ""%ZSTD_DIR%\common\zstd_common.c"" ""%ZSTD_DIR%\decompress\huf_decompress.c"" ""%ZSTD_DIR%\decompress\zstd_ddict.c"" ""%ZSTD_DIR%\decompress\zstd_decompress.c"" ""%ZSTD_DIR%\decompress\zstd_decompress_block.c"""
set "MACOS_EXPORTS=%BUILD_DIR%\macos-exported-symbols.txt"

set "ZIG=zig"
where zig >nul 2>nul
if errorlevel 1 (
    if exist "%SCRIPT_DIR%zig-windows-x86_64-0.13.0\zig.exe" (
        set "ZIG=%SCRIPT_DIR%zig-windows-x86_64-0.13.0\zig.exe"
    ) else (
        echo Zig not found. Install from https://ziglang.org/download/ or place in native\ directory.
        exit /b 1
    )
)

if not exist "%SRC1%" (
    echo Missing source: %SRC1%
    exit /b 1
)
if not exist "%SRC2%" (
    echo Missing source: %SRC2%
    exit /b 1
)

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"
>"%MACOS_EXPORTS%" echo _JNI_OnLoad
>>"%MACOS_EXPORTS%" echo _JNI_OnUnload

echo [1/4] Compiling modular native kernel for Windows x64...
"%ZIG%" cc -O2 -target x86_64-windows-gnu -std=c11 -fPIC -shared -s -fvisibility=hidden -fwrapv -DZSTD_DISABLE_ASM=1 %ZSTD_HIDE% %JNI_INCLUDE% -o "%BUILD_DIR%\js_kernel_windows-x64.dll" "%SRC1%" "%SRC2%" "%SRC3%" "%SRC4%" "%SRC5%" "%SRC6%" "%SRC7%" "%SRC8%" "%SRC9%" "%SRC10%" %ZSTD_SRC%
if errorlevel 1 (echo Windows build failed & exit /b 1)

echo [2/4] Compiling modular native kernel for Linux x64...
"%ZIG%" cc -O2 -target x86_64-linux-gnu -std=c11 -fPIC -shared -s -fvisibility=hidden -fwrapv -DZSTD_DISABLE_ASM=1 %ZSTD_HIDE% %JNI_INCLUDE% -o "%BUILD_DIR%\js_kernel_linux-x64.so" "%SRC1%" "%SRC2%" "%SRC3%" "%SRC4%" "%SRC5%" "%SRC6%" "%SRC7%" "%SRC8%" "%SRC9%" "%SRC10%" %ZSTD_SRC%
if errorlevel 1 (echo Linux build failed & exit /b 1)

echo [3/4] Compiling modular native kernel for macOS x64...
"%ZIG%" cc -O2 -target x86_64-macos-none -std=c11 -fPIC -shared -s -fvisibility=hidden -fwrapv -Wl,-exported_symbols_list,"%MACOS_EXPORTS%" -DZSTD_DISABLE_ASM=1 %ZSTD_HIDE% %JNI_INCLUDE% -o "%BUILD_DIR%\js_kernel_macos-x64.dylib" "%SRC1%" "%SRC2%" "%SRC3%" "%SRC4%" "%SRC5%" "%SRC6%" "%SRC7%" "%SRC8%" "%SRC9%" "%SRC10%" %ZSTD_SRC%
if errorlevel 1 (echo macOS x64 build failed & exit /b 1)

echo [4/4] Compiling modular native kernel for macOS arm64...
"%ZIG%" cc -O2 -target aarch64-macos-none -std=c11 -fPIC -shared -s -fvisibility=hidden -fwrapv -Wl,-exported_symbols_list,"%MACOS_EXPORTS%" -DZSTD_DISABLE_ASM=1 %ZSTD_HIDE% %JNI_INCLUDE% -o "%BUILD_DIR%\js_kernel_macos-arm64.dylib" "%SRC1%" "%SRC2%" "%SRC3%" "%SRC4%" "%SRC5%" "%SRC6%" "%SRC7%" "%SRC8%" "%SRC9%" "%SRC10%" %ZSTD_SRC%
if errorlevel 1 (echo macOS arm64 build failed & exit /b 1)

echo.
echo All declared platforms compiled successfully:
dir /b "%BUILD_DIR%\js_kernel_*"
