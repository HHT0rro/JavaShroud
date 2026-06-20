#!/bin/bash
# build-native-kernel-linux.sh
# Compiles the JavaShroud modular native microkernel for Linux x64.
# Requires: GCC and GraalVM/JDK JNI headers.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC1="$SCRIPT_DIR/js_kernel.c"
SRC2="$SCRIPT_DIR/js_helpers.c"
SRC_COMMON="$SCRIPT_DIR/js_native_common.c"
SRC_CRYPTO="$SCRIPT_DIR/js_crypto.c"
SRC_ANTIDEBUG="$SCRIPT_DIR/js_antidebug.c"
SRC_PROTECTED_SECTION="$SCRIPT_DIR/js_protected_section.c"
SRC_VM_CORE="$SCRIPT_DIR/js_vm_core.c"
SRC_VM_RESOURCE="$SCRIPT_DIR/js_vm_resource.c"
SRC_VM_SYMBOL="$SCRIPT_DIR/js_vm_symbol.c"
SRC_JNI_RUNTIME="$SCRIPT_DIR/js_jni_runtime.c"
ZSTD_DIR="$SCRIPT_DIR/zstd"
BUILD_DIR="$SCRIPT_DIR/build"
JAVA_HOME_EFFECTIVE="${GRAALVM_HOME:-${JAVA_HOME:-/usr/lib/graalvm}}"

if [ ! -f "$SRC1" ]; then
    echo "Missing source: $SRC1"
    exit 1
fi
if [ ! -f "$SRC2" ]; then
    echo "Missing source: $SRC2"
    exit 1
fi
if [ ! -f "$JAVA_HOME_EFFECTIVE/include/jni.h" ]; then
    echo "Missing JNI header: $JAVA_HOME_EFFECTIVE/include/jni.h"
    exit 1
fi

mkdir -p "$BUILD_DIR"

JNI_INCLUDE=("-I$JAVA_HOME_EFFECTIVE/include")
if [ -f "$JAVA_HOME_EFFECTIVE/include/linux/jni_md.h" ]; then
    JNI_INCLUDE+=("-I$JAVA_HOME_EFFECTIVE/include/linux")
elif [ -f "$SCRIPT_DIR/cross-compile/jni_md_linux.h" ]; then
    cp "$SCRIPT_DIR/cross-compile/jni_md_linux.h" "$BUILD_DIR/jni_md.h"
    JNI_INCLUDE+=("-I$BUILD_DIR")
else
    echo "Missing JNI platform header: $JAVA_HOME_EFFECTIVE/include/linux/jni_md.h"
    exit 1
fi

echo "[1/1] Compiling modular native kernel for Linux x64..."
gcc -O2 -shared -fPIC -fwrapv \
    -DZSTDLIB_VISIBLE= -DZSTDERRORLIB_VISIBLE= -DXXH_PUBLIC_API= \
    "${JNI_INCLUDE[@]}" \
    -I"$ZSTD_DIR" -I"$ZSTD_DIR/common" -I"$ZSTD_DIR/decompress" \
    -o "$BUILD_DIR/js_kernel_linux-x64.so" \
    "$SRC1" "$SRC2" "$SRC_COMMON" "$SRC_CRYPTO" "$SRC_ANTIDEBUG" "$SRC_PROTECTED_SECTION" "$SRC_VM_CORE" "$SRC_VM_RESOURCE" "$SRC_VM_SYMBOL" "$SRC_JNI_RUNTIME" \
    "$ZSTD_DIR/common/debug.c" "$ZSTD_DIR/common/entropy_common.c" "$ZSTD_DIR/common/error_private.c" \
    "$ZSTD_DIR/common/fse_decompress.c" "$ZSTD_DIR/common/xxhash.c" "$ZSTD_DIR/common/zstd_common.c" \
    "$ZSTD_DIR/decompress/huf_decompress.c" "$ZSTD_DIR/decompress/zstd_ddict.c" \
    "$ZSTD_DIR/decompress/zstd_decompress.c" "$ZSTD_DIR/decompress/zstd_decompress_block.c" \
    -Wl,--version-script=/dev/stdin <<'VERSION'
{ global: JNI_OnLoad; local: *; };
VERSION

echo "Native kernel ready: $BUILD_DIR/js_kernel_linux-x64.so"
