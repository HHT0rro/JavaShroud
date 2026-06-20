#!/bin/bash
# build-native-kernel-macos.sh
# Compiles the JavaShroud modular native microkernel for macOS (arm64 or x64).
# Requires: Xcode Command Line Tools and GraalVM/JDK JNI headers.

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
JAVA_HOME_EFFECTIVE="${GRAALVM_HOME:-${JAVA_HOME:-$(/usr/libexec/java_home 2>/dev/null || true)}}"

if [ ! -f "$SRC1" ]; then
    echo "Missing source: $SRC1"
    exit 1
fi
if [ ! -f "$SRC2" ]; then
    echo "Missing source: $SRC2"
    exit 1
fi
if [ -z "$JAVA_HOME_EFFECTIVE" ] || [ ! -f "$JAVA_HOME_EFFECTIVE/include/jni.h" ]; then
    echo "Missing JNI header. Set JAVA_HOME or GRAALVM_HOME to a JDK with include/jni.h."
    exit 1
fi
if [ ! -f "$JAVA_HOME_EFFECTIVE/include/darwin/jni_md.h" ]; then
    echo "Missing JNI platform header: $JAVA_HOME_EFFECTIVE/include/darwin/jni_md.h"
    exit 1
fi

mkdir -p "$BUILD_DIR"

ARCH="${1:-$(uname -m)}"
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "macos-arm64" ]; then
    TARGET="macos-arm64"
    CC_FLAGS=("-arch" "arm64")
else
    TARGET="macos-x64"
    CC_FLAGS=("-arch" "x86_64")
fi

echo "[1/1] Compiling modular native kernel for macOS ($TARGET)..."
clang -O2 -shared -dynamiclib -fwrapv "${CC_FLAGS[@]}" \
    -DZSTDLIB_VISIBLE= -DZSTDERRORLIB_VISIBLE= -DXXH_PUBLIC_API= \
    -I"$JAVA_HOME_EFFECTIVE/include" \
    -I"$JAVA_HOME_EFFECTIVE/include/darwin" \
    -I"$ZSTD_DIR" -I"$ZSTD_DIR/common" -I"$ZSTD_DIR/decompress" \
    -o "$BUILD_DIR/js_kernel_$TARGET.dylib" \
    "$SRC1" "$SRC2" "$SRC_COMMON" "$SRC_CRYPTO" "$SRC_ANTIDEBUG" "$SRC_PROTECTED_SECTION" "$SRC_VM_CORE" "$SRC_VM_RESOURCE" "$SRC_VM_SYMBOL" "$SRC_JNI_RUNTIME" \
    "$ZSTD_DIR/common/debug.c" "$ZSTD_DIR/common/entropy_common.c" "$ZSTD_DIR/common/error_private.c" \
    "$ZSTD_DIR/common/fse_decompress.c" "$ZSTD_DIR/common/xxhash.c" "$ZSTD_DIR/common/zstd_common.c" \
    "$ZSTD_DIR/decompress/huf_decompress.c" "$ZSTD_DIR/decompress/zstd_ddict.c" \
    "$ZSTD_DIR/decompress/zstd_decompress.c" "$ZSTD_DIR/decompress/zstd_decompress_block.c" \
    -Wl,-exported_symbols_list,/dev/stdin <<'SYMBOLS'
_JNI_OnLoad
_JNI_OnUnload
SYMBOLS

echo "Native kernel ready: $BUILD_DIR/js_kernel_$TARGET.dylib"
