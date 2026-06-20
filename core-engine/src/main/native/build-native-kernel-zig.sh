#!/bin/bash
# build-native-kernel-zig.sh
#
# Single-host cross-compilation of the JavaShroud native microkernel (js_kernel)
# for every declared platform using a single Zig toolchain.
#
# Unlike the per-platform scripts, this does NOT need platform-specific JDK
# headers (jni_md.h for win32/linux/darwin). It relies on the self-contained
# cross-compile/jni.h that inlines the machine-dependent typedefs, so one
# machine with Zig 0.13+ can build Windows/Linux/macOS artifacts.
#
# Zig resolution order:
#   1. $ZIG environment variable
#   2. zig on PATH
#   3. ./zig-*/zig next to this script
#
# Usage: bash build-native-kernel-zig.sh [target ...]
#   target in: windows-x64 linux-x64 macos-x64 macos-arm64 (default: all)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC="$SCRIPT_DIR/js_kernel.c"
SRC_HELPERS="$SCRIPT_DIR/js_helpers.c"
SRC_COMMON="$SCRIPT_DIR/js_native_common.c"
SRC_CRYPTO="$SCRIPT_DIR/js_crypto.c"
SRC_ANTIDEBUG="$SCRIPT_DIR/js_antidebug.c"
SRC_PROTECTED_SECTION="$SCRIPT_DIR/js_protected_section.c"
SRC_VM_CORE="$SCRIPT_DIR/js_vm_core.c"
SRC_VM_RESOURCE="$SCRIPT_DIR/js_vm_resource.c"
SRC_VM_SYMBOL="$SCRIPT_DIR/js_vm_symbol.c"
SRC_JNI_RUNTIME="$SCRIPT_DIR/js_jni_runtime.c"
BUILD_DIR="$SCRIPT_DIR/build"
CROSS_DIR="$SCRIPT_DIR/cross-compile"
ZSTD_DIR="$SCRIPT_DIR/zstd"

if [ ! -f "$SRC" ]; then
    echo "Missing source: $SRC" >&2
    exit 1
fi
if [ ! -f "$SRC_HELPERS" ]; then
    echo "Missing source: $SRC_HELPERS" >&2
    exit 1
fi
if [ ! -f "$CROSS_DIR/jni.h" ]; then
    echo "Missing self-contained header: $CROSS_DIR/jni.h" >&2
    exit 1
fi

resolve_zig() {
    if [ -n "${ZIG:-}" ] && [ -x "${ZIG}" ]; then
        echo "$ZIG"; return 0
    fi
    if command -v zig >/dev/null 2>&1; then
        command -v zig; return 0
    fi
    local candidate
    candidate="$(find "$SCRIPT_DIR" -maxdepth 2 -type f -name zig 2>/dev/null | head -n1 || true)"
    if [ -n "$candidate" ]; then
        echo "$candidate"; return 0
    fi
    return 1
}

ZIG_BIN="$(resolve_zig || true)"
if [ -z "$ZIG_BIN" ]; then
    echo "Zig not found. Set \$ZIG, put zig on PATH, or unpack zig-*/ next to this script." >&2
    echo "Download: https://ziglang.org/download/" >&2
    exit 1
fi

mkdir -p "$BUILD_DIR"

# Keep Zig's caches local so the build is reproducible and does not pollute HOME.
export ZIG_GLOBAL_CACHE_DIR="$BUILD_DIR/.zig-cache"
export ZIG_LOCAL_CACHE_DIR="$BUILD_DIR/.zig-cache"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR"

COMMON_FLAGS=(cc -O2 -std=c11 -shared -fPIC -fvisibility=hidden -fwrapv -DNDEBUG -DZSTD_DISABLE_ASM=1 -DZSTDLIB_VISIBLE= -DZSTDERRORLIB_VISIBLE= -DXXH_PUBLIC_API= -I"$CROSS_DIR" -I"$ZSTD_DIR" -I"$ZSTD_DIR/common" -I"$ZSTD_DIR/decompress")

build_one() {
    local platform="$1" zig_target="$2" out="$3"
    echo "[zig] $platform <- $zig_target -> $out"
    local export_flags=()
    if [[ "$platform" == macos-* ]]; then
        local export_list="$BUILD_DIR/macos-exported-symbols.txt"
        printf '_JNI_OnLoad\n_JNI_OnUnload\n' > "$export_list"
        export_flags=(-Wl,-exported_symbols_list,"$export_list")
    fi
    "$ZIG_BIN" "${COMMON_FLAGS[@]}" -target "$zig_target" "${export_flags[@]}" -o "$BUILD_DIR/$out" "$SRC" "$SRC_HELPERS" "$SRC_COMMON" "$SRC_CRYPTO" "$SRC_ANTIDEBUG" "$SRC_PROTECTED_SECTION" "$SRC_VM_CORE" "$SRC_VM_RESOURCE" "$SRC_VM_SYMBOL" "$SRC_JNI_RUNTIME" \
        "$ZSTD_DIR/common/debug.c" "$ZSTD_DIR/common/entropy_common.c" "$ZSTD_DIR/common/error_private.c" \
        "$ZSTD_DIR/common/fse_decompress.c" "$ZSTD_DIR/common/xxhash.c" "$ZSTD_DIR/common/zstd_common.c" \
        "$ZSTD_DIR/decompress/huf_decompress.c" "$ZSTD_DIR/decompress/zstd_ddict.c" \
        "$ZSTD_DIR/decompress/zstd_decompress.c" "$ZSTD_DIR/decompress/zstd_decompress_block.c"
}

declare -A TARGETS=(
    [windows-x64]="x86_64-windows-gnu js_kernel_windows-x64.dll"
    [linux-x64]="x86_64-linux-gnu js_kernel_linux-x64.so"
    [macos-x64]="x86_64-macos-none js_kernel_macos-x64.dylib"
    [macos-arm64]="aarch64-macos-none js_kernel_macos-arm64.dylib"
)

if [ "$#" -gt 0 ]; then
    SELECTED=("$@")
else
    SELECTED=(windows-x64 linux-x64 macos-x64 macos-arm64)
fi

echo "Using Zig: $ZIG_BIN ($("$ZIG_BIN" version))"
for platform in "${SELECTED[@]}"; do
    spec="${TARGETS[$platform]:-}"
    if [ -z "$spec" ]; then
        echo "Unknown target: $platform" >&2
        exit 1
    fi
    # shellcheck disable=SC2086
    set -- $spec
    build_one "$platform" "$1" "$2"
done

echo
echo "Native kernels ready in $BUILD_DIR:"
ls -1 "$BUILD_DIR"/js_kernel_* 2>/dev/null || true
