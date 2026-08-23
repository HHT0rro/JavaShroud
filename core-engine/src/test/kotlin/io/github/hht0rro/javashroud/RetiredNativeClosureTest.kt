package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RetiredNativeClosureTest {
    @Test
    fun retired_c_runtime_tree_is_gone() {
        val nativeRoot = workspacePath("core-engine/src/main/native")
        val testNative = workspacePath("core-engine/src/test/native")
        assertFalse(Files.exists(nativeRoot), "AKEN-R1 must not keep a C/Zig native product tree")
        assertFalse(Files.exists(testNative), "AKEN-R1 must not keep C native probe sources")
    }

    @Test
    fun gradle_does_not_package_retired_c_paths() {
        val gradle = Files.readString(workspacePath("core-engine/build.gradle.kts"))
        for (forbidden in listOf(
            "META-INF/native-src",
            "META-INF/js-native",
            "src/main/native",
            "js_kernel.c",
            "js_shell_loader_macho.c",
            "NativeToolchainProvisioner",
            "NativeKernelPacker",
            "NativeKernelShellPacker",
        )) {
            assertFalse(gradle.contains(forbidden), "Gradle production packaging must not retain the retired path: $forbidden")
        }
        assertTrue(gradle.contains("src/main/rust"), "AKEN-R1 production packaging must use the Rust workspace")
        assertTrue(gradle.contains("META-INF/jsrt"), "AKEN-R1 production resources must use the Rust runtime root")
        assertTrue(gradle.contains("x86_64-pc-windows-gnu"), "Windows runtime must use the locked GNU target")
        assertTrue(gradle.contains("x86_64-unknown-linux-gnu.2.17"), "Linux runtime must use the explicit glibc 2.17 target")
    }

    @Test
    fun production_build_and_ci_expose_only_the_two_locked_r1_runtime_routes() {
        val gradle = Files.readString(workspacePath("core-engine/build.gradle.kts"))
        val ci = Files.readString(workspacePath(".github/workflows/ci.yml"))
        val cargo = Files.readString(workspacePath("core-engine/src/main/rust/Cargo.toml"))
        val cargoConfig = Files.readString(workspacePath("core-engine/src/main/rust/.cargo/config.toml"))
        val productionContract = gradle + '\n' + ci + '\n' + cargo + '\n' + cargoConfig

        for (required in listOf(
            "x86_64-pc-windows-gnu",
            "x86_64-unknown-linux-gnu.2.17",
            "META-INF/jsrt/windows-x64",
            "META-INF/jsrt/linux-x64",
            "cargo", "zigbuild",
        )) {
            assertTrue(productionContract.contains(required), "R1 production contract is missing: $required")
        }
        for (retired in listOf(
            "META-INF/native-src",
            "META-INF/js-native",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "macos-x64",
            "macos-arm64",
            "build-native-kernel",
            "js_kernel.c",
            "js_shell_loader_macho.c",
        )) {
            assertFalse(productionContract.contains(retired), "R1 production contract retains retired marker: $retired")
        }
        assertTrue(cargoConfig.contains("it is not a Rust target JSON"), "glibc 2.17 must not be represented as a generic rustup target")
    }

    @Test
    fun rust_cdylib_source_exports_only_r1_lifecycle_and_binding_symbols() {
        val ffi = Files.readString(workspacePath("core-engine/src/main/rust/crates/jsrt-ffi/src/lib.rs"))
        val productionFfi = ffi.substringBefore("    #[cfg(test)]")
        val manifest = Files.readString(workspacePath("core-engine/src/main/rust/crates/jsrt-ffi/Cargo.toml"))
        val header = Files.readString(workspacePath("core-engine/src/main/rust/crates/jsrt-ffi/include/jsrt_ffi.h"))
        val exportedNames = Regex(
            "#\\[no_mangle]\\s+(?:pub\\s+unsafe\\s+|pub\\s+)?extern\\s+\\\"(?:C|system)\\\"\\s+fn\\s+([A-Za-z0-9_]+)",
        ).findAll(productionFfi).map { it.groupValues[1] }.toList()

        assertTrue(manifest.contains("\"cdylib\""), "AKEN-R1 FFI crate must emit a loadable cdylib")
        assertTrue(
            exportedNames.toSet() == setOf(
                "JNI_OnLoad",
                "JNI_OnUnload",
                "jsrt_r1_runtime_binding_digest",
                "jsrt_r1_open_frame",
            ),
            "unexpected R1 FFI exports: $exportedNames",
        )
        assertTrue(header.contains("jsrt_r1_runtime_binding_digest"))
        assertTrue(header.contains("jsrt_r1_open_frame"))
        assertFalse(productionFfi.contains("jsn_k13"))
        assertFalse(productionFfi.contains("nativeInstallBoot"))
    }

    @Test
    fun native_abi_probe_rejects_every_retired_export_family() {
        val requiredR1 = listOf(
            "JNI_OnLoad",
            "JNI_OnUnload",
            "jsrt_r1_runtime_binding_digest",
            "jsrt_r1_open_frame",
        ).joinToString("|")
        assertTrue(
            io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
                .nativeLibraryContainsRequiredJniVmAbi(requiredR1.toByteArray(Charsets.US_ASCII)),
            "complete R1 exports must satisfy the ABI probe",
        )

        for (legacy in listOf(
            "Java_io_github_hht0rro_javashroud_transforms_protection_",
            "js_native_abi_table_v1",
            "jsn_k13",
            "nativeInstallBootMaterial",
            "nativeInstallBootEnvelope",
            "nativeDecodeRuntimeResource",
            "nativeExecuteVmResource",
            "nativePreloadRuntimeResources",
            "js_shell_",
            "js_kernel_",
        )) {
            val candidate = "$requiredR1|$legacy".toByteArray(Charsets.US_ASCII)
            assertFalse(
                io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
                    .nativeLibraryContainsRequiredJniVmAbi(candidate),
                "R1 ABI probe accepted retired export marker: $legacy",
            )
        }
    }

    private fun workspacePath(relative: String): Path {
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val candidate = current.resolve(relative)
            val parentMarker = current.resolve("core-engine/src/main/rust/Cargo.toml")
            if (Files.exists(parentMarker) || Files.exists(current.resolve("settings.gradle.kts"))) {
                return candidate
            }
            current = current.parent ?: return Path.of("").toAbsolutePath().resolve(relative)
        }
    }
}
