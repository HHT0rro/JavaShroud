package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.transforms.protection.qp.qpResourceDir
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class QpNativeCompilerRequestTest {
    @Test
    fun default_request_preserves_the_locked_rust_route_order() {
        val request = QpNativeCompilerRequest.forTargets(
            nativeProtectionLevel = "standard",
            nativePackingLevel = QpPackingLevel.MAX,
        )

        assertEquals(
            listOf("windows-x64", "linux-x64"),
            request.routes.map(NativeRecompilationRoute::platform),
        )
        assertEquals(
            listOf(
                RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
            ),
            request.routes.map(NativeRecompilationRoute::rustTarget),
        )
        assertEquals(
            listOf("qp_ffi.dll", "libqp_ffi.so"),
            request.routes.map(NativeRecompilationRoute::outputName),
        )
        assertEquals(
            listOf(".dll", ".so"),
            request.routes.map(NativeRecompilationRoute::loadSuffix),
        )
        assertEquals(
            listOf(
                "${qpResourceDir()}/windows-x64/qp_ffi.dll",
                "${qpResourceDir()}/linux-x64/libqp_ffi.so",
            ),
            request.routes.map(NativeRecompilationRoute::preSealResourcePath),
        )
        assertEquals(
            listOf("rust-ffi-windows-x64-v1", "rust-ffi-linux-x64-v1"),
            request.routes.map(NativeRecompilationRoute::shellLoaderProfile),
        )
    }

    @Test
    fun locked_routes_are_windows_gnu_x64_and_linux_gnu_glibc_217() {
        assertEquals("x86_64-pc-windows-gnu", RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET)
        assertEquals("x86_64-unknown-linux-gnu.2.17", RustToolchainProvisioner.LINUX_RUNTIME_TARGET)
        assertEquals("2.17", RustToolchainProvisioner.LINUX_GLIBC_FLOOR)
        assertEquals(
            listOf("windows-x64", "linux-x64"),
            NativeRecompilationRoute.canonicalPlatformOrder,
        )
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRoute.normalizePlatform("darwin-arm64")
        }
    }

    @Test
    fun selected_routes_keep_the_requested_platform_order() {
        val request = QpNativeCompilerRequest.forTargets(
            nativeProtectionLevel = "aggressive",
            nativePackingLevel = QpPackingLevel.STANDARD,
            targetPlatforms = listOf("linux-x64", "windows-x64"),
        )

        assertEquals(listOf("linux-x64", "windows-x64"), request.routes.map(NativeRecompilationRoute::platform))
        assertEquals(
            listOf(
                "${qpResourceDir()}/linux-x64/libqp_ffi.so",
                "${qpResourceDir()}/windows-x64/qp_ffi.dll",
            ),
            request.routes.map(NativeRecompilationRoute::preSealResourcePath),
        )
    }

    @Test
    fun all_r1_profiles_emit_direct_rust_cdylibs_without_shell_forms() {
        QpPackingLevel.entries.forEach { level ->
            val request = QpNativeCompilerRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = level,
                targetPlatforms = listOf("windows-x64"),
            )

            assertEquals(level, request.nativePackingLevel)
            assertEquals(
                if (level.hardened) QpOutputForm.HARDENED_DIRECT_RUST_CDYLIB else QpOutputForm.DIRECT_RUST_CDYLIB,
                request.nativePackingProfile.outputForm,
            )
            assertEquals(level.hardened, request.nativePackingProfile.outputForm.hardened)
        }
    }

    @Test
    fun unsupported_or_ambiguous_routes_fail_before_compilation_is_started() {
        assertFailsWith<IllegalArgumentException> {
            QpNativeCompilerRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = QpPackingLevel.OFF,
                targetPlatforms = emptyList(),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            QpNativeCompilerRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = QpPackingLevel.OFF,
                targetPlatforms = listOf("windows-x64", "windows-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            QpNativeCompilerRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = QpPackingLevel.OFF,
                targetPlatforms = listOf("unknown-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            QpNativeCompilerRequest.forTargets(
                nativeProtectionLevel = "unsupported",
                nativePackingLevel = QpPackingLevel.OFF,
                targetPlatforms = listOf("windows-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            QpNativeCompilerRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = QpPackingLevel.OFF,
                targetPlatforms = listOf("macos-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            QpNativeCompilerRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = QpPackingLevel.OFF,
                targetPlatforms = listOf("windows-x64", RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET),
            )
        }
    }

    @Test
    fun locked_rust_target_aliases_resolve_to_canonical_routes() {
        val request = QpNativeCompilerRequest.forTargets(
            nativeProtectionLevel = "standard",
            nativePackingLevel = QpPackingLevel.OFF,
            targetPlatforms = listOf(
                RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
                RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
            ),
        )

        assertEquals(listOf("linux-x64", "windows-x64"), request.routes.map(NativeRecompilationRoute::platform))
    }

    @Test
    fun raw_recompilation_adapter_uses_typed_route_validation_before_toolchain_resolution() {
        val error = assertFailsWith<IllegalArgumentException> {
            QpNativeCompilerPass.recompileWithDiagnostics(
                seed = 0xA6E4_0001L,
                classLoader = javaClass.classLoader,
                targetPlatforms = listOf("windows-x64", "windows-x64"),
                nativeProtectionLevel = "standard",
                nativePackingLevel = "off",
            )
        }

        assertTrue(error.message.orEmpty().contains("unique"))
    }
}
