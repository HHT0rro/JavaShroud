package io.github.hht0rro.javashroud.transforms.protection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NativeRecompilationRequestTest {
    @Test
    fun default_request_preserves_the_locked_rust_route_order() {
        val request = NativeRecompilationRequest.forTargets(
            nativeProtectionLevel = "standard",
            nativePackingLevel = AkenR1PackingLevel.MAX,
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
            listOf("jsrt_ffi.dll", "libjsrt_ffi.so"),
            request.routes.map(NativeRecompilationRoute::outputName),
        )
        assertEquals(
            listOf(".dll", ".so"),
            request.routes.map(NativeRecompilationRoute::loadSuffix),
        )
        assertEquals(
            listOf(
                "META-INF/jsrt/windows-x64/jsrt_ffi.dll",
                "META-INF/jsrt/linux-x64/libjsrt_ffi.so",
            ),
            request.routes.map(NativeRecompilationRoute::preSealResourcePath),
        )
        assertEquals(
            listOf("rust-ffi-windows-x64-v1", "rust-ffi-linux-x64-v1"),
            request.routes.map(NativeRecompilationRoute::shellLoaderProfile),
        )
    }

    @Test
    fun selected_routes_keep_the_requested_platform_order() {
        val request = NativeRecompilationRequest.forTargets(
            nativeProtectionLevel = "aggressive",
            nativePackingLevel = AkenR1PackingLevel.STANDARD,
            targetPlatforms = listOf("linux-x64", "windows-x64"),
        )

        assertEquals(listOf("linux-x64", "windows-x64"), request.routes.map(NativeRecompilationRoute::platform))
        assertEquals(
            listOf(
                "META-INF/jsrt/linux-x64/libjsrt_ffi.so",
                "META-INF/jsrt/windows-x64/jsrt_ffi.dll",
            ),
            request.routes.map(NativeRecompilationRoute::preSealResourcePath),
        )
    }

    @Test
    fun all_r1_profiles_emit_direct_rust_cdylibs_without_shell_forms() {
        AkenR1PackingLevel.entries.forEach { level ->
            val request = NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = level,
                targetPlatforms = listOf("windows-x64"),
            )

            assertEquals(level, request.nativePackingLevel)
            assertEquals(
                if (level.hardened) AkenR1OutputForm.HARDENED_DIRECT_RUST_CDYLIB else AkenR1OutputForm.DIRECT_RUST_CDYLIB,
                request.nativePackingProfile.outputForm,
            )
            assertEquals(level.hardened, request.nativePackingProfile.outputForm.hardened)
        }
    }

    @Test
    fun unsupported_or_ambiguous_routes_fail_before_compilation_is_started() {
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = AkenR1PackingLevel.OFF,
                targetPlatforms = emptyList(),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = AkenR1PackingLevel.OFF,
                targetPlatforms = listOf("windows-x64", "windows-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = AkenR1PackingLevel.OFF,
                targetPlatforms = listOf("unknown-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "unsupported",
                nativePackingLevel = AkenR1PackingLevel.OFF,
                targetPlatforms = listOf("windows-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = AkenR1PackingLevel.OFF,
                targetPlatforms = listOf("macos-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = AkenR1PackingLevel.OFF,
                targetPlatforms = listOf("windows-x64", RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET),
            )
        }
    }

    @Test
    fun locked_rust_target_aliases_resolve_to_canonical_routes() {
        val request = NativeRecompilationRequest.forTargets(
            nativeProtectionLevel = "standard",
            nativePackingLevel = AkenR1PackingLevel.OFF,
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
            NativeRecompilationTransforms.recompileWithDiagnostics(
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
