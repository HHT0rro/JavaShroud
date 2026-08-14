package io.github.hht0rro.javashroud.transforms.protection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeRecompilationRequestTest {
    @Test
    fun default_request_preserves_the_current_canonical_native_route_order() {
        val request = NativeRecompilationRequest.forTargets(
            nativeProtectionLevel = "standard",
            nativePackingLevel = NativeKernelShellPacker.Level.MAX,
        )

        assertEquals(
            listOf("windows-x64", "linux-x64", "macos-x64", "macos-arm64"),
            request.routes.map(NativeRecompilationRoute::platform),
        )
        assertEquals(
            listOf(
                "x86_64-windows-gnu",
                "x86_64-linux-gnu",
                "x86_64-macos-none",
                "aarch64-macos-none",
            ),
            request.routes.map(NativeRecompilationRoute::zigTarget),
        )
        assertEquals(
            listOf(
                "js_kernel_windows-x64.dll",
                "js_kernel_linux-x64.so",
                "js_kernel_macos-x64.dylib",
                "js_kernel_macos-arm64.dylib",
            ),
            request.routes.map(NativeRecompilationRoute::outputName),
        )
        assertEquals(
            listOf(".dll", ".so", ".dylib", ".dylib"),
            request.routes.map(NativeRecompilationRoute::loadSuffix),
        )
        assertEquals(
            listOf(
                "META-INF/js-native/js_kernel_windows-x64.dll",
                "META-INF/js-native/js_kernel_linux-x64.so",
                "META-INF/js-native/js_kernel_macos-x64.dylib",
                "META-INF/js-native/js_kernel_macos-arm64.dylib",
            ),
            request.routes.map(NativeRecompilationRoute::preSealResourcePath),
        )
        assertEquals(
            listOf(
                "pe64-memory-loader-headerdir-reloc-import-export-tlsrange-execbounds-v22",
                "elf64-anonymous-loader-dynnull-hashbounds-strbounds-rela-init-execbounds-v6",
                "macho64-validated-fail-closed-v2",
                "macho64-validated-fail-closed-v2",
            ),
            request.routes.map(NativeRecompilationRoute::shellLoaderProfile),
        )
    }

    @Test
    fun selected_routes_keep_the_requested_platform_order() {
        val request = NativeRecompilationRequest.forTargets(
            nativeProtectionLevel = "aggressive",
            nativePackingLevel = NativeKernelShellPacker.Level.STANDARD,
            targetPlatforms = listOf("macos-arm64", "windows-x64"),
        )

        assertEquals(listOf("macos-arm64", "windows-x64"), request.routes.map(NativeRecompilationRoute::platform))
        assertEquals(
            listOf(
                "META-INF/js-native/js_kernel_macos-arm64.dylib",
                "META-INF/js-native/js_kernel_windows-x64.dll",
            ),
            request.routes.map(NativeRecompilationRoute::preSealResourcePath),
        )
    }

    @Test
    fun packing_profile_preserves_each_existing_packing_branch() {
        val expectedForms = mapOf(
            NativeKernelShellPacker.Level.OFF to NativeRecompilationOutputForm.DIRECT_SECTION_SEALED,
            NativeKernelShellPacker.Level.STANDARD to NativeRecompilationOutputForm.AUTHENTICATED_OVERLAY,
            NativeKernelShellPacker.Level.MAX to NativeRecompilationOutputForm.OUTER_STUB_SHELL,
            NativeKernelShellPacker.Level.MAX_HARDENING to NativeRecompilationOutputForm.HARDENED_OUTER_STUB_SHELL,
        )

        expectedForms.forEach { (level, expectedForm) ->
            val request = NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = level,
                targetPlatforms = listOf("windows-x64"),
            )

            assertEquals(level, request.nativePackingLevel)
            assertEquals(expectedForm, request.nativePackingProfile.outputForm)
            assertEquals(level.usesStubShell, request.nativePackingProfile.outputForm.usesStubShell)
            if (level.usesStubShell) {
                assertTrue(request.nativePackingProfile.outputForm.usesStubShell)
            } else {
                assertFalse(request.nativePackingProfile.outputForm.usesStubShell)
            }
        }
    }

    @Test
    fun unsupported_or_ambiguous_routes_fail_before_compilation_is_started() {
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = NativeKernelShellPacker.Level.OFF,
                targetPlatforms = emptyList(),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = NativeKernelShellPacker.Level.OFF,
                targetPlatforms = listOf("windows-x64", "windows-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "standard",
                nativePackingLevel = NativeKernelShellPacker.Level.OFF,
                targetPlatforms = listOf("unknown-x64"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationRequest.forTargets(
                nativeProtectionLevel = "unsupported",
                nativePackingLevel = NativeKernelShellPacker.Level.OFF,
                targetPlatforms = listOf("windows-x64"),
            )
        }
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
