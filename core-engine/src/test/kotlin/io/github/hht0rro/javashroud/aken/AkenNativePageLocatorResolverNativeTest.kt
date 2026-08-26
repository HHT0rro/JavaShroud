package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** R1 replacement for the retired native source/include resolver fixture. */
class AkenNativePageLocatorResolverNativeTest {
    @Test
    fun r1_runtime_routes_use_only_locked_rust_targets() {
        assertEquals(
            mapOf(
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS to RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX to RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
            ),
            NativeRecompilationTransforms.RUST_TARGETS,
        )
        assertTrue(NativeRecompilationTransforms.RUST_TARGETS.values.all { it.startsWith("x86_64-") })
    }

    @Test
    fun r1_runtime_artifact_validation_rejects_truncation_and_retired_formats() {
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationTransforms.validateRustArtifactForTest(
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
                "jsrt_ffi.dylib",
                byteArrayOf(0x4D, 0x5A),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            NativeRecompilationTransforms.validateRustArtifactForTest(
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX,
                "libjsrt_ffi.so",
                ByteArray(64),
            )
        }
    }

    @Test
    fun r1_cargo_route_is_locked_and_explicitly_targeted() {
        val command = NativeRecompilationTransforms.rustCargoCommandForTest(
            cargoPath = java.nio.file.Path.of("cargo"),
            target = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
            targetDir = java.nio.file.Path.of("build", "r1", "windows"),
        )
        assertEquals("zigbuild", command[1])
        assertTrue(command.contains("--locked"))
        assertTrue(!command.contains("--offline"))
        assertTrue(command.containsAll(listOf("--package", "jsrt-ffi", "--lib", "--release", "--target", "--target-dir")))
    }
}
