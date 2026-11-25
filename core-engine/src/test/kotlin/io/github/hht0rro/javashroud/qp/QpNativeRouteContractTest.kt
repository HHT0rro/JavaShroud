package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.QpNativeCompilerPass
import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Contract checks for the current native source/include resolver. */
class QpNativeRouteContractTest {
    @Test
    fun native_runtime_routes_use_only_locked_rust_targets() {
        assertEquals(
            mapOf(
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS to RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX to RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
            ),
            QpNativeCompilerPass.RUST_TARGETS,
        )
        assertTrue(QpNativeCompilerPass.RUST_TARGETS.values.all { it.startsWith("x86_64-") })
    }

    @Test
    fun native_runtime_artifact_validation_rejects_truncation_and_retired_formats() {
        assertFailsWith<IllegalArgumentException> {
            QpNativeCompilerPass.validateRustArtifactForTest(
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS,
                "qp_ffi.dylib",
                byteArrayOf(0x4D, 0x5A),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            QpNativeCompilerPass.validateRustArtifactForTest(
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX,
                "libqp_ffi.so",
                ByteArray(64),
            )
        }
    }

    @Test
    fun native_cargo_route_is_locked_and_explicitly_targeted() {
        val command = QpNativeCompilerPass.rustCargoCommandForTest(
            cargoPath = java.nio.file.Path.of("cargo"),
            target = RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
            targetDir = java.nio.file.Path.of("build", "native", "windows"),
        )
        assertEquals("zigbuild", command[1])
        assertTrue(command.contains("--locked"))
        assertTrue(!command.contains("--offline"))
        assertTrue(command.containsAll(listOf("--package", "qp-ffi", "--lib", "--release", "--target", "--target-dir")))
    }
}
