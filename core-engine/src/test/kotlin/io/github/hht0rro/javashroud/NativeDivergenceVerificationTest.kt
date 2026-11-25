package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.QpNativeCompilerPass
import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeDivergenceVerificationTest {

    @Test
    fun workspace_is_locked_rust_only_and_has_no_retired_native_sources() {
        val workspace = rustWorkspace()
        assertTrue(Files.isRegularFile(workspace.resolve("Cargo.toml")))
        assertTrue(Files.isRegularFile(workspace.resolve("Cargo.lock")))

        val retiredFiles = Files.walk(workspace).use { stream ->
            stream.filter(Files::isRegularFile)
                .filter { path ->
                    val name = path.fileName.toString().lowercase()
                    name.endsWith(".c") || name.endsWith(".zig") || name.endsWith(".dylib") ||
                        name.contains("macho")
                }
                .count()
        }
        assertEquals(0L, retiredFiles, "Native compilation input must not contain retired C/Zig/Mach-O sources")
    }

    @Test
    fun native_exposes_only_the_locked_runtime_targets() {
        assertEquals(
            mapOf(
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS to RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX to RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
            ),
            QpNativeCompilerPass.RUST_TARGETS,
        )
        assertFalse(QpNativeCompilerPass.RUST_TARGETS.keys.any { it.contains("mac", ignoreCase = true) })
    }

    @Test
    fun native_cargo_commands_are_locked_and_target_directory_is_explicit() {
        val windows = QpNativeCompilerPass.rustCargoCommandForTest(
            Path.of("cargo"),
            RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
            Path.of("build", "windows"),
        ).map { it.replace('\\', '/') }
        assertEquals(
            listOf(
                "cargo",
                "zigbuild",
                "--locked",
                "--package",
                "qp-ffi",
                "--lib",
                "--release",
                "--target",
                RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                "--target-dir",
                "build/windows",
            ),
            windows,
        )

        val linux = QpNativeCompilerPass.rustCargoCommandForTest(
            Path.of("cargo"),
            RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
            Path.of("build", "linux"),
        )
        assertEquals("zigbuild", linux[1])
        assertTrue(linux.contains("--locked"))
        assertFalse(linux.contains("--offline"))
        assertTrue(linux.contains("--target-dir"))
    }

    private fun rustWorkspace(): Path = sequenceOf(
        Path.of("src/main/rust"),
        Path.of("core-engine/src/main/rust"),
    ).map { it.toAbsolutePath().normalize() }
        .firstOrNull { Files.isRegularFile(it.resolve("Cargo.toml")) && Files.isRegularFile(it.resolve("Cargo.lock")) }
        ?: error("Native Rust workspace is not present")
}
