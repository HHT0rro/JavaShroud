package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeDivergenceVerificationTest {

    @Test
    fun r1_workspace_is_locked_rust_only_and_has_no_retired_native_sources() {
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
        assertEquals(0L, retiredFiles, "R1 compilation input must not contain retired C/Zig/Mach-O sources")
    }

    @Test
    fun r1_exposes_only_the_locked_runtime_targets() {
        assertEquals(
            mapOf(
                RustToolchainProvisioner.RUNTIME_TARGET_WINDOWS to RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                RustToolchainProvisioner.RUNTIME_TARGET_LINUX to RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
            ),
            NativeRecompilationTransforms.RUST_TARGETS,
        )
        assertFalse(NativeRecompilationTransforms.RUST_TARGETS.keys.any { it.contains("mac", ignoreCase = true) })
    }

    @Test
    fun r1_cargo_commands_are_locked_offline_and_target_directory_is_explicit() {
        val windows = NativeRecompilationTransforms.rustCargoCommandForTest(
            Path.of("cargo"),
            RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
            Path.of("build", "windows"),
        ).map { it.replace('\\', '/') }
        assertEquals(
            listOf(
                "cargo",
                "build",
                "--locked",
                "--offline",
                "--workspace",
                "--release",
                "--target",
                RustToolchainProvisioner.WINDOWS_RUSTUP_TARGET,
                "--target-dir",
                "build/windows",
            ),
            windows,
        )

        val linux = NativeRecompilationTransforms.rustCargoCommandForTest(
            Path.of("cargo"),
            RustToolchainProvisioner.LINUX_RUNTIME_TARGET,
            Path.of("build", "linux"),
        )
        assertEquals("zigbuild", linux[1])
        assertTrue(linux.contains("--locked"))
        assertTrue(linux.contains("--offline"))
        assertTrue(linux.contains("--target-dir"))
    }

    private fun rustWorkspace(): Path = sequenceOf(
        Path.of("src/main/rust"),
        Path.of("core-engine/src/main/rust"),
    ).map { it.toAbsolutePath().normalize() }
        .firstOrNull { Files.isRegularFile(it.resolve("Cargo.toml")) && Files.isRegularFile(it.resolve("Cargo.lock")) }
        ?: error("R1 Rust workspace is not present")
}
