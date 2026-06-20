package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeToolchainProvisioner
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NativeToolchainProvisionerTest {

    @Test
    fun cacheDirectory_uses_user_home_javashroud_cache() {
        val dir = NativeToolchainProvisioner.cacheDirectory()
        val expected = Path.of(System.getProperty("user.home"), ".javashroud", "zig", "0.13.0")

        assertEquals(expected, dir, "Zig should be cached under the stable per-user JavaShroud cache")
    }

    @Test
    fun cacheDirectory_contains_expected_segments() {
        val dir = NativeToolchainProvisioner.cacheDirectory()
        assertNotNull(dir, "Cache directory should not be null")
        val pathStr = dir.toString()
        assertTrue(pathStr.contains(".javashroud"), "Path should contain '.javashroud': $pathStr")
        assertTrue(pathStr.contains("zig"), "Path should contain 'zig': $pathStr")
        assertTrue(pathStr.contains("0.13.0"), "Path should contain zig version: $pathStr")
    }

    @Test
    fun cacheDirectory_is_consistent_across_calls() {
        val dir1 = NativeToolchainProvisioner.cacheDirectory()
        val dir2 = NativeToolchainProvisioner.cacheDirectory()
        assertEquals(dir1, dir2, "Cache directory should be consistent across calls")
    }

    @Test
    fun detectPlatform_uses_zig_download_naming_order() {
        assertEquals("windows-x86_64", NativeToolchainProvisioner.detectPlatform("Windows 11", "amd64"))
        assertEquals("linux-x86_64", NativeToolchainProvisioner.detectPlatform("Linux", "x86_64"))
        assertEquals("macos-aarch64", NativeToolchainProvisioner.detectPlatform("Mac OS X", "arm64"))
    }

    @Test
    fun resolveWithMessages_reports_resolution_attempt_without_throwing() {
        val result = withZigDownloadDisabled {
            try {
                NativeToolchainProvisioner.resolveWithMessages()
            } catch (e: Exception) {
                throw AssertionError("resolveWithMessages() should not throw when preparing Zig: ${e.message}", e)
            }
        }

        assertTrue(result.messages.isNotEmpty(), "Resolution should report which Zig source was tried or used")
        if (result.toolchain != null) {
            assertTrue(result.toolchain.isAvailable, "If resolved, the toolchain should be available")
            assertTrue(Files.isExecutable(result.toolchain.zigPath), "Zig path should be executable")
            assertTrue(
                result.toolchain.source in setOf("env", "path", "cache", "download"),
                "Unexpected Zig source: ${result.toolchain.source}",
            )
        } else {
            assertTrue(
                result.messages.any { it.level == "warn" || it.message.contains("preparing Zig") },
                "Missing diagnostic for unavailable Zig: ${result.messages}",
            )
        }
    }

    @Test
    fun resolveWithMessages_emits_realtime_progress_messages() {
        withTempUserHome {
            val emitted = mutableListOf<NativeToolchainProvisioner.ResolutionMessage>()
            val result = withZigDownloadDisabled {
                NativeToolchainProvisioner.resolveWithMessages(
                    environment = emptyMap(),
                    pathEnv = null,
                    onMessage = { emitted += it },
                )
            }

            assertEquals(result.messages, emitted, "Realtime callback should receive the same diagnostics returned to callers")
            assertTrue(emitted.any { it.progress != null }, "Zig preparation diagnostics should carry progress for the UI progress bar")
            assertTrue(emitted.any { it.message.contains("正在准备 Zig 工具链") }, "Zig preparation should be visible in logs")
        }
    }

    @Test
    fun resolve_returns_null_or_available_toolchain_without_throwing() {
        val result = withZigDownloadDisabled {
            try {
                NativeToolchainProvisioner.resolve()
            } catch (e: Exception) {
                throw AssertionError("resolve() should not throw when Zig is unavailable: ${e.message}", e)
            }
        }
        if (result != null) {
            assertTrue(result.isAvailable, "If resolved, the toolchain should be available")
            assertTrue(Files.isExecutable(result.zigPath), "Zig path should be executable")
        }
    }

    @Test
    fun resolveWithMessages_prefers_environment_zig_over_path_and_cache() {
        withTempUserHome { home ->
            val envZig = createExecutableZig(home.resolve("env-zig"))
            val pathZig = createExecutableZig(home.resolve("path-zig"))
            createExecutableZig(home.resolve(".javashroud").resolve("zig").resolve("0.13.0"))

            val result = NativeToolchainProvisioner.resolveWithMessages(
                environment = mapOf("JAVASHROUD_ZIG" to envZig.toString()),
                pathEnv = pathZig.parent.toString(),
            )

            assertEquals("env", result.toolchain?.source)
            assertEquals(envZig, result.toolchain?.zigPath)
        }
    }

    @Test
    fun resolveWithMessages_prefers_path_zig_over_cache() {
        withTempUserHome { home ->
            val pathZig = createExecutableZig(home.resolve("path-zig"))
            createExecutableZig(home.resolve(".javashroud").resolve("zig").resolve("0.13.0"))

            val result = NativeToolchainProvisioner.resolveWithMessages(
                environment = emptyMap(),
                pathEnv = pathZig.parent.toString(),
            )

            assertEquals("path", result.toolchain?.source)
            assertEquals(pathZig, result.toolchain?.zigPath)
        }
    }

    @Test
    fun resolveWithMessages_uses_user_cache_before_download() {
        withTempUserHome { home ->
            val cachedZig = createExecutableZig(home.resolve(".javashroud").resolve("zig").resolve("0.13.0"))

            val result = withZigDownloadDisabled {
                NativeToolchainProvisioner.resolveWithMessages(
                    environment = emptyMap(),
                    pathEnv = null,
                )
            }

            assertEquals("cache", result.toolchain?.source)
            assertEquals(cachedZig, result.toolchain?.zigPath)
        }
    }

    private fun <T> withZigDownloadDisabled(block: () -> T): T {
        val previous = System.getProperty("javashroud.zig.disableDownload")
        System.setProperty("javashroud.zig.disableDownload", "true")
        return try {
            block()
        } finally {
            if (previous == null) {
                System.clearProperty("javashroud.zig.disableDownload")
            } else {
                System.setProperty("javashroud.zig.disableDownload", previous)
            }
        }
    }

    private fun <T> withTempUserHome(block: (Path) -> T): T {
        val previous = System.getProperty("user.home")
        val tempHome = Files.createTempDirectory("javashroud-zig-home-")
        System.setProperty("user.home", tempHome.toString())
        return try {
            block(tempHome)
        } finally {
            System.setProperty("user.home", previous)
            tempHome.toFile().deleteRecursively()
        }
    }

    private fun createExecutableZig(directory: Path): Path {
        Files.createDirectories(directory)
        val zig = directory.resolve(if (isWindows()) "zig.exe" else "zig")
        Files.write(zig, byteArrayOf(0x7F, 'J'.code.toByte(), 'S'.code.toByte()))
        if (isWindows()) Files.createDirectories(directory.resolve("lib"))
        zig.toFile().setExecutable(true)
        assertTrue(Files.isExecutable(zig), "Test Zig should be executable: $zig")
        return zig
    }

    private fun isWindows(): Boolean = File.separatorChar == '\\'
}
