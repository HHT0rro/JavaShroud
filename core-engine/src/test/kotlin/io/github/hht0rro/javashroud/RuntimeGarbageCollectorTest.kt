package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.buildGarbageCollectionReport
import io.github.hht0rro.javashroud.maintenance.RuntimeGarbageCollector
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RuntimeGarbageCollectorTest {
    @Test
    fun collect_preview_reports_user_and_workspace_caches_without_deleting() {
        withTempRoots { userHome, workspace ->
            val userCache = writeFile(userHome.resolve(".javashroud/zig/0.13.0/zig.exe"), 3)
            val workspaceCache = writeFile(workspace.resolve("core-engine/.javashroud-native/native/kernel.dll"), 5)

            val result = RuntimeGarbageCollector.collect(userHome, workspace, apply = false)

            assertFalse(result.applied)
            assertEquals(2, result.candidates.size)
            assertEquals(8, result.totalBytes)
            assertTrue(Files.exists(userCache))
            assertTrue(Files.exists(workspaceCache))
        }
    }

    @Test
    fun collect_apply_deletes_only_known_java_shroud_cache_directories() {
        withTempRoots { userHome, workspace ->
            val userCache = userHome.resolve(".javashroud")
            val userNativeCache = userHome.resolve(".javashroud-native")
            val nativeCache = workspace.resolve("core-engine/.javashroud-native")
            val ordinaryDirectory = workspace.resolve("ordinary")
            writeFile(userCache.resolve("zig/0.13.0/zig.exe"), 3)
            writeFile(userNativeCache.resolve("native/kernel.dll"), 2)
            writeFile(nativeCache.resolve("native/kernel.dll"), 5)
            val ordinaryFile = writeFile(ordinaryDirectory.resolve("keep.txt"), 7)

            val result = RuntimeGarbageCollector.collect(userHome, workspace, apply = true)

            assertTrue(result.applied)
            assertEquals(3, result.deleted.size)
            assertFalse(Files.exists(userCache.resolve("zig")))
            assertFalse(Files.exists(userNativeCache))
            assertFalse(Files.exists(nativeCache))
            assertTrue(Files.exists(ordinaryFile))
        }
    }

    @Test
    fun collect_apply_preserves_toolchains_and_rust_workspace() {
        withTempRoots { userHome, workspace ->
            val userCache = userHome.resolve(".javashroud")
            val toolchain = writeFile(userCache.resolve("toolchains/zig-0.13.0-windows-x64/zig.exe"), 3)
            val workspaceFiles = writeFile(userCache.resolve("rust-workspace/aken-r1/Cargo.toml"), 4)
            writeFile(userCache.resolve("zig/0.13.0/zig.exe"), 5)

            RuntimeGarbageCollector.collect(userHome, workspace, apply = true)

            assertTrue(Files.exists(toolchain))
            assertTrue(Files.exists(workspaceFiles))
            assertFalse(Files.exists(userCache.resolve("zig")))
        }
    }

    @Test
    fun collect_skips_workspace_symbolic_link_candidates() {
        withTempRoots { userHome, workspace ->
            val outside = Files.createTempDirectory("javashroud-gc-outside-")
            try {
                writeFile(outside.resolve("keep.txt"), 11)
                val link = workspace.resolve(".javashroud-native")
                runCatching { Files.createSymbolicLink(link, outside) }

                val result = RuntimeGarbageCollector.collect(userHome, workspace, apply = true)

                assertTrue(Files.exists(outside.resolve("keep.txt")))
                if (Files.isSymbolicLink(link)) {
                    assertTrue(result.skipped.any { it.contains("symbolic link") })
                }
            } finally {
                outside.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun buildGarbageCollectionReport_mentions_apply_hint_for_preview() {
        withTempRoots { userHome, workspace ->
            writeFile(userHome.resolve(".javashroud/zig/0.13.0/zig.exe"), 3)

            val result = RuntimeGarbageCollector.collect(userHome, workspace, apply = false)
            val report = buildGarbageCollectionReport(result)

            assertContains(report, "mode=preview")
            assertContains(report, "-gc --apply")
            assertContains(report, ".javashroud")
        }
    }

    private fun withTempRoots(block: (Path, Path) -> Unit) {
        val userHome = Files.createTempDirectory("javashroud-gc-home-")
        val workspace = Files.createTempDirectory("javashroud-gc-workspace-")
        try {
            block(userHome, workspace)
        } finally {
            userHome.toFile().deleteRecursively()
            workspace.toFile().deleteRecursively()
        }
    }

    private fun writeFile(path: Path, size: Int): Path {
        Files.createDirectories(path.parent)
        Files.write(path, ByteArray(size) { it.toByte() })
        return path
    }
}
