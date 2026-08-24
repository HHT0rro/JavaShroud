package io.github.hht0rro.javashroud.maintenance

import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator

object RuntimeGarbageCollector {
    private const val USER_CACHE_DIR_NAME = ".javashroud"
    private const val WORKSPACE_NATIVE_DIR_NAME = ".javashroud-native"

    /**
     * Downloaded Rust/Zig/cargo-zigbuild installs and the extracted Rust
     * workspace live under these directories. Deleting them after every run
     * forces a multi-hundred-megabyte re-download on the next run and races
     * concurrent engine processes, so the garbage collector preserves them.
     */
    private val PRESERVED_USER_CACHE_CHILDREN = setOf("toolchains", "rust-workspace")

    data class GarbageCandidate(
        val path: Path,
        val kind: String,
        val files: Int,
        val directories: Int,
        val bytes: Long,
    )

    data class GarbageCollectionResult(
        val applied: Boolean,
        val candidates: List<GarbageCandidate>,
        val deleted: List<Path>,
        val skipped: List<String>,
    ) {
        val totalBytes: Long get() = candidates.sumOf { it.bytes }
        val totalFiles: Int get() = candidates.sumOf { it.files }
        val totalDirectories: Int get() = candidates.sumOf { it.directories }
    }

    fun collect(apply: Boolean = false): GarbageCollectionResult = collect(
        userHome = Path.of(System.getProperty("user.home")),
        workingDirectory = Path.of(System.getProperty("user.dir")),
        apply = apply,
    )

    internal fun collect(
        userHome: Path,
        workingDirectory: Path,
        apply: Boolean = false,
    ): GarbageCollectionResult {
        val normalizedHome = userHome.toAbsolutePath().normalize()
        val normalizedWorkingDirectory = workingDirectory.toAbsolutePath().normalize()
        val skipped = mutableListOf<String>()
        val candidates = discoverCandidates(normalizedHome, normalizedWorkingDirectory, skipped)
        val deleted = if (apply) {
            candidates.mapNotNull { candidate ->
                deleteCandidate(candidate.path, skipped)
            }
        } else {
            emptyList()
        }

        return GarbageCollectionResult(
            applied = apply,
            candidates = candidates,
            deleted = deleted,
            skipped = skipped,
        )
    }

    private fun discoverCandidates(
        userHome: Path,
        workingDirectory: Path,
        skipped: MutableList<String>,
    ): List<GarbageCandidate> {
        val discovered = linkedMapOf<Path, String>()
        discovered[userHome.resolve(USER_CACHE_DIR_NAME).normalize()] = "user-cache"
        discovered[userHome.resolve(WORKSPACE_NATIVE_DIR_NAME).normalize()] = "user-native-cache"

        findWorkspaceNativeCaches(workingDirectory, skipped).forEach { path ->
            discovered[path] = "workspace-native-cache"
        }

        return discovered.mapNotNull { (path, kind) ->
            if (!Files.exists(path)) return@mapNotNull null
            if (!isAllowedCandidate(path, userHome, workingDirectory)) {
                skipped += "Skipped unsafe candidate outside allowed roots: $path"
                return@mapNotNull null
            }
            if (Files.isSymbolicLink(path)) {
                skipped += "Skipped symbolic link candidate: $path"
                return@mapNotNull null
            }
            summarize(path, kind, skipped)
        }
    }

    private fun findWorkspaceNativeCaches(workingDirectory: Path, skipped: MutableList<String>): List<Path> {
        if (!Files.isDirectory(workingDirectory)) return emptyList()
        return try {
            Files.walk(workingDirectory, 4).use { stream ->
                stream
                    .filter { path -> Files.isDirectory(path) && path.fileName?.toString() == WORKSPACE_NATIVE_DIR_NAME }
                    .map { it.toAbsolutePath().normalize() }
                    .sorted()
                    .toList()
            }
        } catch (error: Exception) {
            skipped += "Failed to scan workspace native caches under $workingDirectory: ${error.message ?: error::class.java.simpleName}"
            emptyList()
        }
    }

    private fun summarize(path: Path, kind: String, skipped: MutableList<String>): GarbageCandidate? {
        return try {
            var files = 0
            var directories = 0
            var bytes = 0L
            Files.walk(path).use { stream ->
                stream.forEach { entry ->
                    when {
                        Files.isDirectory(entry) -> directories += 1
                        Files.isRegularFile(entry) -> {
                            files += 1
                            bytes += runCatching { Files.size(entry) }.getOrDefault(0L)
                        }
                    }
                }
            }
            GarbageCandidate(path = path, kind = kind, files = files, directories = directories, bytes = bytes)
        } catch (error: Exception) {
            skipped += "Failed to summarize $path: ${error.message ?: error::class.java.simpleName}"
            null
        }
    }

    private fun deleteCandidate(path: Path, skipped: MutableList<String>): Path? {
        return try {
            if (path.fileName?.toString() == USER_CACHE_DIR_NAME) {
                deleteUserCacheChildren(path)
            } else {
                Files.walk(path).use { stream ->
                    stream.sorted(Comparator.reverseOrder()).forEach { entry ->
                        Files.deleteIfExists(entry)
                    }
                }
            }
            path
        } catch (error: Exception) {
            skipped += "Failed to delete $path: ${error.message ?: error::class.java.simpleName}"
            null
        }
    }

    private fun deleteUserCacheChildren(userCache: Path) {
        Files.list(userCache).use { stream ->
            stream.forEach { child ->
                if (child.fileName?.toString() in PRESERVED_USER_CACHE_CHILDREN) {
                    return@forEach
                }
                Files.walk(child).use { walk ->
                    walk.sorted(Comparator.reverseOrder()).forEach { entry ->
                        Files.deleteIfExists(entry)
                    }
                }
            }
        }
    }

    private fun isAllowedCandidate(path: Path, userHome: Path, workingDirectory: Path): Boolean {
        val normalized = path.toAbsolutePath().normalize()
        val userCache = userHome.resolve(USER_CACHE_DIR_NAME).toAbsolutePath().normalize()
        val userNativeCache = userHome.resolve(WORKSPACE_NATIVE_DIR_NAME).toAbsolutePath().normalize()
        if (normalized == userCache) return true
        if (normalized == userNativeCache) return true
        return normalized.startsWith(workingDirectory) && normalized.fileName?.toString() == WORKSPACE_NATIVE_DIR_NAME
    }
}
