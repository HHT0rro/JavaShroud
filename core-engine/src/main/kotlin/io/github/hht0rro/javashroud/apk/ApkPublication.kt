package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.config.sameArtifactPath
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.attribute.BasicFileAttributes
import java.util.concurrent.CancellationException

private val apkSidecarSuffixes = listOf(".release-scan.txt", ".build-evidence.json", ".debugmap")

private fun Path.apkStem(): String = fileName.toString().substringBeforeLast('.')

internal fun apkSidecarPaths(apk: Path): List<Path> =
    apkSidecarSuffixes.map { apk.resolveSibling(apk.apkStem() + it) }

internal fun apkPublicationLock(apk: Path): Path = apk.resolveSibling(".${apk.apkStem()}.javashroud-publish")

internal fun requireSeparateApkPaths(first: Path, second: Path) {
    fun isAtOrInside(path: Path, other: Path) =
        generateSequence(path) { it.parent }.any { sameArtifactPath(it, other) }

    require(!isAtOrInside(first, second) && !isAtOrInside(second, first)) {
        "Conflicting APK paths: $first and $second"
    }
}

/** Returns false only for a missing path. Rejects links, directories and special files. */
internal fun existingRegularApkFile(path: Path): Boolean {
    val attributes = try {
        Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
    } catch (_: NoSuchFileException) {
        return false
    }
    require(attributes.isRegularFile) { "APK path must be a regular file: $path" }
    return true
}

internal fun checkApkCancellation() {
    if (Thread.currentThread().isInterrupted) throw CancellationException("APK run interrupted")
}

internal fun moveApkFile(source: Path, target: Path) {
    Files.move(source, target, ATOMIC_MOVE, REPLACE_EXISTING)
}

internal class ApkRollbackException(workDirectory: Path, cause: Throwable) :
    IOException("APK publication could not be fully rolled back. Recovery files: $workDirectory", cause)

/** All staged files and backups live on the destination filesystem. Publish the APK last. */
// A null source removes an obsolete sidecar with the same backup and rollback guarantees.
internal fun publishApkFiles(
    stagedFiles: List<Pair<Path?, Path>>,
    workDirectory: Path,
    lockDirectory: Path,
    afterPublish: () -> Unit,
) {
    checkApkCancellation()
    // Two runs with the same output stem share sidecar names. Only the run that
    // created this directory may replace those files or restore its backups.
    Files.createDirectory(lockDirectory)
    try {
        replaceApkFiles(stagedFiles, workDirectory, afterPublish)
    } finally {
        runCatching { Files.delete(lockDirectory) }
    }
}

private fun replaceApkFiles(stagedFiles: List<Pair<Path?, Path>>, workDirectory: Path, afterPublish: () -> Unit) {
    val backups = stagedFiles.mapIndexed { index, (source, target) ->
        checkApkCancellation()
        if (source != null) require(existingRegularApkFile(source)) { "Staged APK artifact is missing: $source" }
        if (existingRegularApkFile(target)) {
            Files.copy(target, workDirectory.resolve("publication-backup-$index"), NOFOLLOW_LINKS)
        } else {
            null
        }
    }
    var published = 0
    try {
        for ((source, target) in stagedFiles) {
            checkApkCancellation()
            if (source == null) Files.deleteIfExists(target) else moveApkFile(source, target)
            published++
        }
        checkApkCancellation()
        afterPublish()
        checkApkCancellation()
    } catch (error: Throwable) {
        val rollbackFailures = mutableListOf<Throwable>()
        for (index in published - 1 downTo 0) {
            val target = stagedFiles[index].second
            val backup = backups[index]
            try {
                if (backup == null) Files.deleteIfExists(target) else moveApkFile(backup, target)
            } catch (rollbackError: Exception) {
                rollbackFailures += rollbackError
            }
        }
        if (rollbackFailures.isNotEmpty()) {
            throw ApkRollbackException(workDirectory, error).also { failure ->
                rollbackFailures.forEach(failure::addSuppressed)
            }
        }
        throw error
    }
}
