package io.github.hht0rro.javashroud.artifact

import java.io.Closeable
import java.io.IOException
import java.nio.file.FileSystemException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.COPY_ATTRIBUTES
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.attribute.BasicFileAttributes

/** Prepare and validate a JAR and its sidecars before touching any published files. */
internal fun publishValidatedJar(outputJar: Path, prepare: (stagedJar: Path) -> List<Path>) {
    val destination = Files.createDirectories(outputJar.parent)
    val staging = Files.createTempDirectory(destination, ".javashroud-")
    var backups: Path? = null
    var keepBackups = false
    Closeable {
        if (!keepBackups) {
            backups?.let(::deleteStagingDirectory)
            deleteStagingDirectory(staging)
        }
    }.use {
        // Existing writers and validators derive sidecar names and labels from the JAR filename.
        val stagedJar = staging.resolve(outputJar.fileName)
        val stagedSidecars = prepare(stagedJar)

        // Outputs with the same stem share sidecars. Hold the lock through rollback.
        val stem = outputJar.fileName.toString().removeSuffix(".jar")
        val lock = Files.createDirectory(destination.resolve(".$stem.javashroud-publish"))
        Closeable { Files.delete(lock) }.use {
            val backupDirectory = Files.createTempDirectory(staging, "previous-").also { backups = it }
            try {
                replaceJarFiles(stagedJar, stagedSidecars, destination, backupDirectory)
            } catch (error: JarRollbackException) {
                keepBackups = true
                throw error
            }
        }
    }
}

private fun replaceJarFiles(stagedJar: Path, sidecars: List<Path>, destination: Path, backups: Path) {
    val published = mutableListOf<Pair<Path, Path?>>()
    try {
        for (staged in listOf(stagedJar) + sidecars) {
            val target = destination.resolve(staged.fileName)
            val backup = backupJarFile(target, backups.resolve(staged.fileName))
            if (staged != stagedJar && Files.notExists(staged, NOFOLLOW_LINKS)) {
                if (backup == null) continue
                Files.delete(target)
            } else {
                moveJarFile(staged, target)
            }
            published += target to backup
        }
    } catch (error: Throwable) {
        val rollbackFailures = mutableListOf<Exception>()
        for ((target, backup) in published.asReversed()) {
            try {
                if (backup == null) Files.deleteIfExists(target) else moveJarFile(backup, target)
            } catch (rollbackError: Exception) {
                rollbackFailures += rollbackError
            }
        }
        if (rollbackFailures.isNotEmpty()) {
            throw JarRollbackException(backups, error).also { failure ->
                rollbackFailures.forEach(failure::addSuppressed)
            }
        }
        throw error
    }
}

private fun backupJarFile(target: Path, backup: Path): Path? {
    val attributes = try {
        Files.readAttributes(target, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
    } catch (_: NoSuchFileException) {
        return null
    }
    if (!attributes.isRegularFile && !attributes.isSymbolicLink) {
        throw FileSystemException(target.toString(), null, "JAR publication target must be a file or symbolic link")
    }
    return Files.copy(target, backup, NOFOLLOW_LINKS, COPY_ATTRIBUTES)
}

private fun moveJarFile(source: Path, target: Path) {
    Files.move(source, target, ATOMIC_MOVE, REPLACE_EXISTING)
}

private fun deleteStagingDirectory(directory: Path) {
    Files.newDirectoryStream(directory).use { entries -> entries.forEach { Files.deleteIfExists(it) } }
    Files.delete(directory)
}

private class JarRollbackException(backups: Path, cause: Throwable) :
    IOException("JAR publication could not be fully rolled back. Recovery files: $backups", cause)
