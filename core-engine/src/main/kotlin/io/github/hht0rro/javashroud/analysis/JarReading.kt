package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.config.ensureReadableFile
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarInputStream

data class JarReadEntry(
    val name: String,
    val bytes: ByteArray,
)

data class JarReadResult(
    val manifestPresent: Boolean,
    val entries: List<JarReadEntry>,
)

fun readJarEntries(inputJarPath: Path): JarReadResult {
    ensureReadableFile(inputJarPath)

    val entries = mutableListOf<JarReadEntry>()
    var manifestPresent = false
    var manifestBytes: ByteArray? = null

    JarInputStream(Files.newInputStream(inputJarPath)).use { jarInputStream: JarInputStream ->
        // JarInputStream consumes the MANIFEST.MF internally and exposes it via
        // getManifest() rather than returning it from nextJarEntry().  Recover
        // the serialised bytes so the manifest can be written to the output jar.
        jarInputStream.manifest?.let { manifest ->
            val baos = ByteArrayOutputStream()
            manifest.write(baos)
            manifestBytes = baos.toByteArray()
        }

        while (true) {
            val jarEntry = jarInputStream.nextJarEntry ?: break
            val entryData = readJarEntry(jarInputStream, jarEntry.name, jarEntry.isDirectory)
            if (entryData != null) {
                entries += entryData
                manifestPresent = manifestPresent || isManifestEntry(entryData)
            }
            jarInputStream.closeEntry()
        }
    }

    // If the manifest was consumed by JarInputStream (not returned via nextJarEntry),
    // prepend it to the entries list so it is preserved in the output jar.
    if (!manifestPresent && manifestBytes != null) {
        entries.add(0, JarReadEntry(name = MANIFEST_ENTRY_NAME, bytes = manifestBytes!!))
        manifestPresent = true
    }

    return JarReadResult(
        manifestPresent = manifestPresent,
        entries = entries.toList(),
    )
}

internal const val MANIFEST_ENTRY_NAME = "META-INF/MANIFEST.MF"

internal fun readJarEntry(
    jarInputStream: JarInputStream,
    entryName: String,
    isDirectory: Boolean,
): JarReadEntry? {
    if (isDirectory) {
        return null
    }

    return JarReadEntry(
        name = entryName,
        bytes = jarInputStream.readBytes(),
    )
}

internal fun isManifestEntry(entry: JarReadEntry): Boolean = entry.name == MANIFEST_ENTRY_NAME

data class RawJarLoadResult(
    val manifestPresent: Boolean,
    val classEntries: List<RawClassEntry>,
)

data class RawClassEntry(
    val entry: JarEntry,
    val bytes: ByteArray,
)

internal fun buildRawJarLoadResult(jarReadResult: JarReadResult): RawJarLoadResult = RawJarLoadResult(
    manifestPresent = jarReadResult.manifestPresent,
    classEntries = buildRawClassEntries(jarReadResult.entries),
)

fun loadRawClassEntries(inputJarPath: Path): RawJarLoadResult =
    buildRawJarLoadResult(readJarEntries(inputJarPath))
