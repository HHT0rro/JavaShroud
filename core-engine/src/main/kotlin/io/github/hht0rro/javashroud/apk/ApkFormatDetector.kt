package io.github.hht0rro.javashroud.apk

import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipException
import java.util.zip.ZipInputStream

/**
 * Input-format sniffing for the "auto" artifact mode: a zip whose root
 * contains AndroidManifest.xml plus at least one classes.dex/classesN.dex
 * entry is an APK; everything else stays on the jar pipeline.
 */
object ApkFormatDetector {

    private val ZIP_LOCAL_FILE_HEADER_MAGIC = byteArrayOf(0x50, 0x4B, 0x03, 0x04)
    private val DEX_ENTRY_REGEX = Regex("^classes(\\d*)\\.dex$")

    fun looksLikeApk(input: Path): Boolean {
        if (!Files.isRegularFile(input)) return false
        Files.newInputStream(input).buffered().use { stream ->
            val header = ByteArray(4)
            var filled = 0
            while (filled < 4) {
                val read = stream.read(header, filled, 4 - filled)
                if (read < 0) break
                filled += read
            }
            if (filled != 4 || !header.contentEquals(ZIP_LOCAL_FILE_HEADER_MAGIC)) return false
        }
        return zipHasApkMarkers(input)
    }

    internal fun zipHasApkMarkers(input: Path): Boolean {
        val entryNames = mutableListOf<String>()
        try {
            ZipInputStream(Files.newInputStream(input).buffered()).use { zip: ZipInputStream ->
                while (true) {
                    val entry: ZipEntry = zip.nextEntry ?: break
                    entryNames += entry.name
                    if (entryNames.size > 65_536) return false
                }
            }
        } catch (_: ZipException) {
            return false
        } catch (_: java.io.IOException) {
            return false
        }
        return containsApkMarkers(entryNames)
    }

    fun containsApkMarkers(entryNames: List<String>): Boolean {
        val names = entryNames.toSet()
        if (!names.contains("AndroidManifest.xml")) return false
        return names.any { DEX_ENTRY_REGEX.matches(it) }
    }

    /** Reads the raw bytes of one root entry, or null when absent. */
    fun readRootEntry(input: Path, entryName: String): ByteArray? {
        try {
            ZipInputStream(Files.newInputStream(input).buffered()).use { zip: ZipInputStream ->
                while (true) {
                    val entry: ZipEntry = zip.nextEntry ?: break
                    if (entry.name == entryName) {
                        return zip.readBytes()
                    }
                }
            }
        } catch (_: ZipException) {
            return null
        } catch (_: java.io.IOException) {
            return null
        }
        return null
    }

    /** Stream variant for readers that already hold an open manifest stream. */
    fun safeClose(stream: InputStream) {
        runCatching { stream.close() }
    }
}
