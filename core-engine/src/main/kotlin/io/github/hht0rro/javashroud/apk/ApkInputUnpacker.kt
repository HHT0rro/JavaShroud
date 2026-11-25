package io.github.hht0rro.javashroud.apk

import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipFile

/**
 * Random-access APK reader that captures full zip entry metadata plus the raw
 * (still-compressed) bytes of every preserved entry, so the output packer can
 * rebuild the archive byte-faithfully. Dex entries are extracted in numeric
 * order as plain data bytes.
 */
object ApkInputUnpacker {

    /** A non-dex entry kept for byte-faithful re-pack. */
    data class ApkPreservedEntry(
        val name: String,
        val rawCompressedBytes: ByteArray,
        val method: Int,
        val time: Long,
        val crc: Long,
        val compressedSize: Long,
        val size: Long,
        val externalAttributes: Long,
        val extra: ByteArray,
        val isDirectory: Boolean,
        /** Decompressed data, materialized lazily by the reader where required. */
        val data: ByteArray,
    )

    data class ApkDexInput(
        val entryName: String,
        /** Dex index: classes.dex -> 1, classes2.dex -> 2, ... */
        val index: Int,
        val bytes: ByteArray,
    )

    data class ApkUnpacked(
        val preservedEntries: List<ApkPreservedEntry>,
        val dexEntries: List<ApkDexInput>,
        val manifestEntry: ApkPreservedEntry,
        val zipComment: String,
        val nativeLibraryAlignment: Int,
    )

    private val DEX_ENTRY_REGEX = Regex("^classes(\\d*)\\.dex$")

    fun read(apkPath: Path): ApkUnpacked {
        ZipFile.builder().setFile(apkPath.toFile()).get().use { zip: ZipFile ->
            val entryList: List<ZipArchiveEntry> = java.util.Collections.list(zip.getEntries())
            val duplicates = entryList
                .map { it.name }
                .groupingBy { it }
                .eachCount()
                .filterValues { it > 1 }
                .keys
            if (duplicates.isNotEmpty()) {
                throw IllegalArgumentException("APK input contains duplicate zip entries: ${duplicates.sorted()}")
            }

            val preserved = mutableListOf<ApkPreservedEntry>()
            val dexEntries = mutableListOf<ApkDexInput>()
            var manifestEntry: ApkPreservedEntry? = null
            var nativeLibraryAlignment = 4096

            for (entry in entryList) {
                val name = entry.name
                val dexMatch = DEX_ENTRY_REGEX.matchEntire(name)
                if (dexMatch != null) {
                    val suffix = dexMatch.groupValues[1]
                    val index = if (suffix.isEmpty()) 1 else suffix.toIntOrNull()
                    require(index != null && (index == 1 && suffix.isEmpty() || index >= 2 && suffix == index.toString())) {
                        "APK dex entry '$name' does not use the canonical classes.dex/classesN.dex name"
                    }
                    val data = zip.getInputStream(entry).use(InputStream::readBytes)
                    if (data.size < 12) {
                        throw IllegalArgumentException("APK dex entry '$name' is truncated (${data.size} bytes)")
                    }
                    dexEntries += ApkDexInput(entryName = name, index = index, bytes = data)
                    continue
                }
                val preservedEntry = preserveEntry(zip, entry)
                preserved += preservedEntry
                if (entry.method == ZipEntry.STORED && ApkOutputPacker.isNativeLib(name) &&
                    entry.dataOffset > 0 && entry.dataOffset % 16384 == 0L
                ) {
                    nativeLibraryAlignment = 16384
                }
                if (name == "AndroidManifest.xml") {
                    manifestEntry = preservedEntry
                }
            }

            if (manifestEntry == null) {
                throw IllegalArgumentException("APK input is missing the root AndroidManifest.xml entry")
            }
            if (dexEntries.isEmpty()) {
                throw IllegalArgumentException("APK input has no classes.dex/classesN.dex entries")
            }
            val sortedDexEntries = dexEntries.sortedBy { it.index }
            sortedDexEntries.forEachIndexed { offset, dex ->
                val expectedIndex = offset + 1
                require(dex.index == expectedIndex) {
                    val expectedName = if (expectedIndex == 1) "classes.dex" else "classes$expectedIndex.dex"
                    "APK dex entries must be consecutive: expected $expectedName before ${dex.entryName}"
                }
            }

            return ApkUnpacked(
                preservedEntries = preserved,
                dexEntries = sortedDexEntries,
                manifestEntry = manifestEntry!!,
                zipComment = readZipComment(apkPath),
                nativeLibraryAlignment = nativeLibraryAlignment,
            )
        }
    }

    /** commons-compress does not expose the archive comment; read it from the EOCD. */
    internal fun readZipComment(apkPath: Path): String {
        val bytes = Files.readAllBytes(apkPath)
        if (bytes.size < 22) return ""
        val scanStart = maxOf(0, bytes.size - 22 - 65_536)
        for (cursor in bytes.size - 22 downTo scanStart) {
            if (bytes[cursor] == 0x50.toByte() && bytes[cursor + 1] == 0x4B.toByte() &&
                bytes[cursor + 2] == 0x05.toByte() && bytes[cursor + 3] == 0x06.toByte()
            ) {
                val commentLength = (bytes[cursor + 20].toInt() and 0xFF) or
                    ((bytes[cursor + 21].toInt() and 0xFF) shl 8)
                val commentStart = cursor + 22
                if (commentStart + commentLength > bytes.size) return ""
                return if (commentLength == 0) "" else String(bytes, commentStart, commentLength, Charsets.UTF_8)
            }
        }
        return ""
    }

    private fun preserveEntry(zip: ZipFile, entry: ZipArchiveEntry): ApkPreservedEntry {
        val raw = zip.getRawInputStream(entry).use(InputStream::readBytes)
        val data = if (entry.isDirectory) ByteArray(0) else zip.getInputStream(entry).use(InputStream::readBytes)
        return ApkPreservedEntry(
            name = entry.name,
            rawCompressedBytes = raw,
            method = entry.method,
            time = entry.time,
            crc = entry.crc,
            compressedSize = if (entry.method == ZipEntry.STORED) data.size.toLong() else raw.size.toLong(),
            size = if (entry.isDirectory) 0L else data.size.toLong(),
            externalAttributes = entry.externalAttributes,
            extra = entry.extra ?: ByteArray(0),
            isDirectory = entry.isDirectory,
            data = data,
        )
    }

    /** CRC re-computation over preserved data, used by fail-closed re-pack checks. */
    fun crc32Of(data: ByteArray): Long {
        val crc = CRC32()
        crc.update(data)
        return crc.value
    }
}
