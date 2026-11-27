package io.github.hht0rro.javashroud.apk

import java.io.DataOutputStream
import java.io.OutputStream
import java.nio.charset.StandardCharsets
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.ZipEntry

/**
 * Deterministic zip writer used to rebuild the APK: raw entries are copied
 * with their original compressed bytes and header metadata, STORED entries
 * receive extra-field padding so their data offsets satisfy the zipalign
 * invariants, and the central directory is assembled at the end so offsets
 * never move afterwards (the v2 signature block inserts before the CD).
 *
 * This writer intentionally does not implement Zip64: APKs beyond its limits
 * fail closed instead of silently degrading.
 */
class ApkZipWriter(output: OutputStream) : AutoCloseable {

    private companion object {
        const val ZIP_VERSION_NEEDED = 20
    }

    private val stream = DataOutputStream(output)
    private val records = mutableListOf<CentralDirectoryRecord>()
    private var offset: Long = 0L

    private class CentralDirectoryRecord(
        val name: String,
        val nameBytes: ByteArray,
        val extra: ByteArray,
        val comment: ByteArray,
        val method: Int,
        val time: Long,
        val crc: Long,
        val compressedSize: Long,
        val size: Long,
        val externalAttributes: Long,
        val localHeaderOffset: Long,
    )

    val currentOffset: Long get() = offset

    /**
     * Writes one entry with already-compressed payload bytes.
     * [alignment] > 1 pads the local header extra field so that the entry's
     * data starts at a multiple of it (STORED entries only make sense here).
     */
    fun addRawEntry(
        name: String,
        method: Int,
        time: Long,
        crc: Long,
        size: Long,
        compressedSize: Long,
        externalAttributes: Long,
        rawCompressedBytes: ByteArray,
        originalExtra: ByteArray,
        alignment: Int = 1,
    ) {
        require(alignment >= 1) { "alignment must be >= 1" }
        val nameBytes = name.toByteArray(StandardCharsets.UTF_8)
        val headerBase = 30L + nameBytes.size
        val extra = if (alignment > 1 && method == ZipEntry.STORED) {
            alignExtra(originalExtra, alignment, headerBase)
        } else {
            originalExtra
        }
        val dataOffset = offset + headerBase + extra.size
        check(dataOffset % alignment == 0L) {
            "zip alignment invariant violated for $name: dataOffset=$dataOffset alignment=$alignment"
        }

        writeLocalFileHeader(nameBytes, extra, method, time, crc, compressedSize, size)
        stream.write(rawCompressedBytes)
        records += CentralDirectoryRecord(
            name = name,
            nameBytes = nameBytes,
            extra = extra,
            comment = ByteArray(0),
            method = method,
            time = time,
            crc = crc,
            compressedSize = compressedSize,
            size = size,
            externalAttributes = externalAttributes,
            localHeaderOffset = offset,
        )
        offset += headerBase + extra.size + rawCompressedBytes.size
    }

    /** Writes one DEFLATED entry from plain data. */
    fun addDeflatedEntry(name: String, time: Long, data: ByteArray, level: Int = Deflater.DEFAULT_COMPRESSION) {
        val nameBytes = name.toByteArray(StandardCharsets.UTF_8)
        val deflater = Deflater(level, true)
        try {
            deflater.setInput(data)
            deflater.finish()
            val buffer = ByteArray(maxOf(data.size / 2, 1_024))
            val compressed = java.io.ByteArrayOutputStream()
            while (!deflater.finished()) {
                val written = deflater.deflate(buffer)
                if (written > 0) compressed.write(buffer, 0, written)
            }
            val payload = compressed.toByteArray()
            val crc = CRC32().apply { update(data) }
            writeLocalFileHeader(nameBytes, ByteArray(0), ZipEntry.DEFLATED, time, crc.value, payload.size.toLong(), data.size.toLong())
            stream.write(payload)
            records += CentralDirectoryRecord(
                name = name,
                nameBytes = nameBytes,
                extra = ByteArray(0),
                comment = ByteArray(0),
                method = ZipEntry.DEFLATED,
                time = time,
                crc = crc.value,
                compressedSize = payload.size.toLong(),
                size = data.size.toLong(),
                externalAttributes = 0L,
                localHeaderOffset = offset,
            )
            offset += 30L + nameBytes.size + payload.size
        } finally {
            deflater.end()
        }
    }

    fun addDirectoryEntry(name: String, time: Long, externalAttributes: Long) {
        val nameBytes = name.toByteArray(StandardCharsets.UTF_8)
        writeLocalFileHeader(nameBytes, ByteArray(0), ZipEntry.STORED, time, 0L, 0L, 0L)
        records += CentralDirectoryRecord(
            name = name,
            nameBytes = nameBytes,
            extra = ByteArray(0),
            comment = ByteArray(0),
            method = ZipEntry.STORED,
            time = time,
            crc = 0L,
            compressedSize = 0L,
            size = 0L,
            externalAttributes = externalAttributes,
            localHeaderOffset = offset,
        )
        offset += 30L + nameBytes.size
    }

    private fun writeLocalFileHeader(
        nameBytes: ByteArray,
        extra: ByteArray,
        method: Int,
        time: Long,
        crc: Long,
        compressedSize: Long,
        size: Long,
    ) {
        require(extra.size <= 0xFFFF) { "ZIP local extra field exceeds 65535 bytes" }
        write32(stream, 0x04034b50.toInt())
        write16(stream, ZIP_VERSION_NEEDED)
        write16(stream, 0) // general purpose flags
        write16(stream, method)
        write16(stream, dosTime(time))
        write16(stream, dosDate(time))
        write32(stream, crc.toInt())
        write32(stream, compressedSize.toInt())
        write32(stream, size.toInt())
        write16(stream, nameBytes.size)
        write16(stream, extra.size)
        stream.write(nameBytes)
        stream.write(extra)
    }

    private fun alignExtra(originalExtra: ByteArray, alignment: Int, headerBase: Long): ByteArray {
        val currentDataOffset = offset + headerBase + originalExtra.size
        var padding = ((alignment - (currentDataOffset % alignment)) % alignment).toInt()
        // Extra fields carry 4-byte headers, so a valid padding block is 4..alignment+3 bytes.
        if (padding in 1..3) padding += alignment
        if (padding == 0) return originalExtra
        val block = ByteArray(padding)
        block[0] = 0x86.toByte()
        block[1] = 0x19.toByte()
        block[2] = (padding - 4).toByte()
        block[3] = ((padding - 4) ushr 8).toByte()
        return originalExtra + block
    }

    private fun dosTime(unixTimeMillis: Long): Int = dosDateTime(unixTimeMillis).first

    private fun dosDate(unixTimeMillis: Long): Int = dosDateTime(unixTimeMillis).second

    private fun dosDateTime(unixTimeMillis: Long): Pair<Int, Int> {
        if (unixTimeMillis <= 0L) return 0 to 0x0021 // 1980-01-01 00:00:00
        val zoned = java.time.Instant.ofEpochMilli(unixTimeMillis).atZone(java.time.ZoneOffset.UTC)
        val year = zoned.year
        if (year < 1980 || year > 2107) return 0 to 0x0021
        val date = ((year - 1980) shl 9) or (zoned.monthValue shl 5) or zoned.dayOfMonth
        val time = (zoned.hour shl 11) or (zoned.minute shl 5) or (zoned.second / 2)
        return time to date
    }

    fun finish(comment: String = "") {
        val centralDirectoryOffset = offset
        var centralDirectorySize = 0L
        for (record in records) {
            val entrySize = 46L + record.nameBytes.size + record.extra.size + record.comment.size
            write32(stream, 0x02014b50.toInt())
            write16(stream, 0) // version made by
            write16(stream, ZIP_VERSION_NEEDED)
            write16(stream, 0) // flags
            write16(stream, record.method)
            write16(stream, dosTime(record.time))
            write16(stream, dosDate(record.time))
            write32(stream, record.crc.toInt())
            write32(stream, record.compressedSize.toInt())
            write32(stream, record.size.toInt())
            write16(stream, record.nameBytes.size)
            write16(stream, record.extra.size)
            write16(stream, record.comment.size)
            write16(stream, 0) // disk number
            write16(stream, 0) // internal attributes
            write32(stream, record.externalAttributes.toInt())
            write32(stream, record.localHeaderOffset.toInt())
            stream.write(record.nameBytes)
            stream.write(record.extra)
            stream.write(record.comment)
            centralDirectorySize += entrySize
        }
        check(records.size <= 0xFFFF) { "zip has too many entries for a non-Zip64 archive" }
        check(offset <= 0xFFFFFFFFL) { "zip exceeds the non-Zip64 size limit" }
        val commentBytes = comment.toByteArray(StandardCharsets.UTF_8)
        check(commentBytes.size <= 0xFFFF) { "zip comment exceeds the zip limit" }
        write32(stream, 0x06054b50.toInt())
        write16(stream, 0)
        write16(stream, 0)
        write16(stream, records.size)
        write16(stream, records.size)
        write32(stream, centralDirectorySize.toInt())
        write32(stream, centralDirectoryOffset.toInt())
        write16(stream, commentBytes.size)
        stream.write(commentBytes)
        stream.flush()
    }

    override fun close() {
        stream.close()
    }

    // Zip integers are little-endian; DataOutputStream's own writeShort /
    // writeInt members are big-endian, so all integers go through these
    // explicit helpers (extensions would lose overload resolution to the
    // platform members).
    private fun write16(out: DataOutputStream, value: Int) {
        out.write(value and 0xFF)
        out.write((value ushr 8) and 0xFF)
    }

    private fun write32(out: DataOutputStream, value: Int) {
        out.write(value and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 24) and 0xFF)
    }
}

/**
 * Rebuilds the APK from the preserved template plus freshly compiled dex
 * files: raw-entry byte fidelity for everything untouched, old v1 signature
 * material stripped, dex entries replaced in place, zipalign-equivalent
 * alignment for STORED payloads (4 bytes general, configurable page size for
 * native libraries).
 */
object ApkOutputPacker {

    private val STRIPPED_SIGNATURE_SUFFIXES = listOf(".SF", ".RSA", ".EC", ".DSA")

    data class PackResult(
        val outputApk: java.nio.file.Path,
        val dexEntryNames: List<String>,
    )

    fun pack(
        unpacked: ApkInputUnpacker.ApkUnpacked,
        newDexes: List<Pair<String, ByteArray>>,
        outputApk: java.nio.file.Path,
        soPageSize: Int,
    ): PackResult {
        val parent = outputApk.toAbsolutePath().parent
        if (parent != null) java.nio.file.Files.createDirectories(parent)

        val dexNames = newDexes.map { it.first }
        check(dexNames.zipWithNext().all { (a, b) -> dexIndex(a) < dexIndex(b) }) {
            "new dex entries must be supplied in ascending index order"
        }

        val dexWriter = ApkZipWriter(
            java.nio.file.Files.newOutputStream(outputApk).buffered(),
        )
        dexWriter.use { writer ->
            var dexesEmitted = false
            for (entry in unpacked.preservedEntries) {
                if (isStrippedSignatureEntry(entry.name)) continue
                if (entry.name == "META-INF/MANIFEST.MF") continue
                if (isNativeLib(entry.name) && entry.method == ZipEntry.STORED) {
                    writer.addRawEntry(
                        name = entry.name,
                        method = entry.method,
                        time = entry.time,
                        crc = entry.crc,
                        size = entry.size,
                        compressedSize = entry.compressedSize,
                        externalAttributes = entry.externalAttributes,
                        rawCompressedBytes = entry.rawCompressedBytes,
                        originalExtra = entry.extra,
                        alignment = soPageSize,
                    )
                    continue
                }
                if (isDexEntry(entry.name)) {
                    // All new dex files replace the original dex block at the
                    // position of the first original dex entry.
                    if (!dexesEmitted) {
                        for ((name, bytes) in newDexes) {
                            writer.addDeflatedEntry(name = name, time = entry.time, data = bytes)
                        }
                        dexesEmitted = true
                    }
                    continue
                }
                val alignment = if (entry.method == ZipEntry.STORED) 4 else 1
                writer.addRawEntry(
                    name = entry.name,
                    method = entry.method,
                    time = entry.time,
                    crc = entry.crc,
                    size = entry.size,
                    compressedSize = entry.compressedSize,
                    externalAttributes = entry.externalAttributes,
                    rawCompressedBytes = entry.rawCompressedBytes,
                    originalExtra = entry.extra,
                    alignment = alignment,
                )
            }
            if (!dexesEmitted) {
                // No dex entries in the template (should not happen: unpack
                // requires at least one), emit the new dex block at the tail.
                val anchorTime = unpacked.preservedEntries.lastOrNull()?.time ?: 0L
                for ((name, bytes) in newDexes) {
                    writer.addDeflatedEntry(name = name, time = anchorTime, data = bytes)
                }
            }
            writer.finish(comment = unpacked.zipComment)
        }
        return PackResult(outputApk = outputApk, dexEntryNames = dexNames)
    }

    internal fun isStrippedSignatureEntry(name: String): Boolean {
        if (!name.startsWith("META-INF/")) return false
        if ("/" in name.removePrefix("META-INF/")) return false
        return STRIPPED_SIGNATURE_SUFFIXES.any { name.endsWith(it, ignoreCase = true) }
    }

    internal fun isDexEntry(name: String): Boolean = Regex("^classes(\\d*)\\.dex$").matches(name)

    internal fun isNativeLib(name: String): Boolean = name.startsWith("lib/") && name.endsWith(".so")

    internal fun dexIndex(name: String): Int =
        Regex("^classes(\\d*)\\.dex$").matchEntire(name)?.groupValues?.get(1)?.ifEmpty { "1" }?.toInt()
            ?: error("not a dex entry: $name")
}
