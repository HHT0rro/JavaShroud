package io.github.hht0rro.javashroud.apk

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/**
 * Test fixtures: a minimal AXML encoder (so binary-manifest tests do not need
 * aapt2 or checked-in binaries) and a synthetic APK builder that produces
 * archives with realistic entry metadata for the unpacker/packer/signer.
 */
object ApkTestFixtures {

    // --- minimal AXML encoder ------------------------------------------------

    fun binaryManifest(
        packageName: String,
        minSdkVersion: Int? = 26,
        componentClasses: List<String> = emptyList(),
        layoutClickMethod: String? = null,
    ): ByteArray {
        val strings = mutableListOf<String>()
        fun intern(value: String): Int {
            val index = strings.indexOf(value)
            if (index >= 0) return index
            strings += value
            return strings.size - 1
        }

        data class Attribute(
            val name: String,
            val rawStringValue: String?,
            val typedIntValue: Int?,
        )

        data class Element(
            val name: String,
            val attributes: List<Attribute>,
        )

        val elements = mutableListOf<Element>()
        elements += Element("manifest", listOf(Attribute("package", packageName, null)))
        if (minSdkVersion != null) {
            elements += Element("uses-sdk", listOf(Attribute("minSdkVersion", null, minSdkVersion)))
        }
        elements += Element("application", componentClasses.take(1).map { Attribute("name", it, null) })
        componentClasses.drop(1).forEach { component ->
            elements += Element("activity", listOf(Attribute("name", component, null)))
        }
        if (layoutClickMethod != null) {
            elements += Element("Button", listOf(Attribute("onClick", layoutClickMethod, null)))
        }
        val androidNamespace = layoutClickMethod?.let { intern("http://schemas.android.com/apk/res/android") }

        val nameIndices = elements.map { intern(it.name) }
        val attributeIndices = elements.map { element ->
            element.attributes.map { attribute ->
                Triple(intern(attribute.name), attribute.rawStringValue?.let(::intern), attribute.typedIntValue)
            }
        }

        val stringPool = encodeStringPool(strings)
        val body = ByteArrayOutputStream()
        DataOutputStream(body).use { data ->
            for (index in elements.indices) {
                val element = elements[index]
                val attributes = attributeIndices[index]
                val attributeCount = attributes.size
                val chunkSize = 16 + 20 + attributeCount * 20
                data.writeShortLE(0x0102)
                data.writeShortLE(16)
                data.writeIntLE(chunkSize)
                data.writeIntLE(0) // line
                data.writeIntLE(0xFFFFFFFF.toInt()) // comment
                data.writeIntLE(0xFFFFFFFF.toInt()) // ns
                data.writeIntLE(nameIndices[index])
                data.writeShortLE(20) // attributeStart
                data.writeShortLE(20) // attributeSize
                data.writeShortLE(attributeCount)
                data.writeShortLE(0) // idIndex
                data.writeShortLE(0) // classIndex
                data.writeShortLE(0) // styleIndex
                for ((nameIndex, rawValueIndex, typedValue) in attributes) {
                    data.writeIntLE(if (element.name == "Button") requireNotNull(androidNamespace) else -1)
                    data.writeIntLE(nameIndex)
                    data.writeIntLE(rawValueIndex ?: 0xFFFFFFFF.toInt())
                    data.writeShortLE(8) // typed value size
                    data.writeByte(0) // res0
                    data.writeByte(if (typedValue != null) 0x10 else 0x03) // INT_DEC or STRING
                    data.writeIntLE(typedValue ?: 0)
                }
                // end element: 8-byte chunk header + line/comment/ns/name body
                data.writeShortLE(0x0103)
                data.writeShortLE(16)
                data.writeIntLE(24)
                data.writeIntLE(0)
                data.writeIntLE(0xFFFFFFFF.toInt())
                data.writeIntLE(0xFFFFFFFF.toInt())
                data.writeIntLE(nameIndices[index])
            }
        }

        val bodyBytes = body.toByteArray()
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { data ->
            data.writeShortLE(0x0003)
            data.writeShortLE(8)
            data.writeIntLE(8 + stringPool.size + bodyBytes.size)
            data.write(stringPool)
            data.write(bodyBytes)
        }
        return out.toByteArray()
    }

    fun resourceTable(vararg strings: String): ByteArray {
        val pool = encodeStringPool(strings.toList())
        val table = ByteArrayOutputStream()
        DataOutputStream(table).use { data ->
            data.writeShortLE(0x0002)
            data.writeShortLE(12)
            data.writeIntLE(12 + pool.size)
            data.writeIntLE(0) // package count
            data.write(pool)
        }
        return table.toByteArray()
    }

    private fun encodeStringPool(strings: List<String>): ByteArray {
        val out = ByteArrayOutputStream()
        val offsets = mutableListOf<Int>()
        val encoded = ByteArrayOutputStream()
        DataOutputStream(encoded).use { data ->
            for (value in strings) {
                offsets += encoded.size()
                val bytes = value.toByteArray(StandardCharsets.UTF_8)
                val charCount = value.length
                val byteCount = bytes.size
                if (charCount > 127) {
                    data.writeByte(((charCount ushr 8) and 0x7F) or 0x80)
                    data.writeByte(charCount and 0xFF)
                } else {
                    data.writeByte(charCount)
                }
                if (byteCount > 127) {
                    data.writeByte(((byteCount ushr 8) and 0x7F) or 0x80)
                    data.writeByte(byteCount and 0xFF)
                } else {
                    data.writeByte(byteCount)
                }
                data.write(bytes)
                data.writeByte(0)
            }
        }
        val encodedBytes = encoded.toByteArray()
        DataOutputStream(out).use { data ->
            val chunkSize = 28 + strings.size * 4 + encodedBytes.size
            data.writeShortLE(0x0001)
            data.writeShortLE(28)
            data.writeIntLE(chunkSize)
            data.writeIntLE(strings.size)
            data.writeIntLE(0) // style count
            data.writeIntLE(1 shl 8) // UTF-8 flag
            data.writeIntLE(28 + strings.size * 4) // strings start
            data.writeIntLE(0) // styles start
            offsets.forEach { offset -> data.writeIntLE(offset) }
            data.write(encodedBytes)
        }
        return out.toByteArray()
    }

    private fun DataOutputStream.writeShortLE(value: Int) {
        write(value and 0xFF)
        write((value ushr 8) and 0xFF)
    }

    private fun DataOutputStream.writeIntLE(value: Int) {
        write(value and 0xFF)
        write((value ushr 8) and 0xFF)
        write((value ushr 16) and 0xFF)
        write((value ushr 24) and 0xFF)
    }

    // --- synthetic APK builder ----------------------------------------------

    class ApkTemplateEntry(
        val name: String,
        val data: ByteArray,
        val method: Int = ZipEntry.DEFLATED,
    )

    /**
     * Writes a zip with the given entries. Entries marked STORED land with
     * deterministic content so alignment checks are meaningful.
     */
    fun buildZip(vararg entries: ApkTemplateEntry, comment: String = ""): ByteArray {
        val out = ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            for (template in entries) {
                val entry = ZipEntry(template.name)
                if (template.method == ZipEntry.STORED) {
                    entry.method = ZipEntry.STORED
                    entry.size = template.data.size.toLong()
                    val crc = CRC32()
                    crc.update(template.data)
                    entry.crc = crc.value
                }
                zip.putNextEntry(entry)
                if (template.method == ZipEntry.DEFLATED) {
                    zip.setLevel(Deflater.BEST_SPEED)
                }
                zip.write(template.data)
                zip.closeEntry()
            }
            if (comment.isNotEmpty()) zip.setComment(comment)
        }
        return out.toByteArray()
    }

    fun syntheticApk(
        manifestBytes: ByteArray = binaryManifest("com.example.app", minSdkVersion = 26),
        dexBytes: List<ByteArray> = listOf(ByteArray(64) { it.toByte() }),
        extraEntries: List<ApkTemplateEntry> = emptyList(),
        oldSignature: Boolean = false,
        comment: String = "",
    ): ByteArray {
        val entries = mutableListOf<ApkTemplateEntry>()
        entries += ApkTemplateEntry("AndroidManifest.xml", manifestBytes)
        dexBytes.forEachIndexed { index, bytes ->
            entries += ApkTemplateEntry(if (index == 0) "classes.dex" else "classes${index + 1}.dex", bytes)
        }
        entries += extraEntries
        if (oldSignature) {
            entries += ApkTemplateEntry("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n".toByteArray())
            entries += ApkTemplateEntry("META-INF/CERT.SF", "Signature-File\n".toByteArray())
            entries += ApkTemplateEntry("META-INF/CERT.RSA", ByteArray(32))
        }
        return buildZip(*entries.toTypedArray(), comment = comment)
    }

    fun writeApk(path: Path, bytes: ByteArray): Path {
        path.parent?.let { java.nio.file.Files.createDirectories(it) }
        java.nio.file.Files.write(path, bytes)
        return path
    }
}
