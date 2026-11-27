package io.github.hht0rro.javashroud.apk

import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.nio.charset.StandardCharsets

/**
 * Minimal read-only AXML (Android binary XML) parser for AndroidManifest.xml.
 *
 * Walks the chunk stream linearly: the first string-pool chunk supplies every
 * string; start-element chunks supply element names plus attribute name/value
 * pairs. Only the manifest facts the APK pipeline needs are extracted:
 * package name, minSdkVersion, every name target, and Android class-valued
 * attributes on their declared manifest elements. Unknown chunks are skipped using their
 * declared size; malformed input fails closed.
 */
object ApkBinaryXmlReader {

    private const val CHUNK_STRING_POOL = 0x0001
    private const val CHUNK_START_ELEMENT = 0x0102
    private const val ANDROID_NAMESPACE = "http://schemas.android.com/apk/res/android"

    private const val STRING_POOL_UTF8_FLAG = 1 shl 8

    private const val VALUE_TYPE_STRING = 0x03
    private const val VALUE_TYPE_INT_DEC = 0x10
    private const val VALUE_TYPE_INT_HEX = 0x11
    private const val VALUE_TYPE_BOOLEAN = 0x12

    private val CLASS_REFERENCE_PATTERN = Regex(
        """\.?\p{javaJavaIdentifierStart}\p{javaJavaIdentifierPart}*(?:\.\p{javaJavaIdentifierStart}\p{javaJavaIdentifierPart}*)*""",
    )

    data class ApkManifestInfo(
        val packageName: String,
        val minSdkVersion: Int?,
        /** Raw name targets and Android class-valued manifest attribute values. */
        val namedClasses: List<String>,
    )

    fun parse(bytes: ByteArray): ApkManifestInfo {
        var packageName = ""
        var minSdkVersion: Int? = null
        val namedClasses = mutableListOf<String>()
        visitAttributes(bytes) { element, elementNamespaceIndex, attribute ->
            when {
                element == "manifest" && attribute.name == "package" -> packageName = attribute.valueString.orEmpty()
                element == "uses-sdk" && attribute.name == "minSdkVersion" -> minSdkVersion = attribute.intValue
                attribute.name == "name" || isAdditionalClassReference(element, elementNamespaceIndex, attribute) ->
                    attribute.valueString?.takeIf { it.isNotBlank() }?.let(namedClasses::add)
            }
        }
        require(packageName.isNotBlank()) { "AndroidManifest.xml does not declare a package name" }
        return ApkManifestInfo(packageName, minSdkVersion, namedClasses.distinct())
    }

    private fun isAdditionalClassReference(element: String, elementNamespaceIndex: Int, attribute: ApxAttribute): Boolean {
        if (elementNamespaceIndex != -1 || attribute.namespace != ANDROID_NAMESPACE || attribute.valueType != VALUE_TYPE_STRING) {
            return false
        }
        val isClassAttribute = when (attribute.name) {
            "appComponentFactory", "backupAgent", "manageSpaceActivity", "zygotePreloadName", "classLoader" -> element == "application"
            "targetActivity" -> element == "activity-alias"
            "parentActivityName" -> element == "activity" || element == "activity-alias"
            else -> false
        }
        return isClassAttribute && attribute.valueString?.matches(CLASS_REFERENCE_PATTERN) == true
    }

    internal fun layoutClickMethods(bytes: ByteArray): Set<String> {
        if (bytes.size < 8 || readUShort(bytes, 0) != 0x0003) return emptySet()
        return buildSet {
            visitAttributes(bytes) { _, _, attribute ->
                if (attribute.name == "onClick" && attribute.namespace == ANDROID_NAMESPACE) {
                    attribute.valueString?.takeIf { it.isNotBlank() }?.let(::add)
                }
            }
        }
    }

    private fun visitAttributes(bytes: ByteArray, visit: (String, Int, ApxAttribute) -> Unit) {
        val input = DataInputStream(ByteArrayInputStream(bytes))
        val fileHeader = ByteArray(8)
        readFully(input, fileHeader)
        val fileType = readUShort(fileHeader, 0)
        if (fileType != 0x0003) {
            throw IllegalArgumentException("AndroidManifest.xml is not binary XML (chunk type=0x%04x)".format(fileType))
        }

        var strings: List<String> = emptyList()

        while (input.available() > 0) {
            val chunkHeader = ByteArray(8)
            readFully(input, chunkHeader)
            val chunkType = readUShort(chunkHeader, 0)
            val chunkSize = readUInt(chunkHeader, 4).toInt()
            require(chunkSize >= 8 && chunkSize - 8 <= input.available()) {
                "Android binary XML has an invalid chunk size ($chunkSize)"
            }
            when (chunkType) {
                CHUNK_STRING_POOL -> {
                    strings = parseStringPool(input, chunkSize)
                }
                CHUNK_START_ELEMENT -> {
                    val body = ByteArray(chunkSize - 8)
                    readFully(input, body)
                    // body layout: line(4) comment(4) ns(4) name(4) attrStart(2)
                    // attrSize(2) attrCount(2) idIndex(2) classIndex(2) styleIndex(2)
                    val nameIndex = readUInt(body, 12).toInt()
                    val attributeCount = readUShort(body, 20)
                    val element = strings.getOrNull(nameIndex).orEmpty()
                    val elementNamespaceIndex = readUInt(body, 8).toInt()
                    var index = 28
                    var attributeIndex = 0
                    while (attributeIndex < attributeCount) {
                        val attribute = readAttribute(strings, body, index) ?: break
                        visit(element, elementNamespaceIndex, attribute)
                        index += 20
                        attributeIndex += 1
                    }
                }
                else -> {
                    skipFully(input, chunkSize - 8)
                }
            }
        }

    }

    /**
     * Rewrites the uses-sdk minSdkVersion attribute in place. The patched
     * attribute is emitted the way aapt emits integral API levels: typed value
     * INT_DEC, raw string reference cleared. Fails closed when no decodable
     * minSdkVersion attribute exists. AXML carries no checksum, so no digest
     * fixup is required.
     */
    fun patchMinSdkVersion(bytes: ByteArray, newMinSdk: Int): ByteArray {
        require(newMinSdk in 1..0xFFFF) { "minSdkVersion out of the attribute value range: $newMinSdk" }
        val patched = bytes.copyOf()
        val strings = stringPoolFor(patched) ?: throw IllegalArgumentException(
            "AndroidManifest.xml has no string pool chunk; cannot locate the uses-sdk element",
        )
        var cursor = 8 // skip the binary XML file header
        while (cursor + 8 <= patched.size) {
            val chunkType = readUShort(patched, cursor)
            val chunkSize = readUInt(patched, cursor + 4).toInt()
            if (chunkSize < 8 || cursor + chunkSize > patched.size) {
                throw IllegalArgumentException("AndroidManifest.xml contains an undersized or oversized chunk (size=$chunkSize)")
            }
            val bodyStart = cursor + 8
            if (chunkType == CHUNK_START_ELEMENT) {
                val nameIndex = readUInt(patched, bodyStart + 12).toInt()
                if ((strings.getOrNull(nameIndex) ?: "") == "uses-sdk") {
                    val attributeCount = readUShort(patched, bodyStart + 20)
                    var attributeOffset = bodyStart + 28
                    var attributeIndex = 0
                    while (attributeIndex < attributeCount && attributeOffset + 20 <= patched.size) {
                        val attributeName = strings.getOrNull(readUInt(patched, attributeOffset + 4).toInt()) ?: "?"
                        if (attributeName == "minSdkVersion") {
                            // typedValue layout inside the attribute: ns(4) name(4)
                            // rawValue(4) size(2) res0(1) dataType(1) data(4).
                            writeUInt(patched, attributeOffset + 8, 0xFFFFFFFFL)
                            patched[attributeOffset + 14] = 0
                            patched[attributeOffset + 15] = VALUE_TYPE_INT_DEC.toByte()
                            writeUInt(patched, attributeOffset + 16, newMinSdk.toLong() and 0xFFFFFFFFL)
                            return patched
                        }
                        attributeOffset += 20
                        attributeIndex += 1
                    }
                    throw IllegalArgumentException(
                        "AndroidManifest.xml uses-sdk element has no minSdkVersion attribute to patch",
                    )
                }
            }
            cursor += chunkSize
        }
        throw IllegalArgumentException("AndroidManifest.xml has no uses-sdk element to patch")
    }

    /** Re-parses the leading string pool so attribute names can be resolved. */
    private fun stringPoolFor(bytes: ByteArray): List<String>? {
        val input = DataInputStream(ByteArrayInputStream(bytes))
        readFully(input, ByteArray(8))
        val chunkHeader = ByteArray(8)
        return try {
            readFully(input, chunkHeader)
            if (readUShort(chunkHeader, 0) != CHUNK_STRING_POOL) null else parseStringPool(input, readUInt(chunkHeader, 4).toInt())
        } catch (_: EOFException) {
            null
        }
    }

    private fun writeUInt(buffer: ByteArray, offset: Int, value: Long) {
        buffer[offset] = (value and 0xFF).toByte()
        buffer[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        buffer[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        buffer[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    private data class ApxAttribute(
        val name: String,
        val namespace: String?,
        val valueString: String?,
        val valueType: Int,
        val intValue: Int?,
    )

    private fun readAttribute(strings: List<String>, body: ByteArray, offset: Int): ApxAttribute? {
        if (offset + 20 > body.size) return null
        val nameIndex = readUInt(body, offset + 4).toInt()
        val rawValueIndex = readUInt(body, offset + 8).toInt()
        val dataType = body[offset + 15].toInt() and 0xFF
        val data = readUInt(body, offset + 16).toInt()
        val name = strings.getOrNull(nameIndex) ?: return null
        val valueString: String? = when {
            rawValueIndex != -1 -> strings.getOrNull(rawValueIndex)
            dataType == VALUE_TYPE_STRING -> strings.getOrNull(data)
            else -> null
        }
        val intValue: Int? = when (dataType) {
            VALUE_TYPE_INT_DEC, VALUE_TYPE_INT_HEX, VALUE_TYPE_BOOLEAN -> data
            else -> null
        }
        return ApxAttribute(
            name = name,
            namespace = strings.getOrNull(readUInt(body, offset).toInt()),
            valueString = valueString,
            valueType = dataType,
            intValue = intValue,
        )
    }

    private fun parseStringPool(input: DataInputStream, chunkSize: Int): List<String> {
        val body = ByteArray(chunkSize - 8)
        readFully(input, body)
        // body layout: stringCount(4) styleCount(4) flags(4) stringsStart(4) stylesStart(4)
        val stringCount = readUInt(body, 0).toInt()
        val flags = readUInt(body, 8).toInt()
        val stringsStart = readUInt(body, 12).toInt()
        val isUtf8 = flags and STRING_POOL_UTF8_FLAG != 0
        val strings = ArrayList<String>(stringCount.coerceAtMost(65_536))
        for (index in 0 until stringCount) {
            val offsetIndex = 20 + index * 4
            if (offsetIndex + 4 > body.size) break
            val stringOffset = readUInt(body, offsetIndex).toInt()
            // stringsStart is chunk-relative; body starts 8 bytes into the chunk.
            val absolute = stringsStart - 8 + stringOffset
            if (absolute < 0 || absolute >= body.size) {
                strings += ""
                continue
            }
            strings += if (isUtf8) {
                decodeUtf8String(body, absolute)
            } else {
                decodeUtf16String(body, absolute)
            }
        }
        return strings
    }

    private fun decodeUtf16String(body: ByteArray, start: Int): String {
        var cursor = start
        val length = decodeUtf16Length(body, cursor).let { (chars, next) -> cursor = next; chars }
        if (length < 0 || length > 65_536) return ""
        val byteLength = length * 2
        if (cursor + byteLength > body.size) return ""
        return String(body, cursor, byteLength, StandardCharsets.UTF_16LE)
    }

    private fun decodeUtf16Length(body: ByteArray, start: Int): Pair<Int, Int> {
        var cursor = start
        var unit = readUShort(body, cursor).toInt()
        cursor += 2
        if (unit and 0x8000 != 0) {
            val high = unit and 0x7FFF
            unit = readUShort(body, cursor).toInt()
            cursor += 2
            return (high shl 16) or unit to cursor
        }
        return unit to cursor
    }

    private fun decodeUtf8String(body: ByteArray, start: Int): String {
        var cursor = start
        // Character count (may be two units), then byte length, then bytes.
        var unit = body[cursor].toInt() and 0xFF
        cursor += 1
        if (unit and 0x80 != 0) {
            cursor += 1
        }
        unit = body[cursor].toInt() and 0xFF
        cursor += 1
        var byteLength = unit
        if (unit and 0x80 != 0) {
            val high = unit and 0x7F
            val low = body[cursor].toInt() and 0xFF
            cursor += 1
            byteLength = (high shl 8) or low
        }
        if (byteLength < 0 || cursor + byteLength > body.size) return ""
        return String(body, cursor, byteLength, StandardCharsets.UTF_8)
    }

    private fun readFully(input: DataInputStream, buffer: ByteArray) {
        var filled = 0
        while (filled < buffer.size) {
            val read = input.read(buffer, filled, buffer.size - filled)
            if (read < 0) throw EOFException("unexpected end of AndroidManifest.xml")
            filled += read
        }
    }

    private fun skipFully(input: DataInputStream, count: Int) {
        var remaining = count
        while (remaining > 0) {
            val skipped = input.skip(remaining.toLong())
            if (skipped <= 0) {
                if (input.read() < 0) throw EOFException("unexpected end of AndroidManifest.xml")
                remaining -= 1
            } else {
                remaining -= skipped.toInt()
            }
        }
    }

    private fun readUShort(buffer: ByteArray, offset: Int): Int =
        (buffer[offset].toInt() and 0xFF) or ((buffer[offset + 1].toInt() and 0xFF) shl 8)

    private fun readUInt(buffer: ByteArray, offset: Int): Long =
        (buffer[offset].toLong() and 0xFF) or
            ((buffer[offset + 1].toLong() and 0xFF) shl 8) or
            ((buffer[offset + 2].toLong() and 0xFF) shl 16) or
            ((buffer[offset + 3].toLong() and 0xFF) shl 24)
}
