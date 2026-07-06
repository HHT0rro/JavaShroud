package io.github.hht0rro.javashroud.transforms.protection

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal object NativeKernelShellPacker {
    const val PACKER_VERSION: Int = 3
    const val LOADER_MARKER: String = "JS_NATIVE_SHELL_LOADER_V1"
    const val MAX_STUB_MARKER: String = "JS_NATIVE_MAX_STUB_V1"
    const val MAX_PAYLOAD_MARKER: String = "JS_NATIVE_MAX_PAYLOAD_V1"
    const val MAX_PAYLOAD_CHUNK_SIZE: Int = 4096

    private const val maxCompressionCodecNone = 0
    private const val maxCompressionCodecZstd = 1

    private val blockMagic = byteArrayOf(0x4A, 0x53, 0x4B, 0x53, 0x48, 0x45, 0x4C, 0x31) // JSKSHEL1
    private val endMagic = byteArrayOf(0x4A, 0x53, 0x4B, 0x53, 0x45, 0x4E, 0x44, 0x31) // JSKSEND1
    private const val hmacLength = 32

    enum class Level(val id: Int) {
        OFF(0),
        STANDARD(1),
        MAX(2);

        companion object {
            fun parse(value: String): Level = when (value.lowercase()) {
                "off" -> OFF
                "standard" -> STANDARD
                "max" -> MAX
                else -> throw IllegalArgumentException("jni-microkernel-loader nativePackingLevel '$value' is not supported")
            }
        }
    }

    data class ShellInspection(
        val present: Boolean,
        val version: Int = 0,
        val level: Level = Level.OFF,
        val platform: String = "",
        val outputName: String = "",
        val originalSize: Int = 0,
        val encodedPayloadSize: Int = 0,
        val bogusSize: Int = 0,
        val macValid: Boolean = false,
    )

    data class MaxPayloadBundle(
        val headerBytes: ByteArray,
        val encodedPayload: ByteArray,
        val payloadMac: ByteArray,
        val sectionDigest: ByteArray,
        val bogusMetadataDigest: ByteArray,
        val bindingTag: ByteArray,
        val streamKey: ByteArray,
        val nativeMac: ByteArray,
        val nonce: ByteArray,
        val layoutProfile: Int,
        val dispatcherProfile: Int,
        val originalSize: Int,
        val storedPayloadSize: Int,
        val compressionCodec: Int,
        val chunkSize: Int,
        val chunkCount: Int,
        val chunkTags: ByteArray,
    )

    data class MaxPayloadInspection(
        val present: Boolean,
        val version: Int = 0,
        val platform: String = "",
        val outputName: String = "",
        val innerFileType: String = "",
        val originalSize: Int = 0,
        val storedPayloadSize: Int = 0,
        val encodedPayloadSize: Int = 0,
        val compressionCodec: Int = 0,
        val chunkSize: Int = 0,
        val chunkCount: Int = 0,
        val nonceSize: Int = 0,
        val layoutProfile: Int = 0,
        val dispatcherProfile: Int = 0,
        val bogusMetadataDigestValid: Boolean = false,
        val macValid: Boolean = false,
        val bindingTagValid: Boolean = false,
    )

    fun pack(
        bytes: ByteArray,
        platform: String,
        outputName: String,
        seed: Long,
        nativePackingLevel: String,
        keyMaterial: ByteArray,
    ): ByteArray = pack(bytes, platform, outputName, seed, Level.parse(nativePackingLevel), keyMaterial)

    fun pack(
        bytes: ByteArray,
        platform: String,
        outputName: String,
        seed: Long,
        level: Level,
        keyMaterial: ByteArray,
    ): ByteArray {
        if (level == Level.OFF) return bytes
        require(level == Level.STANDARD) { "nativePackingLevel=max must be emitted as a stub shell, not an overlay block" }
        require(bytes.isNotEmpty()) { "native shell packer requires non-empty native bytes" }
        val key = deriveShellKey(seed, level, platform, outputName, keyMaterial)
        return try {
            val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val encodedPayload = encodePayload(bytes, key, nonce, rounds = 1, reverse = false)
            val bogusBytes = bogusDecodeSurface(seed, key, nonce, level)
            val originalDigest = sha256(bytes)
            val header = ByteArrayOutputStream().apply {
                write(blockMagic)
                writeIntLe(PACKER_VERSION)
                writeIntLe(level.id)
                writeString(platform)
                writeString(outputName)
                writeIntLe(bytes.size)
                writeIntLe(encodedPayload.size)
                writeIntLe(bogusBytes.size)
                write(nonce)
                write(originalDigest)
                write(LOADER_MARKER.toByteArray(Charsets.US_ASCII))
                write(0)
                write(bogusBytes)
                write(encodedPayload)
            }.toByteArray()
            val mac = hmac(key, bytes + header)
            val block = ByteArrayOutputStream().apply {
                write(header)
                write(mac)
            }.toByteArray()
            ByteArrayOutputStream(bytes.size + block.size + 12).apply {
                write(bytes)
                write(block)
                writeIntLe(block.size)
                write(endMagic)
            }.toByteArray()
        } finally {
            Arrays.fill(key, 0)
        }
    }

    fun buildMaxPayloadBundle(
        bytes: ByteArray,
        platform: String,
        outputName: String,
        seed: Long,
        keyMaterial: ByteArray,
        bootstrapNativeIndexDigest: ByteArray,
    ): MaxPayloadBundle {
        require(bytes.isNotEmpty()) { "max native shell requires non-empty inner native bytes" }
        val key = deriveShellKey(seed, Level.MAX, platform, outputName, keyMaterial + bootstrapNativeIndexDigest)
        return try {
            val nonce = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val profileSeed = sha256(key + nonce + platform.toByteArray(Charsets.UTF_8))
            val layoutProfile = ((readLongPrefix(profileSeed) ushr 1) % 7L).toInt()
            val dispatcherProfile = ((readLongPrefix(sha256(nonce + key)) ushr 1) % 11L).toInt()
            val streamKey = sha256(key + nonce + "javashroud-native-shell-stream-key-v2".toByteArray(Charsets.US_ASCII))
            val compressed = Vbc4ZstdCodec.compress(bytes)
            val compressionCodec = if (compressed.size < bytes.size) maxCompressionCodecZstd else maxCompressionCodecNone
            val storedPayload = if (compressionCodec == maxCompressionCodecZstd) compressed else bytes
            val encoded = encodeMaxPayloadForStub(storedPayload, streamKey, nonce, layoutProfile, dispatcherProfile, MAX_PAYLOAD_CHUNK_SIZE)
            val sectionDigest = sha256(bytes)
            val bogusMetadataDigest = maxBogusMetadataDigest(seed, key, nonce, layoutProfile, dispatcherProfile, sectionDigest)
            val bindingTag = maxBindingTag(platform, outputName, bootstrapNativeIndexDigest, sectionDigest)
            val headerBytes = ByteArrayOutputStream().apply {
                write(MAX_PAYLOAD_MARKER.toByteArray(Charsets.US_ASCII))
                write(0)
                writeIntLe(PACKER_VERSION)
                writeIntLe(Level.MAX.id)
                writeString(platform)
                writeString(outputName)
                writeString(innerFileType(outputName))
                writeIntLe(bytes.size)
                writeIntLe(storedPayload.size)
                writeIntLe(encoded.encodedPayload.size)
                writeIntLe(compressionCodec)
                writeIntLe(encoded.chunkSize)
                writeIntLe(encoded.chunkCount)
                writeIntLe(nonce.size)
                writeIntLe(layoutProfile)
                writeIntLe(dispatcherProfile)
                write(nonce)
                write(sectionDigest)
                write(bogusMetadataDigest)
                write(bindingTag)
                writeIntLe(encoded.chunkTags.size)
                write(encoded.chunkTags)
            }.toByteArray()
            val payloadMac = hmac(key, headerBytes + encoded.encodedPayload + bootstrapNativeIndexDigest)
            val nativeMac = shellMac32(streamKey, headerBytes, encoded.encodedPayload, bindingTag)
            MaxPayloadBundle(
                headerBytes = headerBytes,
                encodedPayload = encoded.encodedPayload,
                payloadMac = payloadMac,
                sectionDigest = sectionDigest,
                bogusMetadataDigest = bogusMetadataDigest,
                bindingTag = bindingTag,
                streamKey = streamKey,
                nativeMac = nativeMac,
                nonce = nonce,
                layoutProfile = layoutProfile,
                dispatcherProfile = dispatcherProfile,
                originalSize = bytes.size,
                storedPayloadSize = storedPayload.size,
                compressionCodec = compressionCodec,
                chunkSize = encoded.chunkSize,
                chunkCount = encoded.chunkCount,
                chunkTags = encoded.chunkTags,
            )
        } finally {
            Arrays.fill(key, 0)
        }
    }

    fun inspectMaxPayloadBundle(
        headerBytes: ByteArray,
        encodedPayload: ByteArray,
        payloadMac: ByteArray,
        seed: Long,
        keyMaterial: ByteArray,
        bootstrapNativeIndexDigest: ByteArray,
    ): MaxPayloadInspection {
        val parsed = parseMaxPayloadHeader(headerBytes) ?: return MaxPayloadInspection(present = false)
        val key = deriveShellKey(seed, Level.MAX, parsed.platform, parsed.outputName, keyMaterial + bootstrapNativeIndexDigest)
        return try {
            val macValid = parsed.version == PACKER_VERSION &&
                parsed.level == Level.MAX &&
                parsed.originalSize > 0 &&
                parsed.storedPayloadSize > 0 &&
                parsed.encodedPayloadSize == encodedPayload.size &&
                parsed.compressionCodec in setOf(maxCompressionCodecNone, maxCompressionCodecZstd) &&
                parsed.chunkSize > 0 &&
                parsed.chunkCount == chunkCountFor(parsed.encodedPayloadSize, parsed.chunkSize) &&
                parsed.chunkTags.size == parsed.chunkCount * 4 &&
                parsed.nonce.size == parsed.nonceSize &&
                hmac(key, headerBytes + encodedPayload + bootstrapNativeIndexDigest).contentEquals(payloadMac)
            val bindingTagValid = maxBindingTag(parsed.platform, parsed.outputName, bootstrapNativeIndexDigest, parsed.sectionDigest)
                .contentEquals(parsed.bindingTag)
            val bogusMetadataDigestValid = maxBogusMetadataDigest(seed, key, parsed.nonce, parsed.layoutProfile, parsed.dispatcherProfile, parsed.sectionDigest)
                .contentEquals(parsed.bogusMetadataDigest)
            MaxPayloadInspection(
                present = true,
                version = parsed.version,
                platform = parsed.platform,
                outputName = parsed.outputName,
                innerFileType = parsed.innerFileType,
                originalSize = parsed.originalSize,
                storedPayloadSize = parsed.storedPayloadSize,
                encodedPayloadSize = parsed.encodedPayloadSize,
                compressionCodec = parsed.compressionCodec,
                chunkSize = parsed.chunkSize,
                chunkCount = parsed.chunkCount,
                nonceSize = parsed.nonceSize,
                layoutProfile = parsed.layoutProfile,
                dispatcherProfile = parsed.dispatcherProfile,
                bogusMetadataDigestValid = bogusMetadataDigestValid,
                macValid = macValid,
                bindingTagValid = bindingTagValid,
            )
        } finally {
            Arrays.fill(key, 0)
        }
    }

    fun renderMaxPayloadHeader(bundle: MaxPayloadBundle): String = buildString {
        appendLine("/* AUTO-GENERATED JavaShroud max native shell payload - DO NOT EDIT */")
        appendLine("#ifndef JS_SHELL_PAYLOAD_INC")
        appendLine("#define JS_SHELL_PAYLOAD_INC")
        appendLine("#define JS_NATIVE_MAX_STUB_MARKER \"$MAX_STUB_MARKER\"")
        appendLine("#define JS_NATIVE_MAX_PAYLOAD_MARKER \"$MAX_PAYLOAD_MARKER\"")
        appendLine("#define JS_SHELL_PROTOCOL_VERSION $PACKER_VERSION")
        appendLine("#define JS_SHELL_LAYOUT_PROFILE ${bundle.layoutProfile}")
        appendLine("#define JS_SHELL_DISPATCHER_PROFILE ${bundle.dispatcherProfile}")
        appendLine("#define JS_SHELL_ORIGINAL_PAYLOAD_SIZE ${bundle.originalSize}u")
        appendLine("#define JS_SHELL_STORED_PAYLOAD_SIZE ${bundle.storedPayloadSize}u")
        appendLine("#define JS_SHELL_COMPRESSION_CODEC ${bundle.compressionCodec}u")
        appendLine("#define JS_SHELL_CHUNK_SIZE ${bundle.chunkSize}u")
        appendLine("#define JS_SHELL_CHUNK_COUNT ${bundle.chunkCount}u")
        appendLine("static const unsigned char js_shell_payload_header[] = { ${bundle.headerBytes.toCByteArrayLiteral()} };")
        appendLine("static const unsigned char js_shell_payload_bytes[] = { ${bundle.encodedPayload.toCByteArrayLiteral()} };")
        appendLine("static const unsigned char js_shell_payload_mac[32] = { ${bundle.nativeMac.toCByteArrayLiteral()} };")
        appendLine("static const unsigned char js_shell_build_hmac[32] = { ${bundle.payloadMac.toCByteArrayLiteral()} };")
        appendLine("static const unsigned char js_shell_stream_key[32] = { ${bundle.streamKey.toCByteArrayLiteral()} };")
        appendLine("static const unsigned char js_shell_section_digest[32] = { ${bundle.sectionDigest.toCByteArrayLiteral()} };")
        appendLine("static const unsigned char js_shell_bogus_metadata_digest[32] = { ${bundle.bogusMetadataDigest.toCByteArrayLiteral()} };")
        appendLine("static const unsigned char js_shell_binding_tag[32] = { ${bundle.bindingTag.toCByteArrayLiteral()} };")
        appendLine("#define JS_SHELL_PAYLOAD_HEADER_SIZE ${bundle.headerBytes.size}")
        appendLine("#define JS_SHELL_PAYLOAD_SIZE ${bundle.encodedPayload.size}")
        appendLine("#endif")
    }

    fun inspect(bytes: ByteArray, seed: Long, keyMaterial: ByteArray): ShellInspection {
        val parsed = parseBlock(bytes)
        if (parsed == null) return ShellInspection(present = false)
        val key = deriveShellKey(seed, parsed.level, parsed.platform, parsed.outputName, keyMaterial)
        return try {
            val macValid = parsed.version == PACKER_VERSION &&
                parsed.level == Level.STANDARD &&
                parsed.originalSize == parsed.originalBytes.size &&
                sha256(parsed.originalBytes).contentEquals(parsed.originalDigest) &&
                hmac(key, parsed.originalBytes + parsed.macCovered).contentEquals(parsed.mac)
            ShellInspection(
                present = true,
                version = parsed.version,
                level = parsed.level,
                platform = parsed.platform,
                outputName = parsed.outputName,
                originalSize = parsed.originalSize,
                encodedPayloadSize = parsed.encodedPayloadSize,
                bogusSize = parsed.bogusSize,
                macValid = macValid,
            )
        } finally {
            Arrays.fill(key, 0)
        }
    }

    fun isShellPacked(bytes: ByteArray): Boolean = parseBlock(bytes) != null

    private data class ParsedBlock(
        val originalBytes: ByteArray,
        val macCovered: ByteArray,
        val mac: ByteArray,
        val version: Int,
        val level: Level,
        val platform: String,
        val outputName: String,
        val originalSize: Int,
        val encodedPayloadSize: Int,
        val bogusSize: Int,
        val originalDigest: ByteArray,
    )

    private data class ParsedMaxPayloadHeader(
        val version: Int,
        val level: Level,
        val platform: String,
        val outputName: String,
        val innerFileType: String,
        val originalSize: Int,
        val storedPayloadSize: Int,
        val encodedPayloadSize: Int,
        val compressionCodec: Int,
        val chunkSize: Int,
        val chunkCount: Int,
        val nonceSize: Int,
        val layoutProfile: Int,
        val dispatcherProfile: Int,
        val nonce: ByteArray,
        val sectionDigest: ByteArray,
        val bogusMetadataDigest: ByteArray,
        val bindingTag: ByteArray,
        val chunkTags: ByteArray,
    )

    private fun parseBlock(bytes: ByteArray): ParsedBlock? {
        if (bytes.size < 12) return null
        if (!bytes.copyOfRange(bytes.size - 8, bytes.size).contentEquals(endMagic)) return null
        val blockSize = readIntLe(bytes, bytes.size - 12)
        if (blockSize <= hmacLength + blockMagic.size || blockSize > bytes.size - 12) return null
        val blockOffset = bytes.size - 12 - blockSize
        if (blockOffset < 0) return null
        val block = bytes.copyOfRange(blockOffset, blockOffset + blockSize)
        if (!block.copyOfRange(0, blockMagic.size).contentEquals(blockMagic)) return null
        val macCovered = block.copyOfRange(0, block.size - hmacLength)
        return try {
            val reader = BlockReader(macCovered)
            val magic = reader.readBytes(blockMagic.size)
            if (!magic.contentEquals(blockMagic)) return null
            val version = reader.readIntLe()
            val levelId = reader.readIntLe()
            val level = Level.entries.firstOrNull { it.id == levelId } ?: return null
            if (level != Level.STANDARD) return null
            val platform = reader.readString()
            val outputName = reader.readString()
            val originalSize = reader.readIntLe()
            val encodedPayloadSize = reader.readIntLe()
            val bogusSize = reader.readIntLe()
            reader.readBytes(16)
            val originalDigest = reader.readBytes(32)
            val marker = reader.readCString()
            if (marker != LOADER_MARKER) return null
            reader.readBytes(bogusSize)
            reader.readBytes(encodedPayloadSize)
            if (!reader.exhausted()) return null
            ParsedBlock(
                originalBytes = bytes.copyOfRange(0, blockOffset),
                macCovered = macCovered,
                mac = block.copyOfRange(block.size - hmacLength, block.size),
                version = version,
                level = level,
                platform = platform,
                outputName = outputName,
                originalSize = originalSize,
                encodedPayloadSize = encodedPayloadSize,
                bogusSize = bogusSize,
                originalDigest = originalDigest,
            )
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun parseMaxPayloadHeader(headerBytes: ByteArray): ParsedMaxPayloadHeader? {
        return try {
        val reader = BlockReader(headerBytes)
        val marker = reader.readCString()
        if (marker != MAX_PAYLOAD_MARKER) return null
        val version = reader.readIntLe()
        val levelId = reader.readIntLe()
        val level = Level.entries.firstOrNull { it.id == levelId } ?: return null
        val platform = reader.readString()
        val outputName = reader.readString()
        val innerFileType = reader.readString()
        val originalSize = reader.readIntLe()
        val storedPayloadSize = reader.readIntLe()
        val encodedPayloadSize = reader.readIntLe()
        val compressionCodec = reader.readIntLe()
        val chunkSize = reader.readIntLe()
        val chunkCount = reader.readIntLe()
        val nonceSize = reader.readIntLe()
        val layoutProfile = reader.readIntLe()
        val dispatcherProfile = reader.readIntLe()
        val nonce = reader.readBytes(nonceSize)
        val sectionDigest = reader.readBytes(32)
        val bogusMetadataDigest = reader.readBytes(32)
        val bindingTag = reader.readBytes(32)
        val chunkTagsSize = reader.readIntLe()
        val chunkTags = reader.readBytes(chunkTagsSize)
        if (!reader.exhausted()) return null
        ParsedMaxPayloadHeader(
            version = version,
            level = level,
            platform = platform,
            outputName = outputName,
            innerFileType = innerFileType,
            originalSize = originalSize,
            storedPayloadSize = storedPayloadSize,
            encodedPayloadSize = encodedPayloadSize,
            compressionCodec = compressionCodec,
            chunkSize = chunkSize,
            chunkCount = chunkCount,
            nonceSize = nonceSize,
            layoutProfile = layoutProfile,
            dispatcherProfile = dispatcherProfile,
            nonce = nonce,
            sectionDigest = sectionDigest,
            bogusMetadataDigest = bogusMetadataDigest,
            bindingTag = bindingTag,
            chunkTags = chunkTags,
        )
    } catch (_: IllegalArgumentException) {
        null
    }

    }

    private class BlockReader(private val bytes: ByteArray) {
        private var offset = 0
        fun readIntLe(): Int {
            if (offset + 4 > bytes.size) throw IllegalArgumentException("truncated shell block")
            val value = readIntLe(bytes, offset)
            offset += 4
            return value
        }
        fun readBytes(length: Int): ByteArray {
            if (length < 0 || offset + length > bytes.size) throw IllegalArgumentException("truncated shell block")
            return bytes.copyOfRange(offset, offset + length).also { offset += length }
        }
        fun readString(): String {
            val length = readIntLe()
            return String(readBytes(length), Charsets.UTF_8)
        }
        fun readCString(): String {
            val start = offset
            while (offset < bytes.size && bytes[offset].toInt() != 0) offset++
            if (offset >= bytes.size) throw IllegalArgumentException("unterminated shell marker")
            return String(bytes.copyOfRange(start, offset), Charsets.US_ASCII).also { offset++ }
        }
        fun exhausted(): Boolean = offset == bytes.size
    }

    fun decodeMaxPayloadForTest(bundle: MaxPayloadBundle): ByteArray? {
        val stored = decodeMaxPayloadForStub(
            bytes = bundle.encodedPayload,
            streamKey = bundle.streamKey,
            nonce = bundle.nonce,
            layoutProfile = bundle.layoutProfile,
            dispatcherProfile = bundle.dispatcherProfile,
            chunkSize = bundle.chunkSize,
            expectedChunkTags = bundle.chunkTags,
        ) ?: return null
        return when (bundle.compressionCodec) {
            maxCompressionCodecNone -> stored.takeIf { it.size == bundle.originalSize }
            maxCompressionCodecZstd -> Vbc4ZstdCodec.decompress(stored, bundle.originalSize)
            else -> null
        }
    }

    private data class MaxEncodedPayload(
        val encodedPayload: ByteArray,
        val chunkSize: Int,
        val chunkCount: Int,
        val chunkTags: ByteArray,
    )

    private fun encodeMaxPayloadForStub(bytes: ByteArray, streamKey: ByteArray, nonce: ByteArray, layoutProfile: Int, dispatcherProfile: Int, chunkSize: Int): MaxEncodedPayload {
        require(chunkSize > 0) { "max payload chunk size must be positive" }
        val out = bytes.copyOf()
        val chunkCount = chunkCountFor(out.size, chunkSize)
        val tags = ByteArray(chunkCount * 4)
        for (chunkIndex in 0 until chunkCount) {
            val offset = chunkIndex * chunkSize
            val length = minOf(chunkSize, out.size - offset)
            encodeMaxPayloadChunk(out, offset, length, streamKey, nonce, layoutProfile, dispatcherProfile, chunkIndex)
            val tag = shellChunkTag32(streamKey, nonce, layoutProfile, dispatcherProfile, chunkIndex, out, offset, length)
            writeIntLe(tags, chunkIndex * 4, tag)
        }
        return MaxEncodedPayload(out, chunkSize, chunkCount, tags)
    }

    private fun decodeMaxPayloadForStub(bytes: ByteArray, streamKey: ByteArray, nonce: ByteArray, layoutProfile: Int, dispatcherProfile: Int, chunkSize: Int, expectedChunkTags: ByteArray): ByteArray? {
        if (chunkSize <= 0) return null
        val out = bytes.copyOf()
        val chunkCount = chunkCountFor(out.size, chunkSize)
        if (expectedChunkTags.size != chunkCount * 4) return null
        for (chunkIndex in 0 until chunkCount) {
            val offset = chunkIndex * chunkSize
            val length = minOf(chunkSize, out.size - offset)
            val tag = shellChunkTag32(streamKey, nonce, layoutProfile, dispatcherProfile, chunkIndex, out, offset, length)
            if (tag != readIntLe(expectedChunkTags, chunkIndex * 4)) return null
            encodeMaxPayloadChunk(out, offset, length, streamKey, nonce, layoutProfile, dispatcherProfile, chunkIndex)
        }
        return out
    }

    private fun encodeMaxPayloadChunk(bytes: ByteArray, offset: Int, length: Int, streamKey: ByteArray, nonce: ByteArray, layoutProfile: Int, dispatcherProfile: Int, chunkIndex: Int) {
        var state = shellSeed32(streamKey, nonce, layoutProfile, dispatcherProfile) xor shellMix32(chunkIndex * 0x45D9F3B)
        for (index in 0 until length) {
            state = shellMix32(state + index + chunkIndex * 0x119DE1F3 + 0x9E3779B9u.toInt())
            bytes[offset + index] = (bytes[offset + index].toInt() xor (state and 0xFF)).toByte()
        }
    }

    private fun shellChunkTag32(key: ByteArray, nonce: ByteArray, layoutProfile: Int, dispatcherProfile: Int, chunkIndex: Int, bytes: ByteArray, offset: Int, length: Int): Int {
        var state = shellSeed32(key, nonce, layoutProfile, dispatcherProfile) xor shellMix32(chunkIndex xor length)
        for (index in 0 until length) {
            val value = (bytes[offset + index].toInt() and 0xFF) + index * 17 + chunkIndex * 131
            state = shellMix32(state xor value)
        }
        return shellMix32(state xor length xor (chunkIndex * 0x9E3779B9u.toInt()))
    }

    private fun chunkCountFor(size: Int, chunkSize: Int): Int = if (size == 0) 0 else (size + chunkSize - 1) / chunkSize

    private fun shellMac32(key: ByteArray, header: ByteArray, payload: ByteArray, bindingTag: ByteArray): ByteArray {
        val state = intArrayOf(
            0x4A534D32, 0x9E3779B9u.toInt(), 0x243F6A88, 0xB7E15162u.toInt(),
            0xDEADBEEFu.toInt(), 0x8BADF00Du.toInt(), 0xC001D00Du.toInt(), 0x13579BDF,
        )
        val parts = listOf(key, header, payload, bindingTag)
        for ((partIndex, part) in parts.withIndex()) {
            for (index in part.indices) {
                val v = (part[index].toInt() and 0xFF) + index * 17 + partIndex * 131
                val slot = (index + partIndex) and 7
                state[slot] = shellMix32(state[slot] xor v xor state[(index + 3) and 7])
            }
        }
        val total = key.size + header.size + payload.size + bindingTag.size
        val out = ByteArray(32)
        for (round in 0 until 8) {
            state[round] = shellMix32(state[round] xor state[(round + 1) and 7] xor total)
            out[round * 4] = (state[round] and 0xFF).toByte()
            out[round * 4 + 1] = ((state[round] ushr 8) and 0xFF).toByte()
            out[round * 4 + 2] = ((state[round] ushr 16) and 0xFF).toByte()
            out[round * 4 + 3] = ((state[round] ushr 24) and 0xFF).toByte()
        }
        return out
    }

    private fun shellSeed32(key: ByteArray, nonce: ByteArray, layoutProfile: Int, dispatcherProfile: Int): Int {
        var state = 0x6D617870 xor (layoutProfile * 0x45D9F3B) xor (dispatcherProfile * 0x119DE1F3)
        for (index in key.indices) state = shellMix32(state xor (key[index].toInt() and 0xFF) xor (index * 131))
        for (index in 0 until 16) state = shellMix32(state xor (nonce[index].toInt() and 0xFF) xor (index * 257))
        return state
    }

    private fun shellMix32(input: Int): Int {
        var x = input
        x = x xor (x ushr 16)
        x *= 0x7FEB352D
        x = x xor (x ushr 15)
        x *= 0x846CA68Bu.toInt()
        x = x xor (x ushr 16)
        return x
    }
    private fun encodePayload(bytes: ByteArray, key: ByteArray, nonce: ByteArray, rounds: Int, reverse: Boolean): ByteArray {
        val out = bytes.copyOf()
        repeat(rounds) { round -> xorStream(out, key, nonce, round) }
        if (reverse) out.reverse()
        return out
    }

    private fun bogusDecodeSurface(seed: Long, key: ByteArray, nonce: ByteArray, level: Level): ByteArray {
        val length = if (level == Level.MAX) 96 else 32
        val out = ByteArray(length)
        var state = seed xor readLongPrefix(sha256(key + nonce))
        for (index in out.indices) {
            state = state xor (state shl 13)
            state = state xor (state ushr 7)
            state = state xor (state shl 17)
            out[index] = (state.toInt() xor index xor level.id).toByte()
        }
        return out
    }

    private fun xorStream(bytes: ByteArray, key: ByteArray, nonce: ByteArray, round: Int) {
        var offset = 0
        var counter = 0
        while (offset < bytes.size) {
            val digest = MessageDigest.getInstance("SHA-256").apply {
                update("javashroud-native-shell-stream-v2".toByteArray(Charsets.US_ASCII))
                update(key)
                update(nonce)
                updateInt(round)
                updateInt(counter++)
            }.digest()
            for (value in digest) {
                if (offset >= bytes.size) break
                bytes[offset] = (bytes[offset].toInt() xor (value.toInt() and 0xFF)).toByte()
                offset++
            }
        }
    }

    private fun deriveShellKey(seed: Long, level: Level, platform: String, outputName: String, keyMaterial: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").apply {
            update("javashroud-native-shell-key-v2".toByteArray(Charsets.US_ASCII))
            updateLong(seed)
            updateInt(level.id)
            update(platform.toByteArray(Charsets.UTF_8))
            update(0)
            update(outputName.toByteArray(Charsets.UTF_8))
            update(0)
            update(keyMaterial)
        }.digest()

    private fun maxBindingTag(platform: String, outputName: String, bootstrapNativeIndexDigest: ByteArray, sectionDigest: ByteArray): ByteArray =
        sha256(
            MAX_STUB_MARKER.toByteArray(Charsets.US_ASCII) +
                MAX_PAYLOAD_MARKER.toByteArray(Charsets.US_ASCII) +
                platform.toByteArray(Charsets.UTF_8) + byteArrayOf(0) +
                outputName.toByteArray(Charsets.UTF_8) + byteArrayOf(0) +
                bootstrapNativeIndexDigest + sectionDigest,
        )

    private fun maxBogusMetadataDigest(seed: Long, key: ByteArray, nonce: ByteArray, layoutProfile: Int, dispatcherProfile: Int, sectionDigest: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").apply {
            update("javashroud-native-max-bogus-section-metadata-v1".toByteArray(Charsets.US_ASCII))
            updateLong(seed)
            update(key)
            update(nonce)
            updateInt(layoutProfile)
            updateInt(dispatcherProfile)
            update(sectionDigest)
        }.digest()

    private fun innerFileType(outputName: String): String = when {
        outputName.endsWith(".dll", ignoreCase = true) -> "pe64-dll"
        outputName.endsWith(".so", ignoreCase = true) -> "elf64-so"
        outputName.endsWith(".dylib", ignoreCase = true) -> "macho-dylib"
        else -> "native-dynamic-library"
    }

    private fun hmac(key: ByteArray, bytes: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        doFinal(bytes)
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun readLongPrefix(bytes: ByteArray): Long = ByteBuffer.wrap(bytes.copyOfRange(0, 8)).order(ByteOrder.BIG_ENDIAN).long

    private fun ByteArrayOutputStream.writeIntLe(value: Int) {
        write(value and 0xFF)
        write((value ushr 8) and 0xFF)
        write((value ushr 16) and 0xFF)
        write((value ushr 24) and 0xFF)
    }

    private fun ByteArrayOutputStream.writeString(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        writeIntLe(bytes.size)
        write(bytes)
    }

    private fun readIntLe(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)

    private fun writeIntLe(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xFF).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    private fun MessageDigest.updateInt(value: Int) {
        update(((value ushr 24) and 0xFF).toByte())
        update(((value ushr 16) and 0xFF).toByte())
        update(((value ushr 8) and 0xFF).toByte())
        update((value and 0xFF).toByte())
    }

    private fun MessageDigest.updateLong(value: Long) {
        for (shift in 56 downTo 0 step 8) update(((value ushr shift) and 0xFF).toByte())
    }
}
