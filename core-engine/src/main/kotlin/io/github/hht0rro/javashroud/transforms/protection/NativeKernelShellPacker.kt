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
    const val PACKER_VERSION: Int = 6
    const val LOADER_MARKER: String = "JS_NATIVE_SHELL_LOADER_V1"
    const val MAX_STUB_MARKER: String = "AKEN_NATIVE_SHELL_STUB_V4"
    const val MAX_PAYLOAD_MARKER: String = "AKEN_NATIVE_SHELL_PAYLOAD_V4"
    const val MAX_PAYLOAD_CHUNK_SIZE: Int = 2048

    private const val maxCompressionCodecNone = 0
    private const val maxCompressionCodecZstd = 1
    private const val akenBindingLaneCount = 4
    private const val akenBindingLaneSize = 8
    private val akenNativeChunkSizes = intArrayOf(1024, 1536, 2048, 3072)
    private const val akenStreamDomain = "javashroud-aken-v4-native-shell-stream-v1"
    private const val akenProfileDomain = "javashroud-aken-v4-native-shell-profiles-v1"
    private const val akenChunkAesDomain = "javashroud-aken-v4-native-shell-chunk-aes-v1"
    private const val akenChunkHmacDomain = "javashroud-aken-v4-native-shell-chunk-hmac-v1"
    private const val akenChunkIvDomain = "javashroud-aken-v4-native-shell-chunk-iv-v1"
    private const val akenInnerDigestDomain = "javashroud-aken-v4-native-shell-inner-digest-v1"
    private const val akenPayloadCommitmentDomain = "javashroud-aken-v4-native-shell-payload-commitment-v1"

    /**
     * These symbols remain only so the still-unmigrated VBC4 legacy callers
     * compile. AKEN v4 MAX/MAX_HARDENING never reads a provider, environment,
     * file, hexadecimal secret, sidecar, or boot envelope through this object.
     */
    @Deprecated("AKEN v4 removes boot-secret delivery")
    const val BOOT_SECRET_ENV: String = "JAVASHROUD_BOOT_SECRET_V1"
    @Deprecated("AKEN v4 removes boot-secret delivery")
    const val BOOT_SECRET_FILE_ENV: String = "JAVASHROUD_BOOT_SECRET_FILE_V1"
    @Deprecated("AKEN v4 removes boot-secret delivery")
    @Volatile internal var buildBootSecretProvider: (() -> ByteArray?)? = null

    private val blockMagic = byteArrayOf(0x4A, 0x53, 0x4B, 0x53, 0x48, 0x45, 0x4C, 0x31) // JSKSHEL1
    private val endMagic = byteArrayOf(0x4A, 0x53, 0x4B, 0x53, 0x45, 0x4E, 0x44, 0x31) // JSKSEND1
    private const val hmacLength = 32

    enum class Level(val id: Int) {
        OFF(0),
        STANDARD(1),
        MAX(2),
        MAX_HARDENING(3);

        val usesStubShell: Boolean
            get() = this == MAX || this == MAX_HARDENING

        val configValue: String
            get() = name.lowercase().replace('_', '-')

        companion object {
            fun parse(value: String): Level = when (value.lowercase()) {
                "off" -> OFF
                "standard" -> STANDARD
                "max" -> MAX
                "max-hardening" -> MAX_HARDENING
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

    /**
     * Build-only carrier for an AKEN v4 native payload. [bindingSalt] is public
     * binding material, emitted only as shuffled eight-byte C lanes; it is not a
     * Boot KEK, root key, sidecar value, or runtime-delivered secret.
     */
    data class MaxPayloadBundle(
        val level: Level,
        val headerBytes: ByteArray,
        val encodedPayload: ByteArray,
        val payloadCommitment: ByteArray,
        val artifactBindingCommitment: ByteArray,
        val bindingSalt: ByteArray,
        val bindingLaneOrder: IntArray,
        val sectionDigestHmac: ByteArray,
        val bindingTag: ByteArray,
        val streamKey: ByteArray,
        val nonce: ByteArray,
        val layoutProfile: Int,
        val dispatcherProfile: Int,
        val originalSize: Int,
        val storedPayloadSize: Int,
        val compressionCodec: Int,
        val chunkSize: Int,
        val chunkCount: Int,
        val chunkTags: ByteArray,
    ) {
        /** Compatibility name for tests that formerly described this as a MAC. */
        val payloadMac: ByteArray
            get() = payloadCommitment

        internal fun wipeSensitive() {
            Arrays.fill(headerBytes, 0)
            Arrays.fill(encodedPayload, 0)
            Arrays.fill(payloadCommitment, 0)
            Arrays.fill(artifactBindingCommitment, 0)
            Arrays.fill(bindingSalt, 0)
            Arrays.fill(streamKey, 0)
            Arrays.fill(sectionDigestHmac, 0)
            Arrays.fill(bindingTag, 0)
            Arrays.fill(nonce, 0)
            Arrays.fill(chunkTags, 0)
            Arrays.fill(bindingLaneOrder, 0)
        }
    }

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

    /**
     * Builds a self-contained AKEN v4 shell payload. The binding salt and
     * commitment are deliberately public artifact-binding material: the static
     * hardening comes from per-build graph/layout reconstruction cost, not from
     * an external or absent cryptographic secret.
     */
    fun buildMaxPayloadBundle(
        bytes: ByteArray,
        platform: String,
        outputName: String,
        seed: Long,
        bootstrapNativeIndexDigest: ByteArray,
        level: Level = Level.MAX,
    ): MaxPayloadBundle {
        require(bytes.isNotEmpty()) { "AKEN v4 native shell requires non-empty inner native bytes" }
        require(bootstrapNativeIndexDigest.size == 32) { "AKEN v4 native payload binding digest must be exactly 32 bytes" }
        require(level.usesStubShell) { "AKEN v4 native stub shell requires max or max-hardening" }
        val temporaryBuffers = mutableListOf<ByteArray>()
        val outputBuffers = mutableListOf<ByteArray>()
        fun temporary(value: ByteArray): ByteArray = value.also { temporaryBuffers += it }
        fun output(value: ByteArray): ByteArray = value.also { outputBuffers += it }
        var completed = false
        return try {
            val bindingSalt = output(ByteArray(32).also { SecureRandom().nextBytes(it) })
            val bindingLaneOrder = akenBindingLaneOrder()
            val nonce = output(ByteArray(16).also { SecureRandom().nextBytes(it) })
            val bindingTag = output(akenPayloadBindingTag(platform, outputName, seed, level, bootstrapNativeIndexDigest, bindingSalt))
            val profileSeed = temporary(shellKdf(bindingSalt, akenProfileDomain, nonce, bindingTag))
            val layoutProfile = ((readLongPrefix(profileSeed) ushr 1) % 7L).toInt()
            val dispatcherSlice = temporary(profileSeed.copyOfRange(8, 16))
            val dispatcherProfile = ((readLongPrefix(dispatcherSlice) ushr 1) % 11L).toInt()
            val chunkSize = akenNativeChunkSizes[((profileSeed[16].toInt() and 0xFF) % akenNativeChunkSizes.size)]
            val compressed = Vbc4ZstdCodec.compress(bytes)
            if (compressed !== bytes) temporaryBuffers += compressed
            val compressionCodec = if (compressed.size < bytes.size) maxCompressionCodecZstd else maxCompressionCodecNone
            val storedPayload = if (compressionCodec == maxCompressionCodecZstd) compressed else bytes
            val streamKey = output(shellKdf(bindingSalt, akenStreamDomain, nonce, bindingTag))
            val encoded = encodeMaxPayloadForStub(storedPayload, streamKey, nonce, bindingTag, chunkSize)
            output(encoded.encodedPayload)
            output(encoded.chunkTags)
            val innerDigestMaterial = temporary(akenInnerDigestDomain.toByteArray(Charsets.US_ASCII) + bytes)
            val sectionDigestHmac = output(hmac(streamKey, innerDigestMaterial))
            val metadata = temporary(ByteArrayOutputStream().apply {
                writeString(platform)
                writeString(outputName)
                writeString(innerFileType(outputName))
                writeIntLe(bytes.size)
                writeIntLe(storedPayload.size)
                writeIntLe(encoded.encodedPayload.size)
                writeIntLe(compressionCodec)
                writeIntLe(encoded.chunkSize)
                writeIntLe(encoded.chunkCount)
                writeIntLe(layoutProfile)
                writeIntLe(dispatcherProfile)
                write(sectionDigestHmac)
                write(bindingTag)
                writeIntLe(encoded.chunkTags.size)
                write(encoded.chunkTags)
            }.toByteArray())
            val headerBytes = output(ByteArrayOutputStream().apply {
                write(MAX_PAYLOAD_MARKER.toByteArray(Charsets.US_ASCII))
                write(0)
                writeIntLe(PACKER_VERSION)
                writeIntLe(level.id)
                writeIntLe(nonce.size)
                write(nonce)
                writeIntLe(metadata.size)
                write(metadata)
            }.toByteArray())
            val payloadCommitment = output(akenPayloadCommitment(bindingSalt, headerBytes, encoded.encodedPayload))
            val artifactBindingCommitment = output(payloadCommitment.copyOf())
            MaxPayloadBundle(
                level = level,
                headerBytes = headerBytes,
                encodedPayload = encoded.encodedPayload,
                payloadCommitment = payloadCommitment,
                artifactBindingCommitment = artifactBindingCommitment,
                bindingSalt = bindingSalt,
                bindingLaneOrder = bindingLaneOrder,
                sectionDigestHmac = sectionDigestHmac,
                bindingTag = bindingTag,
                streamKey = streamKey,
                nonce = nonce,
                layoutProfile = layoutProfile,
                dispatcherProfile = dispatcherProfile,
                originalSize = bytes.size,
                storedPayloadSize = storedPayload.size,
                compressionCodec = compressionCodec,
                chunkSize = encoded.chunkSize,
                chunkCount = encoded.chunkCount,
                chunkTags = encoded.chunkTags,
            ).also { completed = true }
        } finally {
            temporaryBuffers.forEach { Arrays.fill(it, 0) }
            if (!completed) outputBuffers.forEach { Arrays.fill(it, 0) }
        }
    }

    fun inspectMaxPayloadBundle(
        headerBytes: ByteArray,
        encodedPayload: ByteArray,
        payloadCommitment: ByteArray,
        bindingSalt: ByteArray,
    ): MaxPayloadInspection {
        val parsed = parseMaxPayloadHeader(headerBytes, bindingSalt) ?: return MaxPayloadInspection(present = false)
        var stored: ByteArray? = null
        var inner: ByteArray? = null
        return try {
            val actualCommitment = akenPayloadCommitment(bindingSalt, headerBytes, encodedPayload)
            val commitmentValid = parsed.version == PACKER_VERSION && parsed.level.usesStubShell &&
                parsed.originalSize > 0 && parsed.storedPayloadSize > 0 && parsed.encodedPayloadSize == encodedPayload.size &&
                parsed.compressionCodec in setOf(maxCompressionCodecNone, maxCompressionCodecZstd) && parsed.chunkSize > 0 &&
                parsed.chunkCount == chunkCountFor(parsed.encodedPayloadSize, parsed.chunkSize) && parsed.chunkTags.size == parsed.chunkCount * 32 &&
                payloadCommitment.size == 32 && MessageDigest.isEqual(actualCommitment, payloadCommitment)
            Arrays.fill(actualCommitment, 0)
            if (commitmentValid) {
                stored = decodeMaxPayloadForStub(encodedPayload, parsed.streamKey, parsed.nonce, parsed.bindingTag, parsed.chunkSize, parsed.chunkTags)
                inner = when (parsed.compressionCodec) {
                    maxCompressionCodecNone -> stored?.takeIf { it.size == parsed.originalSize }
                    maxCompressionCodecZstd -> stored?.let { Vbc4ZstdCodec.decompress(it, parsed.originalSize) }
                    else -> null
                }
            }
            val digestValid = inner?.let {
                val material = akenInnerDigestDomain.toByteArray(Charsets.US_ASCII) + it
                val digest = hmac(parsed.streamKey, material)
                val valid = MessageDigest.isEqual(digest, parsed.sectionDigestHmac)
                Arrays.fill(material, 0)
                Arrays.fill(digest, 0)
                valid
            } ?: false
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
                nonceSize = parsed.nonce.size,
                layoutProfile = parsed.layoutProfile,
                dispatcherProfile = parsed.dispatcherProfile,
                macValid = commitmentValid,
                bindingTagValid = commitmentValid && digestValid,
            )
        } finally {
            stored?.fill(0)
            if (inner !== stored) inner?.fill(0)
            parsed.wipeSensitive()
        }
    }

    fun renderMaxPayloadHeader(bundle: MaxPayloadBundle): String = buildString {
        require(bundle.bindingSalt.size == 32) { "AKEN v4 binding salt must be exactly 32 bytes" }
        require(bundle.bindingLaneOrder.size == akenBindingLaneCount && bundle.bindingLaneOrder.toSet().size == akenBindingLaneCount) {
            "AKEN v4 binding-lane order must be a permutation"
        }
        appendLine("/* AUTO-GENERATED JavaShroud AKEN v4 native shell payload - DO NOT EDIT */")
        appendLine("#ifndef JS_SHELL_PAYLOAD_INC")
        appendLine("#define JS_SHELL_PAYLOAD_INC")
        appendLine("#define JS_NATIVE_MAX_STUB_MARKER \"$MAX_STUB_MARKER\"")
        appendLine("#define JS_NATIVE_MAX_PAYLOAD_MARKER \"$MAX_PAYLOAD_MARKER\"")
        appendLine("#define JS_SHELL_PROTOCOL_VERSION $PACKER_VERSION")
        appendLine("#define JS_SHELL_PROTOCOL_LEVEL ${bundle.level.id}u")
        appendLine("#define JS_SHELL_AKEN_BINDING_LANE_COUNT ${akenBindingLaneCount}u")
        appendLine("#define JS_SHELL_AKEN_BINDING_LANE_SIZE ${akenBindingLaneSize}u")
        appendLine("static const unsigned char js_shell_payload_header[] = { ${HexEncodingSupport.toCByteArrayLiteral(bundle.headerBytes)} };")
        appendLine("static const unsigned char js_shell_payload_bytes[] = { ${HexEncodingSupport.toCByteArrayLiteral(bundle.encodedPayload)} };")
        for (physicalLane in 0 until akenBindingLaneCount) {
            val logicalLane = bundle.bindingLaneOrder[physicalLane]
            require(logicalLane in 0 until akenBindingLaneCount) { "AKEN v4 binding lane is out of range" }
            val offset = logicalLane * akenBindingLaneSize
            val lane = bundle.bindingSalt.copyOfRange(offset, offset + akenBindingLaneSize)
            try {
                appendLine("static const unsigned char js_shell_aken_binding_lane_$physicalLane[$akenBindingLaneSize] = { ${HexEncodingSupport.toCByteArrayLiteral(lane)} };")
            } finally {
                Arrays.fill(lane, 0)
            }
        }
        appendLine("static const unsigned char js_shell_aken_binding_lane_order[$akenBindingLaneCount] = { ${bundle.bindingLaneOrder.joinToString(", ") { "${it}u" }} };")
        appendLine("static const unsigned char js_shell_aken_payload_commitment[32] = { ${HexEncodingSupport.toCByteArrayLiteral(bundle.payloadCommitment)} };")
        appendLine("#define JS_SHELL_PAYLOAD_HEADER_SIZE ${bundle.headerBytes.size}u")
        appendLine("#define JS_SHELL_PAYLOAD_SIZE ${bundle.encodedPayload.size}u")
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
        val layoutProfile: Int,
        val dispatcherProfile: Int,
        val nonce: ByteArray,
        val sectionDigestHmac: ByteArray,
        val bindingTag: ByteArray,
        val chunkTags: ByteArray,
        val streamKey: ByteArray,
    ) {
        fun wipeSensitive() {
            Arrays.fill(nonce, 0)
            Arrays.fill(sectionDigestHmac, 0)
            Arrays.fill(bindingTag, 0)
            Arrays.fill(chunkTags, 0)
            Arrays.fill(streamKey, 0)
        }
    }

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

    private fun parseMaxPayloadHeader(headerBytes: ByteArray, bindingSalt: ByteArray): ParsedMaxPayloadHeader? {
        val temporaryBuffers = mutableListOf<ByteArray>()
        val outputBuffers = mutableListOf<ByteArray>()
        fun temporary(value: ByteArray): ByteArray = value.also { temporaryBuffers += it }
        fun output(value: ByteArray): ByteArray = value.also { outputBuffers += it }
        var result: ParsedMaxPayloadHeader? = null
        return try {
            if (bindingSalt.size != 32) return null
            val reader = BlockReader(headerBytes)
            if (reader.readCString() != MAX_PAYLOAD_MARKER) return null
            val version = reader.readIntLe()
            val levelId = reader.readIntLe()
            val level = Level.entries.firstOrNull { it.id == levelId } ?: return null
            val nonce = output(reader.readBytes(reader.readIntLe()))
            val metadata = temporary(reader.readBytes(reader.readIntLe()))
            if (!reader.exhausted() || nonce.size != 16) return null
            val inner = BlockReader(metadata)
            val platform = inner.readString()
            val outputName = inner.readString()
            val innerFileType = inner.readString()
            val originalSize = inner.readIntLe()
            val storedSize = inner.readIntLe()
            val encodedSize = inner.readIntLe()
            val codec = inner.readIntLe()
            val chunkSize = inner.readIntLe()
            val chunkCount = inner.readIntLe()
            val layout = inner.readIntLe()
            val dispatcher = inner.readIntLe()
            val digest = output(inner.readBytes(32))
            val bindingTag = output(inner.readBytes(32))
            val chunkTagsSize = inner.readIntLe()
            if (chunkCount < 0 || chunkCount > Int.MAX_VALUE / 32 || chunkTagsSize != chunkCount * 32) return null
            val tags = output(inner.readBytes(chunkTagsSize))
            if (!inner.exhausted()) return null
            val streamKey = output(shellKdf(bindingSalt, akenStreamDomain, nonce, bindingTag))
            ParsedMaxPayloadHeader(
                version, level, platform, outputName, innerFileType, originalSize, storedSize, encodedSize,
                codec, chunkSize, chunkCount, layout, dispatcher, nonce, digest, bindingTag, tags, streamKey,
            ).also { result = it }
        } catch (_: IllegalArgumentException) {
            null
        } finally {
            temporaryBuffers.forEach { Arrays.fill(it, 0) }
            if (result == null) outputBuffers.forEach { Arrays.fill(it, 0) }
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
        val stored = decodeMaxPayloadForStub(bundle.encodedPayload, bundle.streamKey, bundle.nonce, bundle.bindingTag,
            bundle.chunkSize, bundle.chunkTags) ?: return null
        val decoded = when (bundle.compressionCodec) {
            maxCompressionCodecNone -> stored.takeIf { it.size == bundle.originalSize }
            maxCompressionCodecZstd -> Vbc4ZstdCodec.decompress(stored, bundle.originalSize)
            else -> null
        } ?: run {
            Arrays.fill(stored, 0)
            return null
        }
        val material = akenInnerDigestDomain.toByteArray(Charsets.US_ASCII) + decoded
        val digest = hmac(bundle.streamKey, material)
        Arrays.fill(material, 0)
        val valid = MessageDigest.isEqual(digest, bundle.sectionDigestHmac)
        Arrays.fill(digest, 0)
        if (decoded !== stored) Arrays.fill(stored, 0)
        if (!valid) Arrays.fill(decoded, 0)
        return decoded.takeIf { valid }
    }

    private data class MaxEncodedPayload(val encodedPayload: ByteArray, val chunkSize: Int, val chunkCount: Int, val chunkTags: ByteArray)

    private fun encodeMaxPayloadForStub(bytes: ByteArray, streamKey: ByteArray, nonce: ByteArray, bindingTag: ByteArray, chunkSize: Int): MaxEncodedPayload {
        require(chunkSize > 0) { "max payload chunk size must be positive" }
        val out = bytes.copyOf()
        val chunkCount = chunkCountFor(out.size, chunkSize)
        val tags = ByteArray(chunkCount * 32)
        var completed = false
        return try {
            for (chunkIndex in 0 until chunkCount) {
                val offset = chunkIndex * chunkSize
                val length = minOf(chunkSize, out.size - offset)
                encodeMaxPayloadChunk(out, offset, length, streamKey, nonce, bindingTag, chunkIndex)
                val tag = maxPayloadChunkTag(streamKey, nonce, bindingTag, chunkIndex, out, offset, length)
                try {
                    System.arraycopy(tag, 0, tags, chunkIndex * 32, 32)
                } finally {
                    Arrays.fill(tag, 0)
                }
            }
            MaxEncodedPayload(out, chunkSize, chunkCount, tags).also { completed = true }
        } finally {
            if (!completed) {
                Arrays.fill(out, 0)
                Arrays.fill(tags, 0)
            }
        }
    }

    private fun decodeMaxPayloadForStub(bytes: ByteArray, streamKey: ByteArray, nonce: ByteArray, bindingTag: ByteArray, chunkSize: Int, expectedChunkTags: ByteArray): ByteArray? {
        if (chunkSize <= 0) return null
        val out = bytes.copyOf()
        var completed = false
        return try {
            val chunkCount = chunkCountFor(out.size, chunkSize)
            if (chunkCount > Int.MAX_VALUE / 32 || expectedChunkTags.size != chunkCount * 32) return null
            for (chunkIndex in 0 until chunkCount) {
                val offset = chunkIndex * chunkSize
                val length = minOf(chunkSize, out.size - offset)
                val tag = maxPayloadChunkTag(streamKey, nonce, bindingTag, chunkIndex, out, offset, length)
                val expectedTag = expectedChunkTags.copyOfRange(chunkIndex * 32, chunkIndex * 32 + 32)
                val valid = try {
                    MessageDigest.isEqual(tag, expectedTag)
                } finally {
                    Arrays.fill(tag, 0)
                    Arrays.fill(expectedTag, 0)
                }
                if (!valid) return null
                encodeMaxPayloadChunk(out, offset, length, streamKey, nonce, bindingTag, chunkIndex)
            }
            out.also { completed = true }
        } finally {
            if (!completed) Arrays.fill(out, 0)
        }
    }

    /**
     * Local KDF used only for the self-contained AKEN v4 native shell format.
     * The binding salt and tag are public integrity inputs; this helper never
     * reads boot material, a sidecar, environment variables, or a file.
     */
    private fun shellKdf(
        keyMaterial: ByteArray,
        domain: String,
        nonce: ByteArray,
        bindingTag: ByteArray,
        chunkIndex: Int? = null,
    ): ByteArray {
        require(keyMaterial.isNotEmpty()) { "AKEN native shell KDF requires key material" }
        require(nonce.isNotEmpty()) { "AKEN native shell KDF requires a nonce" }
        require(bindingTag.isNotEmpty()) { "AKEN native shell KDF requires a binding tag" }
        val value = chunkIndex ?: 0
        require(value >= 0) { "AKEN native shell chunk index must be non-negative" }
        val domainBytes = domain.toByteArray(Charsets.US_ASCII)
        require(domainBytes.size <= 96) { "AKEN native shell KDF domain is too long" }
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(keyMaterial, "HmacSHA256"))
        // This byte order intentionally mirrors js_shell_kdf in the generated
        // native stub: nonce || bindingTag || value_be32 || domain_ascii.
        mac.update(nonce)
        mac.update(bindingTag)
        mac.update((value ushr 24).toByte())
        mac.update((value ushr 16).toByte())
        mac.update((value ushr 8).toByte())
        mac.update(value.toByte())
        mac.update(domainBytes)
        return mac.doFinal()
    }

    /** AES-CTR is symmetric, so the same primitive wraps and unwraps a chunk. */
    private fun aesCtr(bytes: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        require(key.size == 16 || key.size == 24 || key.size == 32) {
            "AKEN native shell AES key must be 16, 24, or 32 bytes"
        }
        require(iv.size == 16) { "AKEN native shell AES-CTR IV must be 16 bytes" }
        return javax.crypto.Cipher.getInstance("AES/CTR/NoPadding").run {
            init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, "AES"),
                javax.crypto.spec.IvParameterSpec(iv),
            )
            doFinal(bytes)
        }
    }

    private fun encodeMaxPayloadChunk(bytes: ByteArray, offset: Int, length: Int, streamKey: ByteArray, nonce: ByteArray, bindingTag: ByteArray, chunkIndex: Int) {
        val sensitive = mutableListOf<ByteArray>()
        fun track(value: ByteArray): ByteArray = value.also { sensitive += it }
        try {
            val chunkKey = track(shellKdf(streamKey, akenChunkAesDomain, nonce, bindingTag, chunkIndex))
            val chunkIvMaterial = track(shellKdf(streamKey, akenChunkIvDomain, nonce, bindingTag, chunkIndex))
            val chunkIv = track(chunkIvMaterial.copyOf(16))
            val aesKey = track(chunkKey.copyOf(16))
            val plain = track(bytes.copyOfRange(offset, offset + length))
            val encrypted = track(aesCtr(plain, aesKey, chunkIv))
            System.arraycopy(encrypted, 0, bytes, offset, length)
        } finally {
            sensitive.forEach { Arrays.fill(it, 0) }
        }
    }

    private fun maxPayloadChunkTag(streamKey: ByteArray, nonce: ByteArray, bindingTag: ByteArray, chunkIndex: Int, bytes: ByteArray, offset: Int, length: Int): ByteArray {
        val tagKey = shellKdf(streamKey, akenChunkHmacDomain, nonce, bindingTag, chunkIndex)
        val ciphertext = bytes.copyOfRange(offset, offset + length)
        return try { hmac(tagKey, ciphertext) } finally { Arrays.fill(tagKey, 0); Arrays.fill(ciphertext, 0) }
    }

    private fun chunkCountFor(size: Int, chunkSize: Int): Int = if (size == 0) 0 else 1 + (size - 1) / chunkSize

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

    private fun akenPayloadBindingTag(
        platform: String,
        outputName: String,
        seed: Long,
        level: Level,
        bootstrapNativeIndexDigest: ByteArray,
        bindingSalt: ByteArray,
    ): ByteArray = MessageDigest.getInstance("SHA-256").apply {
        update("javashroud-aken-v4-native-shell-binding-tag-v1".toByteArray(Charsets.US_ASCII))
        updateLong(seed)
        updateInt(level.id)
        update(platform.toByteArray(Charsets.UTF_8))
        update(0)
        update(outputName.toByteArray(Charsets.UTF_8))
        update(0)
        update(bootstrapNativeIndexDigest)
        update(bindingSalt)
    }.digest()

    private fun akenPayloadCommitment(
        bindingSalt: ByteArray,
        headerBytes: ByteArray,
        encodedPayload: ByteArray,
    ): ByteArray {
        require(bindingSalt.size == 32) { "AKEN v4 binding salt must be exactly 32 bytes" }
        val headerDigest = sha256(headerBytes)
        val payloadDigest = sha256(encodedPayload)
        val material = akenPayloadCommitmentDomain.toByteArray(Charsets.US_ASCII) + headerDigest + payloadDigest
        return try {
            hmac(bindingSalt, material)
        } finally {
            Arrays.fill(headerDigest, 0)
            Arrays.fill(payloadDigest, 0)
            Arrays.fill(material, 0)
        }
    }

    private fun akenBindingLaneOrder(): IntArray {
        val order = IntArray(akenBindingLaneCount) { it }
        val random = SecureRandom()
        for (index in order.lastIndex downTo 1) {
            val swap = random.nextInt(index + 1)
            val value = order[index]
            order[index] = order[swap]
            order[swap] = value
        }
        return order
    }

    /**
     * Legacy callers still compile until their VBC4 migration lands. This
     * deliberately has no provider/environment/file/hex/sidecar read path.
     */
    @Deprecated("AKEN v4 removes boot-secret delivery")
    internal fun requireBootSecretForBuild(): ByteArray =
        throw IllegalStateException("AKEN v4 removed Boot KEK delivery; remove bootKeyDelivery and rebuild")

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

    private fun readLongPrefix(bytes: ByteArray): Long = ByteBuffer.wrap(bytes, 0, 8).order(ByteOrder.BIG_ENDIAN).long

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
