package io.github.hht0rro.javashroud.transforms.protection

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

enum class RuntimeResourceKind(val id: Int) {
    VmBytecode(1),
    NativeLibrary(2),
    Manifest(3),
    NativeIndex(4),
}

object RuntimeResourceCodec {
    private val magic = byteArrayOf(0x4A, 0x53, 0x52, 0x50) // JSRP
    private const val version = 7
    private const val headerSize = 27
    private const val metadataSize = 96
    private const val macLength = 32
    private val partitionedAuthDomain = "jsrp-auth-v3".toByteArray(Charsets.US_ASCII)

    fun encode(
        bytes: ByteArray,
        kind: RuntimeResourceKind,
        seed: Int,
        variantId: Int,
        layerCount: Int,
        compress: Boolean = true,
        partitionIdentity: ByteArray? = null,
    ): ByteArray = encodePartitioned(
        bytes = bytes,
        kind = kind,
        seed = seed,
        variantId = variantId,
        layerCount = layerCount,
        compress = compress,
        partitions = requireVbc4BuildContext().runtimeKeyPartitions,
        partitionIdentity = partitionIdentity,
    )

    internal fun encodeForPartition(
        bytes: ByteArray,
        kind: RuntimeResourceKind,
        seed: Int,
        variantId: Int,
        layerCount: Int,
        partitionId: Int,
        compress: Boolean = true,
    ): ByteArray {
        val partitions = requireVbc4BuildContext().runtimeKeyPartitions
        require(partitionId in 0 until partitions.resourcePartitionCount) {
            "resource partition out of range: $partitionId"
        }
        return encodePartitioned(
            bytes = bytes,
            kind = kind,
            seed = seed,
            variantId = variantId,
            layerCount = layerCount,
            compress = compress,
            partitions = partitions,
            partitionIdentity = null,
            forcedPartitionId = partitionId,
        )
    }

    internal fun partitionId(bytes: ByteArray): Int? {
        if (!hasCurrentHeader(bytes) || bytes.size < headerSize) return null
        return readLe16(bytes, 25)
    }

    fun decode(bytes: ByteArray): ByteArray? {
        if (!hasCurrentHeader(bytes)) return null
        return decodePartitioned(bytes, requireVbc4BuildContext().runtimeKeyPartitions)
    }

    private fun encodePartitioned(
        bytes: ByteArray,
        kind: RuntimeResourceKind,
        seed: Int,
        variantId: Int,
        layerCount: Int,
        compress: Boolean,
        partitions: RuntimeKeyPartitions,
        partitionIdentity: ByteArray?,
        forcedPartitionId: Int? = null,
    ): ByteArray {
        val normalizedLayers = layerCount.coerceIn(1, 7)
        val normalizedVariant = variantId and 0x7F
        val compressedCandidate = if (compress) Vbc4ZstdCodec.compress(bytes) else bytes
        val compressed = compress && compressedCandidate.size < bytes.size
        val storedBytes = if (compressed) compressedCandidate else bytes
        val plainHash = sha256(bytes)
        val identity = partitionIdentity
            ?: concatBytes(arrayOf(intBytes(kind.id), intBytes(seed), plainHash))
        val partitionId = forcedPartitionId ?: partitions.partitionFor(identity)
        val key = partitions.copyResourceKey(partitionId)
        return try {
            val kindBytes = intBytes(kind.id)
            val variantBytes = intBytes(normalizedVariant)
            val layerBytes = intBytes(normalizedLayers)
            val storedHash = sha256(storedBytes)
            val nonce = randomNonce()
            val metadataPlain = encodeMetadata(
                kindId = kind.id,
                layerCount = normalizedLayers,
                variantId = normalizedVariant,
                compressed = compressed,
                plainLength = bytes.size,
                storedLength = storedBytes.size,
                bodyLength = storedBytes.size,
                keyId = readBe32(hmacSha256WithKey(key, "jsrp-key-id-v3".toByteArray(Charsets.US_ASCII), nonce), 0),
                seed = seed,
                plainHash = plainHash,
                storedHash = storedHash,
                partitionId = partitionId,
            )
            val metadataCipher = aesCtrCrypt(metadataPlain, nonce, key, intBytes(0), intBytes(0), intBytes(0))
            val body = aesCtrCrypt(storedBytes, nonce, key, kindBytes, variantBytes, layerBytes)
            val out = ByteArray(headerSize + metadataCipher.size + body.size + macLength + 1)
            System.arraycopy(magic, 0, out, 0, magic.size)
            out[4] = version.toByte()
            System.arraycopy(nonce, 0, out, 5, nonce.size)
            writeLe16(out, 21, metadataCipher.size)
            writeLe16(out, 23, macLength)
            writeLe16(out, 25, partitionId)
            System.arraycopy(metadataCipher, 0, out, headerSize, metadataCipher.size)
            System.arraycopy(body, 0, out, headerSize + metadataCipher.size, body.size)
            val tagOffset = headerSize + metadataCipher.size + body.size
            val tag = hmacSha256WithKey(key, out, 0, tagOffset, partitionedAuthDomain, nonce)
            System.arraycopy(tag, 0, out, tagOffset, tag.size)
            out[out.lastIndex] = macLength.toByte()
            out
        } finally {
            Arrays.fill(key, 0)
        }
    }

    internal fun decodePartitioned(bytes: ByteArray, partitions: RuntimeKeyPartitions): ByteArray? {
        if (!hasCurrentHeader(bytes)) return null
        if (bytes.size < headerSize + metadataSize + macLength + 1) return null
        if ((bytes.last().toInt() and 0xFF) != macLength) return null
        val nonce = bytes.copyOfRange(5, 21)
        val metadataLength = readLe16(bytes, 21)
        val declaredMacLength = readLe16(bytes, 23)
        val partitionId = readLe16(bytes, 25)
        if (metadataLength != metadataSize || declaredMacLength != macLength) return null
        if (partitionId >= partitions.resourcePartitionCount) return null
        val metadataOffset = headerSize
        val bodyOffset = metadataOffset + metadataLength
        if (bodyOffset + macLength + 1 > bytes.size) return null
        val key = partitions.copyResourceKey(partitionId)
        return try {
            val tagOffset = bytes.size - macLength - 1
            val expectedTag = hmacSha256WithKey(key, bytes, 0, tagOffset, partitionedAuthDomain, nonce)
            if (!constantTimeEquals(expectedTag, bytes, tagOffset)) return null
            val metadataCipher = bytes.copyOfRange(metadataOffset, bodyOffset)
            val metadataPlain = aesCtrCrypt(metadataCipher, nonce, key, intBytes(0), intBytes(0), intBytes(0))
            val metadata = parseMetadata(metadataPlain) ?: return null
            if (metadata.partitionId != partitionId) return null
            if (metadata.kindId !in 1..4) return null
            if (metadata.layerCount !in 1..7 || metadata.variantId > 127) return null
            if (metadata.plainLength < 0 || metadata.storedLength < 0 || metadata.bodyLength < 0) return null
            if (bodyOffset + metadata.bodyLength != tagOffset) return null
            val body = bytes.copyOfRange(bodyOffset, tagOffset)
            val stored = aesCtrCrypt(body, nonce, key, intBytes(metadata.kindId), intBytes(metadata.variantId), intBytes(metadata.layerCount))
            if (stored.size != metadata.storedLength) return null
            if (!sha256(stored).contentEquals(metadata.storedHash)) return null
            val plain = if (metadata.compressed) Vbc4ZstdCodec.decompress(stored, metadata.plainLength) else stored
            if (plain == null || plain.size != metadata.plainLength) return null
            if (!sha256(plain).contentEquals(metadata.plainHash)) return null
            plain
        } finally {
            Arrays.fill(key, 0)
        }
    }

    fun hasCurrentHeader(bytes: ByteArray): Boolean =
        bytes.size >= 5 && magic.indices.all { index -> bytes[index] == magic[index] } &&
            (bytes[4].toInt() and 0xFF) == version

    private fun aesCtrCrypt(
        bytes: ByteArray,
        nonce: ByteArray,
        runtimeKey: ByteArray,
        kindBytes: ByteArray,
        variantBytes: ByteArray,
        layerBytes: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        val key = hmacSha256WithKey(
            runtimeKey,
            "jsrp-aes-key".toByteArray(Charsets.US_ASCII),
            nonce,
            kindBytes,
            variantBytes,
            layerBytes,
        ).copyOfRange(0, 16)
        val iv = hmacSha256WithKey(
            runtimeKey,
            "jsrp-aes-iv".toByteArray(Charsets.US_ASCII),
            nonce,
            kindBytes,
            variantBytes,
            layerBytes,
        ).copyOfRange(0, 16)
        return try {
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            cipher.doFinal(bytes)
        } finally {
            Arrays.fill(key, 0)
            Arrays.fill(iv, 0)
        }
    }

    private fun hmacSha256WithKey(runtimeKey: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(runtimeKey, "HmacSHA256"))
        for (part in parts) mac.update(part)
        return mac.doFinal()
    }

    private fun hmacSha256WithKey(runtimeKey: ByteArray, data: ByteArray, offset: Int, length: Int, vararg prefixes: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(runtimeKey, "HmacSHA256"))
        for (prefix in prefixes) mac.update(prefix)
        mac.update(data, offset, length)
        return mac.doFinal()
    }

    private fun randomNonce(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }

    private data class Metadata(
        val partitionId: Int,
        val kindId: Int,
        val layerCount: Int,
        val variantId: Int,
        val compressed: Boolean,
        val plainLength: Int,
        val storedLength: Int,
        val bodyLength: Int,
        val keyId: Int,
        val seed: Int,
        val plainHash: ByteArray,
        val storedHash: ByteArray,
    )

    private fun encodeMetadata(
        kindId: Int,
        layerCount: Int,
        variantId: Int,
        compressed: Boolean,
        plainLength: Int,
        storedLength: Int,
        bodyLength: Int,
        keyId: Int,
        seed: Int,
        plainHash: ByteArray,
        storedHash: ByteArray,
        partitionId: Int = 0,
    ): ByteArray {
        val out = ByteArray(metadataSize)
        out[0] = 0x4D
        out[1] = 0x32
        out[2] = 1
        out[3] = kindId.toByte()
        out[4] = layerCount.toByte()
        out[5] = variantId.toByte()
        out[6] = if (compressed) 1 else 0
        out[7] = partitionId.toByte()
        writeLe32(out, 8, plainLength)
        writeLe32(out, 12, storedLength)
        writeLe32(out, 16, bodyLength)
        writeLe32(out, 20, keyId)
        writeLe32(out, 24, seed)
        System.arraycopy(plainHash, 0, out, 28, 32)
        System.arraycopy(storedHash, 0, out, 60, 32)
        writeLe32(out, 92, readBe32(sha256(out.copyOfRange(0, 92)), 0))
        return out
    }

    private fun parseMetadata(bytes: ByteArray): Metadata? {
        if (bytes.size != metadataSize) return null
        if (bytes[0] != 0x4D.toByte() || bytes[1] != 0x32.toByte() || bytes[2] != 1.toByte()) return null
        if (readLe32(bytes, 92) != readBe32(sha256(bytes.copyOfRange(0, 92)), 0)) return null
        val flags = bytes[6].toInt() and 0xFF
        if ((flags and 0xFE) != 0) return null
        return Metadata(
            partitionId = bytes[7].toInt() and 0xFF,
            kindId = bytes[3].toInt() and 0xFF,
            layerCount = bytes[4].toInt() and 0xFF,
            variantId = bytes[5].toInt() and 0xFF,
            compressed = (flags and 1) != 0,
            plainLength = readLe32(bytes, 8),
            storedLength = readLe32(bytes, 12),
            bodyLength = readLe32(bytes, 16),
            keyId = readLe32(bytes, 20),
            seed = readLe32(bytes, 24),
            plainHash = bytes.copyOfRange(28, 60),
            storedHash = bytes.copyOfRange(60, 92),
        )
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun intBytes(value: Int): ByteArray = byteArrayOf(
        ((value ushr 24) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte(),
    )

    private fun constantTimeEquals(expected: ByteArray, actual: ByteArray, actualOffset: Int): Boolean {
        if (actualOffset < 0 || actualOffset + expected.size > actual.size) return false
        var diff = 0
        for (index in expected.indices) diff = diff or ((expected[index].toInt() xor actual[actualOffset + index].toInt()) and 0xFF)
        return diff == 0
    }

    private fun writeLe32(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value and 0xFF).toByte()
        out[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        out[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        out[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }

    private fun writeLe16(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value and 0xFF).toByte()
        out[offset + 1] = ((value ushr 8) and 0xFF).toByte()
    }

    private fun readLe16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)

    private fun readLe32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)

    private fun readBe32(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)
}
