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
    private const val version = 6
    private const val legacyVersion = 5
    private const val headerSize = 25
    private const val legacyHeaderSize = 40
    private const val metadataSize = 96
    private const val macLength = 32

    fun encode(
        bytes: ByteArray,
        kind: RuntimeResourceKind,
        seed: Int,
        variantId: Int,
        layerCount: Int,
        compress: Boolean = true,
    ): ByteArray {
        val normalizedLayers = layerCount.coerceIn(1, 7)
        val normalizedVariant = variantId and 0x7F
        val compressedCandidate = if (compress) Vbc4ZstdCodec.compress(bytes) else bytes
        val compressed = compress && compressedCandidate.size < bytes.size
        val storedBytes = if (compressed) compressedCandidate else bytes
        val key = runtimeResourceKey()
        return try {
            val kindBytes = intBytes(kind.id)
            val variantBytes = intBytes(normalizedVariant)
            val layerBytes = intBytes(normalizedLayers)
            val plainHash = sha256(bytes)
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
                keyId = readBe32(hmacSha256WithKey(key, "jsrp-key-id-v2".toByteArray(Charsets.US_ASCII), nonce), 0),
                seed = seed,
                plainHash = plainHash,
                storedHash = storedHash,
            )
            val metadataCipher = aesCtrCrypt(metadataPlain, nonce, key, intBytes(0), intBytes(0), intBytes(0))
            val body = aesCtrCrypt(storedBytes, nonce, key, kindBytes, variantBytes, layerBytes)
            val out = ByteArray(headerSize + metadataCipher.size + body.size + macLength + 1)
            System.arraycopy(magic, 0, out, 0, magic.size)
            out[4] = version.toByte()
            System.arraycopy(nonce, 0, out, 5, nonce.size)
            writeLe16(out, 21, metadataCipher.size)
            writeLe16(out, 23, macLength)
            System.arraycopy(metadataCipher, 0, out, headerSize, metadataCipher.size)
            System.arraycopy(body, 0, out, headerSize + metadataCipher.size, body.size)
            val tagOffset = headerSize + metadataCipher.size + body.size
            val tag = hmacSha256WithKey(key, out, 0, tagOffset, "jsrp-auth-v2".toByteArray(Charsets.US_ASCII), nonce)
            System.arraycopy(tag, 0, out, tagOffset, tag.size)
            out[out.lastIndex] = macLength.toByte()
            out
        } finally {
            Arrays.fill(key, 0)
        }
    }

    fun decode(bytes: ByteArray): ByteArray? {
        if (!hasCurrentHeader(bytes)) return null
        return when (bytes[4].toInt() and 0xFF) {
            version -> decodeCurrent(bytes)
            legacyVersion -> decodeLegacy(bytes)
            else -> null
        }
    }

    fun hasCurrentHeader(bytes: ByteArray): Boolean =
        bytes.size >= 5 && magic.indices.all { index -> bytes[index] == magic[index] } &&
            ((bytes[4].toInt() and 0xFF) == version || (bytes[4].toInt() and 0xFF) == legacyVersion)

    private fun decodeCurrent(bytes: ByteArray): ByteArray? {
        if (bytes.size < headerSize + metadataSize + macLength + 1) return null
        if ((bytes.last().toInt() and 0xFF) != macLength) return null
        val nonce = bytes.copyOfRange(5, 21)
        val metadataLength = readLe16(bytes, 21)
        val declaredMacLength = readLe16(bytes, 23)
        if (metadataLength != metadataSize || declaredMacLength != macLength) return null
        val metadataOffset = headerSize
        val bodyOffset = metadataOffset + metadataLength
        if (bodyOffset + macLength + 1 > bytes.size) return null
        val expectedTag = hmacSha256(bytes, 0, bytes.size - macLength - 1, "jsrp-auth-v2".toByteArray(Charsets.US_ASCII), nonce)
        if (!constantTimeEquals(expectedTag, bytes, bytes.size - macLength - 1)) return null
        val key = runtimeResourceKey()
        val metadataPlain = try {
            aesCtrCrypt(
                bytes.copyOfRange(metadataOffset, bodyOffset),
                nonce,
                key,
                intBytes(0),
                intBytes(0),
                intBytes(0),
            )
        } finally {
            Arrays.fill(key, 0)
        }
        val metadata = parseMetadata(metadataPlain) ?: return null
        val kindId = metadata.kindId
        val layerCount = metadata.layerCount
        val variantId = metadata.variantId
        val compressed = metadata.compressed
        if (kindId !in RuntimeResourceKind.entries.map { it.id }) return null
        if (layerCount !in 1..7) return null
        if (variantId !in 0..127) return null
        val plainLength = metadata.plainLength
        val storedLength = metadata.storedLength
        val bodyLength = metadata.bodyLength
        if (plainLength < 0 || storedLength < 0 || bodyLength < 0) return null
        val tagOffset = bodyOffset + bodyLength
        if (tagOffset + macLength + 1 != bytes.size) return null
        val body = bytes.copyOfRange(bodyOffset, tagOffset)
        val storedBytes = aesCtrCrypt(body, nonce, kindId, variantId, layerCount)
        if (storedBytes.size != storedLength) return null
        if (!sha256(storedBytes).contentEquals(metadata.storedHash)) return null
        val plain = if (compressed) Vbc4ZstdCodec.decompress(storedBytes, plainLength) ?: return null else storedBytes
        return if (plain.size == plainLength && sha256(plain).contentEquals(metadata.plainHash)) plain else null
    }

    private fun decodeLegacy(bytes: ByteArray): ByteArray? {
        if (bytes.size < legacyHeaderSize + macLength + 1) return null
        if ((bytes.last().toInt() and 0xFF) != macLength) return null
        val kindId = bytes[5].toInt() and 0xFF
        val layerCount = bytes[6].toInt() and 0xFF
        val flags = bytes[7].toInt() and 0xFF
        val compressed = (flags and 0x80) != 0
        val variantId = flags and 0x7F
        if (layerCount !in 1..7) return null
        val nonce = bytes.copyOfRange(8, 24)
        val plainLength = readLe32(bytes, 24)
        val storedLength = readLe32(bytes, 28)
        val bodyLength = readLe32(bytes, 32)
        if (plainLength < 0 || storedLength < 0 || bodyLength < 0) return null
        val bodyOffset = legacyHeaderSize
        val tagOffset = bodyOffset + bodyLength
        if (tagOffset + macLength + 1 != bytes.size) return null
        val expectedTag = hmacSha256(bytes, 0, tagOffset, "jsrp-auth".toByteArray(Charsets.US_ASCII), nonce)
        if (!constantTimeEquals(expectedTag, bytes, tagOffset)) return null
        val body = bytes.copyOfRange(bodyOffset, tagOffset)
        val storedBytes = aesCtrCrypt(body, nonce, kindId, variantId, layerCount)
        if (storedBytes.size != storedLength) return null
        val plain = if (compressed) Vbc4ZstdCodec.decompress(storedBytes, plainLength) ?: return null else storedBytes
        return if (plain.size == plainLength) plain else null
    }

    private fun aesCtrCrypt(bytes: ByteArray, nonce: ByteArray, kindId: Int, variantId: Int, layerCount: Int): ByteArray =
        runtimeResourceKey().let { key ->
            try {
                aesCtrCrypt(bytes, nonce, key, intBytes(kindId), intBytes(variantId), intBytes(layerCount))
            } finally {
                Arrays.fill(key, 0)
            }
        }

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

    private fun hmacSha256(vararg parts: ByteArray): ByteArray {
        val key = runtimeResourceKey()
        return try {
            hmacSha256WithKey(key, *parts)
        } finally {
            Arrays.fill(key, 0)
        }
    }

    private fun hmacSha256WithKey(runtimeKey: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(runtimeKey, "HmacSHA256"))
        for (part in parts) mac.update(part)
        return mac.doFinal()
    }

    private fun hmacSha256(data: ByteArray, offset: Int, length: Int, vararg prefixes: ByteArray): ByteArray {
        val key = runtimeResourceKey()
        return try {
            hmacSha256WithKey(key, data, offset, length, *prefixes)
        } finally {
            Arrays.fill(key, 0)
        }
    }

    private fun hmacSha256WithKey(runtimeKey: ByteArray, data: ByteArray, offset: Int, length: Int, vararg prefixes: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(runtimeKey, "HmacSHA256"))
        for (prefix in prefixes) mac.update(prefix)
        mac.update(data, offset, length)
        return mac.doFinal()
    }

    private fun runtimeResourceKey(): ByteArray =
        requireVbc4BuildContext().copyRuntimeResourceKey()

    private fun randomNonce(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }

    private data class Metadata(
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
    ): ByteArray {
        val out = ByteArray(metadataSize)
        out[0] = 0x4D
        out[1] = 0x32
        out[2] = 1
        out[3] = kindId.toByte()
        out[4] = layerCount.toByte()
        out[5] = variantId.toByte()
        out[6] = if (compressed) 1 else 0
        out[7] = 0
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
