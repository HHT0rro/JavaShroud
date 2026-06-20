package io.github.hht0rro.javashroud.transforms.protection

import java.security.MessageDigest
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
    private const val version = 5
    private const val headerSize = 40
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
        val storedBytes = Vbc4ZstdCodec.compress(bytes)
        val compressed = storedBytes.size < bytes.size
        @Suppress("UNUSED_VARIABLE")
        val requestedCompression = compress
        val key = runtimeResourceKey()
        return try {
            val kindBytes = intBytes(kind.id)
            val variantBytes = intBytes(normalizedVariant)
            val layerBytes = intBytes(normalizedLayers)
            val plainHash = sha256(bytes)
            val storedHash = sha256(storedBytes)
            val nonce = deriveNonce(
                seed = seed,
                kindBytes = kindBytes,
                variantBytes = variantBytes,
                layerBytes = layerBytes,
                plainHash = plainHash,
                storedHash = storedHash,
                key = key,
            )
            val body = aesCtrCrypt(storedBytes, nonce, key, kindBytes, variantBytes, layerBytes)
            val out = ByteArray(headerSize + body.size + macLength + 1)
            System.arraycopy(magic, 0, out, 0, magic.size)
            out[4] = version.toByte()
            out[5] = kind.id.toByte()
            out[6] = normalizedLayers.toByte()
            out[7] = (normalizedVariant or if (compressed) 0x80 else 0).toByte()
            System.arraycopy(nonce, 0, out, 8, nonce.size)
            writeLe32(out, 24, bytes.size)
            writeLe32(out, 28, storedBytes.size)
            writeLe32(out, 32, body.size)
            writeLe32(out, 36, readBe32(hmacSha256WithKey(key, "jsrp-key-id".toByteArray(Charsets.US_ASCII), nonce), 0))
            System.arraycopy(body, 0, out, headerSize, body.size)
            val tag = hmacSha256WithKey(key, out, 0, headerSize + body.size, "jsrp-auth".toByteArray(Charsets.US_ASCII), nonce)
            System.arraycopy(tag, 0, out, headerSize + body.size, tag.size)
            out[out.lastIndex] = macLength.toByte()
            out
        } finally {
            Arrays.fill(key, 0)
        }
    }

    fun decode(bytes: ByteArray): ByteArray? {
        if (!hasCurrentHeader(bytes)) return null
        return decodeCurrent(bytes)
    }

    fun hasCurrentHeader(bytes: ByteArray): Boolean =
        bytes.size >= headerSize && magic.indices.all { index -> bytes[index] == magic[index] } &&
            (bytes[4].toInt() and 0xFF) == version

    private fun decodeCurrent(bytes: ByteArray): ByteArray? {
        if (bytes.size < headerSize + macLength + 1) return null
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
        val bodyOffset = headerSize
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

    private fun deriveNonce(
        seed: Int,
        kindBytes: ByteArray,
        variantBytes: ByteArray,
        layerBytes: ByteArray,
        plainHash: ByteArray,
        storedHash: ByteArray,
        key: ByteArray,
    ): ByteArray = hmacSha256WithKey(
        key,
        "jsrp-nonce".toByteArray(Charsets.US_ASCII),
        intBytes(seed),
        kindBytes,
        variantBytes,
        layerBytes,
        plainHash,
        storedHash,
    ).copyOfRange(0, 16)

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

