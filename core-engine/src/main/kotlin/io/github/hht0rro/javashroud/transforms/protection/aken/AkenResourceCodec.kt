package io.github.hht0rro.javashroud.transforms.protection.aken

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AES-256-GCM codec for one independently keyed AKEN v4 page.
 *
 * A page carries a fixed logical header inside a per-build physical frame.
 * The frame, all public bindings, and the header are authenticated together;
 * a layout is therefore an executable codec parameter rather than decorative
 * metadata.
 */
object AkenResourceCodec {
    const val FORMAT_VERSION: Int = 4
    const val LOGICAL_HEADER_SIZE: Int = 202
    const val GCM_TAG_SIZE: Int = 16
    const val NONCE_SIZE: Int = 12

    const val OFFSET_VERSION: Int = 0
    const val OFFSET_KIND: Int = 1
    const val OFFSET_PAGE_INDEX: Int = 2
    const val OFFSET_PLAINTEXT_LENGTH: Int = 6
    const val OFFSET_NONCE: Int = 10
    const val OFFSET_COMMITMENT: Int = 22
    const val OFFSET_IDENTITY_HASH: Int = 54
    const val OFFSET_EVALUATOR_FINGERPRINT: Int = 86
    const val OFFSET_CODEC_HASH: Int = 118
    const val OFFSET_LAYOUT_HASH: Int = 150
    const val OFFSET_LOCATOR: Int = 182
    const val OFFSET_CIPHERTEXT_LENGTH: Int = 198

    const val CANONICAL_CODEC_VARIANT: String = "aes-256-gcm-v4"

    private val AAD_DOMAIN = "AKEN-v4-page-aad".toByteArray(StandardCharsets.US_ASCII)

    /**
     * Canonicalize the only supported page cipher. Rejecting unknown values
     * makes the codec field an enforced protocol choice instead of decorative
     * metadata.
     */
    fun normalizeCodecVariant(variant: String): String = when (variant.trim().lowercase()) {
        "gcm",
        "aes-256-gcm",
        CANONICAL_CODEC_VARIANT,
        -> CANONICAL_CODEC_VARIANT

        else -> throw IllegalArgumentException("unsupported AKEN codec variant: $variant")
    }

    fun encode(
        plain: ByteArray,
        dek: ByteArray,
        commitment: ByteArray,
        identity: ByteArray,
        pageIndex: Int,
        kind: AkenResourceKind,
        fingerprint: ByteArray,
        codec: String,
        layout: AkenPageLayout,
        locator: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        require(dek.size == 32) { "AKEN DEK must be 32 bytes" }
        require(commitment.size == 32) { "AKEN artifact commitment must be 32 bytes" }
        require(identity.isNotEmpty()) { "AKEN logical identity must not be empty" }
        require(pageIndex >= 0) { "AKEN page index must be non-negative" }
        require(fingerprint.size == 32) { "AKEN evaluator fingerprint must be 32 bytes" }
        require(locator.size == AkenHandle.LOCATOR_TOKEN_SIZE) { "AKEN locator token must be 16 bytes" }
        require(plain.size <= Int.MAX_VALUE - GCM_TAG_SIZE) { "AKEN plaintext is too large" }

        var nonce: ByteArray? = null
        var header: ByteArray? = null
        var identityHash: ByteArray? = null
        var codecBytes: ByteArray? = null
        var codecHash: ByteArray? = null
        var layoutBytes: ByteArray? = null
        var layoutHash: ByteArray? = null
        var prefix: ByteArray? = null
        var suffix: ByteArray? = null
        var aad: ByteArray? = null
        var key: ByteArray? = null
        var body: ByteArray? = null

        try {
            val canonicalCodec = normalizeCodecVariant(codec)
            val layoutVariant = layout.variant
            nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
            header = ByteArray(LOGICAL_HEADER_SIZE)
            identityHash = sha256(identity)
            codecBytes = canonicalCodec.toByteArray(StandardCharsets.UTF_8)
            codecHash = sha256(codecBytes)
            layoutBytes = layoutVariant.toByteArray(StandardCharsets.UTF_8)
            layoutHash = sha256(layoutBytes)

            header[OFFSET_VERSION] = FORMAT_VERSION.toByte()
            header[OFFSET_KIND] = kind.id.toByte()
            writeInt(header, OFFSET_PAGE_INDEX, pageIndex)
            writeInt(header, OFFSET_PLAINTEXT_LENGTH, plain.size)
            nonce.copyInto(header, OFFSET_NONCE)
            commitment.copyInto(header, OFFSET_COMMITMENT)
            identityHash.copyInto(header, OFFSET_IDENTITY_HASH)
            fingerprint.copyInto(header, OFFSET_EVALUATOR_FINGERPRINT)
            codecHash.copyInto(header, OFFSET_CODEC_HASH)
            layoutHash.copyInto(header, OFFSET_LAYOUT_HASH)
            locator.copyInto(header, OFFSET_LOCATOR)
            writeInt(header, OFFSET_CIPHERTEXT_LENGTH, plain.size + GCM_TAG_SIZE)

            prefix = ByteArray(layout.prefixLength).also(random::nextBytes)
            suffix = ByteArray(layout.suffixLength).also(random::nextBytes)
            aad = buildAad(
                commitment = commitment,
                identity = identity,
                pageIndex = pageIndex,
                kind = kind,
                fingerprint = fingerprint,
                codecBytes = codecBytes,
                layoutBytes = layoutBytes,
                locator = locator,
                header = header,
                prefix = prefix,
                suffix = suffix,
            )
            key = dek.copyOf()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.ENCRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(GCM_TAG_SIZE * 8, nonce),
            )
            cipher.updateAAD(aad)
            body = cipher.doFinal(plain)
            check(body.size == plain.size + GCM_TAG_SIZE) {
                "AKEN AES-GCM output length did not match the declared page length"
            }

            return frame(layout, prefix, header, body, suffix)
        } finally {
            nonce?.fill(0)
            header?.fill(0)
            identityHash?.fill(0)
            codecBytes?.fill(0)
            codecHash?.fill(0)
            layoutBytes?.fill(0)
            layoutHash?.fill(0)
            prefix?.fill(0)
            suffix?.fill(0)
            aad?.fill(0)
            key?.fill(0)
            body?.fill(0)
        }
    }

    /**
     * Decode exactly one page under its bound context. Any malformed header,
     * framing mismatch, binding mismatch, or GCM authentication failure returns
     * null so callers can fail closed without a Java fallback path.
     */
    fun decode(
        encoded: ByteArray,
        dek: ByteArray,
        commitment: ByteArray,
        identity: ByteArray,
        pageIndex: Int,
        kind: AkenResourceKind,
        fingerprint: ByteArray,
        codec: String,
        layout: AkenPageLayout,
        locator: ByteArray,
    ): ByteArray? {
        if (
            dek.size != 32 ||
            commitment.size != 32 ||
            identity.isEmpty() ||
            pageIndex < 0 ||
            fingerprint.size != 32 ||
            locator.size != AkenHandle.LOCATOR_TOKEN_SIZE
        ) {
            return null
        }

        var header: ByteArray? = null
        var nonce: ByteArray? = null
        var identityHash: ByteArray? = null
        var codecBytes: ByteArray? = null
        var codecHash: ByteArray? = null
        var layoutBytes: ByteArray? = null
        var layoutHash: ByteArray? = null
        var prefix: ByteArray? = null
        var suffix: ByteArray? = null
        var aad: ByteArray? = null
        var key: ByteArray? = null
        var plain: ByteArray? = null

        try {
            val canonicalCodec = normalizeCodecVariant(codec)
            val layoutVariant = layout.variant
            if (encoded.size < layout.encodedLength(GCM_TAG_SIZE)) return null

            val headerOffset = layout.headerOffset(encoded.size)
            if (headerOffset < 0 || headerOffset + LOGICAL_HEADER_SIZE > encoded.size) return null
            header = encoded.copyOfRange(headerOffset, headerOffset + LOGICAL_HEADER_SIZE)

            val declaredPlainLength = readInt(header, OFFSET_PLAINTEXT_LENGTH)
            val declaredBodyLength = readInt(header, OFFSET_CIPHERTEXT_LENGTH)
            if (declaredPlainLength < 0 || declaredPlainLength > Int.MAX_VALUE - GCM_TAG_SIZE) return null
            if (declaredBodyLength != declaredPlainLength + GCM_TAG_SIZE) return null
            if (layout.encodedLength(declaredBodyLength) != encoded.size) return null

            val bodyOffset = layout.bodyOffset()
            val expectedHeaderOffset = if (layout.headerAfterBody) {
                bodyOffset + declaredBodyLength
            } else {
                bodyOffset - LOGICAL_HEADER_SIZE
            }
            if (expectedHeaderOffset != headerOffset) return null
            if (bodyOffset < 0 || bodyOffset + declaredBodyLength > encoded.size) return null

            val suffixOffset = encoded.size - layout.suffixLength
            if (suffixOffset < 0 || suffixOffset < bodyOffset + declaredBodyLength) return null
            prefix = encoded.copyOfRange(0, layout.prefixLength)
            suffix = encoded.copyOfRange(suffixOffset, encoded.size)
            nonce = header.copyOfRange(OFFSET_NONCE, OFFSET_NONCE + NONCE_SIZE)
            identityHash = sha256(identity)
            codecBytes = canonicalCodec.toByteArray(StandardCharsets.UTF_8)
            codecHash = sha256(codecBytes)
            layoutBytes = layoutVariant.toByteArray(StandardCharsets.UTF_8)
            layoutHash = sha256(layoutBytes)

            val headerMatches =
                (header[OFFSET_VERSION].toInt() and 0xFF) == FORMAT_VERSION &&
                    (header[OFFSET_KIND].toInt() and 0xFF) == kind.id &&
                    readInt(header, OFFSET_PAGE_INDEX) == pageIndex &&
                    constantTimeEquals(header, OFFSET_COMMITMENT, commitment) &&
                    constantTimeEquals(header, OFFSET_IDENTITY_HASH, identityHash) &&
                    constantTimeEquals(header, OFFSET_EVALUATOR_FINGERPRINT, fingerprint) &&
                    constantTimeEquals(header, OFFSET_CODEC_HASH, codecHash) &&
                    constantTimeEquals(header, OFFSET_LAYOUT_HASH, layoutHash) &&
                    constantTimeEquals(header, OFFSET_LOCATOR, locator)
            if (!headerMatches) return null

            aad = buildAad(
                commitment = commitment,
                identity = identity,
                pageIndex = pageIndex,
                kind = kind,
                fingerprint = fingerprint,
                codecBytes = codecBytes,
                layoutBytes = layoutBytes,
                locator = locator,
                header = header,
                prefix = prefix,
                suffix = suffix,
            )
            key = dek.copyOf()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(key, "AES"),
                GCMParameterSpec(GCM_TAG_SIZE * 8, nonce),
            )
            cipher.updateAAD(aad)
            plain = cipher.doFinal(encoded, bodyOffset, declaredBodyLength)
            if (plain.size != declaredPlainLength) return null

            val result = plain
            plain = null
            return result
        } catch (_: Exception) {
            return null
        } finally {
            header?.fill(0)
            nonce?.fill(0)
            identityHash?.fill(0)
            codecBytes?.fill(0)
            codecHash?.fill(0)
            layoutBytes?.fill(0)
            layoutHash?.fill(0)
            prefix?.fill(0)
            suffix?.fill(0)
            aad?.fill(0)
            key?.fill(0)
            plain?.fill(0)
        }
    }

    private fun frame(
        layout: AkenPageLayout,
        prefix: ByteArray,
        header: ByteArray,
        body: ByteArray,
        suffix: ByteArray,
    ): ByteArray {
        val encoded = ByteArray(layout.encodedLength(body.size))
        var offset = 0
        prefix.copyInto(encoded, offset)
        offset += prefix.size
        if (layout.headerAfterBody) {
            body.copyInto(encoded, offset)
            offset += body.size
            header.copyInto(encoded, offset)
            offset += header.size
        } else {
            header.copyInto(encoded, offset)
            offset += header.size
            body.copyInto(encoded, offset)
            offset += body.size
        }
        suffix.copyInto(encoded, offset)
        offset += suffix.size
        check(offset == encoded.size) { "AKEN frame length mismatch" }
        return encoded
    }

    private fun buildAad(
        commitment: ByteArray,
        identity: ByteArray,
        pageIndex: Int,
        kind: AkenResourceKind,
        fingerprint: ByteArray,
        codecBytes: ByteArray,
        layoutBytes: ByteArray,
        locator: ByteArray,
        header: ByteArray,
        prefix: ByteArray,
        suffix: ByteArray,
    ): ByteArray {
        val total = AAD_DOMAIN.size.toLong() +
            commitment.size.toLong() +
            framedLength(identity) +
            Int.SIZE_BYTES.toLong() +
            1L +
            fingerprint.size.toLong() +
            framedLength(codecBytes) +
            framedLength(layoutBytes) +
            locator.size.toLong() +
            framedLength(header) +
            framedLength(prefix) +
            framedLength(suffix)
        require(total <= Int.MAX_VALUE) { "AKEN AAD is too large" }

        val aad = ByteArray(total.toInt())
        var offset = 0
        AAD_DOMAIN.copyInto(aad, offset)
        offset += AAD_DOMAIN.size
        commitment.copyInto(aad, offset)
        offset += commitment.size
        offset = writeFramed(aad, offset, identity)
        writeInt(aad, offset, pageIndex)
        offset += Int.SIZE_BYTES
        aad[offset++] = kind.id.toByte()
        fingerprint.copyInto(aad, offset)
        offset += fingerprint.size
        offset = writeFramed(aad, offset, codecBytes)
        offset = writeFramed(aad, offset, layoutBytes)
        locator.copyInto(aad, offset)
        offset += locator.size
        offset = writeFramed(aad, offset, header)
        offset = writeFramed(aad, offset, prefix)
        offset = writeFramed(aad, offset, suffix)
        check(offset == aad.size) { "AKEN AAD framing length mismatch" }
        return aad
    }

    private fun framedLength(value: ByteArray): Long = Int.SIZE_BYTES.toLong() + value.size.toLong()

    private fun writeFramed(target: ByteArray, offset: Int, value: ByteArray): Int {
        writeInt(target, offset, value.size)
        value.copyInto(target, offset + Int.SIZE_BYTES)
        return offset + Int.SIZE_BYTES + value.size
    }

    private fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

    private fun constantTimeEquals(source: ByteArray, offset: Int, expected: ByteArray): Boolean {
        if (offset < 0 || offset + expected.size > source.size) return false
        var difference = 0
        for (index in expected.indices) {
            difference = difference or ((source[offset + index].toInt() xor expected[index].toInt()) and 0xFF)
        }
        return difference == 0
    }

    private fun writeInt(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 24).toByte()
        target[offset + 1] = (value ushr 16).toByte()
        target[offset + 2] = (value ushr 8).toByte()
        target[offset + 3] = value.toByte()
    }

    private fun readInt(source: ByteArray, offset: Int): Int =
        ((source[offset].toInt() and 0xFF) shl 24) or
            ((source[offset + 1].toInt() and 0xFF) shl 16) or
            ((source[offset + 2].toInt() and 0xFF) shl 8) or
            (source[offset + 3].toInt() and 0xFF)
}
