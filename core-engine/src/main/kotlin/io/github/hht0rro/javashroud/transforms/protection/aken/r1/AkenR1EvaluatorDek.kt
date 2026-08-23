package io.github.hht0rro.javashroud.transforms.protection.aken.r1

import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** Current-page seven-share evaluator DEK wrap used by the AKEN-R1 native runtime. */
internal object AkenR1EvaluatorDek {
    const val MAGIC: String = "AKEN-R1/Eval7/v1"
    const val SHARE_COUNT: Int = 7
    const val TAG_SIZE: Int = 8
    const val STATE_WIDTH: Int = 32

    private val MAGIC_BYTES = MAGIC.toByteArray(Charsets.US_ASCII)
    private val SHARE_DOMAIN = "JavaShroud/AKEN-R1/EvaluatorShare/v1".toByteArray(Charsets.US_ASCII)
    private val TAG_DOMAIN = "JavaShroud/AKEN-R1/EvaluatorShareTag/v1".toByteArray(Charsets.US_ASCII)

    fun wrap(dek: ByteArray, fingerprint: ByteArray): ByteArray {
        require(dek.size == STATE_WIDTH) { "AKEN-R1 evaluator DEK must be 32 bytes" }
        require(fingerprint.size == STATE_WIDTH) { "AKEN-R1 evaluator fingerprint must be 32 bytes" }
        val shares = Array(SHARE_COUNT) { ByteArray(STATE_WIDTH) }
        val terminal = dek.copyOf()
        try {
            for (index in 0 until SHARE_COUNT - 1) {
                hmac(fingerprint, SHARE_DOMAIN, dek, byteArrayOf(index.toByte())).copyInto(shares[index])
                xorInto(terminal, shares[index])
            }
            shares[SHARE_COUNT - 1] = terminal.copyOf()
            val opaque = ByteArray(MAGIC_BYTES.size + SHARE_COUNT * STATE_WIDTH + TAG_SIZE)
            MAGIC_BYTES.copyInto(opaque)
            var offset = MAGIC_BYTES.size
            shares.forEach { share ->
                share.copyInto(opaque, offset)
                offset += STATE_WIDTH
            }
            val tag = hmac(fingerprint, TAG_DOMAIN, opaque.copyOf(MAGIC_BYTES.size + SHARE_COUNT * STATE_WIDTH))
            tag.copyInto(opaque, destinationOffset = offset, endIndex = TAG_SIZE)
            return opaque
        } finally {
            Arrays.fill(terminal, 0)
            shares.forEach { Arrays.fill(it, 0) }
        }
    }

    fun recover(opaque: ByteArray, fingerprint: ByteArray): ByteArray {
        require(fingerprint.size == STATE_WIDTH) { "AKEN-R1 evaluator fingerprint must be 32 bytes" }
        val shareBytes = SHARE_COUNT * STATE_WIDTH
        val expected = MAGIC_BYTES.size + shareBytes + TAG_SIZE
        require(opaque.size == expected && opaque.copyOf(MAGIC_BYTES.size).contentEquals(MAGIC_BYTES)) {
            "AKEN-R1 evaluator page key is missing"
        }
        val tagged = opaque.copyOf(MAGIC_BYTES.size + shareBytes)
        val expectedTag = hmac(fingerprint, TAG_DOMAIN, tagged)
        try {
            require(MessageDigest.isEqual(opaque.copyOfRange(MAGIC_BYTES.size + shareBytes, opaque.size), expectedTag.copyOf(TAG_SIZE))) {
                "AKEN-R1 evaluator share tag is invalid"
            }
            val dek = ByteArray(STATE_WIDTH)
            var offset = MAGIC_BYTES.size
            repeat(SHARE_COUNT) {
                xorInto(dek, opaque.copyOfRange(offset, offset + STATE_WIDTH))
                offset += STATE_WIDTH
            }
            return dek
        } finally {
            Arrays.fill(expectedTag, 0)
            Arrays.fill(tagged, 0)
        }
    }

    private fun hmac(key: ByteArray, vararg fields: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        fields.forEach { mac.update(it) }
        return mac.doFinal()
    }

    private fun xorInto(target: ByteArray, other: ByteArray) {
        for (index in target.indices) {
            target[index] = (target[index].toInt() xor other[index].toInt()).toByte()
        }
    }
}
