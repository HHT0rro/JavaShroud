package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import java.security.MessageDigest
import java.util.Arrays

/**
 * Per-build VM dialect consumed by parser, verifier and executor.
 * Opcode numbers, operand mix, aliases, super-ops and handler order all bind
 * to authenticated build material. Cross-build reuse must fail.
 */
internal class VmDialectDescriptor private constructor(
    val encode: IntArray,
    val decode: IntArray,
    val handlerOrder: IntArray,
    val operandMix: Int,
    val dispatchFamily: Int,
    val fusedOpcode: Int,
    val commitment: ByteArray,
) {
    fun encodeOpcode(semantic: Int): Int {
        val key = semantic and 0xFFFF
        val mapped = encode[key]
        return if (mapped >= 0) mapped else key
    }

    fun decodeOpcode(encoded: Int): Int {
        val key = encoded and 0xFFFF
        val mapped = decode[key]
        return if (mapped >= 0) mapped else key
    }

    companion object {
        const val TABLE_SIZE = 65536
        const val FUSED_IADD_DUP = 0x1F0
        private val DOMAIN = "javashroud-aken-r1-vm-dialect-v1".toByteArray(Charsets.US_ASCII)

        private val LIVE_OPCODES: IntArray = intArrayOf(
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
            0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
            0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
            0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
            0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
            0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0xf2, 0xf3, 0xf6, 0xf7,
            0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
        )

        fun fromBuildContext(context: Vbc4BuildContext): VmDialectDescriptor {
            val crypto = io.github.hht0rro.javashroud.transforms.protection.AkenVbc4InnerMaterial.copyCryptoDomainMaterial(context)
            val layout = io.github.hht0rro.javashroud.transforms.protection.AkenVbc4InnerMaterial.copyStateBindingLayoutDigest(context)
            try {
                return fromKeyMaterial(crypto, layout)
            } finally {
                Arrays.fill(crypto, 0)
                Arrays.fill(layout, 0)
            }
        }

        fun fromKeyMaterial(cryptoDomainMaterial: ByteArray, layoutDigest: ByteArray): VmDialectDescriptor {
            val stream = expandStream(cryptoDomainMaterial, layoutDigest)
            try {
                return fromStream(stream)
            } finally {
                Arrays.fill(stream, 0)
            }
        }

        private fun expandStream(cryptoDomainMaterial: ByteArray, layoutDigest: ByteArray): ByteArray {
            val out = ByteArray(4096)
            var offset = 0
            var counter = 1
            while (offset < out.size) {
                val mac = javax.crypto.Mac.getInstance("HmacSHA256")
                mac.init(javax.crypto.spec.SecretKeySpec(cryptoDomainMaterial, "HmacSHA256"))
                mac.update(DOMAIN)
                mac.update(layoutDigest)
                mac.update(counter.toByte())
                val block = mac.doFinal()
                val take = minOf(block.size, out.size - offset)
                block.copyInto(out, offset, 0, take)
                Arrays.fill(block, 0)
                offset += take
                counter++
            }
            return out
        }

        internal fun fromStream(stream: ByteArray): VmDialectDescriptor {
            require(stream.size >= 256) { "VM dialect stream is truncated" }
            val live = LIVE_OPCODES.copyOf()
            var offset = 0
            for (i in live.size - 1 downTo 1) {
                val take = ((stream[offset].toInt() and 0xFF) shl 8) or (stream[offset + 1].toInt() and 0xFF)
                offset = (offset + 2) % (stream.size - 1)
                val j = take % (i + 1)
                val tmp = live[i]
                live[i] = live[j]
                live[j] = tmp
            }
            val encode = IntArray(TABLE_SIZE) { -1 }
            val decode = IntArray(TABLE_SIZE) { -1 }
            for (index in LIVE_OPCODES.indices) {
                val semantic = LIVE_OPCODES[index]
                val encoded = live[index]
                encode[semantic] = encoded
                decode[encoded] = semantic
            }
            encode[FUSED_IADD_DUP] = FUSED_IADD_DUP xor (stream[0].toInt() and 0x7F) or 0x100
            decode[encode[FUSED_IADD_DUP]] = FUSED_IADD_DUP
            val handlerOrder = IntArray(live.size) { live[it] }
            val operandMix = stream[32].toInt() and 0xFF
            val dispatchFamily = stream[33].toInt() and 3
            val fusedOpcode = encode[FUSED_IADD_DUP]
            val commitment = MessageDigest.getInstance("SHA-256").apply {
                update(DOMAIN)
                live.forEach { opcode ->
                    update(((opcode ushr 8) and 0xFF).toByte())
                    update((opcode and 0xFF).toByte())
                }
                update(operandMix.toByte())
                update(dispatchFamily.toByte())
            }.digest()
            return VmDialectDescriptor(encode, decode, handlerOrder, operandMix, dispatchFamily, fusedOpcode, commitment)
        }
    }
}
