package io.github.hht0rro.javashroud.transforms.protection

import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Build-time envelope for the material which must only become available after
 * the deployment supplies its boot KEK.  The envelope is safe to distribute;
 * the KEK is deliberately obtained outside the output artifact.
 */
internal object BootMaterialEnvelope {
    const val RESOURCE_PATH: String = "META-INF/.r/boot.dat"
    private const val VERSION = 2
    private const val SHELL_BINDING_SIZE = 32
    private val MAGIC = byteArrayOf(0x4A, 0x53, 0x42, 0x4D) // JSBM
    private val AAD = "javashroud-boot-material-v2".toByteArray(Charsets.US_ASCII)
    private val PLATFORM_IDS = linkedMapOf(
        "windows-x64" to 1,
        "linux-x64" to 2,
        "macos-x64" to 3,
        "macos-arm64" to 4,
    )

    fun encode(
        context: Vbc4BuildContext,
        bootSecret: ByteArray,
        shellBindingCommitments: Map<String, ByteArray> = emptyMap(),
    ): ByteArray {
        require(bootSecret.size == 32) { "boot KEK must be exactly 32 bytes" }
        val partitions = context.runtimeKeyPartitions
        require(partitions.totalSlots in 2..17) { "boot material slot count is unsupported" }
        require(shellBindingCommitments.size <= PLATFORM_IDS.size) { "too many native shell binding commitments" }
        val platformBindings = shellBindingCommitments.map { (platform, commitment) ->
            val platformId = PLATFORM_IDS[platform]
                ?: throw IllegalArgumentException("native shell binding platform is unsupported: $platform")
            require(commitment.size == SHELL_BINDING_SIZE && commitment.any { it.toInt() != 0 }) {
                "native shell binding commitment for $platform must be a non-zero 32-byte value"
            }
            platformId to commitment
        }.sortedBy { it.first }
        val plain = ByteArray(4 + 64 + partitions.totalSlots * 32 + platformBindings.size * (1 + SHELL_BINDING_SIZE))
        plain[0] = VERSION.toByte()
        plain[1] = partitions.resourcePartitionCount.toByte()
        plain[2] = partitions.totalSlots.toByte()
        plain[3] = platformBindings.size.toByte()
        context.masterKey.copyInto(plain, destinationOffset = 4)
        context.jarLayoutDigest.copyInto(plain, destinationOffset = 36)
        for (slot in 0 until partitions.totalSlots) {
            val key = partitions.copyKeyForSlot(slot)
            try {
                key.copyInto(plain, destinationOffset = 68 + slot * 32)
            } finally {
                Arrays.fill(key, 0)
            }
        }
        var bindingOffset = 68 + partitions.totalSlots * 32
        for ((platformId, commitment) in platformBindings) {
            plain[bindingOffset++] = platformId.toByte()
            commitment.copyInto(plain, destinationOffset = bindingOffset)
            bindingOffset += SHELL_BINDING_SIZE
        }
        val nonce = ByteArray(12)
        var sealed = ByteArray(0)
        return try {
            SecureRandom().nextBytes(nonce)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(bootSecret, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(AAD)
            sealed = cipher.doFinal(plain)
            ByteArrayOutputStream(MAGIC.size + 2 + nonce.size + 4 + sealed.size).apply {
                write(MAGIC)
                write(VERSION)
                write(nonce.size)
                write(nonce)
                writeLe32(sealed.size)
                write(sealed)
            }.toByteArray()
        } finally {
            Arrays.fill(plain, 0)
            Arrays.fill(nonce, 0)
            Arrays.fill(sealed, 0)
        }
    }

    private fun ByteArrayOutputStream.writeLe32(value: Int) {
        write(value and 0xFF)
        write((value ushr 8) and 0xFF)
        write((value ushr 16) and 0xFF)
        write((value ushr 24) and 0xFF)
    }

}
