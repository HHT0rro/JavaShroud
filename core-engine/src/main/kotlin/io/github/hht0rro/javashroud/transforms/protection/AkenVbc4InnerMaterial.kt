package io.github.hht0rro.javashroud.transforms.protection

import java.util.Arrays

/**
 * Build-scoped material for the VBC4 inner frame codec.
 *
 * The outer AKEN page remains the runtime confidentiality boundary, while
 * these values bind the deterministic inner grammar to one build artifact.
 * Domain labels are HKDF separation labels only; they are never key material.
 */
internal object AkenVbc4InnerMaterial {
    private val cryptoDomainLabel = byteArrayOf(
        0x30, 0x3b, 0x2c, 0x3b, 0x29, 0x32, 0x28, 0x35, 0x2f, 0x3e, 0x77, 0x3b, 0x31, 0x3f, 0x34,
        0x77, 0x28, 0x6b, 0x77, 0x2c, 0x38, 0x39, 0x6e, 0x77, 0x33, 0x34, 0x34, 0x3f, 0x28, 0x77,
        0x39, 0x28, 0x23, 0x2a, 0x2e, 0x35, 0x77, 0x2c, 0x69,
    )
    private val stateBindingLayoutLabel = byteArrayOf(
        0x30, 0x3b, 0x2c, 0x3b, 0x29, 0x32, 0x28, 0x35, 0x2f, 0x3e, 0x77, 0x3b, 0x31, 0x3f, 0x34,
        0x77, 0x28, 0x6b, 0x77, 0x2c, 0x38, 0x39, 0x6e, 0x77, 0x33, 0x34, 0x34, 0x3f, 0x28, 0x77,
        0x29, 0x2e, 0x3b, 0x2e, 0x3f, 0x77, 0x38, 0x33, 0x34, 0x3e, 0x33, 0x34, 0x3d, 0x77, 0x2c, 0x69,
    )
    private val vmBuildKeyDomain = byteArrayOf(
        0x30, 0x3b, 0x2c, 0x3b, 0x29, 0x32, 0x28, 0x35, 0x2f, 0x3e, 0x77, 0x3b, 0x31, 0x3f, 0x34,
        0x77, 0x28, 0x6b, 0x77, 0x2c, 0x37, 0x77, 0x38, 0x2f, 0x33, 0x36, 0x3e, 0x77, 0x31, 0x3f,
        0x23, 0x77, 0x2c, 0x69,
    )

    fun copyCryptoDomainMaterial(context: Vbc4BuildContext): ByteArray {
        val stateDigest = copyStateBindingLayoutDigest(context)
        return try {
            hkdfSha256(
                ikm = stateDigest,
                salt = cryptoDomainLabel,
                info = ByteArray(0),
                length = VBC4_MASTER_KEY_SIZE,
            )
        } finally {
            Arrays.fill(stateDigest, 0)
        }
    }

    fun copyStateBindingLayoutDigest(context: Vbc4BuildContext): ByteArray {
        val masterKey = context.copyMasterKey()
        val layoutDigest = context.jarLayoutDigest.copyOf()
        val cryptoMaterial = try {
            hkdfSha256(
                ikm = masterKey,
                salt = stateBindingLayoutLabel,
                info = layoutDigest,
                length = VBC4_LAYOUT_DIGEST_SIZE,
            )
        } finally {
            Arrays.fill(masterKey, 0)
            Arrays.fill(layoutDigest, 0)
        }
        return cryptoMaterial
    }

    fun copyStateBindingLayoutDigest(): ByteArray =
        copyStateBindingLayoutDigest(requireVbc4BuildContext())

    fun deriveVmBuildKey(context: Vbc4BuildContext): ByteArray {
        val cryptoMaterial = copyCryptoDomainMaterial(context)
        val stateDigest = copyStateBindingLayoutDigest(context)
        return try {
            hkdfSha256(
                ikm = cryptoMaterial,
                salt = vmBuildKeyDomain,
                info = stateDigest,
                length = VBC4_MASTER_KEY_SIZE,
            )
        } finally {
            Arrays.fill(cryptoMaterial, 0)
            Arrays.fill(stateDigest, 0)
        }
    }
}
