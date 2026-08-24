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
    private val cryptoDomainLabel =
        "javashroud-aken-r1-vbc4-inner-crypto-v3".toByteArray(Charsets.US_ASCII)
    private val stateBindingLayoutLabel =
        "javashroud-aken-r1-vbc4-inner-state-binding-v3".toByteArray(Charsets.US_ASCII)
    private val vmBuildKeyDomain =
        "javashroud-aken-r1-vm-build-key-v3".toByteArray(Charsets.US_ASCII)

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
