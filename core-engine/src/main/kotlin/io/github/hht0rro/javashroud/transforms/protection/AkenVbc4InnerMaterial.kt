package io.github.hht0rro.javashroud.transforms.protection

import java.security.MessageDigest
import java.util.Arrays

/**
 * Public, deterministic compatibility material used only by the inner VBC4
 * frame codec after an AKEN v4 page evaluator has opened the page.
 *
 * This is deliberately not a build root, DEK, slot key, or external secret.
 * AKEN's per-page evaluator remains the confidentiality and authenticity
 * boundary; these values merely keep the legacy VBC4 frame grammar
 * deterministic without reviving a boot-material dependency.
 */
internal object AkenVbc4InnerMaterial {
    private val cryptoDomainLabel =
        "javashroud-aken-v4-vbc4-inner-crypto-public-v1".toByteArray(Charsets.US_ASCII)
    private val stateBindingLayoutLabel =
        "javashroud-aken-v4-vbc4-inner-state-binding-public-v1".toByteArray(Charsets.US_ASCII)
    private val vmBuildKeyDomain =
        "javashroud-vbc4-vm-build-key-v1".toByteArray(Charsets.US_ASCII)

    fun copyCryptoDomainMaterial(): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(cryptoDomainLabel)

    fun copyStateBindingLayoutDigest(): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(stateBindingLayoutLabel)

    /**
     * Mirrors the native VBC4 build-key derivation with public compatibility
     * material, so VBC4 string constants and runtime session metadata do not
     * require BootMaterialEnvelope state.
     */
    fun deriveVmBuildKey(): ByteArray {
        val cryptoDomainMaterial = copyCryptoDomainMaterial()
        val stateBindingLayoutDigest = copyStateBindingLayoutDigest()
        return try {
            hkdfSha256(
                ikm = cryptoDomainMaterial,
                salt = vmBuildKeyDomain,
                info = stateBindingLayoutDigest,
                length = 32,
            )
        } finally {
            Arrays.fill(cryptoDomainMaterial, 0)
            Arrays.fill(stateBindingLayoutDigest, 0)
        }
    }
}
