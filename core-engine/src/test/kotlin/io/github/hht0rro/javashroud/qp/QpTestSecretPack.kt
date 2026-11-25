package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.NativeVmSecretPackDraft

/** Deterministic test secret pack; material is fixed and never production. */
internal fun testSecretPackDraft(): NativeVmSecretPackDraft {
    val ikm = ByteArray(32) { (it + 17).toByte() }
    return try {
        NativeVmSecretPackDraft.create(NativeVmSecretPackDraft.derivePackRoot(ikm))
    } finally {
        ikm.fill(0)
    }
}
