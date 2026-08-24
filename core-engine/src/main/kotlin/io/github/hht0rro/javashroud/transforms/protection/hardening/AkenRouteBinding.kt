package io.github.hht0rro.javashroud.transforms.protection.hardening

import java.security.MessageDigest
import java.util.Arrays

/**
 * Canonical commitment for page-open, catalog-open, VM dispatch and typed JNI routes.
 * Any mismatched field must fail closed and wipe sensitive copies.
 */
internal class AkenRouteBinding private constructor(
    val artifactDigest: ByteArray,
    val resourceKind: String,
    val routeId: ByteArray,
    val descriptorDigest: ByteArray,
    val handleDigest: ByteArray,
    val callSiteProof: ByteArray,
    val sessionLeaf: ByteArray,
    val pageCommitment: ByteArray,
) {
    val commitment: ByteArray = digestCanonical()

    fun matches(other: AkenRouteBinding): Boolean {
        return MessageDigest.isEqual(commitment, other.commitment)
    }

    fun wipe() {
        artifactDigest.fill(0)
        routeId.fill(0)
        descriptorDigest.fill(0)
        handleDigest.fill(0)
        callSiteProof.fill(0)
        sessionLeaf.fill(0)
        pageCommitment.fill(0)
        commitment.fill(0)
    }

    private fun digestCanonical(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(DOMAIN)
        digest.update(ProtectionFormat.CURRENT.toByteArray(Charsets.US_ASCII))
        digest.update(artifactDigest)
        digest.update(resourceKind.toByteArray(Charsets.US_ASCII))
        digest.update(routeId)
        digest.update(descriptorDigest)
        digest.update(handleDigest)
        digest.update(callSiteProof)
        digest.update(sessionLeaf)
        digest.update(pageCommitment)
        return digest.digest()
    }

    companion object {
        private val DOMAIN = "javashroud-aken-r1-route-binding-v1".toByteArray(Charsets.US_ASCII)

        fun create(
            artifactDigest: ByteArray,
            resourceKind: String,
            routeId: ByteArray,
            descriptorDigest: ByteArray,
            handleDigest: ByteArray,
            callSiteProof: ByteArray,
            sessionLeaf: ByteArray,
            pageCommitment: ByteArray,
        ): AkenRouteBinding {
            require(artifactDigest.size == 32) { "artifact digest must be 32 bytes" }
            require(descriptorDigest.size == 32) { "descriptor digest must be 32 bytes" }
            require(handleDigest.size == 32) { "handle digest must be 32 bytes" }
            require(callSiteProof.size == 32) { "call-site proof must be 32 bytes" }
            require(sessionLeaf.size == 32) { "session leaf must be 32 bytes" }
            require(pageCommitment.size == 32) { "page commitment must be 32 bytes" }
            require(routeId.isNotEmpty() && routeId.size <= 64) { "route id length is invalid" }
            require(resourceKind.isNotBlank() && resourceKind.length <= 64) { "resource kind is invalid" }
            return AkenRouteBinding(
                artifactDigest = artifactDigest.copyOf(),
                resourceKind = resourceKind,
                routeId = routeId.copyOf(),
                descriptorDigest = descriptorDigest.copyOf(),
                handleDigest = handleDigest.copyOf(),
                callSiteProof = callSiteProof.copyOf(),
                sessionLeaf = sessionLeaf.copyOf(),
                pageCommitment = pageCommitment.copyOf(),
            )
        }

        fun sha256(value: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(value)

        fun sha256(value: String): ByteArray = sha256(value.toByteArray(Charsets.UTF_8))
    }
}
