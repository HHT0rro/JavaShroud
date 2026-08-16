package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64

/**
 * Build-only ClassPage source captured before artifact sealing has assigned
 * its final resource path.
 *
 * A generated string bootstrap already owns the opaque handle and proof when
 * this candidate is created. The candidate deliberately has no runtime
 * descriptor, locator record, evaluator graph, or DEK; it is copied only
 * inside the active build context, projected into a route-safe reference for
 * sealing, then converted to [AkenPendingClassPage] after a final route is
 * reserved.
 */
internal class AkenClassPageCandidate private constructor(
    val pageIndex: Int,
    val targetPageSize: Int,
    val layoutVariant: String,
    logicalIdentity: ByteArray,
    plaintext: ByteArray,
    callSiteProof: ByteArray,
    encodedHandle: ByteArray,
    val logicalBindingPath: String,
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var plaintextValue: ByteArray = plaintext.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()
    private var encodedHandleValue: ByteArray = encodedHandle.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(logicalIdentityValue.isNotEmpty()) { "AKEN ClassPage candidate identity must not be empty" }
        require(plaintextValue.isNotEmpty()) { "AKEN ClassPage candidate plaintext must not be empty" }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "AKEN ClassPage candidate call-site proof length is invalid"
        }
        require(encodedHandleValue.size == AkenHandle.ENCODED_HANDLE_SIZE) {
            "AKEN ClassPage candidate handle length is invalid"
        }
        require(pageIndex >= 0) { "AKEN ClassPage candidate page index must be non-negative" }
        require(targetPageSize in AkenPageSizePolicy.DEFAULT.allowedSizes(AkenResourceKind.EncryptedClassPage)) {
            "AKEN ClassPage candidate target size is unsupported"
        }
        AkenVbc4RouteCandidateRef.requireValidArtifactEntryPath(
            value = logicalBindingPath,
            label = "AKEN ClassPage candidate logical binding path",
        )
        validateLayout(layoutVariant)
    }

    val isWiped: Boolean
        get() = wiped

    internal fun copyLogicalIdentityForBuild(): ByteArray {
        requireLive()
        return logicalIdentityValue.copyOf()
    }

    internal fun copyPlaintextForBuild(): ByteArray {
        requireLive()
        return plaintextValue.copyOf()
    }

    internal fun copyCallSiteProofForBuild(): ByteArray {
        requireLive()
        return callSiteProofValue.copyOf()
    }

    internal fun copyEncodedHandleForBuild(): ByteArray {
        requireLive()
        return encodedHandleValue.copyOf()
    }

    internal fun identityPageKeyForBuild(): String {
        requireLive()
        return akenClassPageIdentityPageKey(logicalIdentityValue, pageIndex)
    }

    internal fun copyForBuild(): AkenClassPageCandidate {
        requireLive()
        return AkenClassPageCandidate(
            pageIndex = pageIndex,
            targetPageSize = targetPageSize,
            layoutVariant = layoutVariant,
            logicalIdentity = logicalIdentityValue,
            plaintext = plaintextValue,
            callSiteProof = callSiteProofValue,
            encodedHandle = encodedHandleValue,
            logicalBindingPath = logicalBindingPath,
        )
    }

    /**
     * Converts this logical candidate into one final-route pending page.
     * The caller owns and wipes the returned page and this candidate
     * independently so a broader finalization transaction can fail closed.
     */
    internal fun toPendingPage(route: AkenClassPagePreSealRoute): AkenPendingClassPage {
        requireLive()
        require(route.identityPageKey == identityPageKeyForBuild()) {
            "AKEN ClassPage pre-seal route does not match its candidate identity"
        }
        require(route.logicalBindingPath == logicalBindingPath) {
            "AKEN ClassPage pre-seal route does not match its logical binding path"
        }
        val identity = logicalIdentityValue.copyOf()
        val plaintext = plaintextValue.copyOf()
        val proof = callSiteProofValue.copyOf()
        val handle = encodedHandleValue.copyOf()
        return try {
            AkenPendingClassPage.create(
                logicalIdentity = identity,
                plaintext = plaintext,
                resourcePath = route.futureResourcePath,
                pageIndex = pageIndex,
                callSiteProof = proof,
                encodedHandle = handle,
                resourceOffset = 0,
                layoutVariant = layoutVariant,
                targetPageSize = targetPageSize,
                logicalBindingPath = logicalBindingPath,
            )
        } finally {
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(handle, 0)
        }
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(logicalIdentityValue, 0)
        Arrays.fill(plaintextValue, 0)
        Arrays.fill(callSiteProofValue, 0)
        Arrays.fill(encodedHandleValue, 0)
        logicalIdentityValue = ByteArray(0)
        plaintextValue = ByteArray(0)
        callSiteProofValue = ByteArray(0)
        encodedHandleValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN ClassPage candidate has been wiped" }
    }

    companion object {
        private const val MAX_CALL_SITE_PROOF_SIZE = 4096

        fun create(
            logicalIdentity: ByteArray,
            plaintext: ByteArray,
            pageIndex: Int,
            callSiteProof: ByteArray,
            encodedHandle: ByteArray,
            logicalBindingPath: String,
            layoutVariant: String? = null,
            targetPageSize: Int? = null,
            random: SecureRandom = SecureRandom(),
        ): AkenClassPageCandidate {
            targetPageSize?.let { requestedTargetSize ->
                require(requestedTargetSize in AkenPageSizePolicy.DEFAULT.allowedSizes(AkenResourceKind.EncryptedClassPage)) {
                    "AKEN requested ClassPage target size is unsupported"
                }
            }
            var generatedLayout: AkenPageLayout? = null
            val selectedVariant = try {
                layoutVariant ?: AkenPageLayout.create("class", random).also { generatedLayout = it }.variant
            } finally {
                generatedLayout?.wipe()
            }
            return AkenClassPageCandidate(
                pageIndex = pageIndex,
                targetPageSize = targetPageSize
                    ?: AkenPageSizePolicy.DEFAULT.choose(AkenResourceKind.EncryptedClassPage, random),
                layoutVariant = selectedVariant,
                logicalIdentity = logicalIdentity,
                plaintext = plaintext,
                callSiteProof = callSiteProof,
                encodedHandle = encodedHandle,
                logicalBindingPath = logicalBindingPath,
            )
        }

        private fun validateLayout(variant: String) {
            var layout: AkenPageLayout? = null
            try {
                layout = AkenPageLayout.fromVariant(variant)
            } finally {
                layout?.wipe()
            }
        }
    }
}

/** Build-only route correlation key for one logical encrypted class page. */
internal fun akenClassPageIdentityPageKey(
    logicalIdentity: ByteArray,
    pageIndex: Int,
): String {
    require(logicalIdentity.isNotEmpty()) { "AKEN ClassPage route identity must not be empty" }
    require(pageIndex >= 0) { "AKEN ClassPage route page index must be non-negative" }
    val digest = MessageDigest.getInstance("SHA-256").apply {
        update(CLASS_PAGE_IDENTITY_KEY_DOMAIN)
        update(AkenResourceKind.EncryptedClassPage.id.toByte())
        updateInt(this, pageIndex)
        updateFramed(this, logicalIdentity)
    }.digest()
    return try {
        Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    } finally {
        Arrays.fill(digest, 0)
    }
}

private val CLASS_PAGE_IDENTITY_KEY_DOMAIN =
    "AKEN-v4-encrypted-class-page-route-key-v1".toByteArray(Charsets.US_ASCII)

private fun updateFramed(digest: MessageDigest, value: ByteArray) {
    updateInt(digest, value.size)
    digest.update(value)
}

private fun updateInt(digest: MessageDigest, value: Int) {
    digest.update((value ushr 24).toByte())
    digest.update((value ushr 16).toByte())
    digest.update((value ushr 8).toByte())
    digest.update(value.toByte())
}
