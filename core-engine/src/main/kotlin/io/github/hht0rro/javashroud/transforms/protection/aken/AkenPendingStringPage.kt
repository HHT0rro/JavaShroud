package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64

/**
 * Build-only ownership record for one UTF-8 string page whose generated
 * bootstrap has already received its page-specific handle and proof.
 *
 * This record is deliberately not a runtime descriptor. It owns the plaintext,
 * page-local handle binding, proof, frame reservation, and final resource
 * route only until it is converted into an [AkenPageMaterializationInput].
 * The later materializer consumes that input together with the complete build
 * plan and emits the page-local descriptor and ciphertext.
 */
internal class AkenPendingStringPage private constructor(
    val resourcePath: String,
    val resourceOffset: Int,
    val pageIndex: Int,
    val targetPageSize: Int,
    val layoutVariant: String,
    logicalIdentity: ByteArray,
    plaintext: ByteArray,
    callSiteProof: ByteArray,
    val logicalBindingPath: String,
    encodedHandle: ByteArray,
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var plaintextValue: ByteArray = plaintext.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()
    private var encodedHandleValue: ByteArray = encodedHandle.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(logicalIdentityValue.isNotEmpty()) { "AKEN pending StringPage identity must not be empty" }
        require(plaintextValue.isNotEmpty()) { "AKEN pending StringPage plaintext must not be empty" }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "AKEN pending StringPage call-site proof length is invalid"
        }
        require(encodedHandleValue.size == AkenHandle.ENCODED_HANDLE_SIZE) {
            "AKEN pending StringPage handle length is invalid"
        }
        require(pageIndex >= 0) { "AKEN pending StringPage index must be non-negative" }
        require(resourceOffset >= 0) { "AKEN pending StringPage offset must be non-negative" }
        require(isValidArtifactPath(resourcePath)) { "AKEN pending StringPage resource path is invalid" }
        require(isValidArtifactPath(logicalBindingPath)) { "AKEN pending StringPage logical binding path is invalid" }
        require(targetPageSize in AkenPageSizePolicy.DEFAULT.allowedSizes(AkenResourceKind.StringPage)) {
            "AKEN pending StringPage target size is unsupported"
        }
        validateLayout(layoutVariant)
        require(expectedStoredLength > 0) { "AKEN pending StringPage stored length is invalid" }
    }

    val isWiped: Boolean
        get() = wiped

    /** Exact physical page length reserved before the page-local DEK is minted. */
    internal val expectedStoredLength: Int
        get() {
            requireLive()
            var layout: AkenPageLayout? = null
            return try {
                layout = AkenPageLayout.fromVariant(layoutVariant)
                layout.encodedLength(plaintextValue.size + AkenResourceCodec.GCM_TAG_SIZE)
            } finally {
                layout?.wipe()
            }
        }

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

    /**
     * Build-only route-match key. The public handle is intentionally excluded:
     * route ownership follows the logical page identity and page index, while
     * the evaluator graph separately authenticates the handle binding.
     */
    internal fun identityPageKeyForBuild(): String {
        requireLive()
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(IDENTITY_PAGE_KEY_DOMAIN)
        digest.update(AkenResourceKind.StringPage.id.toByte())
        updateInt(digest, pageIndex)
        updateFramed(digest, logicalIdentityValue)
        val encoded = digest.digest()
        return try {
            Base64.getUrlEncoder().withoutPadding().encodeToString(encoded)
        } finally {
            Arrays.fill(encoded, 0)
        }
    }

    /**
     * Creates an owned build-only materialization input and preserves this
     * pending page until the caller has completed the wider finalization
     * transaction. The caller must wipe this record in its surrounding
     * success/failure path.
     */
    internal fun toMaterializationInput(plan: AkenBuildPlan): AkenPageMaterializationInput {
        requireLive()
        val identity = logicalIdentityValue.copyOf()
        val plaintext = plaintextValue.copyOf()
        val proof = callSiteProofValue.copyOf()
        val handle = encodedHandleValue.copyOf()
        return try {
            val page = plan.registerPage(
                kind = AkenResourceKind.StringPage,
                identity = identity,
                pageIndex = pageIndex,
                layoutVariant = layoutVariant,
                targetPageSize = targetPageSize,
                encodedHandleOverride = handle,
            )
            AkenPageMaterializationInput.create(
                page = page,
                plaintext = plaintext,
                resourcePath = resourcePath,
                resourceOffset = resourceOffset,
                callSiteProof = proof,
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
        check(!wiped) { "AKEN pending StringPage has been wiped" }
    }

    companion object {
        private const val MAX_CALL_SITE_PROOF_SIZE = 4096
        private val IDENTITY_PAGE_KEY_DOMAIN =
            "AKEN-v4-pending-string-page-key-v1".toByteArray(Charsets.US_ASCII)

        /**
         * Reserves one StringPage frame. A pre-reserved complete layout variant
         * and target can be supplied by a broader build planner; otherwise this
         * owner generates an independent frame and chooses from the configured
         * StringPage target-size family.
         */
        fun create(
            logicalIdentity: ByteArray,
            plaintext: ByteArray,
            resourcePath: String,
            pageIndex: Int,
            callSiteProof: ByteArray,
            encodedHandle: ByteArray,
            resourceOffset: Int = 0,
            layoutVariant: String? = null,
            targetPageSize: Int? = null,
            random: SecureRandom = SecureRandom(),
            logicalBindingPath: String = resourcePath,
        ): AkenPendingStringPage {
            targetPageSize?.let { requestedTargetSize ->
                require(requestedTargetSize in AkenPageSizePolicy.DEFAULT.allowedSizes(AkenResourceKind.StringPage)) {
                    "AKEN requested StringPage target size is unsupported"
                }
            }
            var generatedLayout: AkenPageLayout? = null
            val selectedVariant = try {
                layoutVariant ?: AkenPageLayout.create("string", random).also { generatedLayout = it }.variant
            } finally {
                generatedLayout?.wipe()
            }
            val selectedTargetPageSize =
                targetPageSize ?: AkenPageSizePolicy.DEFAULT.choose(AkenResourceKind.StringPage, random)
            return AkenPendingStringPage(
                resourcePath = resourcePath,
                resourceOffset = resourceOffset,
                pageIndex = pageIndex,
                targetPageSize = selectedTargetPageSize,
                layoutVariant = selectedVariant,
                logicalIdentity = logicalIdentity,
                plaintext = plaintext,
                callSiteProof = callSiteProof,
                logicalBindingPath = logicalBindingPath,
                encodedHandle = encodedHandle,
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

        private fun isValidArtifactPath(path: String): Boolean {
            if (path.isBlank() || '\u0000' in path || '\\' in path || path.startsWith('/') || path.endsWith('/')) return false
            return path.split('/').all { segment ->
                segment.isNotEmpty() && segment != "." && segment != ".." &&
                    segment.none { character -> character == '\r' || character == '\n' || character == '|' }
            }
        }

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
    }
}
