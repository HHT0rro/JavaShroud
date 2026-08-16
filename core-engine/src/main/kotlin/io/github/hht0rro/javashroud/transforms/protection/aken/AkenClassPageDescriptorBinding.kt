package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.MessageDigest
import java.util.Arrays

/**
 * Build-only link between a generated encrypted class and one of its logical
 * ClassPage candidates. It owns only the class identity, page index, and
 * logical-page identity needed to join a final materialized binding back to
 * one class-local descriptor. It deliberately owns no plaintext, handle,
 * evaluator plan, locator path, or runtime catalog entry.
 */
internal class AkenClassPageDescriptorSource private constructor(
    val internalName: String,
    val pageIndex: Int,
    logicalIdentity: ByteArray,
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(isValidAkenClassPageInternalName(internalName)) {
            "AKEN ClassPage descriptor source internal name is invalid"
        }
        require(pageIndex >= 0) { "AKEN ClassPage descriptor source index must be non-negative" }
        require(logicalIdentityValue.isNotEmpty()) {
            "AKEN ClassPage descriptor source logical identity must not be empty"
        }
    }

    internal val isWiped: Boolean
        get() = wiped

    /**
     * Build-only correlation key shared with the class-page candidate and final
     * materialized binding. It is never emitted as a runtime lookup table.
     */
    internal fun identityPageKeyForBuild(): String {
        requireLive()
        return akenClassPageIdentityPageKey(logicalIdentityValue, pageIndex)
    }

    internal fun copyLogicalIdentityForBuild(): ByteArray {
        requireLive()
        return logicalIdentityValue.copyOf()
    }

    internal fun copyForBuild(): AkenClassPageDescriptorSource {
        requireLive()
        return AkenClassPageDescriptorSource(internalName, pageIndex, logicalIdentityValue)
    }

    /**
     * Confirms that a final ClassPage binding belongs to exactly this logical
     * class page. The comparison remains build-only and does not expose either
     * owner beyond the callback scope.
     */
    internal fun matchesBindingForBuild(binding: AkenClassPageBinding): Boolean {
        if (wiped) return false
        var identity: ByteArray? = null
        return try {
            identity = binding.copyLogicalIdentityForBuild()
            pageIndex == binding.pageIndex && MessageDigest.isEqual(logicalIdentityValue, identity)
        } catch (_: IllegalStateException) {
            false
        } finally {
            identity?.let { Arrays.fill(it, 0) }
        }
    }

    override fun close() = wipe()

    internal fun wipe() {
        if (wiped) return
        Arrays.fill(logicalIdentityValue, 0)
        logicalIdentityValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN ClassPage descriptor source has been wiped" }
    }

    internal companion object {
        fun create(
            internalName: String,
            pageIndex: Int,
            logicalIdentity: ByteArray,
        ): AkenClassPageDescriptorSource = AkenClassPageDescriptorSource(
            internalName = internalName,
            pageIndex = pageIndex,
            logicalIdentity = logicalIdentity,
        )

        fun fromCandidate(
            internalName: String,
            candidate: AkenClassPageCandidate,
        ): AkenClassPageDescriptorSource {
            val logicalIdentity = candidate.copyLogicalIdentityForBuild()
            return try {
                create(
                    internalName = internalName,
                    pageIndex = candidate.pageIndex,
                    logicalIdentity = logicalIdentity,
                )
            } finally {
                Arrays.fill(logicalIdentity, 0)
            }
        }
    }
}

/**
 * One finalized encrypted ClassPage binding projected from the unified AKEN
 * materialization. The owner is callback-scoped and wiped as soon as the
 * caller finishes constructing class-local descriptor bytes.
 */
internal class AkenClassPageBinding private constructor(
    val pageIndex: Int,
    logicalIdentity: ByteArray,
    encodedHandle: ByteArray,
    callSiteProof: ByteArray,
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var encodedHandleValue: ByteArray = encodedHandle.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(pageIndex >= 0) { "AKEN ClassPage binding index must be non-negative" }
        require(logicalIdentityValue.isNotEmpty()) {
            "AKEN ClassPage binding logical identity must not be empty"
        }
        require(encodedHandleValue.size == AkenHandle.ENCODED_HANDLE_SIZE) {
            "AKEN ClassPage binding handle length is invalid"
        }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "AKEN ClassPage binding call-site proof length is invalid"
        }
    }

    internal val isWiped: Boolean
        get() = wiped

    internal fun identityPageKeyForBuild(): String {
        requireLive()
        return akenClassPageIdentityPageKey(logicalIdentityValue, pageIndex)
    }

    internal fun copyLogicalIdentityForBuild(): ByteArray {
        requireLive()
        return logicalIdentityValue.copyOf()
    }

    internal fun copyEncodedHandleForBuild(): ByteArray {
        requireLive()
        return encodedHandleValue.copyOf()
    }

    internal fun copyCallSiteProofForBuild(): ByteArray {
        requireLive()
        return callSiteProofValue.copyOf()
    }

    internal fun matchesForBuild(
        pageIndex: Int,
        logicalIdentity: ByteArray,
        encodedHandle: ByteArray,
        callSiteProof: ByteArray,
    ): Boolean =
        !wiped &&
            this.pageIndex == pageIndex &&
            MessageDigest.isEqual(logicalIdentityValue, logicalIdentity) &&
            MessageDigest.isEqual(encodedHandleValue, encodedHandle) &&
            MessageDigest.isEqual(callSiteProofValue, callSiteProof)

    override fun close() = wipe()

    internal fun wipe() {
        if (wiped) return
        Arrays.fill(logicalIdentityValue, 0)
        Arrays.fill(encodedHandleValue, 0)
        Arrays.fill(callSiteProofValue, 0)
        logicalIdentityValue = ByteArray(0)
        encodedHandleValue = ByteArray(0)
        callSiteProofValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN ClassPage binding has been wiped" }
    }

    internal companion object {
        private const val MAX_CALL_SITE_PROOF_SIZE = 4096

        fun fromMaterializedPage(page: AkenMaterializedPage): AkenClassPageBinding {
            val descriptor = page.descriptorForBuild
            require(descriptor.resourceKind == AkenResourceKind.EncryptedClassPage) {
                "AKEN ClassPage binding source is not an encrypted ClassPage"
            }

            var logicalIdentity: ByteArray? = null
            var encodedHandle: ByteArray? = null
            var callSiteProof: ByteArray? = null
            var handle: AkenHandle? = null
            try {
                logicalIdentity = descriptor.logicalIdentity
                callSiteProof = descriptor.proof.callSiteProof
                handle = descriptor.handle
                require(descriptor.matches(handle)) {
                    "AKEN ClassPage materialized descriptor handle binding is invalid"
                }
                encodedHandle = handle.encoded
                return AkenClassPageBinding(
                    pageIndex = descriptor.pageIndex,
                    logicalIdentity = logicalIdentity,
                    encodedHandle = encodedHandle,
                    callSiteProof = callSiteProof,
                )
            } finally {
                logicalIdentity?.let { Arrays.fill(it, 0) }
                encodedHandle?.let { Arrays.fill(it, 0) }
                callSiteProof?.let { Arrays.fill(it, 0) }
                handle?.wipe()
            }
        }
    }
}
