package io.github.hht0rro.javashroud.transforms.protection.aken

import java.util.Arrays

/**
 * Build-only logical method identity captured before final artifact routes,
 * page frames, and the canonical commitment are available.
 *
 * This deliberately identifies the current VBC4 producer instead of trying to
 * reuse a legacy runtime binding as a future AKEN call-site proof. The latter
 * is minted only after final page routing exists.
 */
internal data class AkenVbc4LogicalMethodIdentity private constructor(
    val dispatchClassToken: String,
    val dispatchMethodToken: String,
    val descriptor: String,
    val logicalVmResourcePath: String,
) {
    companion object {
        fun create(
            dispatchClassToken: String,
            dispatchMethodToken: String,
            descriptor: String,
            logicalVmResourcePath: String,
        ): AkenVbc4LogicalMethodIdentity {
            require(dispatchClassToken.isNotBlank()) { "AKEN VBC4 dispatch class token must not be blank" }
            require(dispatchMethodToken.isNotBlank()) { "AKEN VBC4 dispatch method token must not be blank" }
            require(descriptor.isNotBlank()) { "AKEN VBC4 method descriptor must not be blank" }
            require(isValidLogicalResourcePath(logicalVmResourcePath)) {
                "AKEN VBC4 method candidate logical resource path is invalid"
            }
            return AkenVbc4LogicalMethodIdentity(
                dispatchClassToken = dispatchClassToken,
                dispatchMethodToken = dispatchMethodToken,
                descriptor = descriptor,
                logicalVmResourcePath = logicalVmResourcePath,
            )
        }

        private fun isValidLogicalResourcePath(value: String): Boolean =
            value.isNotBlank() &&
                !value.startsWith('/') &&
                !value.contains('\\') &&
                value.split('/').all { segment -> segment.isNotBlank() && segment != "." && segment != ".." }
    }
}

/**
 * Build-only VBC4 method candidate captured before final artifact routes,
 * page frames, and the canonical commitment are available.
 *
 * This owner never retains an evaluator graph, page descriptor, or DEK. A
 * dispatcher-bearing candidate may additionally hold one opaque page-zero
 * handle/proof pair, minted before canonical commitment so the generated
 * method body can bind to the same exact page without a post-seal class
 * rewrite. It is only the hand-off from method virtualization to the later
 * page planner and is never serialized as a runtime catalog.
 */
internal class AkenVbc4MethodCandidate private constructor(
    val entryToken: Long,
    val logicalMethod: AkenVbc4LogicalMethodIdentity,
    logicalIdentity: ByteArray,
    serializedProgram: ByteArray,
    pageZeroEncodedHandle: ByteArray?,
    pageZeroCallSiteProof: ByteArray?,
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var serializedProgramValue: ByteArray = serializedProgram.copyOf()
    private var pageZeroEncodedHandleValue: ByteArray? = pageZeroEncodedHandle?.copyOf()
    private var pageZeroCallSiteProofValue: ByteArray? = pageZeroCallSiteProof?.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(logicalIdentityValue.isNotEmpty()) { "AKEN VBC4 method candidate identity must not be empty" }
        require(serializedProgramValue.isNotEmpty()) { "AKEN VBC4 method candidate program must not be empty" }
        require((pageZeroEncodedHandleValue == null) == (pageZeroCallSiteProofValue == null)) {
            "AKEN VBC4 page-zero dispatch binding must include both handle and proof"
        }
        pageZeroEncodedHandleValue?.let { encodedHandle ->
            require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) {
                "AKEN VBC4 page-zero dispatch handle has an invalid length"
            }
        }
        pageZeroCallSiteProofValue?.let { callSiteProof ->
            require(callSiteProof.isNotEmpty() && callSiteProof.size <= MAX_CALL_SITE_PROOF_SIZE) {
                "AKEN VBC4 page-zero dispatch proof has an invalid length"
            }
        }
    }

    val isWiped: Boolean
        get() = wiped

    internal fun copyLogicalIdentityForBuild(): ByteArray {
        requireLive()
        return logicalIdentityValue.copyOf()
    }

    internal fun copySerializedProgramForBuild(): ByteArray {
        requireLive()
        return serializedProgramValue.copyOf()
    }

    internal val hasPageZeroDispatchBindingForBuild: Boolean
        get() {
            requireLive()
            return pageZeroEncodedHandleValue != null
        }

    internal fun copyPageZeroEncodedHandleForBuild(): ByteArray? {
        requireLive()
        return pageZeroEncodedHandleValue?.copyOf()
    }

    internal fun copyPageZeroCallSiteProofForBuild(): ByteArray? {
        requireLive()
        return pageZeroCallSiteProofValue?.copyOf()
    }

    internal fun copyForBuild(): AkenVbc4MethodCandidate {
        requireLive()
        return AkenVbc4MethodCandidate(
            entryToken = entryToken,
            logicalMethod = logicalMethod,
            logicalIdentity = logicalIdentityValue,
            serializedProgram = serializedProgramValue,
            pageZeroEncodedHandle = pageZeroEncodedHandleValue,
            pageZeroCallSiteProof = pageZeroCallSiteProofValue,
        )
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(logicalIdentityValue, 0)
        Arrays.fill(serializedProgramValue, 0)
        pageZeroEncodedHandleValue?.let { Arrays.fill(it, 0) }
        pageZeroCallSiteProofValue?.let { Arrays.fill(it, 0) }
        logicalIdentityValue = ByteArray(0)
        serializedProgramValue = ByteArray(0)
        pageZeroEncodedHandleValue = null
        pageZeroCallSiteProofValue = null
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 method candidate has been wiped" }
    }

    companion object {
        private const val MAX_CALL_SITE_PROOF_SIZE = 4096

        fun create(
            entryToken: Long,
            logicalMethod: AkenVbc4LogicalMethodIdentity,
            logicalIdentity: ByteArray,
            serializedProgram: ByteArray,
            pageZeroEncodedHandle: ByteArray? = null,
            pageZeroCallSiteProof: ByteArray? = null,
        ): AkenVbc4MethodCandidate {
            require(logicalIdentity.isNotEmpty()) { "AKEN VBC4 method candidate identity must not be empty" }
            require(serializedProgram.isNotEmpty()) { "AKEN VBC4 method candidate program must not be empty" }
            require((pageZeroEncodedHandle == null) == (pageZeroCallSiteProof == null)) {
                "AKEN VBC4 page-zero dispatch binding must include both handle and proof"
            }
            return AkenVbc4MethodCandidate(
                entryToken = entryToken,
                logicalMethod = logicalMethod,
                logicalIdentity = logicalIdentity,
                serializedProgram = serializedProgram,
                pageZeroEncodedHandle = pageZeroEncodedHandle,
                pageZeroCallSiteProof = pageZeroCallSiteProof,
            )
        }
    }
}
