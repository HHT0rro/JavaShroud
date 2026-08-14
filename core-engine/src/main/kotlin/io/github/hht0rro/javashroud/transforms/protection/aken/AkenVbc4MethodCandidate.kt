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
 * This owner deliberately retains neither an AKEN handle, evaluator graph,
 * page descriptor, nor a call-site proof. It is only the hand-off from method
 * virtualization to the later page planner, which splits the serialised VBC4
 * program on basic-block boundaries and converts it into page-local pending
 * inputs. It is never serialized into the artifact or exposed by a runtime
 * API.
 */
internal class AkenVbc4MethodCandidate private constructor(
    val entryToken: Long,
    val logicalMethod: AkenVbc4LogicalMethodIdentity,
    logicalIdentity: ByteArray,
    serializedProgram: ByteArray,
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var serializedProgramValue: ByteArray = serializedProgram.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(logicalIdentityValue.isNotEmpty()) { "AKEN VBC4 method candidate identity must not be empty" }
        require(serializedProgramValue.isNotEmpty()) { "AKEN VBC4 method candidate program must not be empty" }
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

    internal fun copyForBuild(): AkenVbc4MethodCandidate {
        requireLive()
        return AkenVbc4MethodCandidate(
            entryToken = entryToken,
            logicalMethod = logicalMethod,
            logicalIdentity = logicalIdentityValue,
            serializedProgram = serializedProgramValue,
        )
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(logicalIdentityValue, 0)
        Arrays.fill(serializedProgramValue, 0)
        logicalIdentityValue = ByteArray(0)
        serializedProgramValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 method candidate has been wiped" }
    }

    companion object {
        fun create(
            entryToken: Long,
            logicalMethod: AkenVbc4LogicalMethodIdentity,
            logicalIdentity: ByteArray,
            serializedProgram: ByteArray,
        ): AkenVbc4MethodCandidate {
            require(logicalIdentity.isNotEmpty()) { "AKEN VBC4 method candidate identity must not be empty" }
            require(serializedProgram.isNotEmpty()) { "AKEN VBC4 method candidate program must not be empty" }
            return AkenVbc4MethodCandidate(
                entryToken = entryToken,
                logicalMethod = logicalMethod,
                logicalIdentity = logicalIdentity,
                serializedProgram = serializedProgram,
            )
        }
    }
}
