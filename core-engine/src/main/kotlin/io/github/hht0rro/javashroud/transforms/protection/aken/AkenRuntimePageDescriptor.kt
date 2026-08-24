package io.github.hht0rro.javashroud.transforms.protection.aken

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Arrays

/**
 * Current-format evaluator descriptor for one page-bound opaque evaluator.
 *
 * The runtime never receives a generic evaluator graph, fixed lane topology, or
 * recoverable DEK field.  The only serialized evaluator state is the
 * artifact-specific opaque binding produced by [AkenBoundDecryptorPlan].
 */
class AkenRuntimeEvaluatorPlan private constructor(
    private val boundDecryptorValue: AkenBoundDecryptorPlan,
    fingerprint: ByteArray,
) {
    private val fingerprintValue = fingerprint.copyOf()

    init {
        require(fingerprintValue.size == AkenHandle.FINGERPRINT_SIZE) {
            "AKEN runtime evaluator fingerprint length is invalid"
        }
    }

    val fingerprint: ByteArray
        get() = fingerprintValue.copyOf()

    /** Copy only the current page's opaque native evaluator descriptor. */
    internal fun copyBoundDecryptorForNative(): ByteArray =
        boundDecryptorValue.copyOpaqueForNative()

    fun encode(): ByteArray = ByteArrayOutputStream().use { out ->
        val opaque = boundDecryptorValue.copyOpaqueForNative()
        try {
            writeRuntimeFramed(out, opaque)
            out.write(fingerprintValue)
        } finally {
            Arrays.fill(opaque, 0)
        }
        out.toByteArray().also {
            require(it.size <= MAX_PLAN_ENCODING_SIZE) {
                "runtime evaluator plan encoding is too large"
            }
        }
    }

    override fun equals(other: Any?): Boolean =
        other is AkenRuntimeEvaluatorPlan &&
            boundDecryptorValue == other.boundDecryptorValue &&
            Arrays.equals(fingerprintValue, other.fingerprintValue)

    override fun hashCode(): Int =
        31 * boundDecryptorValue.hashCode() + fingerprintValue.contentHashCode()

    override fun toString(): String = "AkenRuntimeEvaluatorPlan(bound-page)"

    /** Verify the complete page binding committed by this current-format plan. */
    internal fun matchesDescriptorBinding(
        resourceKind: AkenResourceKind,
        logicalIdentity: ByteArray,
        pageIndex: Int,
        targetPageSize: Int,
        route: AkenRoutingMetadata,
        proof: AkenSealingProofMetadata,
        handleEncoding: ByteArray,
        locatorToken: ByteArray,
    ): Boolean {
        var artifactCommitment: ByteArray? = null
        var callSiteProof: ByteArray? = null
        return try {
            artifactCommitment = proof.artifactCanonicalCommitment
            callSiteProof = proof.callSiteProof
            boundDecryptorValue.matchesPageBinding(
                resourceKind = resourceKind,
                logicalIdentity = logicalIdentity,
                pageIndex = pageIndex,
                targetPageSize = targetPageSize,
                codecVariant = route.codecVariant,
                layoutVariant = route.layoutVariant,
                handleEncoding = handleEncoding,
                locatorToken = locatorToken,
                evaluatorFingerprint = fingerprintValue,
                artifactCanonicalCommitment = checkNotNull(artifactCommitment),
                route = route,
                callSiteProof = checkNotNull(callSiteProof),
            )
        } finally {
            artifactCommitment?.let { Arrays.fill(it, 0) }
            callSiteProof?.let { Arrays.fill(it, 0) }
        }
    }

    companion object {
        private const val MAX_PLAN_ENCODING_SIZE = 128 * 1024

        /** Current-format production representation: one opaque page-bound evaluator. */
        internal fun createBound(
            boundDecryptor: AkenBoundDecryptorPlan,
            fingerprint: ByteArray,
        ): AkenRuntimeEvaluatorPlan = AkenRuntimeEvaluatorPlan(boundDecryptor, fingerprint)

        fun decode(encoded: ByteArray): AkenRuntimeEvaluatorPlan {
            require(encoded.isNotEmpty() && encoded.size <= MAX_PLAN_ENCODING_SIZE) {
                "AKEN runtime evaluator plan encoding length is invalid"
            }
            return decodeBound(AkenRuntimeDescriptorReader(encoded))
        }

        private fun decodeBound(reader: AkenRuntimeDescriptorReader): AkenRuntimeEvaluatorPlan {
            var opaque: ByteArray? = null
            var fingerprint: ByteArray? = null
            return try {
                opaque = reader.readFramed(
                    MAX_PLAN_ENCODING_SIZE - AkenHandle.FINGERPRINT_SIZE - 5,
                    "AKEN bound evaluator",
                    allowEmpty = false,
                )
                fingerprint = reader.readFixed(
                    AkenHandle.FINGERPRINT_SIZE,
                    "AKEN runtime evaluator fingerprint",
                )
                reader.requireFullyRead("AKEN runtime bound evaluator plan")
                createBound(
                    AkenBoundDecryptorPlan.fromOpaque(checkNotNull(opaque)),
                    checkNotNull(fingerprint),
                )
            } finally {
                opaque?.let { Arrays.fill(it, 0) }
                fingerprint?.let { Arrays.fill(it, 0) }
            }
        }
    }
}

/**
 * Runtime-neutral metadata for exactly one high-value AKEN v4 page.
 *
 * It combines one opaque handle binding, the corresponding logical identity,
 * one route, one integrity/call-site proof, and one AKEN-7 graph. It offers no
 * directory, traversal, or arbitrary-resource decoding surface.
 */
class AkenRuntimePageDescriptor private constructor(
    private val leafIdentityValue: AkenHighValueLeafIdentity,
    private val routeValue: AkenRoutingMetadata,
    private val proofValue: AkenSealingProofMetadata,
    val targetPageSize: Int,
    private val evaluatorPlanValue: AkenRuntimeEvaluatorPlan,
) {
    init {
        validateBinding(leafIdentityValue, routeValue, proofValue, targetPageSize, evaluatorPlanValue)
    }

    val resourceKind: AkenResourceKind
        get() = leafIdentityValue.resourceKind

    val pageIndex: Int
        get() = leafIdentityValue.pageIndex

    val logicalIdentity: ByteArray
        get() = leafIdentityValue.logicalIdentity

    /** A fresh opaque handle for this descriptor's only page binding. */
    val handle: AkenHandle
        get() = handleFromIdentity(leafIdentityValue)

    val route: AkenRoutingMetadata
        get() = routeValue

    val proof: AkenSealingProofMetadata
        get() = proofValue

    val evaluatorPlan: AkenRuntimeEvaluatorPlan
        get() = evaluatorPlanValue

    fun matches(candidate: AkenHandle): Boolean = leafIdentityValue.matches(candidate)

    fun encode(): ByteArray = ByteArrayOutputStream().use { out ->
        val route = routeValue.encode()
        val proof = proofValue.encode()
        val evaluator = evaluatorPlanValue.encode()
        try {
            writeRuntimeFramed(out, route)
            writeRuntimeFramed(out, proof)
            writeRuntimeInt(out, targetPageSize)
            writeRuntimeFramed(out, evaluator)
            out.toByteArray().also {
                require(it.size <= MAX_DESCRIPTOR_ENCODING_SIZE) {
                    "AKEN runtime page descriptor encoding is too large"
                }
            }
        } finally {
            Arrays.fill(route, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(evaluator, 0)
        }
    }

    override fun toString(): String =
        "AkenRuntimePageDescriptor(kind=" + resourceKind.logicalName + ", page=" + pageIndex + ")"

    companion object {
        private const val MAX_DESCRIPTOR_ENCODING_SIZE = 384 * 1024
        private const val MAX_ROUTE_ENCODING_SIZE = 128 * 1024
        private const val MAX_PROOF_ENCODING_SIZE = 160 * 1024
        private const val MAX_EVALUATOR_PLAN_ENCODING_SIZE = 128 * 1024

        fun create(
            handle: AkenHandle,
            logicalIdentity: ByteArray,
            route: AkenRoutingMetadata,
            proof: AkenSealingProofMetadata,
            targetPageSize: Int,
            evaluatorPlan: AkenRuntimeEvaluatorPlan,
        ): AkenRuntimePageDescriptor {
            val identity = AkenHighValueLeafIdentity.fromHandle(handle, logicalIdentity)
            return fromMetadata(identity, route, proof, targetPageSize, evaluatorPlan)
        }

        fun decode(encoded: ByteArray): AkenRuntimePageDescriptor {
            require(encoded.isNotEmpty() && encoded.size <= MAX_DESCRIPTOR_ENCODING_SIZE) {
                "AKEN runtime page descriptor encoding length is invalid"
            }
            val reader = AkenRuntimeDescriptorReader(encoded)
            var routeBytes: ByteArray? = null
            var proofBytes: ByteArray? = null
            var evaluatorBytes: ByteArray? = null
            return try {
                routeBytes = reader.readFramed(MAX_ROUTE_ENCODING_SIZE, "AKEN runtime page route", allowEmpty = false)
                val route = AkenRoutingMetadata.decode(checkNotNull(routeBytes))
                proofBytes = reader.readFramed(MAX_PROOF_ENCODING_SIZE, "AKEN runtime page proof", allowEmpty = false)
                val proof = AkenSealingProofMetadata.decode(checkNotNull(proofBytes))
                val targetPageSize = reader.readInt("AKEN runtime target page size")
                evaluatorBytes = reader.readFramed(
                    MAX_EVALUATOR_PLAN_ENCODING_SIZE,
                    "AKEN runtime evaluator plan",
                    allowEmpty = false,
                )
                val evaluatorPlan = AkenRuntimeEvaluatorPlan.decode(checkNotNull(evaluatorBytes))
                reader.requireFullyRead("AKEN runtime page descriptor")
                fromMetadata(route.leafIdentity, route, proof, targetPageSize, evaluatorPlan)
            } finally {
                routeBytes?.let { Arrays.fill(it, 0) }
                proofBytes?.let { Arrays.fill(it, 0) }
                evaluatorBytes?.let { Arrays.fill(it, 0) }
            }
        }

        private fun fromMetadata(
            identity: AkenHighValueLeafIdentity,
            route: AkenRoutingMetadata,
            proof: AkenSealingProofMetadata,
            targetPageSize: Int,
            evaluatorPlan: AkenRuntimeEvaluatorPlan,
        ): AkenRuntimePageDescriptor = AkenRuntimePageDescriptor(
            identity,
            route,
            proof,
            targetPageSize,
            evaluatorPlan,
        )

        private fun validateBinding(
            identity: AkenHighValueLeafIdentity,
            route: AkenRoutingMetadata,
            proof: AkenSealingProofMetadata,
            targetPageSize: Int,
            evaluatorPlan: AkenRuntimeEvaluatorPlan,
        ) {
            require(route.leafIdentity == identity) { "AKEN runtime route does not bind the current page" }
            require(proof.leafIdentity == identity) { "AKEN runtime proof does not bind the current page" }
            require(route.codecVariant == proof.codecVariant) { "AKEN runtime route/proof codec mismatch" }
            require(route.layoutVariant == proof.layoutVariant) { "AKEN runtime route/proof layout mismatch" }

            var logicalIdentity: ByteArray? = null
            var handleEncoding: ByteArray? = null
            var locatorToken: ByteArray? = null
            var expectedFingerprint: ByteArray? = null
            var graphFingerprint: ByteArray? = null
            try {
                logicalIdentity = identity.logicalIdentity
                handleEncoding = identity.handleEncoding
                locatorToken = identity.locatorToken
                expectedFingerprint = identity.evaluatorFingerprint
                graphFingerprint = evaluatorPlan.fingerprint
                require(Arrays.equals(expectedFingerprint, graphFingerprint)) {
                    "AKEN runtime evaluator fingerprint does not match the page handle"
                }
                require(
                    evaluatorPlan.matchesDescriptorBinding(
                        resourceKind = identity.resourceKind,
                        logicalIdentity = checkNotNull(logicalIdentity),
                        pageIndex = identity.pageIndex,
                        targetPageSize = targetPageSize,
                        route = route,
                        proof = proof,
                        handleEncoding = checkNotNull(handleEncoding),
                        locatorToken = checkNotNull(locatorToken),
                    ),
                ) { "AKEN runtime evaluator graph binding is invalid" }
            } finally {
                logicalIdentity?.let { Arrays.fill(it, 0) }
                handleEncoding?.let { Arrays.fill(it, 0) }
                locatorToken?.let { Arrays.fill(it, 0) }
                expectedFingerprint?.let { Arrays.fill(it, 0) }
                graphFingerprint?.let { Arrays.fill(it, 0) }
            }
        }

        private fun handleFromIdentity(identity: AkenHighValueLeafIdentity): AkenHandle {
            var encoded: ByteArray? = null
            var locator: ByteArray? = null
            var fingerprint: ByteArray? = null
            return try {
                encoded = identity.handleEncoding
                locator = identity.locatorToken
                fingerprint = identity.evaluatorFingerprint
                AkenHandle.create(
                    identity.resourceKind,
                    identity.pageIndex,
                    checkNotNull(encoded),
                    checkNotNull(locator),
                    checkNotNull(fingerprint),
                )
            } finally {
                encoded?.let { Arrays.fill(it, 0) }
                locator?.let { Arrays.fill(it, 0) }
                fingerprint?.let { Arrays.fill(it, 0) }
            }
        }
    }
}

private const val MAX_LOGICAL_IDENTITY_SIZE = 64 * 1024

private fun writeRuntimeInt(out: ByteArrayOutputStream, value: Int) {
    out.write((value ushr 24) and 0xFF)
    out.write((value ushr 16) and 0xFF)
    out.write((value ushr 8) and 0xFF)
    out.write(value and 0xFF)
}

private fun writeRuntimeFramed(out: ByteArrayOutputStream, value: ByteArray) {
    writeRuntimeInt(out, value.size)
    out.write(value)
}

private fun updateRuntimeInt(digest: MessageDigest, value: Int) {
    digest.update((value ushr 24).toByte())
    digest.update((value ushr 16).toByte())
    digest.update((value ushr 8).toByte())
    digest.update(value.toByte())
}

private fun updateRuntimeFramed(digest: MessageDigest, value: ByteArray) {
    updateRuntimeInt(digest, value.size)
    digest.update(value)
}

private class AkenRuntimeDescriptorReader(private val bytes: ByteArray) {
    private var offset = 0

    fun readUnsignedByte(label: String): Int {
        requireRemaining(1, label)
        return bytes[offset++].toInt() and 0xFF
    }

    fun readInt(label: String): Int {
        requireRemaining(Int.SIZE_BYTES, label)
        val value =
            ((bytes[offset].toInt() and 0xFF) shl 24) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
                (bytes[offset + 3].toInt() and 0xFF)
        offset += Int.SIZE_BYTES
        return value
    }

    fun readFixed(length: Int, label: String): ByteArray {
        require(length >= 0) { "AKEN runtime fixed length must be non-negative" }
        requireRemaining(length, label)
        return bytes.copyOfRange(offset, offset + length).also { offset += length }
    }

    fun readFramed(maximumLength: Int, label: String, allowEmpty: Boolean = true): ByteArray {
        val length = readInt("$label length")
        require(length >= 0 && length <= maximumLength && (allowEmpty || length > 0)) {
            "$label length is invalid"
        }
        return readFixed(length, label)
    }

    fun requireFullyRead(label: String) {
        require(offset == bytes.size) { "$label contains trailing bytes" }
    }

    private fun requireRemaining(length: Int, label: String) {
        require(length >= 0 && offset <= bytes.size - length) { "$label is truncated" }
    }
}
