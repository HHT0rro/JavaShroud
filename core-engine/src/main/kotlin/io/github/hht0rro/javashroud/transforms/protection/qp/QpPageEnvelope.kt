package io.github.hht0rro.javashroud.transforms.protection.qp

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Arrays
import kotlin.jvm.JvmSynthetic

/**
 * Opaque, current-page-only compact locator envelope stored behind an
 * artifact-specific native locator.
 *
 * This is deliberately not a resource catalog and not a decoder. It binds
 * exactly one [QpPageDescriptor] to one generated entry token, one
 * [QpHandle], one page index, the descriptor's raw call-site proof, artifact
 * commitment, and route/locator metadata. No API here lists envelopes,
 * accepts arbitrary resource bytes, returns a DEK, or reconstructs a page.
 *
 * The Java typed JNI bridge continues to receive the descriptor's original raw
 * call-site proof as its proof argument. It never receives this envelope
 * encoding. The native locator resolves this one envelope and then the exact
 * descriptor through the artifact-specific route, calling
 * [matchesDescriptor] before it constructs a native page request.
 *
 * The compact locator record commits to the exact descriptor encoding, raw
 * call-site proof, route, locator, and artifact commitment with independent
 * SHA-256 bindings; it deliberately never carries the descriptor bytes, an
 * evaluator plan, a DEK, or any page material inline. Older envelope forms
 * (inline descriptor and the previous compact id) are rejected at parse.
 *
 * The digests in this type are public integrity bindings, not secret material.
 */
internal class QpPageEnvelope private constructor(
    val entryToken: Long,
    val resourceKind: QpResourceKind,
    val pageIndex: Int,
    private val formValue: Form,
    encodedHandle: ByteArray,
    locatorToken: ByteArray,
    keyCommitmentFingerprint: ByteArray,
    artifactCommitment: ByteArray,
    descriptorBinding: ByteArray,
    callSiteProofBinding: ByteArray,
    routeBinding: ByteArray,
    envelopeBinding: ByteArray,
) : AutoCloseable {
    private var encodedHandleValue = encodedHandle.copyOf()
    private var locatorTokenValue = locatorToken.copyOf()
    private var keyCommitmentFingerprintValue = keyCommitmentFingerprint.copyOf()
    private var artifactCommitmentValue = artifactCommitment.copyOf()
    private var descriptorBindingValue = descriptorBinding.copyOf()
    private var callSiteProofBindingValue = callSiteProofBinding.copyOf()
    private var routeBindingValue = routeBinding.copyOf()
    private var envelopeBindingValue = envelopeBinding.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(pageIndex >= 0) { "Qp native page envelope index must be non-negative" }
        require(encodedHandleValue.size == QpHandle.ENCODED_HANDLE_SIZE) {
            "Qp native page envelope handle length is invalid"
        }
        require(locatorTokenValue.size == QpHandle.LOCATOR_TOKEN_SIZE) {
            "Qp native page envelope locator length is invalid"
        }
        require(keyCommitmentFingerprintValue.size == QpHandle.FINGERPRINT_SIZE) {
            "Qp native page envelope key commitment length is invalid"
        }
        require(artifactCommitmentValue.size == QpArtifactCommitment.DIGEST_SIZE) {
            "Qp native page envelope artifact commitment length is invalid"
        }
        require(descriptorBindingValue.size == BINDING_DIGEST_SIZE) {
            "Qp native page envelope descriptor binding length is invalid"
        }
        require(callSiteProofBindingValue.size == BINDING_DIGEST_SIZE) {
            "Qp native page envelope call-site binding length is invalid"
        }
        require(routeBindingValue.size == BINDING_DIGEST_SIZE) {
            "Qp native page envelope route binding length is invalid"
        }
        require(envelopeBindingValue.size == BINDING_DIGEST_SIZE) {
            "Qp native page envelope binding length is invalid"
        }
    }

    /** True only while this exact-page owner remains live. */
    val isWiped: Boolean
        get() = wiped

    /** Exact serialized size of this one envelope. Always at most 4096 bytes. */
    val encodedSize: Int
        get() {
            requireLive()
            return FIXED_WIRE_SIZE
        }

    @JvmSynthetic
    internal fun copyEncodedHandleForCurrentPage(): ByteArray {
        requireLive()
        return encodedHandleValue.copyOf()
    }

    @JvmSynthetic
    internal fun copyLocatorTokenForCurrentPage(): ByteArray {
        requireLive()
        return locatorTokenValue.copyOf()
    }

    @JvmSynthetic
    internal fun copyArtifactCommitmentForCurrentPage(): ByteArray {
        requireLive()
        return artifactCommitmentValue.copyOf()
    }

    /** Exact commitment to the descriptor bytes used to mint this envelope. */
    @JvmSynthetic
    internal fun copyDescriptorBindingForCurrentPage(): ByteArray {
        requireLive()
        return descriptorBindingValue.copyOf()
    }

    /** Exact commitment to the original call-site proof, not the proof bytes. */
    @JvmSynthetic
    internal fun copyCallSiteProofBindingForCurrentPage(): ByteArray {
        requireLive()
        return callSiteProofBindingValue.copyOf()
    }

    /** Exact commitment to the descriptor route plus its locator token. */
    @JvmSynthetic
    internal fun copyRouteBindingForCurrentPage(): ByteArray {
        requireLive()
        return routeBindingValue.copyOf()
    }

    /**
     * Constant-time comparison against the exact values supplied to a
     * purpose-specific native VM/string/class/chunk bridge. The final
     * [rawCallSiteProof] is the original proof emitted for this call site; it
     * is never this envelope's encoded bytes. The envelope is resolved by the
     * artifact-specific native locator before this check, so this method
     * validates no other resource and exposes no decoder surface.
     */
    fun matchesTypedBridgeRequest(
        entryToken: Long,
        encodedHandle: ByteArray,
        pageIndex: Int,
        rawCallSiteProof: ByteArray,
    ): Boolean {
        if (wiped) return false
        if (encodedHandle.size != QpHandle.ENCODED_HANDLE_SIZE ||
            pageIndex < 0 || rawCallSiteProof.isEmpty() || rawCallSiteProof.size > MAX_CALL_SITE_PROOF_SIZE
        ) {
            return false
        }

        var suppliedProofBinding: ByteArray? = null
        return try {
            suppliedProofBinding = callSiteProofBinding(rawCallSiteProof)
            val tokenMatches = this.entryToken == entryToken
            val pageMatches = this.pageIndex == pageIndex
            val handleMatches = MessageDigest.isEqual(encodedHandleValue, encodedHandle)
            val proofMatches = MessageDigest.isEqual(callSiteProofBindingValue, checkNotNull(suppliedProofBinding))
            tokenMatches && pageMatches && handleMatches && proofMatches
        } catch (_: IllegalArgumentException) {
            false
        } finally {
            suppliedProofBinding?.let { Arrays.fill(it, 0) }
        }
    }

    /**
     * Rechecks that a resolved current descriptor is the exact descriptor bound
     * when this envelope was minted. This is the compact form's required native
     * locator handoff check; it does not decode a payload or derive a key.
     */
    fun matchesDescriptor(descriptor: QpPageDescriptor): Boolean {
        if (wiped) return false

        var candidateHandle: QpHandle? = null
        var candidateHandleEncoding: ByteArray? = null
        var candidateLocator: ByteArray? = null
        var candidateFingerprint: ByteArray? = null
        var candidateCommitment: ByteArray? = null
        var candidateCallSiteProof: ByteArray? = null
        var candidateDescriptor: ByteArray? = null
        var candidateRoute: ByteArray? = null
        var candidateDescriptorBinding: ByteArray? = null
        var candidateCallSiteBinding: ByteArray? = null
        var candidateRouteBinding: ByteArray? = null
        return try {
            if (descriptor.resourceKind != resourceKind || descriptor.pageIndex != pageIndex) return false

            candidateHandle = descriptor.handle
            candidateHandleEncoding = candidateHandle.encoded
            candidateLocator = candidateHandle.locatorToken
            candidateFingerprint = candidateHandle.keyCommitmentFingerprint
            candidateCommitment = descriptor.proof.artifactCanonicalCommitment
            candidateCallSiteProof = descriptor.proof.callSiteProof
            candidateDescriptor = descriptor.encode()
            candidateRoute = descriptor.route.encode()
            candidateDescriptorBinding = descriptorBinding(checkNotNull(candidateDescriptor))
            candidateCallSiteBinding = callSiteProofBinding(checkNotNull(candidateCallSiteProof))
            candidateRouteBinding = routeBinding(checkNotNull(candidateRoute), checkNotNull(candidateLocator))

            val kindMatches = descriptor.resourceKind == resourceKind
            val pageMatches = descriptor.pageIndex == pageIndex
            val handleMatches = MessageDigest.isEqual(encodedHandleValue, checkNotNull(candidateHandleEncoding))
            val locatorMatches = MessageDigest.isEqual(locatorTokenValue, checkNotNull(candidateLocator))
            val fingerprintMatches = MessageDigest.isEqual(
                keyCommitmentFingerprintValue,
                checkNotNull(candidateFingerprint),
            )
            val commitmentMatches = MessageDigest.isEqual(artifactCommitmentValue, checkNotNull(candidateCommitment))
            val descriptorMatches = MessageDigest.isEqual(
                descriptorBindingValue,
                checkNotNull(candidateDescriptorBinding),
            )
            val proofMatches = MessageDigest.isEqual(
                callSiteProofBindingValue,
                checkNotNull(candidateCallSiteBinding),
            )
            val routeMatches = MessageDigest.isEqual(routeBindingValue, checkNotNull(candidateRouteBinding))
            kindMatches && pageMatches && handleMatches && locatorMatches && fingerprintMatches &&
                commitmentMatches && descriptorMatches && proofMatches && routeMatches
        } catch (_: IllegalArgumentException) {
            false
        } catch (_: IllegalStateException) {
            false
        } finally {
            candidateHandleEncoding?.let { Arrays.fill(it, 0) }
            candidateLocator?.let { Arrays.fill(it, 0) }
            candidateFingerprint?.let { Arrays.fill(it, 0) }
            candidateCommitment?.let { Arrays.fill(it, 0) }
            candidateCallSiteProof?.let { Arrays.fill(it, 0) }
            candidateDescriptor?.let { Arrays.fill(it, 0) }
            candidateRoute?.let { Arrays.fill(it, 0) }
            candidateDescriptorBinding?.let { Arrays.fill(it, 0) }
            candidateCallSiteBinding?.let { Arrays.fill(it, 0) }
            candidateRouteBinding?.let { Arrays.fill(it, 0) }
            candidateHandle?.wipe()
        }
    }

    /**
     * Current-page-only combined validation used by the typed native bridge
     * after its artifact-specific locator has resolved this envelope and
     * exactly one descriptor route. [rawCallSiteProof] remains the original
     * proof passed in the typed JNI argument; it is not the locator envelope.
     * Both checks are evaluated so request and descriptor inputs are not
     * short-circuited into a partial matching API.
     */
    fun matchesCurrentPage(
        entryToken: Long,
        encodedHandle: ByteArray,
        pageIndex: Int,
        rawCallSiteProof: ByteArray,
        descriptor: QpPageDescriptor,
    ): Boolean {
        val requestMatches = matchesTypedBridgeRequest(entryToken, encodedHandle, pageIndex, rawCallSiteProof)
        val descriptorMatches = matchesDescriptor(descriptor)
        return requestMatches && descriptorMatches
    }

    /** Serializes only this exact current-page binding. */
    fun encode(): ByteArray {
        requireLive()
        return ByteArrayOutputStream(encodedSize).use { out ->
            out.write(formValue.id)
            writeLong(out, entryToken)
            out.write(resourceKind.id)
            writeInt(out, pageIndex)
            out.write(encodedHandleValue)
            out.write(locatorTokenValue)
            out.write(keyCommitmentFingerprintValue)
            out.write(artifactCommitmentValue)
            out.write(descriptorBindingValue)
            out.write(callSiteProofBindingValue)
            out.write(routeBindingValue)
            out.write(envelopeBindingValue)
            out.toByteArray().also { encoded ->
                require(encoded.size <= MAX_ENCODED_SIZE) {
                    "Qp native page envelope exceeds bounded locator-record limit"
                }
            }
        }
    }

    override fun close() = wipe()

    /** Clears all retained current-page byte material and invalidates this owner. */
    fun wipe() {
        if (wiped) return
        Arrays.fill(encodedHandleValue, 0)
        Arrays.fill(locatorTokenValue, 0)
        Arrays.fill(keyCommitmentFingerprintValue, 0)
        Arrays.fill(artifactCommitmentValue, 0)
        Arrays.fill(descriptorBindingValue, 0)
        Arrays.fill(callSiteProofBindingValue, 0)
        Arrays.fill(routeBindingValue, 0)
        Arrays.fill(envelopeBindingValue, 0)
        encodedHandleValue = ByteArray(0)
        locatorTokenValue = ByteArray(0)
        keyCommitmentFingerprintValue = ByteArray(0)
        artifactCommitmentValue = ByteArray(0)
        descriptorBindingValue = ByteArray(0)
        callSiteProofBindingValue = ByteArray(0)
        routeBindingValue = ByteArray(0)
        envelopeBindingValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "Qp native page envelope has been wiped" }
    }

    private fun verifyEncodedBinding() {
        var expected: ByteArray? = null
        try {
            expected = envelopeBinding(
                form = formValue,
                entryToken = entryToken,
                resourceKind = resourceKind,
                pageIndex = pageIndex,
                encodedHandle = encodedHandleValue,
                locatorToken = locatorTokenValue,
                keyCommitmentFingerprint = keyCommitmentFingerprintValue,
                artifactCommitment = artifactCommitmentValue,
                descriptorBinding = descriptorBindingValue,
                callSiteProofBinding = callSiteProofBindingValue,
                routeBinding = routeBindingValue,
            )
            require(MessageDigest.isEqual(envelopeBindingValue, checkNotNull(expected))) {
                "Qp native page envelope binding is invalid"
            }
        } finally {
            expected?.let { Arrays.fill(it, 0) }
        }
    }

    private enum class Form(val id: Int) {
        /**
         * The only current form. Older inline (1) and legacy compact (2)
         * envelope encodings are rejected at parse.
         */
        CompactLocator(3),
        ;

        companion object {
            fun fromId(id: Int): Form? = entries.firstOrNull { it.id == id }
        }
    }

    private class CapturedDescriptorBinding(
        val resourceKind: QpResourceKind,
        val pageIndex: Int,
        val encodedHandle: ByteArray,
        val locatorToken: ByteArray,
        val keyCommitmentFingerprint: ByteArray,
        val artifactCommitment: ByteArray,
        val descriptorBinding: ByteArray,
        val callSiteProofBinding: ByteArray,
        val routeBinding: ByteArray,
    ) {
        fun wipe() {
            Arrays.fill(encodedHandle, 0)
            Arrays.fill(locatorToken, 0)
            Arrays.fill(keyCommitmentFingerprint, 0)
            Arrays.fill(artifactCommitment, 0)
            Arrays.fill(descriptorBinding, 0)
            Arrays.fill(callSiteProofBinding, 0)
            Arrays.fill(routeBinding, 0)
        }
    }

    companion object {
        /** Bounded native locator-record maximum; it matches the raw-proof ABI cap without sharing its transport role. */
        internal const val MAX_ENCODED_SIZE: Int = 4096

        private const val MAX_CALL_SITE_PROOF_SIZE: Int = 4096
        private const val BINDING_DIGEST_SIZE: Int = 32
        private const val FIXED_WIRE_SIZE: Int =
            1 + // form
                Long.SIZE_BYTES +
                1 + // resource kind
                Int.SIZE_BYTES +
                QpHandle.ENCODED_HANDLE_SIZE +
                QpHandle.LOCATOR_TOKEN_SIZE +
                QpHandle.FINGERPRINT_SIZE +
                QpArtifactCommitment.DIGEST_SIZE +
                BINDING_DIGEST_SIZE + // descriptor binding
                BINDING_DIGEST_SIZE + // call-site proof binding
                BINDING_DIGEST_SIZE + // route binding
                BINDING_DIGEST_SIZE // complete envelope binding

        private val DESCRIPTOR_BINDING_DOMAIN = "page-envelope-descriptor".encodeToByteArray()
        private val CALL_SITE_BINDING_DOMAIN = "page-envelope-call-site".encodeToByteArray()
        private val ROUTE_BINDING_DOMAIN = "page-envelope-route".encodeToByteArray()
        private val ENVELOPE_BINDING_DOMAIN = "page-envelope".encodeToByteArray()

        /**
         * Captures and validates exactly one descriptor/page request. The
         * envelope is written to the artifact-specific native locator; the
         * typed JNI proof argument remains [rawCallSiteProof] and must not be
         * replaced by [encode].
         */
        @JvmSynthetic
        fun create(
            entryToken: Long,
            handle: QpHandle,
            descriptor: QpPageDescriptor,
            rawCallSiteProof: ByteArray,
        ): QpPageEnvelope {
            require(rawCallSiteProof.isNotEmpty() && rawCallSiteProof.size <= MAX_CALL_SITE_PROOF_SIZE) {
                "Qp native page envelope call-site proof length is invalid"
            }

            var captured: CapturedDescriptorBinding? = null
            var binding: ByteArray? = null
            try {
                captured = captureDescriptorBinding(handle, descriptor, rawCallSiteProof)
                binding = envelopeBinding(
                    form = Form.CompactLocator,
                    entryToken = entryToken,
                    resourceKind = captured.resourceKind,
                    pageIndex = captured.pageIndex,
                    encodedHandle = captured.encodedHandle,
                    locatorToken = captured.locatorToken,
                    keyCommitmentFingerprint = captured.keyCommitmentFingerprint,
                    artifactCommitment = captured.artifactCommitment,
                    descriptorBinding = captured.descriptorBinding,
                    callSiteProofBinding = captured.callSiteProofBinding,
                    routeBinding = captured.routeBinding,
                )
                return QpPageEnvelope(
                    entryToken = entryToken,
                    resourceKind = captured.resourceKind,
                    pageIndex = captured.pageIndex,
                    formValue = Form.CompactLocator,
                    encodedHandle = captured.encodedHandle,
                    locatorToken = captured.locatorToken,
                    keyCommitmentFingerprint = captured.keyCommitmentFingerprint,
                    artifactCommitment = captured.artifactCommitment,
                    descriptorBinding = captured.descriptorBinding,
                    callSiteProofBinding = captured.callSiteProofBinding,
                    routeBinding = captured.routeBinding,
                    envelopeBinding = checkNotNull(binding),
                ).also { result ->
                    result.verifyEncodedBinding()
                }
            } finally {
                captured?.wipe()
                binding?.let { Arrays.fill(it, 0) }
            }
        }

        /**
         * Strictly parses one current-page compact envelope. Only the current
         * form id is accepted; every older encoding fails closed here.
         */
        @JvmSynthetic
        fun decode(encoded: ByteArray): QpPageEnvelope {
            require(encoded.isNotEmpty() && encoded.size <= MAX_ENCODED_SIZE) {
                "Qp native page envelope encoding length is invalid"
            }
            val reader = EnvelopeReader(encoded)
            val form = Form.fromId(reader.readUnsignedByte("Qp native page envelope form"))
                ?: throw IllegalArgumentException("unknown Qp native page envelope form")
            val entryToken = reader.readLong("Qp native page envelope entry token")
            val resourceKind = QpResourceKind.fromId(reader.readUnsignedByte("Qp native page envelope resource kind"))
                ?: throw IllegalArgumentException("unknown Qp native page envelope resource kind")
            val pageIndex = reader.readInt("Qp native page envelope page index")
            var encodedHandle: ByteArray? = null
            var locatorToken: ByteArray? = null
            var keyCommitmentFingerprint: ByteArray? = null
            var artifactCommitment: ByteArray? = null
            var descriptorBinding: ByteArray? = null
            var callSiteProofBinding: ByteArray? = null
            var routeBinding: ByteArray? = null
            var envelopeBinding: ByteArray? = null
            var result: QpPageEnvelope? = null
            var completed = false
            try {
                require(pageIndex >= 0) { "Qp native page envelope page index is invalid" }
                require(encoded.size == FIXED_WIRE_SIZE) {
                    "Qp native page envelope compact record length is invalid"
                }
                encodedHandle = reader.readFixed(QpHandle.ENCODED_HANDLE_SIZE, "Qp native page envelope handle")
                locatorToken = reader.readFixed(QpHandle.LOCATOR_TOKEN_SIZE, "Qp native page envelope locator")
                keyCommitmentFingerprint = reader.readFixed(
                    QpHandle.FINGERPRINT_SIZE,
                    "Qp native page envelope key commitment",
                )
                artifactCommitment = reader.readFixed(
                    QpArtifactCommitment.DIGEST_SIZE,
                    "Qp native page envelope artifact commitment",
                )
                descriptorBinding = reader.readFixed(BINDING_DIGEST_SIZE, "Qp native page envelope descriptor binding")
                callSiteProofBinding = reader.readFixed(BINDING_DIGEST_SIZE, "Qp native page envelope call-site binding")
                routeBinding = reader.readFixed(BINDING_DIGEST_SIZE, "Qp native page envelope route binding")
                envelopeBinding = reader.readFixed(BINDING_DIGEST_SIZE, "Qp native page envelope binding")
                reader.requireFullyRead("Qp native page envelope")
                result = QpPageEnvelope(
                    entryToken = entryToken,
                    resourceKind = resourceKind,
                    pageIndex = pageIndex,
                    formValue = form,
                    encodedHandle = checkNotNull(encodedHandle),
                    locatorToken = checkNotNull(locatorToken),
                    keyCommitmentFingerprint = checkNotNull(keyCommitmentFingerprint),
                    artifactCommitment = checkNotNull(artifactCommitment),
                    descriptorBinding = checkNotNull(descriptorBinding),
                    callSiteProofBinding = checkNotNull(callSiteProofBinding),
                    routeBinding = checkNotNull(routeBinding),
                    envelopeBinding = checkNotNull(envelopeBinding),
                )
                result.verifyEncodedBinding()
                completed = true
                return result
            } finally {
                encodedHandle?.let { Arrays.fill(it, 0) }
                locatorToken?.let { Arrays.fill(it, 0) }
                keyCommitmentFingerprint?.let { Arrays.fill(it, 0) }
                artifactCommitment?.let { Arrays.fill(it, 0) }
                descriptorBinding?.let { Arrays.fill(it, 0) }
                callSiteProofBinding?.let { Arrays.fill(it, 0) }
                routeBinding?.let { Arrays.fill(it, 0) }
                envelopeBinding?.let { Arrays.fill(it, 0) }
                if (!completed) result?.wipe()
            }
        }

        private fun captureDescriptorBinding(
            handle: QpHandle,
            descriptor: QpPageDescriptor,
            callSiteProof: ByteArray,
        ): CapturedDescriptorBinding {
            var suppliedHandle: ByteArray? = null
            var suppliedLocator: ByteArray? = null
            var suppliedFingerprint: ByteArray? = null
            var descriptorHandle: QpHandle? = null
            var descriptorHandleEncoding: ByteArray? = null
            var descriptorLocator: ByteArray? = null
            var descriptorFingerprint: ByteArray? = null
            var artifactCommitment: ByteArray? = null
            var descriptorCallSiteProof: ByteArray? = null
            var descriptorEncoding: ByteArray? = null
            var routeEncoding: ByteArray? = null
            var descriptorDigest: ByteArray? = null
            var proofDigest: ByteArray? = null
            var routeDigest: ByteArray? = null
            try {
                require(descriptor.resourceKind == handle.resourceKind) {
                    "Qp native page envelope descriptor kind does not match handle"
                }
                require(descriptor.pageIndex == handle.pageIndex) {
                    "Qp native page envelope descriptor index does not match handle"
                }
                suppliedHandle = handle.encoded
                suppliedLocator = handle.locatorToken
                suppliedFingerprint = handle.keyCommitmentFingerprint
                descriptorHandle = descriptor.handle
                descriptorHandleEncoding = descriptorHandle.encoded
                descriptorLocator = descriptorHandle.locatorToken
                descriptorFingerprint = descriptorHandle.keyCommitmentFingerprint
                artifactCommitment = descriptor.proof.artifactCanonicalCommitment
                descriptorCallSiteProof = descriptor.proof.callSiteProof
                descriptorEncoding = descriptor.encode()
                routeEncoding = descriptor.route.encode()

                val identityMatches = MessageDigest.isEqual(checkNotNull(suppliedHandle), checkNotNull(descriptorHandleEncoding)) &&
                    MessageDigest.isEqual(checkNotNull(suppliedLocator), checkNotNull(descriptorLocator)) &&
                    MessageDigest.isEqual(checkNotNull(suppliedFingerprint), checkNotNull(descriptorFingerprint))
                val callSiteMatches = MessageDigest.isEqual(
                    checkNotNull(descriptorCallSiteProof),
                    callSiteProof,
                )
                require(identityMatches && callSiteMatches) {
                    "Qp native page envelope request does not bind the current descriptor"
                }

                descriptorDigest = descriptorBinding(checkNotNull(descriptorEncoding))
                proofDigest = callSiteProofBinding(checkNotNull(descriptorCallSiteProof))
                routeDigest = routeBinding(checkNotNull(routeEncoding), checkNotNull(descriptorLocator))
                return CapturedDescriptorBinding(
                    resourceKind = descriptor.resourceKind,
                    pageIndex = descriptor.pageIndex,
                    encodedHandle = checkNotNull(suppliedHandle).copyOf(),
                    locatorToken = checkNotNull(suppliedLocator).copyOf(),
                    keyCommitmentFingerprint = checkNotNull(suppliedFingerprint).copyOf(),
                    artifactCommitment = checkNotNull(artifactCommitment).copyOf(),
                    descriptorBinding = checkNotNull(descriptorDigest).copyOf(),
                    callSiteProofBinding = checkNotNull(proofDigest).copyOf(),
                    routeBinding = checkNotNull(routeDigest).copyOf(),
                )
            } finally {
                suppliedHandle?.let { Arrays.fill(it, 0) }
                suppliedLocator?.let { Arrays.fill(it, 0) }
                suppliedFingerprint?.let { Arrays.fill(it, 0) }
                descriptorHandleEncoding?.let { Arrays.fill(it, 0) }
                descriptorLocator?.let { Arrays.fill(it, 0) }
                descriptorFingerprint?.let { Arrays.fill(it, 0) }
                artifactCommitment?.let { Arrays.fill(it, 0) }
                descriptorCallSiteProof?.let { Arrays.fill(it, 0) }
                descriptorEncoding?.let { Arrays.fill(it, 0) }
                routeEncoding?.let { Arrays.fill(it, 0) }
                descriptorDigest?.let { Arrays.fill(it, 0) }
                proofDigest?.let { Arrays.fill(it, 0) }
                routeDigest?.let { Arrays.fill(it, 0) }
                descriptorHandle?.wipe()
            }
        }

        private fun descriptorBinding(descriptorEncoding: ByteArray): ByteArray = digest(DESCRIPTOR_BINDING_DOMAIN) { digest ->
            updateFramed(digest, descriptorEncoding)
        }

        private fun callSiteProofBinding(callSiteProof: ByteArray): ByteArray = digest(CALL_SITE_BINDING_DOMAIN) { digest ->
            updateFramed(digest, callSiteProof)
        }

        private fun routeBinding(routeEncoding: ByteArray, locatorToken: ByteArray): ByteArray =
            digest(ROUTE_BINDING_DOMAIN) { digest ->
                updateFramed(digest, routeEncoding)
                updateFramed(digest, locatorToken)
            }

        private fun envelopeBinding(
            form: Form,
            entryToken: Long,
            resourceKind: QpResourceKind,
            pageIndex: Int,
            encodedHandle: ByteArray,
            locatorToken: ByteArray,
            keyCommitmentFingerprint: ByteArray,
            artifactCommitment: ByteArray,
            descriptorBinding: ByteArray,
            callSiteProofBinding: ByteArray,
            routeBinding: ByteArray,
        ): ByteArray = digest(ENVELOPE_BINDING_DOMAIN) { digest ->
            digest.update(form.id.toByte())
            updateLong(digest, entryToken)
            digest.update(resourceKind.id.toByte())
            updateInt(digest, pageIndex)
            updateFramed(digest, encodedHandle)
            updateFramed(digest, locatorToken)
            updateFramed(digest, keyCommitmentFingerprint)
            updateFramed(digest, artifactCommitment)
            updateFramed(digest, descriptorBinding)
            updateFramed(digest, callSiteProofBinding)
            updateFramed(digest, routeBinding)
        }

        private inline fun digest(domain: ByteArray, block: (MessageDigest) -> Unit): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(domain)
            block(digest)
            return digest.digest()
        }

        private fun writeInt(out: ByteArrayOutputStream, value: Int) {
            out.write((value ushr 24) and 0xFF)
            out.write((value ushr 16) and 0xFF)
            out.write((value ushr 8) and 0xFF)
            out.write(value and 0xFF)
        }

        private fun writeLong(out: ByteArrayOutputStream, value: Long) {
            for (shift in 56 downTo 0 step 8) out.write((value ushr shift).toInt() and 0xFF)
        }

        private fun updateInt(digest: MessageDigest, value: Int) {
            digest.update((value ushr 24).toByte())
            digest.update((value ushr 16).toByte())
            digest.update((value ushr 8).toByte())
            digest.update(value.toByte())
        }

        private fun updateLong(digest: MessageDigest, value: Long) {
            for (shift in 56 downTo 0 step 8) digest.update((value ushr shift).toByte())
        }

        private fun updateFramed(digest: MessageDigest, value: ByteArray) {
            updateInt(digest, value.size)
            digest.update(value)
        }
    }
}

/** Strict bounded parser for the native current-page envelope only. */
private class EnvelopeReader(private val bytes: ByteArray) {
    private var offset: Int = 0

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

    fun readLong(label: String): Long {
        requireRemaining(Long.SIZE_BYTES, label)
        var value = 0L
        repeat(Long.SIZE_BYTES) {
            value = (value shl 8) or (bytes[offset++].toLong() and 0xFFL)
        }
        return value
    }

    fun readFixed(length: Int, label: String): ByteArray {
        require(length >= 0) { "Qp native page envelope fixed length is invalid" }
        requireRemaining(length, label)
        return bytes.copyOfRange(offset, offset + length).also { offset += length }
    }

    fun requireFullyRead(label: String) {
        require(offset == bytes.size) { "$label contains trailing bytes" }
    }

    private fun requireRemaining(length: Int, label: String) {
        require(length >= 0 && offset <= bytes.size - length) { "$label is truncated" }
    }
}
