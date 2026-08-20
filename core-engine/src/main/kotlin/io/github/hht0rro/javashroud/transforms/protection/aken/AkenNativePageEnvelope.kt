package io.github.hht0rro.javashroud.transforms.protection.aken

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Arrays
import kotlin.jvm.JvmSynthetic

/**
 * Opaque, current-page-only envelope stored behind an artifact-specific native
 * locator.
 *
 * This is deliberately not a resource catalog and not a decoder. It binds
 * exactly one [AkenRuntimePageDescriptor] to one generated entry token, one
 * [AkenHandle], one page index, the descriptor's raw call-site proof, artifact
 * commitment, and route/locator metadata. No API here lists envelopes,
 * accepts arbitrary resource bytes, returns a DEK, or reconstructs a page.
 *
 * The Java typed JNI bridge continues to receive the descriptor's original raw
 * call-site proof as its proof argument. It never receives this envelope
 * encoding. Before the typed bridge validates that raw proof, the
 * artifact-specific native locator resolves this one envelope and either reads
 * its inline descriptor or resolves the same descriptor through its compact
 * route. The bounded envelope record is capped at 4096 bytes to keep native
 * parser allocation bounded; that cap intentionally matches the raw-proof
 * ABI limit without changing the byte-array argument's meaning.
 *
 * For ordinary descriptors the exact descriptor encoding is carried inline. A
 * legal descriptor may exceed the bounded record when its own raw call-site
 * proof approaches 4096 bytes. In that case the codec emits a compact locator
 * form: it commits to the exact descriptor encoding, raw call-site proof,
 * route, locator, and artifact commitment with independent SHA-256 bindings,
 * but deliberately does not copy the large descriptor bytes into the record.
 * The native locator must resolve that one descriptor through the
 * artifact-specific route and call [matchesDescriptor] before it constructs a
 * native page request.
 *
 * The digests in this type are public integrity bindings, not secret material.
 * They do not claim to create an artifact-external cryptographic secret.
 */
internal class AkenNativePageEnvelope private constructor(
    val entryToken: Long,
    val resourceKind: AkenResourceKind,
    val pageIndex: Int,
    private val formValue: Form,
    encodedHandle: ByteArray,
    locatorToken: ByteArray,
    evaluatorFingerprint: ByteArray,
    artifactCommitment: ByteArray,
    descriptorBinding: ByteArray,
    callSiteProofBinding: ByteArray,
    routeBinding: ByteArray,
    inlineDescriptor: ByteArray?,
    envelopeBinding: ByteArray,
) : AutoCloseable {
    private var encodedHandleValue = encodedHandle.copyOf()
    private var locatorTokenValue = locatorToken.copyOf()
    private var evaluatorFingerprintValue = evaluatorFingerprint.copyOf()
    private var artifactCommitmentValue = artifactCommitment.copyOf()
    private var descriptorBindingValue = descriptorBinding.copyOf()
    private var callSiteProofBindingValue = callSiteProofBinding.copyOf()
    private var routeBindingValue = routeBinding.copyOf()
    private var inlineDescriptorValue = inlineDescriptor?.copyOf()
    private var envelopeBindingValue = envelopeBinding.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(pageIndex >= 0) { "AKEN native page envelope index must be non-negative" }
        require(encodedHandleValue.size == AkenHandle.ENCODED_HANDLE_SIZE) {
            "AKEN native page envelope handle length is invalid"
        }
        require(locatorTokenValue.size == AkenHandle.LOCATOR_TOKEN_SIZE) {
            "AKEN native page envelope locator length is invalid"
        }
        require(evaluatorFingerprintValue.size == AkenHandle.FINGERPRINT_SIZE) {
            "AKEN native page envelope evaluator fingerprint length is invalid"
        }
        require(artifactCommitmentValue.size == AkenArtifactCommitment.DIGEST_SIZE) {
            "AKEN native page envelope artifact commitment length is invalid"
        }
        require(descriptorBindingValue.size == BINDING_DIGEST_SIZE) {
            "AKEN native page envelope descriptor binding length is invalid"
        }
        require(callSiteProofBindingValue.size == BINDING_DIGEST_SIZE) {
            "AKEN native page envelope call-site binding length is invalid"
        }
        require(routeBindingValue.size == BINDING_DIGEST_SIZE) {
            "AKEN native page envelope route binding length is invalid"
        }
        require(envelopeBindingValue.size == BINDING_DIGEST_SIZE) {
            "AKEN native page envelope binding length is invalid"
        }
        when (formValue) {
            Form.InlineDescriptor -> {
                require(inlineDescriptorValue != null && inlineDescriptorValue!!.isNotEmpty()) {
                    "AKEN native inline page descriptor is missing"
                }
            }

            Form.CompactLocator -> require(inlineDescriptorValue == null) {
                "AKEN native compact page envelope must not retain descriptor bytes"
            }
        }
    }

    /** True only while this exact-page owner remains live. */
    val isWiped: Boolean
        get() = wiped

    /** Whether the transport contains the exact descriptor encoding inline. */
    val hasInlineDescriptor: Boolean
        get() {
            requireLive()
            return formValue == Form.InlineDescriptor
        }

    /** Exact serialized size of this one envelope. Always at most 4096 bytes. */
    val encodedSize: Int
        get() {
            requireLive()
            return encodedSizeFor(formValue, inlineDescriptorValue?.size ?: 0)
        }

    /**
     * Defensive copy for the native current-page handoff only. The compact
     * form intentionally returns null; it does not reintroduce a large
     * descriptor transport or a Java-side catalog lookup.
     */
    @JvmSynthetic
    internal fun copyInlineDescriptorEncodingForCurrentPage(): ByteArray? {
        requireLive()
        return inlineDescriptorValue?.copyOf()
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
        if (encodedHandle.size != AkenHandle.ENCODED_HANDLE_SIZE ||
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
    fun matchesDescriptor(descriptor: AkenRuntimePageDescriptor): Boolean {
        if (wiped) return false

        var candidateHandle: AkenHandle? = null
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
            candidateFingerprint = candidateHandle.evaluatorPlanFingerprint
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
            val fingerprintMatches = MessageDigest.isEqual(evaluatorFingerprintValue, checkNotNull(candidateFingerprint))
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
     * Current-page-only combined validation used by a future typed native
     * bridge after its artifact-specific locator has resolved this envelope and
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
        descriptor: AkenRuntimePageDescriptor,
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
            out.write(evaluatorFingerprintValue)
            out.write(artifactCommitmentValue)
            out.write(descriptorBindingValue)
            out.write(callSiteProofBindingValue)
            out.write(routeBindingValue)
            if (formValue == Form.InlineDescriptor) {
                writeFramed(out, checkNotNull(inlineDescriptorValue))
            }
            out.write(envelopeBindingValue)
            out.toByteArray().also { encoded ->
                require(encoded.size <= MAX_ENCODED_SIZE) {
                    "AKEN native page envelope exceeds bounded locator-record limit"
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
        Arrays.fill(evaluatorFingerprintValue, 0)
        Arrays.fill(artifactCommitmentValue, 0)
        Arrays.fill(descriptorBindingValue, 0)
        Arrays.fill(callSiteProofBindingValue, 0)
        Arrays.fill(routeBindingValue, 0)
        inlineDescriptorValue?.let { Arrays.fill(it, 0) }
        Arrays.fill(envelopeBindingValue, 0)
        encodedHandleValue = ByteArray(0)
        locatorTokenValue = ByteArray(0)
        evaluatorFingerprintValue = ByteArray(0)
        artifactCommitmentValue = ByteArray(0)
        descriptorBindingValue = ByteArray(0)
        callSiteProofBindingValue = ByteArray(0)
        routeBindingValue = ByteArray(0)
        inlineDescriptorValue = null
        envelopeBindingValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN native page envelope has been wiped" }
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
                evaluatorFingerprint = evaluatorFingerprintValue,
                artifactCommitment = artifactCommitmentValue,
                descriptorBinding = descriptorBindingValue,
                callSiteProofBinding = callSiteProofBindingValue,
                routeBinding = routeBindingValue,
                inlineDescriptor = inlineDescriptorValue,
            )
            require(MessageDigest.isEqual(envelopeBindingValue, checkNotNull(expected))) {
                "AKEN native page envelope binding is invalid"
            }

            if (formValue == Form.InlineDescriptor) {
                val descriptor = AkenRuntimePageDescriptor.decode(checkNotNull(inlineDescriptorValue))
                require(matchesDescriptor(descriptor)) {
                    "AKEN native inline page descriptor binding is invalid"
                }
            }
        } finally {
            expected?.let { Arrays.fill(it, 0) }
        }
    }

    private enum class Form(val id: Int) {
        InlineDescriptor(1),
        CompactLocator(2),
        ;

        companion object {
            fun fromId(id: Int): Form? = entries.firstOrNull { it.id == id }
        }
    }

    private class CapturedDescriptorBinding(
        val resourceKind: AkenResourceKind,
        val pageIndex: Int,
        val encodedHandle: ByteArray,
        val locatorToken: ByteArray,
        val evaluatorFingerprint: ByteArray,
        val artifactCommitment: ByteArray,
        val descriptorEncoding: ByteArray,
        val descriptorBinding: ByteArray,
        val callSiteProofBinding: ByteArray,
        val routeBinding: ByteArray,
    ) {
        fun wipe() {
            Arrays.fill(encodedHandle, 0)
            Arrays.fill(locatorToken, 0)
            Arrays.fill(evaluatorFingerprint, 0)
            Arrays.fill(artifactCommitment, 0)
            Arrays.fill(descriptorEncoding, 0)
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
                AkenHandle.ENCODED_HANDLE_SIZE +
                AkenHandle.LOCATOR_TOKEN_SIZE +
                AkenHandle.FINGERPRINT_SIZE +
                AkenArtifactCommitment.DIGEST_SIZE +
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
            handle: AkenHandle,
            descriptor: AkenRuntimePageDescriptor,
            rawCallSiteProof: ByteArray,
        ): AkenNativePageEnvelope {
            require(rawCallSiteProof.isNotEmpty() && rawCallSiteProof.size <= MAX_CALL_SITE_PROOF_SIZE) {
                "AKEN native page envelope call-site proof length is invalid"
            }

            var captured: CapturedDescriptorBinding? = null
            var inlineDescriptor: ByteArray? = null
            var binding: ByteArray? = null
            try {
                captured = captureDescriptorBinding(handle, descriptor, rawCallSiteProof)
                val form = if (encodedSizeFor(Form.InlineDescriptor, captured.descriptorEncoding.size) <= MAX_ENCODED_SIZE) {
                    inlineDescriptor = captured.descriptorEncoding.copyOf()
                    Form.InlineDescriptor
                } else {
                    Form.CompactLocator
                }
                binding = envelopeBinding(
                    form = form,
                    entryToken = entryToken,
                    resourceKind = captured.resourceKind,
                    pageIndex = captured.pageIndex,
                    encodedHandle = captured.encodedHandle,
                    locatorToken = captured.locatorToken,
                    evaluatorFingerprint = captured.evaluatorFingerprint,
                    artifactCommitment = captured.artifactCommitment,
                    descriptorBinding = captured.descriptorBinding,
                    callSiteProofBinding = captured.callSiteProofBinding,
                    routeBinding = captured.routeBinding,
                    inlineDescriptor = inlineDescriptor,
                )
                return AkenNativePageEnvelope(
                    entryToken = entryToken,
                    resourceKind = captured.resourceKind,
                    pageIndex = captured.pageIndex,
                    formValue = form,
                    encodedHandle = captured.encodedHandle,
                    locatorToken = captured.locatorToken,
                    evaluatorFingerprint = captured.evaluatorFingerprint,
                    artifactCommitment = captured.artifactCommitment,
                    descriptorBinding = captured.descriptorBinding,
                    callSiteProofBinding = captured.callSiteProofBinding,
                    routeBinding = captured.routeBinding,
                    inlineDescriptor = inlineDescriptor,
                    envelopeBinding = checkNotNull(binding),
                ).also { result ->
                    result.verifyEncodedBinding()
                }
            } finally {
                captured?.wipe()
                inlineDescriptor?.let { Arrays.fill(it, 0) }
                binding?.let { Arrays.fill(it, 0) }
            }
        }

        /**
         * Strictly parses one current-page envelope. Inline envelopes reparse
         * and rebind the descriptor immediately. Compact envelopes retain only
         * fixed-size commitments and must later be paired with one resolved
         * descriptor through [matchesDescriptor].
         */
        @JvmSynthetic
        fun decode(encoded: ByteArray): AkenNativePageEnvelope {
            require(encoded.isNotEmpty() && encoded.size <= MAX_ENCODED_SIZE) {
                "AKEN native page envelope encoding length is invalid"
            }
            val reader = EnvelopeReader(encoded)
            val form = Form.fromId(reader.readUnsignedByte("AKEN native page envelope form"))
                ?: throw IllegalArgumentException("unknown AKEN native page envelope form")
            val entryToken = reader.readLong("AKEN native page envelope entry token")
            val resourceKind = AkenResourceKind.fromId(reader.readUnsignedByte("AKEN native page envelope resource kind"))
                ?: throw IllegalArgumentException("unknown AKEN native page envelope resource kind")
            val pageIndex = reader.readInt("AKEN native page envelope page index")
            var encodedHandle: ByteArray? = null
            var locatorToken: ByteArray? = null
            var evaluatorFingerprint: ByteArray? = null
            var artifactCommitment: ByteArray? = null
            var descriptorBinding: ByteArray? = null
            var callSiteProofBinding: ByteArray? = null
            var routeBinding: ByteArray? = null
            var inlineDescriptor: ByteArray? = null
            var envelopeBinding: ByteArray? = null
            var result: AkenNativePageEnvelope? = null
            var completed = false
            try {
                require(pageIndex >= 0) { "AKEN native page envelope page index is invalid" }
                encodedHandle = reader.readFixed(AkenHandle.ENCODED_HANDLE_SIZE, "AKEN native page envelope handle")
                locatorToken = reader.readFixed(AkenHandle.LOCATOR_TOKEN_SIZE, "AKEN native page envelope locator")
                evaluatorFingerprint = reader.readFixed(
                    AkenHandle.FINGERPRINT_SIZE,
                    "AKEN native page envelope evaluator fingerprint",
                )
                artifactCommitment = reader.readFixed(
                    AkenArtifactCommitment.DIGEST_SIZE,
                    "AKEN native page envelope artifact commitment",
                )
                descriptorBinding = reader.readFixed(BINDING_DIGEST_SIZE, "AKEN native page envelope descriptor binding")
                callSiteProofBinding = reader.readFixed(BINDING_DIGEST_SIZE, "AKEN native page envelope call-site binding")
                routeBinding = reader.readFixed(BINDING_DIGEST_SIZE, "AKEN native page envelope route binding")
                if (form == Form.InlineDescriptor) {
                    inlineDescriptor = reader.readFramed(
                        maximumLength = MAX_ENCODED_SIZE - FIXED_WIRE_SIZE - Int.SIZE_BYTES,
                        label = "AKEN native inline page descriptor",
                        allowEmpty = false,
                    )
                }
                envelopeBinding = reader.readFixed(BINDING_DIGEST_SIZE, "AKEN native page envelope binding")
                reader.requireFullyRead("AKEN native page envelope")
                result = AkenNativePageEnvelope(
                    entryToken = entryToken,
                    resourceKind = resourceKind,
                    pageIndex = pageIndex,
                    formValue = form,
                    encodedHandle = checkNotNull(encodedHandle),
                    locatorToken = checkNotNull(locatorToken),
                    evaluatorFingerprint = checkNotNull(evaluatorFingerprint),
                    artifactCommitment = checkNotNull(artifactCommitment),
                    descriptorBinding = checkNotNull(descriptorBinding),
                    callSiteProofBinding = checkNotNull(callSiteProofBinding),
                    routeBinding = checkNotNull(routeBinding),
                    inlineDescriptor = inlineDescriptor,
                    envelopeBinding = checkNotNull(envelopeBinding),
                )
                result.verifyEncodedBinding()
                completed = true
                return result
            } finally {
                encodedHandle?.let { Arrays.fill(it, 0) }
                locatorToken?.let { Arrays.fill(it, 0) }
                evaluatorFingerprint?.let { Arrays.fill(it, 0) }
                artifactCommitment?.let { Arrays.fill(it, 0) }
                descriptorBinding?.let { Arrays.fill(it, 0) }
                callSiteProofBinding?.let { Arrays.fill(it, 0) }
                routeBinding?.let { Arrays.fill(it, 0) }
                inlineDescriptor?.let { Arrays.fill(it, 0) }
                envelopeBinding?.let { Arrays.fill(it, 0) }
                if (!completed) result?.wipe()
            }
        }

        private fun captureDescriptorBinding(
            handle: AkenHandle,
            descriptor: AkenRuntimePageDescriptor,
            callSiteProof: ByteArray,
        ): CapturedDescriptorBinding {
            var suppliedHandle: ByteArray? = null
            var suppliedLocator: ByteArray? = null
            var suppliedFingerprint: ByteArray? = null
            var descriptorHandle: AkenHandle? = null
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
                    "AKEN native page envelope descriptor kind does not match handle"
                }
                require(descriptor.pageIndex == handle.pageIndex) {
                    "AKEN native page envelope descriptor index does not match handle"
                }
                suppliedHandle = handle.encoded
                suppliedLocator = handle.locatorToken
                suppliedFingerprint = handle.evaluatorPlanFingerprint
                descriptorHandle = descriptor.handle
                descriptorHandleEncoding = descriptorHandle.encoded
                descriptorLocator = descriptorHandle.locatorToken
                descriptorFingerprint = descriptorHandle.evaluatorPlanFingerprint
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
                    "AKEN native page envelope request does not bind the current descriptor"
                }

                descriptorDigest = descriptorBinding(checkNotNull(descriptorEncoding))
                proofDigest = callSiteProofBinding(checkNotNull(descriptorCallSiteProof))
                routeDigest = routeBinding(checkNotNull(routeEncoding), checkNotNull(descriptorLocator))
                return CapturedDescriptorBinding(
                    resourceKind = descriptor.resourceKind,
                    pageIndex = descriptor.pageIndex,
                    encodedHandle = checkNotNull(suppliedHandle).copyOf(),
                    locatorToken = checkNotNull(suppliedLocator).copyOf(),
                    evaluatorFingerprint = checkNotNull(suppliedFingerprint).copyOf(),
                    artifactCommitment = checkNotNull(artifactCommitment).copyOf(),
                    descriptorEncoding = checkNotNull(descriptorEncoding).copyOf(),
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
            resourceKind: AkenResourceKind,
            pageIndex: Int,
            encodedHandle: ByteArray,
            locatorToken: ByteArray,
            evaluatorFingerprint: ByteArray,
            artifactCommitment: ByteArray,
            descriptorBinding: ByteArray,
            callSiteProofBinding: ByteArray,
            routeBinding: ByteArray,
            inlineDescriptor: ByteArray?,
        ): ByteArray = digest(ENVELOPE_BINDING_DOMAIN) { digest ->
            digest.update(form.id.toByte())
            updateLong(digest, entryToken)
            digest.update(resourceKind.id.toByte())
            updateInt(digest, pageIndex)
            updateFramed(digest, encodedHandle)
            updateFramed(digest, locatorToken)
            updateFramed(digest, evaluatorFingerprint)
            updateFramed(digest, artifactCommitment)
            updateFramed(digest, descriptorBinding)
            updateFramed(digest, callSiteProofBinding)
            updateFramed(digest, routeBinding)
            if (form == Form.InlineDescriptor) {
                updateFramed(digest, checkNotNull(inlineDescriptor))
            }
        }

        private inline fun digest(domain: ByteArray, block: (MessageDigest) -> Unit): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(domain)
            block(digest)
            return digest.digest()
        }

        private fun encodedSizeFor(form: Form, inlineDescriptorLength: Int): Int {
            require(inlineDescriptorLength >= 0) { "AKEN native page envelope descriptor length is invalid" }
            val size = when (form) {
                Form.InlineDescriptor -> FIXED_WIRE_SIZE.toLong() + Int.SIZE_BYTES + inlineDescriptorLength.toLong()
                Form.CompactLocator -> FIXED_WIRE_SIZE.toLong()
            }
            require(size <= Int.MAX_VALUE.toLong()) { "AKEN native page envelope size overflows" }
            return size.toInt()
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

        private fun writeFramed(out: ByteArrayOutputStream, value: ByteArray) {
            writeInt(out, value.size)
            out.write(value)
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
        require(length >= 0) { "AKEN native page envelope fixed length is invalid" }
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
