package io.github.hht0rro.javashroud.transforms.protection.aken

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Arrays

/**
 * Build-only native compiler input for one exact AKEN v4 high-value page.
 *
 * This owner serializes one current-page locator record for the native
 * compilation phase. It is intentionally not a Java runtime locator, a
 * directory, or an arbitrary-resource decoder: its only matching operation
 * accepts the exact typed bridge tuple for this page and verifies it against
 * the independently encoded envelope and descriptor.
 *
 * The raw call-site proof has no standalone compiler-record field. It can
 * remain within the exact resolved descriptor encoding required for descriptor
 * binding, while the typed JNI argument stays the independent proof transport
 * at page-access time.
 */
internal class AkenNativePageLocatorCompileInput private constructor(
    val entryToken: Long,
    val resourceKind: AkenResourceKind,
    val pageIndex: Int,
    val resourcePath: String,
    val resourceOffset: Int,
    val storedLength: Int,
    encodedHandle: ByteArray,
    nativeEnvelope: ByteArray,
    resolvedDescriptor: ByteArray,
    routeEncoding: ByteArray,
    pageBindingDigest: ByteArray,
) : AutoCloseable {
    private var encodedHandleValue: ByteArray = encodedHandle.copyOf()
    private var nativeEnvelopeValue: ByteArray = nativeEnvelope.copyOf()
    private var resolvedDescriptorValue: ByteArray = resolvedDescriptor.copyOf()
    private var routeEncodingValue: ByteArray = routeEncoding.copyOf()
    private var pageBindingDigestValue: ByteArray = pageBindingDigest.copyOf()
    private var recordBindingValue: ByteArray = compilerRecordBinding(
        entryToken = entryToken,
        resourceKind = resourceKind,
        pageIndex = pageIndex,
        encodedHandle = encodedHandleValue,
        nativeEnvelope = nativeEnvelopeValue,
        resolvedDescriptor = resolvedDescriptorValue,
        routeEncoding = routeEncodingValue,
        pageBindingDigest = pageBindingDigestValue,
    )

    @Volatile
    private var wiped: Boolean = false

    init {
        require(pageIndex >= 0) { "AKEN native page locator page index must be non-negative" }
        require(resourcePath.isNotBlank() && '\u0000' !in resourcePath && '\\' !in resourcePath) {
            "AKEN native page locator resource path is invalid"
        }
        require(resourceOffset >= 0 && storedLength > 0) {
            "AKEN native page locator route bounds are invalid"
        }
        require(encodedHandleValue.size == AkenHandle.ENCODED_HANDLE_SIZE) {
            "AKEN native page locator handle length is invalid"
        }
        require(nativeEnvelopeValue.isNotEmpty() && nativeEnvelopeValue.size <= MAX_ENVELOPE_BYTES) {
            "AKEN native page locator envelope length is invalid"
        }
        require(resolvedDescriptorValue.isNotEmpty() && resolvedDescriptorValue.size <= MAX_DESCRIPTOR_BYTES) {
            "AKEN native page locator descriptor length is invalid"
        }
        require(routeEncodingValue.isNotEmpty() && routeEncodingValue.size <= MAX_ROUTE_BYTES) {
            "AKEN native page locator route length is invalid"
        }
        require(pageBindingDigestValue.size == PAGE_BINDING_DIGEST_SIZE) {
            "AKEN native page locator page-binding digest length is invalid"
        }
        require(recordBindingValue.size == RECORD_BINDING_SIZE) {
            "AKEN native page locator record binding length is invalid"
        }
        verifyStaticBindings()
    }

    val isWiped: Boolean
        get() = wiped

    /**
     * Returns a defensive compiler-only copy of the current-page opaque handle.
     * This does not open the page or expose a catalog.
     */
    internal fun copyEncodedHandleForCompiler(): ByteArray {
        requireLive()
        return encodedHandleValue.copyOf()
    }

    /** Returns the bounded native locator envelope for this one page. */
    internal fun copyNativeEnvelopeForCompiler(): ByteArray {
        requireLive()
        return nativeEnvelopeValue.copyOf()
    }

    /** Returns the exact descriptor bytes that a native-private locator must resolve. */
    internal fun copyResolvedDescriptorForCompiler(): ByteArray {
        requireLive()
        return resolvedDescriptorValue.copyOf()
    }

    /** Returns the exact route encoding bound by the envelope. */
    internal fun copyRouteEncodingForCompiler(): ByteArray {
        requireLive()
        return routeEncodingValue.copyOf()
    }

    /**
     * Returns the public page-specific binding digest for this one current
     * page. VBC4 carries its state-layout digest here; typed non-VBC4 records
     * carry their handle/route binding. It is integrity metadata, never a DEK
     * or root key.
     */
    internal fun copyPageBindingDigestForCompiler(): ByteArray {
        requireLive()
        return pageBindingDigestValue.copyOf()
    }

    /**
     * Emits a framed native compiler record for exactly one page. The record
     * contains no DEK, plaintext, raw proof, root-key chain, or resource list.
     */
    internal fun copyNativeLocatorRecordForCompiler(): ByteArray {
        requireLive()
        return ByteArrayOutputStream().use { out ->
            writeLong(out, entryToken)
            out.write(resourceKind.id)
            writeInt(out, pageIndex)
            writeFramed(out, encodedHandleValue)
            writeFramed(out, nativeEnvelopeValue)
            writeFramed(out, resolvedDescriptorValue)
            writeFramed(out, routeEncodingValue)
            out.write(pageBindingDigestValue)
            out.write(recordBindingValue)
            out.toByteArray().also { encoded ->
                require(encoded.size <= MAX_COMPILER_RECORD_BYTES) {
                    "AKEN native page locator compiler record exceeds its bounded size"
                }
            }
        }
    }

    /**
     * Build-time exact current-page match. The proof argument is the raw typed
     * JNI proof, not the native envelope bytes.
     */
    internal fun matchesCurrentPageForBuild(
        entryToken: Long,
        encodedHandle: ByteArray,
        pageIndex: Int,
        rawCallSiteProof: ByteArray,
    ): Boolean {
        if (wiped) return false
        if (encodedHandle.size != AkenHandle.ENCODED_HANDLE_SIZE || rawCallSiteProof.isEmpty()) return false

        var descriptor: AkenRuntimePageDescriptor? = null
        var envelope: AkenNativePageEnvelope? = null
        var encodedRoute: ByteArray? = null
        try {
            descriptor = AkenRuntimePageDescriptor.decode(resolvedDescriptorValue)
            envelope = AkenNativePageEnvelope.decode(nativeEnvelopeValue)
            val route = descriptor.route
            encodedRoute = route.encode()
            val exactRequest = this.entryToken == entryToken &&
                this.pageIndex == pageIndex &&
                MessageDigest.isEqual(encodedHandleValue, encodedHandle)
            val exactRoute = descriptor.resourceKind == resourceKind &&
                descriptor.pageIndex == this.pageIndex &&
                route.resourcePath == resourcePath &&
                route.resourceOffset == resourceOffset &&
                route.storedLength == storedLength &&
                MessageDigest.isEqual(checkNotNull(encodedRoute), routeEncodingValue)
            return exactRequest &&
                exactRoute &&
                envelope.matchesCurrentPage(
                    entryToken = entryToken,
                    encodedHandle = encodedHandle,
                    pageIndex = pageIndex,
                    rawCallSiteProof = rawCallSiteProof,
                    descriptor = descriptor,
                )
        } catch (_: IllegalArgumentException) {
            return false
        } finally {
            encodedRoute?.let { Arrays.fill(it, 0) }
            envelope?.wipe()
        }
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(encodedHandleValue, 0)
        Arrays.fill(nativeEnvelopeValue, 0)
        Arrays.fill(resolvedDescriptorValue, 0)
        Arrays.fill(routeEncodingValue, 0)
        Arrays.fill(pageBindingDigestValue, 0)
        Arrays.fill(recordBindingValue, 0)
        encodedHandleValue = ByteArray(0)
        nativeEnvelopeValue = ByteArray(0)
        resolvedDescriptorValue = ByteArray(0)
        routeEncodingValue = ByteArray(0)
        pageBindingDigestValue = ByteArray(0)
        recordBindingValue = ByteArray(0)
        wiped = true
    }

    private fun verifyStaticBindings() {
        var descriptor: AkenRuntimePageDescriptor? = null
        var envelope: AkenNativePageEnvelope? = null
        var route: ByteArray? = null
        var handle: AkenHandle? = null
        var expectedBinding: ByteArray? = null
        try {
            descriptor = AkenRuntimePageDescriptor.decode(resolvedDescriptorValue)
            require(descriptor.resourceKind == resourceKind && descriptor.pageIndex == pageIndex) {
                "AKEN native page locator descriptor identity is invalid"
            }
            route = descriptor.route.encode()
            require(MessageDigest.isEqual(route, routeEncodingValue)) {
                "AKEN native page locator descriptor route binding is invalid"
            }
            require(
                descriptor.route.resourcePath == resourcePath &&
                    descriptor.route.resourceOffset == resourceOffset &&
                    descriptor.route.storedLength == storedLength,
            ) { "AKEN native page locator route metadata is invalid" }

            handle = descriptor.handle
            val descriptorHandle = handle.encoded
            try {
                require(MessageDigest.isEqual(descriptorHandle, encodedHandleValue)) {
                    "AKEN native page locator handle binding is invalid"
                }
            } finally {
                Arrays.fill(descriptorHandle, 0)
            }

            envelope = AkenNativePageEnvelope.decode(nativeEnvelopeValue)
            val proof = descriptor.proof.callSiteProof
            try {
                require(
                    envelope.matchesCurrentPage(
                        entryToken = entryToken,
                        encodedHandle = encodedHandleValue,
                        pageIndex = pageIndex,
                        rawCallSiteProof = proof,
                        descriptor = descriptor,
                    ),
                ) { "AKEN native page locator envelope binding is invalid" }
            } finally {
                Arrays.fill(proof, 0)
            }

            expectedBinding = compilerRecordBinding(
                entryToken = entryToken,
                resourceKind = resourceKind,
                pageIndex = pageIndex,
                encodedHandle = encodedHandleValue,
                nativeEnvelope = nativeEnvelopeValue,
                resolvedDescriptor = resolvedDescriptorValue,
                routeEncoding = routeEncodingValue,
                pageBindingDigest = pageBindingDigestValue,
            )
            require(MessageDigest.isEqual(expectedBinding, recordBindingValue)) {
                "AKEN native page locator compiler record binding is invalid"
            }
        } finally {
            route?.let { Arrays.fill(it, 0) }
            expectedBinding?.let { Arrays.fill(it, 0) }
            handle?.wipe()
            envelope?.wipe()
        }
    }

    private fun requireLive() {
        check(!wiped) { "AKEN native page locator compiler input has been wiped" }
    }

    companion object {
        private const val MAX_ENVELOPE_BYTES = 4096
        private const val MAX_DESCRIPTOR_BYTES = 384 * 1024
        private const val MAX_ROUTE_BYTES = 128 * 1024
        private const val MAX_COMPILER_RECORD_BYTES = 512 * 1024
        private const val RECORD_BINDING_SIZE = 32
        private const val PAGE_BINDING_DIGEST_SIZE = 32
        private val RECORD_BINDING_DOMAIN =
            "native-page-locator-compile-input".toByteArray(Charsets.US_ASCII)

        /**
         * Converts one independently materialized VBC4 page into native compile
         * input. The resulting object owns fresh copies and can therefore
         * outlive the immediately adjacent emission owner until the native
         * compiler consumes it.
         */
        @JvmSynthetic
        fun fromVbc4Emission(
            emission: AkenVbc4PageEmission,
            vbc4StateBindingLayoutDigest: ByteArray,
        ): AkenNativePageLocatorCompileInput {
            require(vbc4StateBindingLayoutDigest.size == PAGE_BINDING_DIGEST_SIZE) {
                "AKEN native page locator VBC4 state-binding layout digest length is invalid"
            }
            var descriptorBytes: ByteArray? = null
            var routeBytes: ByteArray? = null
            var rawCallSiteProof: ByteArray? = null
            var descriptorProof: ByteArray? = null
            var encodedHandle: ByteArray? = null
            var envelopeBytes: ByteArray? = null
            var descriptor: AkenRuntimePageDescriptor? = null
            var handle: AkenHandle? = null
            var envelope: AkenNativePageEnvelope? = null
            try {
                descriptorBytes = emission.copyDescriptorBytesForBuild()
                descriptor = AkenRuntimePageDescriptor.decode(descriptorBytes)
                require(descriptor.resourceKind == AkenResourceKind.Vbc4Method) {
                    "AKEN native page locator requires a VBC4 descriptor"
                }
                require(descriptor.pageIndex == emission.pageIndex) {
                    "AKEN native page locator descriptor page index is invalid"
                }

                val route = descriptor.route
                require(
                    route.resourcePath == emission.resourcePath &&
                        route.resourceOffset == emission.resourceOffset &&
                        route.storedLength == emission.storedLength,
                ) { "AKEN native page locator emission route is invalid" }

                rawCallSiteProof = emission.copyCallSiteProofForBuild()
                descriptorProof = descriptor.proof.callSiteProof
                require(MessageDigest.isEqual(rawCallSiteProof, descriptorProof)) {
                    "AKEN native page locator call-site proof is invalid"
                }

                handle = emission.copyHandleForBuild()
                require(descriptor.matches(handle)) {
                    "AKEN native page locator handle does not match descriptor"
                }
                encodedHandle = handle.encoded
                envelope = AkenNativePageEnvelope.create(
                    entryToken = emission.entryToken,
                    handle = handle,
                    descriptor = descriptor,
                    rawCallSiteProof = rawCallSiteProof,
                )
                envelopeBytes = envelope.encode()
                routeBytes = route.encode()

                return AkenNativePageLocatorCompileInput(
                    entryToken = emission.entryToken,
                    resourceKind = descriptor.resourceKind,
                    pageIndex = descriptor.pageIndex,
                    resourcePath = route.resourcePath,
                    resourceOffset = route.resourceOffset,
                    storedLength = route.storedLength,
                    encodedHandle = encodedHandle,
                    nativeEnvelope = envelopeBytes,
                    resolvedDescriptor = descriptorBytes,
                    routeEncoding = routeBytes,
                    pageBindingDigest = vbc4StateBindingLayoutDigest,
                )
            } finally {
                descriptorBytes?.let { Arrays.fill(it, 0) }
                routeBytes?.let { Arrays.fill(it, 0) }
                rawCallSiteProof?.let { Arrays.fill(it, 0) }
                descriptorProof?.let { Arrays.fill(it, 0) }
                encodedHandle?.let { Arrays.fill(it, 0) }
                envelopeBytes?.let { Arrays.fill(it, 0) }
                envelope?.wipe()
                handle?.wipe()
            }
        }

        /**
         * Converts one already-materialized typed page into native compiler
         * input.  The entry token is derived only from the exact non-VBC4
         * kind/page/handle tuple so the typed JNI bridge does not need to accept
         * a caller-controlled token.
         */
        @JvmSynthetic
        fun fromTypedPage(
            descriptor: AkenRuntimePageDescriptor,
            rawCallSiteProof: ByteArray,
        ): AkenNativePageLocatorCompileInput {
            require(descriptor.resourceKind != AkenResourceKind.Vbc4Method) {
                "AKEN typed native page locator does not apply to VBC4"
            }
            var descriptorBytes: ByteArray? = null
            var routeBytes: ByteArray? = null
            var copiedProof: ByteArray? = null
            var descriptorProof: ByteArray? = null
            var encodedHandle: ByteArray? = null
            var envelopeBytes: ByteArray? = null
            var pageBindingDigest: ByteArray? = null
            var handle: AkenHandle? = null
            var envelope: AkenNativePageEnvelope? = null
            try {
                descriptorBytes = descriptor.encode()
                val resolvedDescriptor = AkenRuntimePageDescriptor.decode(descriptorBytes)
                require(resolvedDescriptor.resourceKind != AkenResourceKind.Vbc4Method) {
                    "AKEN typed native page locator requires a non-VBC4 descriptor"
                }
                copiedProof = rawCallSiteProof.copyOf()
                descriptorProof = resolvedDescriptor.proof.callSiteProof
                require(MessageDigest.isEqual(copiedProof, descriptorProof)) {
                    "AKEN typed native page locator call-site proof is invalid"
                }

                handle = resolvedDescriptor.handle
                require(resolvedDescriptor.matches(handle)) {
                    "AKEN typed native page locator handle does not match descriptor"
                }
                encodedHandle = handle.encoded
                val route = resolvedDescriptor.route
                routeBytes = route.encode()
                val entryToken = AkenTypedPageEntryToken.derive(
                    resourceKind = resolvedDescriptor.resourceKind,
                    pageIndex = resolvedDescriptor.pageIndex,
                    encodedHandle = encodedHandle,
                )
                envelope = AkenNativePageEnvelope.create(
                    entryToken = entryToken,
                    handle = handle,
                    descriptor = resolvedDescriptor,
                    rawCallSiteProof = copiedProof,
                )
                envelopeBytes = envelope.encode()
                pageBindingDigest = AkenTypedPageEntryToken.pageBinding(
                    resourceKind = resolvedDescriptor.resourceKind,
                    pageIndex = resolvedDescriptor.pageIndex,
                    encodedHandle = encodedHandle,
                    routeEncoding = routeBytes,
                )
                return AkenNativePageLocatorCompileInput(
                    entryToken = entryToken,
                    resourceKind = resolvedDescriptor.resourceKind,
                    pageIndex = resolvedDescriptor.pageIndex,
                    resourcePath = route.resourcePath,
                    resourceOffset = route.resourceOffset,
                    storedLength = route.storedLength,
                    encodedHandle = encodedHandle,
                    nativeEnvelope = envelopeBytes,
                    resolvedDescriptor = descriptorBytes,
                    routeEncoding = routeBytes,
                    pageBindingDigest = pageBindingDigest,
                )
            } finally {
                descriptorBytes?.let { Arrays.fill(it, 0) }
                routeBytes?.let { Arrays.fill(it, 0) }
                copiedProof?.let { Arrays.fill(it, 0) }
                descriptorProof?.let { Arrays.fill(it, 0) }
                encodedHandle?.let { Arrays.fill(it, 0) }
                envelopeBytes?.let { Arrays.fill(it, 0) }
                pageBindingDigest?.let { Arrays.fill(it, 0) }
                envelope?.wipe()
                handle?.wipe()
            }
        }

        private fun compilerRecordBinding(
            entryToken: Long,
            resourceKind: AkenResourceKind,
            pageIndex: Int,
            encodedHandle: ByteArray,
            nativeEnvelope: ByteArray,
            resolvedDescriptor: ByteArray,
            routeEncoding: ByteArray,
            pageBindingDigest: ByteArray,
        ): ByteArray = MessageDigest.getInstance("SHA-256").apply {
            update(RECORD_BINDING_DOMAIN)
            updateLong(this, entryToken)
            update(resourceKind.id.toByte())
            updateInt(this, pageIndex)
            updateFramed(this, encodedHandle)
            updateFramed(this, nativeEnvelope)
            updateFramed(this, resolvedDescriptor)
            updateFramed(this, routeEncoding)
            update(pageBindingDigest)
        }.digest()

        private fun writeLong(out: ByteArrayOutputStream, value: Long) {
            for (shift in 56 downTo 0 step 8) {
                out.write((value ushr shift).toInt() and 0xFF)
            }
        }

        private fun writeInt(out: ByteArrayOutputStream, value: Int) {
            out.write((value ushr 24) and 0xFF)
            out.write((value ushr 16) and 0xFF)
            out.write((value ushr 8) and 0xFF)
            out.write(value and 0xFF)
        }

        private fun writeFramed(out: ByteArrayOutputStream, value: ByteArray) {
            writeInt(out, value.size)
            out.write(value)
        }

        private fun updateLong(digest: MessageDigest, value: Long) {
            for (shift in 56 downTo 0 step 8) {
                digest.update(((value ushr shift).toInt() and 0xFF).toByte())
            }
        }

        private fun updateInt(digest: MessageDigest, value: Int) {
            digest.update(((value ushr 24) and 0xFF).toByte())
            digest.update(((value ushr 16) and 0xFF).toByte())
            digest.update(((value ushr 8) and 0xFF).toByte())
            digest.update((value and 0xFF).toByte())
        }

        private fun updateFramed(digest: MessageDigest, value: ByteArray) {
            updateInt(digest, value.size)
            digest.update(value)
        }
    }
}
