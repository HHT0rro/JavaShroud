package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.MessageDigest
import java.util.Arrays
import java.util.Base64
import kotlin.jvm.JvmSynthetic

/**
 * Build-only ownership wrapper for one already-registered VBC4 AKEN page.
 *
 * The request keeps defensive copies of its plaintext, logical identity, and
 * call-site proof until [AkenVbc4PageEmitter] consumes it. It never exposes a
 * DEK, a page decoder, or a runtime resource lookup surface. The supplied
 * identity must exactly match the registered page identity, while distinct
 * [AkenBuildPlan.Page.pageIndex] values remain independent pages of the same
 * logical VBC4 method.
 */
internal class AkenVbc4PageEmissionRequest private constructor(
    internal val page: AkenBuildPlan.Page,
    val entryToken: Long,
    logicalIdentity: ByteArray,
    plaintext: ByteArray,
    val resourcePath: String,
    val resourceOffset: Int,
    callSiteProof: ByteArray,
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var plaintextValue: ByteArray = plaintext.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(page.resourceKind == AkenResourceKind.Vbc4Method) {
            "AKEN VBC4 page emission requires a Vbc4Method page"
        }
        require(logicalIdentityValue.isNotEmpty()) { "AKEN VBC4 logical identity must not be empty" }
        require(plaintextValue.isNotEmpty()) { "AKEN VBC4 page plaintext must not be empty" }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "AKEN VBC4 call-site proof length is invalid"
        }
        require(resourcePath.isNotBlank() && '\u0000' !in resourcePath) {
            "AKEN VBC4 resource path is invalid"
        }
        require(resourceOffset >= 0) { "AKEN VBC4 resource offset must be non-negative" }
        verifyPageBinding()
    }

    val pageIndex: Int
        get() {
            requireLive()
            return page.pageIndex
        }

    val isWiped: Boolean
        get() = wiped

    internal fun toMaterializationInput(): AkenPageMaterializationInput {
        requireLive()
        val plaintext = plaintextValue.copyOf()
        val callSiteProof = callSiteProofValue.copyOf()
        return try {
            AkenPageMaterializationInput.create(
                page = page,
                plaintext = plaintext,
                resourcePath = resourcePath,
                resourceOffset = resourceOffset,
                callSiteProof = callSiteProof,
            )
        } finally {
            Arrays.fill(plaintext, 0)
            Arrays.fill(callSiteProof, 0)
        }
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(logicalIdentityValue, 0)
        Arrays.fill(plaintextValue, 0)
        Arrays.fill(callSiteProofValue, 0)
        logicalIdentityValue = ByteArray(0)
        plaintextValue = ByteArray(0)
        callSiteProofValue = ByteArray(0)
        wiped = true
    }

    private fun verifyPageBinding() {
        val registeredIdentity = page.logicalIdentity
        try {
            require(MessageDigest.isEqual(registeredIdentity, logicalIdentityValue)) {
                "AKEN VBC4 request identity does not match its registered page"
            }
        } finally {
            Arrays.fill(registeredIdentity, 0)
        }
    }

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 page emission request has been wiped" }
    }

    companion object {
        private const val MAX_CALL_SITE_PROOF_SIZE = 4096

        fun create(
            page: AkenBuildPlan.Page,
            entryToken: Long,
            logicalIdentity: ByteArray,
            plaintext: ByteArray,
            resourcePath: String,
            resourceOffset: Int = 0,
            callSiteProof: ByteArray,
        ): AkenVbc4PageEmissionRequest = AkenVbc4PageEmissionRequest(
            page = page,
            entryToken = entryToken,
            logicalIdentity = logicalIdentity,
            plaintext = plaintext,
            resourcePath = resourcePath,
            resourceOffset = resourceOffset,
            callSiteProof = callSiteProof,
        )
    }
}

/**
 * One build-only, independently materialized VBC4 page resource.
 *
 * Stored payload, descriptor, handle components, logical identity, and
 * call-site proof are private mutable storage solely so [wipe] can clear them.
 * All readable byte material is returned as a fresh defensive copy. There is
 * deliberately no method that opens a payload, returns a DEK, or accepts an
 * arbitrary resource/key pair.
 */
internal class AkenVbc4PageEmission private constructor(
    val entryToken: Long,
    val resourcePath: String,
    val resourceOffset: Int,
    val storedLength: Int,
    val pageIndex: Int,
    descriptorBytes: ByteArray,
    encryptedPayload: ByteArray,
    handleEncoding: ByteArray,
    locatorToken: ByteArray,
    evaluatorFingerprint: ByteArray,
    logicalIdentity: ByteArray,
    callSiteProof: ByteArray,
) : AutoCloseable {
    private var descriptorBytesValue: ByteArray = descriptorBytes.copyOf()
    private var encryptedPayloadValue: ByteArray = encryptedPayload.copyOf()
    private var handleEncodingValue: ByteArray = handleEncoding.copyOf()
    private var locatorTokenValue: ByteArray = locatorToken.copyOf()
    private var evaluatorFingerprintValue: ByteArray = evaluatorFingerprint.copyOf()
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(resourcePath.isNotBlank() && '\u0000' !in resourcePath) { "AKEN VBC4 output path is invalid" }
        require(resourceOffset >= 0) { "AKEN VBC4 output offset must be non-negative" }
        require(storedLength > 0 && storedLength == encryptedPayloadValue.size) {
            "AKEN VBC4 output payload length is invalid"
        }
        require(pageIndex >= 0) { "AKEN VBC4 output page index must be non-negative" }
        require(descriptorBytesValue.isNotEmpty()) { "AKEN VBC4 descriptor bytes must not be empty" }
        require(handleEncodingValue.size == AkenHandle.ENCODED_HANDLE_SIZE) {
            "AKEN VBC4 output handle encoding length is invalid"
        }
        require(locatorTokenValue.size == AkenHandle.LOCATOR_TOKEN_SIZE) {
            "AKEN VBC4 output locator token length is invalid"
        }
        require(evaluatorFingerprintValue.size == AkenHandle.FINGERPRINT_SIZE) {
            "AKEN VBC4 output evaluator fingerprint length is invalid"
        }
        require(logicalIdentityValue.isNotEmpty()) { "AKEN VBC4 output logical identity must not be empty" }
        require(callSiteProofValue.isNotEmpty()) { "AKEN VBC4 output call-site proof must not be empty" }
    }

    val isWiped: Boolean
        get() = wiped

    internal fun copyEncryptedPayloadForBuild(): ByteArray {
        requireLive()
        return encryptedPayloadValue.copyOf()
    }

    internal fun copyDescriptorBytesForBuild(): ByteArray {
        requireLive()
        return descriptorBytesValue.copyOf()
    }

    /** Produces a new opaque handle for this exact VBC4 page only. */
    internal fun copyHandleForBuild(): AkenHandle {
        requireLive()
        return AkenHandle.create(
            resourceKind = AkenResourceKind.Vbc4Method,
            pageIndex = pageIndex,
            encoded = handleEncodingValue,
            locatorToken = locatorTokenValue,
            evaluatorFingerprint = evaluatorFingerprintValue,
        )
    }

    internal fun copyLogicalIdentityForBuild(): ByteArray {
        requireLive()
        return logicalIdentityValue.copyOf()
    }

    internal fun copyCallSiteProofForBuild(): ByteArray {
        requireLive()
        return callSiteProofValue.copyOf()
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(descriptorBytesValue, 0)
        Arrays.fill(encryptedPayloadValue, 0)
        Arrays.fill(handleEncodingValue, 0)
        Arrays.fill(locatorTokenValue, 0)
        Arrays.fill(evaluatorFingerprintValue, 0)
        Arrays.fill(logicalIdentityValue, 0)
        Arrays.fill(callSiteProofValue, 0)
        descriptorBytesValue = ByteArray(0)
        encryptedPayloadValue = ByteArray(0)
        handleEncodingValue = ByteArray(0)
        locatorTokenValue = ByteArray(0)
        evaluatorFingerprintValue = ByteArray(0)
        logicalIdentityValue = ByteArray(0)
        callSiteProofValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 page emission has been wiped" }
    }

    companion object {
        internal fun fromMaterialized(
            page: AkenMaterializedPage,
            entryToken: Long,
        ): AkenVbc4PageEmission {
            val descriptor = page.descriptorForBuild
            require(descriptor.resourceKind == AkenResourceKind.Vbc4Method) {
                "AKEN VBC4 emitter received a non-VBC4 materialized page"
            }

            var descriptorBytes: ByteArray? = null
            var encryptedPayload: ByteArray? = null
            var handle: AkenHandle? = null
            var handleEncoding: ByteArray? = null
            var locatorToken: ByteArray? = null
            var evaluatorFingerprint: ByteArray? = null
            var logicalIdentity: ByteArray? = null
            var callSiteProof: ByteArray? = null
            try {
                val route = descriptor.route
                require(route.resourceKind == AkenResourceKind.Vbc4Method) {
                    "AKEN VBC4 route does not bind a VBC4 page"
                }
                require(route.pageIndex == descriptor.pageIndex) {
                    "AKEN VBC4 route page index does not match descriptor"
                }

                descriptorBytes = descriptor.encode()
                encryptedPayload = page.copyEncodedPayloadForBuild()
                require(encryptedPayload.size == route.storedLength) {
                    "AKEN VBC4 materialized payload length does not match its route"
                }
                logicalIdentity = descriptor.logicalIdentity
                callSiteProof = descriptor.proof.callSiteProof
                handle = descriptor.handle
                require(descriptor.matches(handle) && route.matches(handle)) {
                    "AKEN VBC4 descriptor handle binding is invalid"
                }
                handleEncoding = handle.encoded
                locatorToken = handle.locatorToken
                evaluatorFingerprint = handle.evaluatorPlanFingerprint

                return AkenVbc4PageEmission(
                    entryToken = entryToken,
                    resourcePath = route.resourcePath,
                    resourceOffset = route.resourceOffset,
                    storedLength = route.storedLength,
                    pageIndex = descriptor.pageIndex,
                    descriptorBytes = checkNotNull(descriptorBytes),
                    encryptedPayload = checkNotNull(encryptedPayload),
                    handleEncoding = checkNotNull(handleEncoding),
                    locatorToken = checkNotNull(locatorToken),
                    evaluatorFingerprint = checkNotNull(evaluatorFingerprint),
                    logicalIdentity = checkNotNull(logicalIdentity),
                    callSiteProof = checkNotNull(callSiteProof),
                )
            } finally {
                descriptorBytes?.let { Arrays.fill(it, 0) }
                encryptedPayload?.let { Arrays.fill(it, 0) }
                handleEncoding?.let { Arrays.fill(it, 0) }
                locatorToken?.let { Arrays.fill(it, 0) }
                evaluatorFingerprint?.let { Arrays.fill(it, 0) }
                logicalIdentity?.let { Arrays.fill(it, 0) }
                callSiteProof?.let { Arrays.fill(it, 0) }
                handle?.wipe()
            }
        }
    }
}

/**
 * Build-only owner for a VBC4 page-emission batch.
 *
 * The returned list exists only for the immediately following artifact writer;
 * it is not a runtime catalog. Closing the owner wipes every page record and
 * the copied mesh root.
 */
internal class AkenVbc4PageEmissionSet private constructor(
    meshRoot: ByteArray,
    pages: List<AkenVbc4PageEmission>,
) : AutoCloseable {
    private var meshRootValue: ByteArray = meshRoot.copyOf()
    private var pagesValue: List<AkenVbc4PageEmission> = pages.toList()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(meshRootValue.size == AkenArtifactCommitment.DIGEST_SIZE) {
            "AKEN VBC4 mesh root length is invalid"
        }
        require(pagesValue.isNotEmpty()) { "AKEN VBC4 emission set requires at least one page" }
    }

    val isWiped: Boolean
        get() = wiped

    /** Build-only writer order; this is never exposed through an injected runtime API. */
    internal fun pagesForBuild(): List<AkenVbc4PageEmission> {
        requireLive()
        return pagesValue.toList()
    }

    internal fun copyMeshRootForBuild(): ByteArray {
        requireLive()
        return meshRootValue.copyOf()
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        pagesValue.forEach { it.wipe() }
        pagesValue = emptyList()
        Arrays.fill(meshRootValue, 0)
        meshRootValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 page emission set has been wiped" }
    }

    companion object {
        internal fun create(
            meshRoot: ByteArray,
            pages: List<AkenVbc4PageEmission>,
        ): AkenVbc4PageEmissionSet = AkenVbc4PageEmissionSet(meshRoot, pages)
    }
}

/**
 * Converts already-registered [AkenResourceKind.Vbc4Method] pages into
 * independently routed VBC4 page resources.
 *
 * This is an intentionally narrow build bridge, not a VBC4 runtime decoder:
 * it delegates AEAD emission and mesh construction to [AkenPageMaterializer],
 * copies only the final page-local writer artifacts, and then wipes the input
 * requests, materialization owner, and build plan on every outcome.
 */
internal object AkenVbc4PageEmitter {
    @JvmSynthetic
    fun emitAndWipe(
        plan: AkenBuildPlan,
        requests: Iterable<AkenVbc4PageEmissionRequest>,
    ): AkenVbc4PageEmissionSet {
        val requestList = ArrayList<AkenVbc4PageEmissionRequest>()
        val inputList = ArrayList<AkenPageMaterializationInput>()
        val emittedPages = ArrayList<AkenVbc4PageEmission>()
        var materialization: AkenPageMaterialization? = null
        var meshRoot: ByteArray? = null
        var output: AkenVbc4PageEmissionSet? = null
        var completed = false

        try {
            // Snapshot first so an iterator failure still reaches the single
            // owner cleanup path below.
            for (request in requests) {
                require(request.page.resourceKind == AkenResourceKind.Vbc4Method) {
                    "AKEN VBC4 emitter received a non-VBC4 page request"
                }
                requestList += request
            }
            require(requestList.isNotEmpty()) { "AKEN VBC4 page emission requires at least one request" }

            requestList.forEach { request ->
                inputList += request.toMaterializationInput()
            }
            // Page indices are local to a logical VBC4 method.  Different
            // methods may therefore both have page zero; use the opaque page
            // handle as the build-only correlation key rather than turning the
            // batch into a single global page-index namespace.
            val requestsByHandle = requestList.associateBy(::requestHandleBinding)
            require(requestsByHandle.size == requestList.size) {
                "AKEN VBC4 page emission contains duplicate page handle bindings"
            }

            materialization = AkenPageMaterializer.materializeAndWipe(plan, inputList)
            val materializedPages = materialization.pagesForBuild()
            require(materializedPages.size == requestList.size) {
                "AKEN VBC4 materialization page count does not match its requests"
            }
            require(materializedPages.all(materialization::verifyPageForBuild)) {
                "AKEN VBC4 materialization did not verify its generated page binding"
            }

            meshRoot = materialization.copyMeshRootForBuild()
            materializedPages.forEach { materialized ->
                val request = requestsByHandle[materializedHandleBinding(materialized)]
                    ?: error("AKEN VBC4 materialization emitted an unknown page handle binding")
                emittedPages += AkenVbc4PageEmission.fromMaterialized(
                    page = materialized,
                    entryToken = request.entryToken,
                )
            }
            output = AkenVbc4PageEmissionSet.create(checkNotNull(meshRoot), emittedPages)
            completed = true
            return output
        } finally {
            // AkenPageMaterializer owns/wipes the plan after it starts. If
            // request conversion or iteration failed before that handoff, this
            // bridge becomes the owner and closes it itself.
            if (materialization == null) {
                plan.wipe()
            }
            inputList.forEach { it.wipe() }
            requestList.forEach { it.wipe() }
            materialization?.wipe()
            meshRoot?.let { Arrays.fill(it, 0) }
            if (!completed) {
                output?.wipe()
                emittedPages.forEach { it.wipe() }
            }
        }
    }

    private fun requestHandleBinding(request: AkenVbc4PageEmissionRequest): String {
        val encoded = request.page.handle.encoded
        return try {
            Base64.getUrlEncoder().withoutPadding().encodeToString(encoded)
        } finally {
            Arrays.fill(encoded, 0)
        }
    }

    private fun materializedHandleBinding(page: AkenMaterializedPage): String {
        val handle = page.descriptorForBuild.handle
        val encoded = handle.encoded
        return try {
            Base64.getUrlEncoder().withoutPadding().encodeToString(encoded)
        } finally {
            Arrays.fill(encoded, 0)
            handle.wipe()
        }
    }
}
