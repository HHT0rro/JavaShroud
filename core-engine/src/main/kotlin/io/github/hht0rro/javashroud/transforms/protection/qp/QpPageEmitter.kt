package io.github.hht0rro.javashroud.transforms.protection.qp

import java.security.MessageDigest
import java.util.Arrays
import java.util.Base64
import kotlin.jvm.JvmSynthetic

/**
 * Build-only ownership wrapper for one already-registered Qp VM Qp page.
 *
 * The request keeps defensive copies of its plaintext, logical identity, and
 * call-site proof until [QpPageEmitter] consumes it. It never exposes a
 * DEK, a page decoder, or a runtime resource lookup surface. The supplied
 * identity must exactly match the registered page identity, while distinct
 * [QpBuildPlan.Page.pageIndex] values remain independent pages of the same
 * logical Qp VM method.
 */
internal class QpPageEmissionRequest private constructor(
    internal val page: QpBuildPlan.Page,
    val entryToken: Long,
    logicalIdentity: ByteArray,
    plaintext: ByteArray,
    val resourcePath: String,
    val resourceOffset: Int,
    callSiteProof: ByteArray,
    val logicalBindingPath: String,
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var plaintextValue: ByteArray = plaintext.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(page.resourceKind == QpResourceKind.QpMethod) {
            "Qp current-format page emission requires a QpMethod page"
        }
        require(logicalIdentityValue.isNotEmpty()) { "Qp current-format logical identity must not be empty" }
        require(plaintextValue.isNotEmpty()) { "Qp current-format page plaintext must not be empty" }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "Qp current-format call-site proof length is invalid"
        }
        require(resourcePath.isNotBlank() && '\u0000' !in resourcePath) {
            "Qp current-format resource path is invalid"
        }
        require(logicalBindingPath.isNotBlank() && '\u0000' !in logicalBindingPath && '\\' !in logicalBindingPath) {
            "Qp current-format logical binding path is invalid"
        }
        require(resourceOffset >= 0) { "Qp current-format resource offset must be non-negative" }
        verifyPageBinding()
    }

    val pageIndex: Int
        get() {
            requireLive()
            return page.pageIndex
        }

    val isWiped: Boolean
        get() = wiped

    internal fun toMaterializationInput(): QpPageMaterializationInput {
        requireLive()
        val plaintext = plaintextValue.copyOf()
        val callSiteProof = callSiteProofValue.copyOf()
        return try {
            QpPageMaterializationInput.create(
                page = page,
                plaintext = plaintext,
                resourcePath = resourcePath,
                resourceOffset = resourceOffset,
                callSiteProof = callSiteProof,
                logicalBindingPath = logicalBindingPath,
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
                "Qp current-format request identity does not match its registered page"
            }
        } finally {
            Arrays.fill(registeredIdentity, 0)
        }
    }

    private fun requireLive() {
        check(!wiped) { "Qp current-format page emission request has been wiped" }
    }

    companion object {
        private const val MAX_CALL_SITE_PROOF_SIZE = 4096

        fun create(
            page: QpBuildPlan.Page,
            entryToken: Long,
            logicalIdentity: ByteArray,
            plaintext: ByteArray,
            resourcePath: String,
            resourceOffset: Int = 0,
            callSiteProof: ByteArray,
            logicalBindingPath: String = resourcePath,
        ): QpPageEmissionRequest = QpPageEmissionRequest(
            page = page,
            entryToken = entryToken,
            logicalIdentity = logicalIdentity,
            plaintext = plaintext,
            resourcePath = resourcePath,
            resourceOffset = resourceOffset,
            callSiteProof = callSiteProof,
            logicalBindingPath = logicalBindingPath,
        )
    }
}

/**
 * One build-only, independently materialized Qp VM page resource.
 *
 * Stored payload, descriptor, handle components, logical identity, and
 * call-site proof are private mutable storage solely so [wipe] can clear them.
 * All readable byte material is returned as a fresh defensive copy. There is
 * deliberately no method that opens a payload, returns a DEK, or accepts an
 * arbitrary resource/key pair.
 */
internal class QpPageEmission private constructor(
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
        require(resourcePath.isNotBlank() && '\u0000' !in resourcePath) { "Qp current-format output path is invalid" }
        require(resourceOffset >= 0) { "Qp current-format output offset must be non-negative" }
        require(storedLength > 0 && storedLength == encryptedPayloadValue.size) {
            "Qp current-format output payload length is invalid"
        }
        require(pageIndex >= 0) { "Qp current-format output page index must be non-negative" }
        require(descriptorBytesValue.isNotEmpty()) { "Qp current-format descriptor bytes must not be empty" }
        require(handleEncodingValue.size == QpHandle.ENCODED_HANDLE_SIZE) {
            "Qp current-format output handle encoding length is invalid"
        }
        require(locatorTokenValue.size == QpHandle.LOCATOR_TOKEN_SIZE) {
            "Qp current-format output locator token length is invalid"
        }
        require(evaluatorFingerprintValue.size == QpHandle.FINGERPRINT_SIZE) {
            "Qp current-format output evaluator fingerprint length is invalid"
        }
        require(logicalIdentityValue.isNotEmpty()) { "Qp current-format output logical identity must not be empty" }
        require(callSiteProofValue.isNotEmpty()) { "Qp current-format output call-site proof must not be empty" }
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

    /** Produces a new opaque handle for this exact Qp VM page only. */
    internal fun copyHandleForBuild(): QpHandle {
        requireLive()
        return QpHandle.create(
            resourceKind = QpResourceKind.QpMethod,
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
        check(!wiped) { "Qp current-format page emission has been wiped" }
    }

    companion object {
        internal fun fromMaterialized(
            page: QpMaterializedPage,
            entryToken: Long,
        ): QpPageEmission {
            val descriptor = page.descriptorForBuild
            require(descriptor.resourceKind == QpResourceKind.QpMethod) {
                "Qp current-format emitter received a non-Qp VM materialized page"
            }

            var descriptorBytes: ByteArray? = null
            var encryptedPayload: ByteArray? = null
            var handle: QpHandle? = null
            var handleEncoding: ByteArray? = null
            var locatorToken: ByteArray? = null
            var evaluatorFingerprint: ByteArray? = null
            var logicalIdentity: ByteArray? = null
            var callSiteProof: ByteArray? = null
            try {
                val route = descriptor.route
                require(route.resourceKind == QpResourceKind.QpMethod) {
                    "Qp current-format route does not bind a Qp VM page"
                }
                require(route.pageIndex == descriptor.pageIndex) {
                    "Qp current-format route page index does not match descriptor"
                }

                descriptorBytes = descriptor.encode()
                encryptedPayload = page.copyEncodedPayloadForBuild()
                require(encryptedPayload.size == route.storedLength) {
                    "Qp current-format materialized payload length does not match its route"
                }
                logicalIdentity = descriptor.logicalIdentity
                callSiteProof = descriptor.proof.callSiteProof
                handle = descriptor.handle
                require(descriptor.matches(handle) && route.matches(handle)) {
                    "Qp current-format descriptor handle binding is invalid"
                }
                handleEncoding = handle.encoded
                locatorToken = handle.locatorToken
                evaluatorFingerprint = handle.evaluatorPlanFingerprint

                return QpPageEmission(
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
 * Build-only owner for a Qp VM page-emission batch.
 *
 * The returned list exists only for the immediately following artifact writer;
 * it is not a runtime catalog. Closing the owner wipes every page record and
 * the copied mesh root.
 */
internal class QpPageEmissionSet private constructor(
    meshRoot: ByteArray,
    pages: List<QpPageEmission>,
) : AutoCloseable {
    private var meshRootValue: ByteArray = meshRoot.copyOf()
    private var pagesValue: List<QpPageEmission> = pages.toList()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(meshRootValue.size == QpArtifactCommitment.DIGEST_SIZE) {
            "Qp current-format mesh root length is invalid"
        }
        require(pagesValue.isNotEmpty()) { "Qp current-format emission set requires at least one page" }
    }

    val isWiped: Boolean
        get() = wiped

    /** Build-only writer order; this is never exposed through an injected runtime API. */
    internal fun pagesForBuild(): List<QpPageEmission> {
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
        check(!wiped) { "Qp current-format page emission set has been wiped" }
    }

    companion object {
        internal fun create(
            meshRoot: ByteArray,
            pages: List<QpPageEmission>,
        ): QpPageEmissionSet = QpPageEmissionSet(meshRoot, pages)
    }
}

/**
 * Converts already-registered [QpResourceKind.QpMethod] pages into
 * independently routed Qp VM page resources.
 *
 * This is an intentionally narrow build bridge, not a Qp VM runtime decoder:
 * it delegates AEAD emission and mesh construction to [QpPageMaterializer],
 * copies only the final page-local writer artifacts, and then wipes the input
 * requests, materialization owner, and build plan on every outcome.
 */
internal object QpPageEmitter {
    @JvmSynthetic
    fun emitAndWipe(
        plan: QpBuildPlan,
        requests: Iterable<QpPageEmissionRequest>,
    ): QpPageEmissionSet {
        val requestList = ArrayList<QpPageEmissionRequest>()
        val inputList = ArrayList<QpPageMaterializationInput>()
        val emittedPages = ArrayList<QpPageEmission>()
        var materialization: QpPageMaterialization? = null
        var meshRoot: ByteArray? = null
        var output: QpPageEmissionSet? = null
        var completed = false

        try {
            // Snapshot first so an iterator failure still reaches the single
            // owner cleanup path below.
            for (request in requests) {
                require(request.page.resourceKind == QpResourceKind.QpMethod) {
                    "Qp current-format emitter received a non-Qp VM page request"
                }
                requestList += request
            }
            require(requestList.isNotEmpty()) { "Qp current-format page emission requires at least one request" }

            requestList.forEach { request ->
                inputList += request.toMaterializationInput()
            }
            // Page indices are local to a logical Qp VM method.  Different
            // methods may therefore both have page zero; use the opaque page
            // handle as the build-only correlation key rather than turning the
            // batch into a single global page-index namespace.
            val requestsByHandle = requestList.associateBy(::requestHandleBinding)
            require(requestsByHandle.size == requestList.size) {
                "Qp current-format page emission contains duplicate page handle bindings"
            }

            materialization = QpPageMaterializer.materializeAndWipe(plan, inputList)
            val materializedPages = materialization.pagesForBuild()
            require(materializedPages.size == requestList.size) {
                "Qp current-format materialization page count does not match its requests"
            }
            require(materializedPages.all(materialization::verifyPageForBuild)) {
                "Qp current-format materialization did not verify its generated page binding"
            }

            meshRoot = materialization.copyMeshRootForBuild()
            materializedPages.forEach { materialized ->
                val request = requestsByHandle[materializedHandleBinding(materialized)]
                    ?: error("Qp current-format materialization emitted an unknown page handle binding")
                emittedPages += QpPageEmission.fromMaterialized(
                    page = materialized,
                    entryToken = request.entryToken,
                )
            }
            output = QpPageEmissionSet.create(checkNotNull(meshRoot), emittedPages)
            completed = true
            return output
        } finally {
            // QpPageMaterializer owns/wipes the plan after it starts. If
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

    private fun requestHandleBinding(request: QpPageEmissionRequest): String {
        val encoded = request.page.handle.encoded
        return try {
            Base64.getUrlEncoder().withoutPadding().encodeToString(encoded)
        } finally {
            Arrays.fill(encoded, 0)
        }
    }

    private fun materializedHandleBinding(page: QpMaterializedPage): String {
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
