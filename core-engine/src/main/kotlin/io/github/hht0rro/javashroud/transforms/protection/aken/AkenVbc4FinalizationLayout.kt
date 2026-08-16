package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64

/**
 * Build-only pending definition for one VBC4 page before its final artifact
 * commitment exists.
 *
 * The physical frame is chosen here because its exact length is part of the
 * canonical reservation. The evaluator graph and DEK are still minted only
 * after [AkenArtifactCommitment.reserve] has produced the final commitment.
 * Page zero may carry one preassigned opaque handle encoding so an already
 * generated VBC4 dispatcher can address precisely that page; it is neither a
 * key nor a traversal capability.
 */
internal class AkenVbc4PendingPage private constructor(
    val entryToken: Long,
    val resourcePath: String,
    val resourceOffset: Int,
    val pageIndex: Int,
    val targetPageSize: Int,
    val layoutVariant: String,
    logicalIdentity: ByteArray,
    plaintext: ByteArray,
    callSiteProof: ByteArray,
    val logicalBindingPath: String,
    encodedHandleOverride: ByteArray?,
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var plaintextValue: ByteArray = plaintext.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()
    private var encodedHandleOverrideValue: ByteArray? = encodedHandleOverride?.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(logicalIdentityValue.isNotEmpty()) { "AKEN VBC4 pending-page identity must not be empty" }
        require(plaintextValue.isNotEmpty()) { "AKEN VBC4 pending-page plaintext must not be empty" }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "AKEN VBC4 pending-page call-site proof length is invalid"
        }
        encodedHandleOverrideValue?.let { encodedHandle ->
            require(pageIndex == 0 && encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) {
                "AKEN VBC4 pending-page handle override is invalid"
            }
        }
        require(pageIndex >= 0) { "AKEN VBC4 pending-page index must be non-negative" }
        require(resourceOffset >= 0) { "AKEN VBC4 pending-page offset must be non-negative" }
        require(isValidResourcePath(resourcePath)) { "AKEN VBC4 pending-page resource path is invalid" }
        require(isValidResourcePath(logicalBindingPath)) { "AKEN VBC4 pending-page logical binding path is invalid" }
        require(targetPageSize in AkenPageSizePolicy.DEFAULT.allowedSizes(AkenResourceKind.Vbc4Method)) {
            "AKEN VBC4 pending-page target size is unsupported"
        }
        validateLayout(layoutVariant)
        require(expectedStoredLength > 0) { "AKEN VBC4 pending-page stored length is invalid" }
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

    /** Build-only optional page-zero handle preassigned by the generated dispatcher. */
    internal fun copyEncodedHandleOverrideForBuild(): ByteArray? {
        requireLive()
        return encodedHandleOverrideValue?.copyOf()
    }

    internal fun identityPageKeyForBuild(): String {
        requireLive()
        return identityPageKey(logicalIdentityValue, pageIndex)
    }

    internal fun toEmissionRequest(page: AkenBuildPlan.Page): AkenVbc4PageEmissionRequest {
        requireLive()
        val identity = logicalIdentityValue.copyOf()
        val plaintext = plaintextValue.copyOf()
        val proof = callSiteProofValue.copyOf()
        return try {
            AkenVbc4PageEmissionRequest.create(
                page = page,
                entryToken = entryToken,
                logicalIdentity = identity,
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
        }
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(logicalIdentityValue, 0)
        Arrays.fill(plaintextValue, 0)
        Arrays.fill(callSiteProofValue, 0)
        encodedHandleOverrideValue?.let { Arrays.fill(it, 0) }
        logicalIdentityValue = ByteArray(0)
        plaintextValue = ByteArray(0)
        callSiteProofValue = ByteArray(0)
        encodedHandleOverrideValue = null
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 pending page has been wiped" }
    }

    companion object {
        private const val MAX_CALL_SITE_PROOF_SIZE = 4096

        /**
         * Builds a page reservation with a freshly randomized physical frame.
         * A caller that already reserved a frame may instead pass its complete
         * [layoutVariant] and [targetPageSize] so the later evaluator graph
         * binds that exact frame and VBC4 block-cluster geometry.
         */
        fun create(
            entryToken: Long,
            logicalIdentity: ByteArray,
            plaintext: ByteArray,
            resourcePath: String,
            pageIndex: Int,
            callSiteProof: ByteArray,
            resourceOffset: Int = 0,
            layoutVariant: String? = null,
            targetPageSize: Int? = null,
            random: SecureRandom = SecureRandom(),
            logicalBindingPath: String = resourcePath,
            encodedHandleOverride: ByteArray? = null,
        ): AkenVbc4PendingPage {
            targetPageSize?.let { requestedTargetSize ->
                require(requestedTargetSize in AkenPageSizePolicy.DEFAULT.allowedSizes(AkenResourceKind.Vbc4Method)) {
                    "AKEN requested VBC4 page target size is unsupported"
                }
            }
            var generatedLayout: AkenPageLayout? = null
            val selectedVariant = try {
                layoutVariant ?: AkenPageLayout.create("vbc4", random).also { generatedLayout = it }.variant
            } finally {
                generatedLayout?.wipe()
            }
            val selectedTargetPageSize =
                targetPageSize ?: AkenPageSizePolicy.DEFAULT.choose(AkenResourceKind.Vbc4Method, random)
            return AkenVbc4PendingPage(
                entryToken = entryToken,
                resourcePath = resourcePath,
                resourceOffset = resourceOffset,
                pageIndex = pageIndex,
                targetPageSize = selectedTargetPageSize,
                layoutVariant = selectedVariant,
                logicalIdentity = logicalIdentity,
                plaintext = plaintext,
                callSiteProof = callSiteProof,
                logicalBindingPath = logicalBindingPath,
                encodedHandleOverride = encodedHandleOverride,
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
    }
}

/**
 * One mutable final writer entry owned by [AkenVbc4FinalizationLayout].
 *
 * It is intentionally a build-side carrier rather than a JAR abstraction.  It
 * has no resource discovery, decode, or key API; callers may only obtain a
 * defensive byte copy for the immediately adjacent writer/verifier.
 */
internal class AkenVbc4FinalizationEntry private constructor(
    val name: String,
    bytes: ByteArray,
) : AutoCloseable {
    private var bytesValue: ByteArray = bytes.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(isValidResourcePath(name)) { "AKEN VBC4 finalization entry name is invalid" }
    }

    val byteSize: Int
        get() {
            requireLive()
            return bytesValue.size
        }

    val isWiped: Boolean
        get() = wiped

    internal fun copyBytesForBuild(): ByteArray {
        requireLive()
        return bytesValue.copyOf()
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(bytesValue, 0)
        bytesValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 finalization entry has been wiped" }
    }

    companion object {
        internal fun create(name: String, bytes: ByteArray): AkenVbc4FinalizationEntry =
            AkenVbc4FinalizationEntry(name, bytes)
    }
}

/**
 * Build-only binding for the first page of exactly one virtualized method.
 *
 * The binding is deliberately callback-scoped: callers receive defensive
 * copies of the opaque handle, proof, and logical identity, and the owning
 * layout wipes every binding immediately after the callback returns. It is not
 * a runtime catalog and exposes no page enumeration or decode operation.
 */
internal class AkenVbc4DispatchBinding private constructor(
    val entryToken: Long,
    val pageIndex: Int,
    encodedHandle: ByteArray,
    callSiteProof: ByteArray,
    logicalIdentity: ByteArray,
) : AutoCloseable {
    private var encodedHandleValue = encodedHandle.copyOf()
    private var callSiteProofValue = callSiteProof.copyOf()
    private var logicalIdentityValue = logicalIdentity.copyOf()
    private var wiped = false

    init {
        require(pageIndex == 0) { "AKEN VBC4 dispatch binding must target page zero" }
        require(encodedHandleValue.size == AkenHandle.ENCODED_HANDLE_SIZE) {
            "AKEN VBC4 dispatch binding has an invalid handle length"
        }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= 4096) {
            "AKEN VBC4 dispatch binding has an invalid call-site proof"
        }
        require(logicalIdentityValue.isNotEmpty()) {
            "AKEN VBC4 dispatch binding has an empty logical identity"
        }
    }

    internal val isWiped: Boolean
        get() = wiped

    internal fun copyEncodedHandleForBuild(): ByteArray {
        requireLive()
        return encodedHandleValue.copyOf()
    }

    internal fun copyCallSiteProofForBuild(): ByteArray {
        requireLive()
        return callSiteProofValue.copyOf()
    }

    internal fun copyLogicalIdentityForBuild(): ByteArray {
        requireLive()
        return logicalIdentityValue.copyOf()
    }

    internal fun matchesForBuild(
        entryToken: Long,
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
    ): Boolean =
        !wiped &&
            this.entryToken == entryToken &&
            this.pageIndex == pageIndex &&
            MessageDigest.isEqual(encodedHandleValue, encodedHandle) &&
            MessageDigest.isEqual(callSiteProofValue, callSiteProof)

    override fun close() = wipe()

    internal fun wipe() {
        if (wiped) return
        Arrays.fill(encodedHandleValue, 0)
        Arrays.fill(callSiteProofValue, 0)
        Arrays.fill(logicalIdentityValue, 0)
        encodedHandleValue = ByteArray(0)
        callSiteProofValue = ByteArray(0)
        logicalIdentityValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 dispatch binding has been wiped" }
    }

    internal companion object {
        fun fromPageZeroEmission(emission: AkenVbc4PageEmission): AkenVbc4DispatchBinding {
            require(emission.pageIndex == 0) { "AKEN VBC4 dispatch binding source must be page zero" }
            val handle = emission.copyHandleForBuild()
            var encodedHandle: ByteArray? = null
            var callSiteProof: ByteArray? = null
            var logicalIdentity: ByteArray? = null
            try {
                encodedHandle = handle.encoded
                callSiteProof = emission.copyCallSiteProofForBuild()
                logicalIdentity = emission.copyLogicalIdentityForBuild()
                return AkenVbc4DispatchBinding(
                    entryToken = emission.entryToken,
                    pageIndex = emission.pageIndex,
                    encodedHandle = encodedHandle,
                    callSiteProof = callSiteProof,
                    logicalIdentity = logicalIdentity,
                )
            } finally {
                handle.wipe()
                encodedHandle?.let { Arrays.fill(it, 0) }
                callSiteProof?.let { Arrays.fill(it, 0) }
                logicalIdentity?.let { Arrays.fill(it, 0) }
            }
        }
    }
}

/**
 * Pre-seal AKEN layout reservation plus current-page native compiler inputs.
 *
 * This is the deliberately narrow S1 bridge between page planning and the
 * later native recompilation stage. It owns one full-payload materialization
 * mesh across VBC4 and typed pages, final page bytes, and per-page native
 * locator inputs only while the build is active. It is never injected as a
 * Java runtime catalog and offers no `find`, `list`, arbitrary resource
 * decode, DEK getter, root-key getter, or page plaintext getter.
 */
internal class AkenVbc4FinalizationLayout private constructor(
    private val commitmentValue: AkenArtifactCommitment,
    private var finalEntriesValue: List<AkenVbc4FinalizationEntry>,
    private var materializationValue: AkenPageMaterialization?,
    private var emissionsValue: AkenVbc4PageEmissionSet?,
    private var nativeInputsValue: List<AkenNativePageLocatorCompileInput>,
) : AutoCloseable {
    @Volatile
    private var wiped: Boolean = false

    init {
        require(finalEntriesValue.isNotEmpty()) { "AKEN VBC4 finalization layout requires final entries" }
        require(materializationValue?.isWiped == false) {
            "AKEN VBC4 finalization layout requires a live unified page materialization"
        }
        require(nativeInputsValue.isNotEmpty()) { "AKEN VBC4 finalization layout requires native page inputs" }
        require(finalEntriesValue.map { it.name }.distinct().size == finalEntriesValue.size) {
            "AKEN VBC4 finalization layout contains duplicate final entries"
        }
    }

    val isWiped: Boolean
        get() = wiped

    /** Build-only defensive view of the final canonical artifact commitment. */
    internal fun copyArtifactCommitmentForBuild(): ByteArray {
        requireLive()
        return commitmentValue.copyBytes()
    }

    /** Build-only final entry order for the immediately adjacent artifact writer. */
    internal fun entriesForBuild(): List<AkenVbc4FinalizationEntry> {
        requireLive()
        return finalEntriesValue.toList()
    }

    /** Build-only membership check for a route already emitted by this layout. */
    internal fun hasEntryForBuild(name: String): Boolean {
        requireLive()
        return finalEntriesValue.any { entry -> entry.name == name }
    }

    /**
     * Supplies copies of one current-page native locator record per page to a
     * native code generator, then wipes every callback copy before returning.
     */
    internal fun <T> withNativeLocatorRecordsForBuild(block: (List<ByteArray>) -> T): T {
        requireLive()
        val records = ArrayList<ByteArray>(nativeInputsValue.size)
        try {
            nativeInputsValue.forEach { records += it.copyNativeLocatorRecordForCompiler() }
            return block(records.toList())
        } finally {
            records.forEach { Arrays.fill(it, 0) }
        }
    }

    /**
     * Supplies finalized encrypted ClassPage bindings to the immediately
     * adjacent class-local descriptor emitter. The projection contains only a
     * page's logical identity, opaque handle, and call-site proof; it exposes
     * no resource directory, plaintext, evaluator graph, or generic decoder.
     */
    internal fun <T> withClassPageBindingsForBuild(
        block: (List<AkenClassPageBinding>) -> T,
    ): T {
        requireLive()
        val materialization = materializationValue
            ?: error("AKEN ClassPage binding projection requires a live materialization")
        val bindings = ArrayList<AkenClassPageBinding>()
        try {
            materialization.pagesForBuild()
                .asSequence()
                .filter { page ->
                    page.descriptorForBuild.resourceKind == AkenResourceKind.EncryptedClassPage
                }
                .forEach { page -> bindings += AkenClassPageBinding.fromMaterializedPage(page) }
            bindings.sortWith(
                compareBy<AkenClassPageBinding> { binding -> binding.identityPageKeyForBuild() }
                    .thenBy { binding -> binding.pageIndex },
            )
            require(bindings.mapTo(linkedSetOf()) { binding -> binding.identityPageKeyForBuild() }.size == bindings.size) {
                "AKEN ClassPage finalization contains duplicate logical page bindings"
            }
            return block(bindings.toList())
        } finally {
            bindings.forEach { binding -> binding.wipe() }
        }
    }

    /**
     * Supplies one callback-scoped page-zero binding per virtualized method.
     * Typed non-VBC4 pages deliberately do not enter this dispatcher-facing
     * surface; a StringPage-only build therefore supplies an empty list.
     */
    internal fun <T> withPageZeroDispatchBindingsForBuild(
        block: (List<AkenVbc4DispatchBinding>) -> T,
    ): T {
        requireLive()
        val pages = emissionsValue?.pagesForBuild().orEmpty()
        val expectedEntryTokens = pages.mapTo(linkedSetOf()) { page -> page.entryToken }
        val bindings = ArrayList<AkenVbc4DispatchBinding>(expectedEntryTokens.size)
        try {
            pages
                .asSequence()
                .filter { page -> page.pageIndex == 0 }
                .sortedBy { page -> page.entryToken }
                .forEach { page -> bindings += AkenVbc4DispatchBinding.fromPageZeroEmission(page) }
            require(bindings.mapTo(linkedSetOf()) { binding -> binding.entryToken } == expectedEntryTokens) {
                "AKEN VBC4 finalization is missing a unique page-zero dispatch binding"
            }
            return block(bindings.toList())
        } finally {
            bindings.forEach { binding -> binding.wipe() }
        }
    }

    /**
     * Rechecks the exact writer-equivalent artifact after a caller has emitted
     * the reserved bytes. The generic materialization owner validates the
     * canonical artifact commitment, root shards, every page route/payload, and
     * one full-payload Merkle mesh spanning VBC4 and typed pages. This layout
     * adds the exact current-page native record binding for every page.
     */
    internal fun verifyWriterEquivalentArtifactForBuild(entries: Iterable<AkenArtifactEntry>): Boolean {
        if (wiped) return false
        val entriesByName = LinkedHashMap<String, AkenArtifactEntry>()
        try {
            for (entry in entries) {
                if (entriesByName.put(entry.name, entry) != null) return false
            }
            val materialization = materializationValue ?: return false
            if (!materialization.verifyWriterEquivalentArtifactForBuild(commitmentValue, entriesByName.values)) {
                return false
            }
            return verifyNativeInputBindingsForBuild(materialization)
        } catch (_: IllegalArgumentException) {
            return false
        } catch (_: IllegalStateException) {
            return false
        }
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        finalEntriesValue.forEach { it.wipe() }
        finalEntriesValue = emptyList()
        materializationValue?.wipe()
        materializationValue = null
        emissionsValue?.wipe()
        emissionsValue = null
        nativeInputsValue.forEach { it.wipe() }
        nativeInputsValue = emptyList()
        wiped = true
    }

    private fun verifyAndCapturePage(
        emission: AkenVbc4PageEmission,
        nativeInput: AkenNativePageLocatorCompileInput,
        entriesByName: Map<String, AkenArtifactEntry>,
        artifactCommitment: ByteArray,
    ): VerifiedPage? {
        var descriptorBytes: ByteArray? = null
        var payload: ByteArray? = null
        var expectedPayload: ByteArray? = null
        var handle: AkenHandle? = null
        var rawProof: ByteArray? = null
        var entryBytes: ByteArray? = null
        var leafEncoding: ByteArray? = null
        try {
            descriptorBytes = emission.copyDescriptorBytesForBuild()
            val descriptor = AkenRuntimePageDescriptor.decode(descriptorBytes)
            val route = descriptor.route
            if (
                descriptor.resourceKind != AkenResourceKind.Vbc4Method ||
                descriptor.pageIndex != emission.pageIndex ||
                route.resourcePath != emission.resourcePath ||
                route.resourceOffset != emission.resourceOffset ||
                route.storedLength != emission.storedLength
            ) return null

            entryBytes = entriesByName[route.resourcePath]?.copyBytesForCommitment() ?: return null
            val end = route.resourceOffset.toLong() + route.storedLength.toLong()
            if (end > entryBytes.size.toLong()) return null
            payload = entryBytes.copyOfRange(route.resourceOffset, end.toInt())
            expectedPayload = emission.copyEncryptedPayloadForBuild()
            if (!MessageDigest.isEqual(payload, expectedPayload)) return null

            handle = emission.copyHandleForBuild()
            rawProof = emission.copyCallSiteProofForBuild()
            if (!descriptor.matches(handle)) return null
            if (!nativeInput.matchesCurrentPageForBuild(emission.entryToken, handle.encoded, emission.pageIndex, rawProof)) {
                return null
            }
            val proofCommitment = descriptor.proof.artifactCanonicalCommitment
            try {
                if (!MessageDigest.isEqual(proofCommitment, artifactCommitment)) return null
            } finally {
                Arrays.fill(proofCommitment, 0)
            }
            leafEncoding = route.leafIdentity.encode()
            return VerifiedPage(
                descriptor = descriptor,
                leafEncoding = checkNotNull(leafEncoding),
                payload = checkNotNull(payload),
            ).also {
                leafEncoding = null
                payload = null
            }
        } finally {
            descriptorBytes?.let { Arrays.fill(it, 0) }
            payload?.let { Arrays.fill(it, 0) }
            expectedPayload?.let { Arrays.fill(it, 0) }
            rawProof?.let { Arrays.fill(it, 0) }
            entryBytes?.let { Arrays.fill(it, 0) }
            leafEncoding?.let { Arrays.fill(it, 0) }
            handle?.wipe()
        }
    }

    private fun proofMatches(
        proof: AkenSealingProofMetadata,
        leafEncoding: ByteArray,
        mesh: AkenIntegrityMesh,
        artifactCommitment: ByteArray,
    ): Boolean {
        val expected = mesh.proofFor(leafEncoding) ?: return false
        val proofCommitment = proof.artifactCanonicalCommitment
        val proofRoot = proof.merkleRoot
        val proofLeaf = proof.currentLeafDigest
        val expectedRoot = expected.root
        val expectedLeaf = expected.leafDigest
        val proofSiblings = proof.siblingDigests
        val expectedSiblings = expected.siblings
        return try {
            if (!MessageDigest.isEqual(proofCommitment, artifactCommitment)) return false
            if (!MessageDigest.isEqual(proofRoot, expectedRoot)) return false
            if (!MessageDigest.isEqual(proofLeaf, expectedLeaf)) return false
            if (proof.siblingDirections != expected.siblingIsLeft || proofSiblings.size != expectedSiblings.size) return false
            proofSiblings.indices.all { index -> MessageDigest.isEqual(proofSiblings[index], expectedSiblings[index]) }
        } finally {
            Arrays.fill(proofCommitment, 0)
            Arrays.fill(proofRoot, 0)
            Arrays.fill(proofLeaf, 0)
            Arrays.fill(expectedRoot, 0)
            Arrays.fill(expectedLeaf, 0)
            proofSiblings.forEach { Arrays.fill(it, 0) }
            expectedSiblings.forEach { Arrays.fill(it, 0) }
        }
    }

    /**
     * The materialization owner authenticates payloads and the unified Merkle
     * mesh. This second build-only pass checks that each materialized page has
     * exactly one matching current-page native compiler record. VBC4 records
     * retain their dispatcher entry token; typed pages derive their token from
     * their own kind/page/handle tuple.
     */
    private fun verifyNativeInputBindingsForBuild(materialization: AkenPageMaterialization): Boolean {
        val vbc4TokensByHandle = LinkedHashMap<String, Long>()
        val matchedNativeInputs = BooleanArray(nativeInputsValue.size)
        val pages = materialization.pagesForBuild()
        try {
            val vbc4Emissions = emissionsValue?.pagesForBuild().orEmpty()
            for (emission in vbc4Emissions) {
                var handle: AkenHandle? = null
                var encodedHandle: ByteArray? = null
                try {
                    handle = emission.copyHandleForBuild()
                    encodedHandle = handle.encoded
                    val handleKey = handleBindingKey(encodedHandle)
                    require(vbc4TokensByHandle.put(handleKey, emission.entryToken) == null) {
                        "AKEN VBC4 finalization contains duplicate native handle bindings"
                    }
                } finally {
                    encodedHandle?.let { Arrays.fill(it, 0) }
                    handle?.wipe()
                }
            }

            val vbc4PageCount = pages.count { page ->
                page.descriptorForBuild.resourceKind == AkenResourceKind.Vbc4Method
            }
            if (vbc4TokensByHandle.size != vbc4PageCount || nativeInputsValue.size != pages.size) {
                return false
            }

            for (page in pages) {
                val descriptor = page.descriptorForBuild
                var handle: AkenHandle? = null
                var encodedHandle: ByteArray? = null
                var rawProof: ByteArray? = null
                try {
                    handle = descriptor.handle
                    encodedHandle = handle.encoded
                    rawProof = descriptor.proof.callSiteProof
                    val entryToken = when (descriptor.resourceKind) {
                        AkenResourceKind.Vbc4Method ->
                            vbc4TokensByHandle[handleBindingKey(encodedHandle)]
                                ?: return false
                        else -> AkenTypedPageEntryToken.derive(
                            resourceKind = descriptor.resourceKind,
                            pageIndex = descriptor.pageIndex,
                            encodedHandle = encodedHandle,
                        )
                    }

                    var matchedIndex = -1
                    for (index in nativeInputsValue.indices) {
                        if (
                            !matchedNativeInputs[index] &&
                            nativeInputsValue[index].matchesCurrentPageForBuild(
                                entryToken = entryToken,
                                encodedHandle = encodedHandle,
                                pageIndex = descriptor.pageIndex,
                                rawCallSiteProof = rawProof,
                            )
                        ) {
                            if (matchedIndex >= 0) return false
                            matchedIndex = index
                        }
                    }
                    if (matchedIndex < 0) return false
                    matchedNativeInputs[matchedIndex] = true
                } finally {
                    rawProof?.let { Arrays.fill(it, 0) }
                    encodedHandle?.let { Arrays.fill(it, 0) }
                    handle?.wipe()
                }
            }
            return matchedNativeInputs.all { it }
        } finally {
            vbc4TokensByHandle.clear()
        }
    }

    private fun handleBindingKey(encodedHandle: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(encodedHandle)

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 finalization layout has been wiped" }
    }

    private class VerifiedPage(
        val descriptor: AkenRuntimePageDescriptor,
        leafEncoding: ByteArray,
        payload: ByteArray,
    ) {
        val leafEncoding: ByteArray = leafEncoding.copyOf()
        val payload: ByteArray = payload.copyOf()

        fun wipe() {
            Arrays.fill(leafEncoding, 0)
            Arrays.fill(payload, 0)
        }
    }

    companion object {
        /**
         * Materializes one pre-seal AKEN page layout using a plan already bound
         * to [commitment]. VBC4, typed StringPage, and encrypted ClassPage
         * records enter the same page materializer, so their descriptors share one canonical artifact
         * commitment and one full-payload Merkle mesh.
         *
         * The supplied plan and every pending candidate are consumed and wiped
         * on every outcome. The returned owner is the only object allowed to
         * survive until native compilation/final writer verification.
         */
        @JvmSynthetic
        fun materializeAndWipe(
            plan: AkenBuildPlan,
            commitment: AkenArtifactCommitment,
            pendingPages: Iterable<AkenVbc4PendingPage>,
            fixedEntries: Iterable<AkenArtifactEntry>,
            pendingStringPages: Iterable<AkenPendingStringPage> = emptyList(),
            pendingClassPages: Iterable<AkenPendingClassPage> = emptyList(),
            rootShardRanges: Iterable<AkenRootShardRange> = emptyList(),
            vbc4StateBindingLayoutDigest: ByteArray,
        ): AkenVbc4FinalizationLayout {
            val pages = ArrayList<AkenVbc4PendingPage>()
            val stringPages = ArrayList<AkenPendingStringPage>()
            val classPages = ArrayList<AkenPendingClassPage>()
            val fixed = LinkedHashMap<String, ByteArray>()
            val pageBuffers = LinkedHashMap<String, ByteArray>()
            val expectedLengths = LinkedHashMap<String, Int>()
            val reservations = ArrayList<AkenCanonicalReservation>()
            val selfReferential = LinkedHashMap<String, MutableList<AkenCanonicalExclusionRange>>()
            val vbc4PageDefinitions = LinkedHashMap<String, AkenVbc4PendingPage>()
            val stringPageDefinitions = LinkedHashMap<String, AkenPendingStringPage>()
            val classPageDefinitions = LinkedHashMap<String, AkenPendingClassPage>()
            val vbc4Requests = ArrayList<AkenVbc4PageEmissionRequest>()
            val materializationInputs = ArrayList<AkenPageMaterializationInput>()
            val emittedVbc4Pages = ArrayList<AkenVbc4PageEmission>()
            val compilerInputs = ArrayList<AkenNativePageLocatorCompileInput>()
            val finalEntries = ArrayList<AkenVbc4FinalizationEntry>()
            val rootRanges = rootShardRanges.toList()
            var materialization: AkenPageMaterialization? = null
            var emissions: AkenVbc4PageEmissionSet? = null
            var output: AkenVbc4FinalizationLayout? = null
            var planCommitment: ByteArray? = null
            var stateBindingLayoutDigest: ByteArray? = null
            var completed = false

            fun finalizationPageKey(
                resourceKind: AkenResourceKind,
                logicalIdentity: ByteArray,
                pageIndex: Int,
            ): String = resourceKind.id.toString() + ":" + identityPageKey(logicalIdentity, pageIndex)

            fun reservePhysicalRange(
                definitionKey: String,
                resourcePath: String,
                resourceOffset: Int,
                expectedLength: Int,
                ownerLabel: String,
            ) {
                require(resourcePath !in fixed) {
                    "AKEN " + ownerLabel + " path collides with a fixed final entry: " + resourcePath
                }
                val end = resourceOffset.toLong() + expectedLength.toLong()
                require(end <= Int.MAX_VALUE.toLong()) {
                    "AKEN " + ownerLabel + " reservation exceeds JVM array bounds"
                }
                val existing = pageBuffers[resourcePath]
                if (existing == null || existing.size < end.toInt()) {
                    val replacement = ByteArray(end.toInt())
                    existing?.copyInto(replacement)
                    existing?.let { Arrays.fill(it, 0) }
                    pageBuffers[resourcePath] = replacement
                }
                expectedLengths[definitionKey] = expectedLength
                selfReferential.getOrPut(resourcePath) { mutableListOf() } += AkenCanonicalExclusionRange(
                    entryName = resourcePath,
                    offset = resourceOffset,
                    length = expectedLength,
                    kind = AkenCanonicalExclusionKind.HighValuePayload,
                )
            }

            try {
                require(vbc4StateBindingLayoutDigest.size == 32) {
                    "AKEN VBC4 state-binding layout digest must be 32 bytes"
                }
                stateBindingLayoutDigest = vbc4StateBindingLayoutDigest.copyOf()
                for (page in pendingPages) pages += page
                for (page in pendingStringPages) stringPages += page
                for (page in pendingClassPages) classPages += page
                require(pages.isNotEmpty() || stringPages.isNotEmpty() || classPages.isNotEmpty()) {
                    "AKEN finalization requires at least one pending page"
                }
                for (entry in fixedEntries) {
                    require(fixed.put(entry.name, entry.copyBytesForCommitment()) == null) {
                        "AKEN finalization contains duplicate fixed entry: " + entry.name
                    }
                }

                planCommitment = plan.artifactCanonicalCommitment
                val suppliedCommitment = commitment.copyBytes()
                try {
                    require(MessageDigest.isEqual(planCommitment, suppliedCommitment)) {
                        "AKEN finalization plan is not bound to its reserved artifact commitment"
                    }
                } finally {
                    Arrays.fill(suppliedCommitment, 0)
                }

                pages.forEach { page ->
                    val identity = page.copyLogicalIdentityForBuild()
                    try {
                        val definitionKey = finalizationPageKey(
                            resourceKind = AkenResourceKind.Vbc4Method,
                            logicalIdentity = identity,
                            pageIndex = page.pageIndex,
                        )
                        require(vbc4PageDefinitions.put(definitionKey, page) == null) {
                            "AKEN VBC4 finalization contains duplicate logical identity/page index"
                        }
                        reservePhysicalRange(
                            definitionKey = definitionKey,
                            resourcePath = page.resourcePath,
                            resourceOffset = page.resourceOffset,
                            expectedLength = page.expectedStoredLength,
                            ownerLabel = "VBC4 page",
                        )
                    } finally {
                        Arrays.fill(identity, 0)
                    }
                }
                stringPages.forEach { page ->
                    val identity = page.copyLogicalIdentityForBuild()
                    try {
                        val definitionKey = finalizationPageKey(
                            resourceKind = AkenResourceKind.StringPage,
                            logicalIdentity = identity,
                            pageIndex = page.pageIndex,
                        )
                        require(stringPageDefinitions.put(definitionKey, page) == null) {
                            "AKEN StringPage finalization contains duplicate logical identity/page index"
                        }
                        reservePhysicalRange(
                            definitionKey = definitionKey,
                            resourcePath = page.resourcePath,
                            resourceOffset = page.resourceOffset,
                            expectedLength = page.expectedStoredLength,
                            ownerLabel = "StringPage",
                        )
                    } finally {
                        Arrays.fill(identity, 0)
                    }
                }
                classPages.forEach { page ->
                    val identity = page.copyLogicalIdentityForBuild()
                    try {
                        val definitionKey = finalizationPageKey(
                            resourceKind = AkenResourceKind.EncryptedClassPage,
                            logicalIdentity = identity,
                            pageIndex = page.pageIndex,
                        )
                        require(classPageDefinitions.put(definitionKey, page) == null) {
                            "AKEN ClassPage finalization contains duplicate logical identity/page index"
                        }
                        reservePhysicalRange(
                            definitionKey = definitionKey,
                            resourcePath = page.resourcePath,
                            resourceOffset = page.resourceOffset,
                            expectedLength = page.expectedStoredLength,
                            ownerLabel = "ClassPage",
                        )
                    } finally {
                        Arrays.fill(identity, 0)
                    }
                }

                validateNonOverlappingPageRanges(selfReferential)
                val rootRangesByEntry = rootRanges.groupBy { it.entryName }
                fixed.forEach { (name, bytes) ->
                    reservations += AkenCanonicalReservation(
                        entryName = name,
                        canonicalBytes = bytes,
                        rootShardRanges = rootRangesByEntry[name].orEmpty(),
                    )
                }
                pageBuffers.forEach { (name, bytes) ->
                    reservations += AkenCanonicalReservation(
                        entryName = name,
                        canonicalBytes = bytes,
                        rootShardRanges = rootRangesByEntry[name].orEmpty(),
                        selfReferentialRanges = selfReferential.getValue(name),
                    )
                }
                val reservedCommitment = AkenArtifactCommitment.reserve(reservations)
                val reservedBytes = reservedCommitment.copyBytes()
                val expectedBytes = commitment.copyBytes()
                try {
                    require(MessageDigest.isEqual(reservedBytes, expectedBytes)) {
                        "AKEN finalization reservation does not reproduce the active artifact commitment"
                    }
                } finally {
                    Arrays.fill(reservedBytes, 0)
                    Arrays.fill(expectedBytes, 0)
                }

                pages.forEach { pending ->
                    val identity = pending.copyLogicalIdentityForBuild()
                    val encodedHandleOverride = pending.copyEncodedHandleOverrideForBuild()
                    try {
                        val registered = plan.registerPage(
                            kind = AkenResourceKind.Vbc4Method,
                            identity = identity,
                            pageIndex = pending.pageIndex,
                            layoutVariant = pending.layoutVariant,
                            targetPageSize = pending.targetPageSize,
                            encodedHandleOverride = encodedHandleOverride,
                        )
                        vbc4Requests += pending.toEmissionRequest(registered)
                    } finally {
                        Arrays.fill(identity, 0)
                        encodedHandleOverride?.let { Arrays.fill(it, 0) }
                    }
                }
                stringPages.forEach { pending ->
                    materializationInputs += pending.toMaterializationInput(plan)
                }
                classPages.forEach { pending ->
                    materializationInputs += pending.toMaterializationInput(plan)
                }
                vbc4Requests.forEach { request ->
                    materializationInputs += request.toMaterializationInput()
                }
                require(materializationInputs.size == pages.size + stringPages.size + classPages.size) {
                    "AKEN finalization did not create one materialization input per page"
                }

                materialization = AkenPageMaterializer.materializeAndWipe(plan, materializationInputs)
                val outputPages = checkNotNull(materialization).pagesForBuild()
                require(outputPages.size == pages.size + stringPages.size + classPages.size) {
                    "AKEN finalization emitted an unexpected page count"
                }

                var materializedVbc4PageCount = 0
                var materializedStringPageCount = 0
                var materializedClassPageCount = 0
                outputPages.forEach { materializedPage ->
                    val descriptor = materializedPage.descriptorForBuild
                    when (descriptor.resourceKind) {
                        AkenResourceKind.Vbc4Method -> {
                            materializedVbc4PageCount += 1
                            val identity = descriptor.logicalIdentity
                            var proof: ByteArray? = null
                            try {
                                val definitionKey = finalizationPageKey(
                                    resourceKind = AkenResourceKind.Vbc4Method,
                                    logicalIdentity = identity,
                                    pageIndex = descriptor.pageIndex,
                                )
                                val pending = vbc4PageDefinitions[definitionKey]
                                    ?: error("AKEN VBC4 finalization emitted an unknown logical page")
                                val emission = AkenVbc4PageEmission.fromMaterialized(
                                    page = materializedPage,
                                    entryToken = pending.entryToken,
                                )
                                try {
                                    require(emission.resourcePath == pending.resourcePath &&
                                        emission.resourceOffset == pending.resourceOffset) {
                                        "AKEN VBC4 finalization route drifted from its reservation"
                                    }
                                    require(emission.storedLength == expectedLengths.getValue(definitionKey)) {
                                        "AKEN VBC4 finalization payload length drifted from its reservation"
                                    }
                                    val descriptorBytes = emission.copyDescriptorBytesForBuild()
                                    try {
                                        val emittedDescriptor = AkenRuntimePageDescriptor.decode(descriptorBytes)
                                        require(emittedDescriptor.targetPageSize == pending.targetPageSize) {
                                            "AKEN VBC4 finalization evaluator target size drifted from its block-cluster page"
                                        }
                                    } finally {
                                        Arrays.fill(descriptorBytes, 0)
                                    }
                                    proof = emission.copyCallSiteProofForBuild()
                                    val expectedProof = pending.copyCallSiteProofForBuild()
                                    try {
                                        require(MessageDigest.isEqual(proof, expectedProof)) {
                                            "AKEN VBC4 finalization call-site proof drifted"
                                        }
                                    } finally {
                                        Arrays.fill(expectedProof, 0)
                                    }
                                    val payload = emission.copyEncryptedPayloadForBuild()
                                    try {
                                        payload.copyInto(
                                            destination = checkNotNull(pageBuffers[emission.resourcePath]),
                                            destinationOffset = emission.resourceOffset,
                                        )
                                    } finally {
                                        Arrays.fill(payload, 0)
                                    }
                                    compilerInputs += AkenNativePageLocatorCompileInput.fromVbc4Emission(
                                        emission = emission,
                                        vbc4StateBindingLayoutDigest = checkNotNull(stateBindingLayoutDigest),
                                    )
                                    emittedVbc4Pages += emission
                                } catch (error: Throwable) {
                                    emission.wipe()
                                    throw error
                                }
                            } finally {
                                proof?.let { Arrays.fill(it, 0) }
                                Arrays.fill(identity, 0)
                            }
                        }

                        AkenResourceKind.StringPage -> {
                            materializedStringPageCount += 1
                            val identity = descriptor.logicalIdentity
                            var proof: ByteArray? = null
                            try {
                                val definitionKey = finalizationPageKey(
                                    resourceKind = AkenResourceKind.StringPage,
                                    logicalIdentity = identity,
                                    pageIndex = descriptor.pageIndex,
                                )
                                val pending = stringPageDefinitions[definitionKey]
                                    ?: error("AKEN StringPage finalization emitted an unknown logical page")
                                val route = descriptor.route
                                require(descriptor.targetPageSize == pending.targetPageSize) {
                                    "AKEN StringPage evaluator target size drifted from its reserved page"
                                }
                                require(
                                    route.resourcePath == pending.resourcePath &&
                                        route.resourceOffset == pending.resourceOffset &&
                                        route.storedLength == expectedLengths.getValue(definitionKey),
                                ) {
                                    "AKEN StringPage finalization route drifted from its reservation"
                                }
                                require(materializedPage.encodedLength == expectedLengths.getValue(definitionKey)) {
                                    "AKEN StringPage finalization payload length drifted from its reservation"
                                }
                                proof = descriptor.proof.callSiteProof
                                val expectedProof = pending.copyCallSiteProofForBuild()
                                try {
                                    require(MessageDigest.isEqual(proof, expectedProof)) {
                                        "AKEN StringPage finalization call-site proof drifted"
                                    }
                                } finally {
                                    Arrays.fill(expectedProof, 0)
                                }
                                val payload = materializedPage.copyEncodedPayloadForBuild()
                                try {
                                    payload.copyInto(
                                        destination = checkNotNull(pageBuffers[route.resourcePath]),
                                        destinationOffset = route.resourceOffset,
                                    )
                                } finally {
                                    Arrays.fill(payload, 0)
                                }
                                compilerInputs += AkenNativePageLocatorCompileInput.fromTypedPage(
                                    descriptor = descriptor,
                                    rawCallSiteProof = proof,
                                )
                            } finally {
                                proof?.let { Arrays.fill(it, 0) }
                                Arrays.fill(identity, 0)
                            }
                        }

                        AkenResourceKind.EncryptedClassPage -> {
                            materializedClassPageCount += 1
                            val identity = descriptor.logicalIdentity
                            var proof: ByteArray? = null
                            try {
                                val definitionKey = finalizationPageKey(
                                    resourceKind = AkenResourceKind.EncryptedClassPage,
                                    logicalIdentity = identity,
                                    pageIndex = descriptor.pageIndex,
                                )
                                val pending = classPageDefinitions[definitionKey]
                                    ?: error("AKEN ClassPage finalization emitted an unknown logical page")
                                val route = descriptor.route
                                require(descriptor.targetPageSize == pending.targetPageSize) {
                                    "AKEN ClassPage evaluator target size drifted from its reserved page"
                                }
                                require(
                                    route.resourcePath == pending.resourcePath &&
                                        route.resourceOffset == pending.resourceOffset &&
                                        route.storedLength == expectedLengths.getValue(definitionKey),
                                ) {
                                    "AKEN ClassPage finalization route drifted from its reservation"
                                }
                                require(materializedPage.encodedLength == expectedLengths.getValue(definitionKey)) {
                                    "AKEN ClassPage finalization payload length drifted from its reservation"
                                }
                                proof = descriptor.proof.callSiteProof
                                val expectedProof = pending.copyCallSiteProofForBuild()
                                try {
                                    require(MessageDigest.isEqual(proof, expectedProof)) {
                                        "AKEN ClassPage finalization call-site proof drifted"
                                    }
                                } finally {
                                    Arrays.fill(expectedProof, 0)
                                }
                                val payload = materializedPage.copyEncodedPayloadForBuild()
                                try {
                                    payload.copyInto(
                                        destination = checkNotNull(pageBuffers[route.resourcePath]),
                                        destinationOffset = route.resourceOffset,
                                    )
                                } finally {
                                    Arrays.fill(payload, 0)
                                }
                                compilerInputs += AkenNativePageLocatorCompileInput.fromTypedPage(
                                    descriptor = descriptor,
                                    rawCallSiteProof = proof,
                                )
                            } finally {
                                proof?.let { Arrays.fill(it, 0) }
                                Arrays.fill(identity, 0)
                            }
                        }

                        else -> error("AKEN finalization received an unsupported typed page resource kind")
                    }
                }
                require(materializedVbc4PageCount == pages.size) {
                    "AKEN finalization did not emit every VBC4 page"
                }
                require(materializedStringPageCount == stringPages.size) {
                    "AKEN finalization did not emit every StringPage"
                }
                require(materializedClassPageCount == classPages.size) {
                    "AKEN finalization did not emit every ClassPage"
                }
                require(compilerInputs.size == outputPages.size) {
                    "AKEN finalization did not create one native input per page"
                }

                if (emittedVbc4Pages.isNotEmpty()) {
                    val meshRoot = checkNotNull(materialization).copyMeshRootForBuild()
                    try {
                        emissions = AkenVbc4PageEmissionSet.create(meshRoot, emittedVbc4Pages)
                    } finally {
                        Arrays.fill(meshRoot, 0)
                    }
                }

                val finalBytes = LinkedHashMap<String, ByteArray>()
                fixed.forEach { (name, bytes) -> finalBytes[name] = bytes.copyOf() }
                pageBuffers.forEach { (name, bytes) -> finalBytes[name] = bytes.copyOf() }
                applyRootShards(commitment, finalBytes)
                finalBytes.forEach { (name, bytes) ->
                    try {
                        finalEntries += AkenVbc4FinalizationEntry.create(name, bytes)
                    } finally {
                        Arrays.fill(bytes, 0)
                    }
                }
                val retainedMaterialization = checkNotNull(materialization)
                output = AkenVbc4FinalizationLayout(
                    commitmentValue = commitment,
                    finalEntriesValue = finalEntries,
                    materializationValue = retainedMaterialization,
                    emissionsValue = emissions,
                    nativeInputsValue = compilerInputs,
                )
                materialization = null
                require(output.verifyOwnedEntriesForBuild()) {
                    "AKEN finalization did not verify its own writer-equivalent artifact"
                }
                completed = true
                return output
            } finally {
                plan.wipe()
                pages.forEach { it.wipe() }
                stringPages.forEach { it.wipe() }
                classPages.forEach { it.wipe() }
                vbc4Requests.forEach { it.wipe() }
                materializationInputs.forEach { it.wipe() }
                fixed.values.forEach { Arrays.fill(it, 0) }
                pageBuffers.values.forEach { Arrays.fill(it, 0) }
                planCommitment?.let { Arrays.fill(it, 0) }
                stateBindingLayoutDigest?.let { Arrays.fill(it, 0) }
                if (!completed) {
                    output?.wipe()
                    materialization?.wipe()
                    emissions?.wipe()
                    emittedVbc4Pages.forEach { it.wipe() }
                    compilerInputs.forEach { it.wipe() }
                    finalEntries.forEach { it.wipe() }
                }
            }
        }

        /**
         * Computes the exact one-pass canonical commitment for pending VBC4,
         * typed StringPage, and encrypted ClassPage records without consuming their plaintext owners.
         * Callers initialize one [AkenBuildPlan] from the resulting commitment
         * and then hand the same candidates to [materializeAndWipe].
         */
        @JvmSynthetic
        fun reserve(
            pendingPages: Iterable<AkenVbc4PendingPage>,
            fixedEntries: Iterable<AkenArtifactEntry>,
            pendingStringPages: Iterable<AkenPendingStringPage> = emptyList(),
            pendingClassPages: Iterable<AkenPendingClassPage> = emptyList(),
            rootShardRanges: Iterable<AkenRootShardRange> = emptyList(),
        ): AkenArtifactCommitment {
            val pages = ArrayList<AkenVbc4PendingPage>()
            val stringPages = ArrayList<AkenPendingStringPage>()
            val classPages = ArrayList<AkenPendingClassPage>()
            val fixed = LinkedHashMap<String, ByteArray>()
            val pageBuffers = LinkedHashMap<String, ByteArray>()
            val selfReferential = LinkedHashMap<String, MutableList<AkenCanonicalExclusionRange>>()
            val definitions = HashSet<String>()
            val reservations = ArrayList<AkenCanonicalReservation>()
            val rootRanges = rootShardRanges.toList()

            fun finalizationPageKey(
                resourceKind: AkenResourceKind,
                logicalIdentity: ByteArray,
                pageIndex: Int,
            ): String = resourceKind.id.toString() + ":" + identityPageKey(logicalIdentity, pageIndex)

            fun reservePhysicalRange(
                definitionKey: String,
                resourcePath: String,
                resourceOffset: Int,
                expectedLength: Int,
                ownerLabel: String,
            ) {
                require(resourcePath !in fixed) {
                    "AKEN " + ownerLabel + " path collides with a fixed final entry: " + resourcePath
                }
                require(definitions.add(definitionKey)) {
                    "AKEN " + ownerLabel + " finalization contains duplicate logical identity/page index"
                }
                val end = resourceOffset.toLong() + expectedLength.toLong()
                require(end <= Int.MAX_VALUE.toLong()) {
                    "AKEN " + ownerLabel + " reservation exceeds JVM array bounds"
                }
                val existing = pageBuffers[resourcePath]
                if (existing == null || existing.size < end.toInt()) {
                    val replacement = ByteArray(end.toInt())
                    existing?.copyInto(replacement)
                    existing?.let { Arrays.fill(it, 0) }
                    pageBuffers[resourcePath] = replacement
                }
                selfReferential.getOrPut(resourcePath) { mutableListOf() } += AkenCanonicalExclusionRange(
                    entryName = resourcePath,
                    offset = resourceOffset,
                    length = expectedLength,
                    kind = AkenCanonicalExclusionKind.HighValuePayload,
                )
            }

            try {
                for (page in pendingPages) pages += page
                for (page in pendingStringPages) stringPages += page
                for (page in pendingClassPages) classPages += page
                require(pages.isNotEmpty() || stringPages.isNotEmpty() || classPages.isNotEmpty()) {
                    "AKEN finalization requires at least one pending page"
                }
                for (entry in fixedEntries) {
                    require(fixed.put(entry.name, entry.copyBytesForCommitment()) == null) {
                        "AKEN finalization contains duplicate fixed entry: " + entry.name
                    }
                }
                pages.forEach { page ->
                    val identity = page.copyLogicalIdentityForBuild()
                    try {
                        reservePhysicalRange(
                            definitionKey = finalizationPageKey(
                                resourceKind = AkenResourceKind.Vbc4Method,
                                logicalIdentity = identity,
                                pageIndex = page.pageIndex,
                            ),
                            resourcePath = page.resourcePath,
                            resourceOffset = page.resourceOffset,
                            expectedLength = page.expectedStoredLength,
                            ownerLabel = "VBC4 page",
                        )
                    } finally {
                        Arrays.fill(identity, 0)
                    }
                }
                stringPages.forEach { page ->
                    val identity = page.copyLogicalIdentityForBuild()
                    try {
                        reservePhysicalRange(
                            definitionKey = finalizationPageKey(
                                resourceKind = AkenResourceKind.StringPage,
                                logicalIdentity = identity,
                                pageIndex = page.pageIndex,
                            ),
                            resourcePath = page.resourcePath,
                            resourceOffset = page.resourceOffset,
                            expectedLength = page.expectedStoredLength,
                            ownerLabel = "StringPage",
                        )
                    } finally {
                        Arrays.fill(identity, 0)
                    }
                }
                classPages.forEach { page ->
                    val identity = page.copyLogicalIdentityForBuild()
                    try {
                        reservePhysicalRange(
                            definitionKey = finalizationPageKey(
                                resourceKind = AkenResourceKind.EncryptedClassPage,
                                logicalIdentity = identity,
                                pageIndex = page.pageIndex,
                            ),
                            resourcePath = page.resourcePath,
                            resourceOffset = page.resourceOffset,
                            expectedLength = page.expectedStoredLength,
                            ownerLabel = "ClassPage",
                        )
                    } finally {
                        Arrays.fill(identity, 0)
                    }
                }

                validateNonOverlappingPageRanges(selfReferential)
                val rootRangesByEntry = rootRanges.groupBy { it.entryName }
                fixed.forEach { (name, bytes) ->
                    reservations += AkenCanonicalReservation(
                        entryName = name,
                        canonicalBytes = bytes,
                        rootShardRanges = rootRangesByEntry[name].orEmpty(),
                    )
                }
                pageBuffers.forEach { (name, bytes) ->
                    reservations += AkenCanonicalReservation(
                        entryName = name,
                        canonicalBytes = bytes,
                        rootShardRanges = rootRangesByEntry[name].orEmpty(),
                        selfReferentialRanges = selfReferential.getValue(name),
                    )
                }
                return AkenArtifactCommitment.reserve(reservations)
            } finally {
                fixed.values.forEach { Arrays.fill(it, 0) }
                pageBuffers.values.forEach { Arrays.fill(it, 0) }
            }
        }

        private fun AkenVbc4FinalizationLayout.verifyOwnedEntriesForBuild(): Boolean {
            val artifactEntries = ArrayList<AkenArtifactEntry>()
            val sourceCopies = ArrayList<ByteArray>()
            return try {
                entriesForBuild().forEach { entry ->
                    val bytes = entry.copyBytesForBuild()
                    sourceCopies += bytes
                    artifactEntries += AkenArtifactEntry(entry.name, bytes)
                }
                verifyWriterEquivalentArtifactForBuild(artifactEntries)
            } finally {
                sourceCopies.forEach { Arrays.fill(it, 0) }
            }
        }

        private fun applyRootShards(
            commitment: AkenArtifactCommitment,
            finalBytes: Map<String, ByteArray>,
        ) {
            commitment.rootShardRanges.forEach { range ->
                val entry = finalBytes[range.entryName]
                    ?: throw IllegalArgumentException("AKEN VBC4 root shard references missing final entry: ${range.entryName}")
                val shard = commitment.copyExpectedRootShardBytesForBuild(range)
                try {
                    require(range.endExclusive <= entry.size.toLong()) {
                        "AKEN VBC4 root shard exceeds final entry bounds: ${range.entryName}"
                    }
                    shard.copyInto(entry, destinationOffset = range.offset)
                } finally {
                    Arrays.fill(shard, 0)
                }
            }
        }

        private fun validateNonOverlappingPageRanges(
            rangesByEntry: Map<String, List<AkenCanonicalExclusionRange>>,
        ) {
            rangesByEntry.forEach { (entry, ranges) ->
                val sorted = ranges.sortedBy { it.offset }
                var priorEnd = 0L
                sorted.forEachIndexed { index, range ->
                    if (index > 0) {
                        require(priorEnd <= range.offset.toLong()) {
                            "AKEN VBC4 page reservations overlap in '$entry'"
                        }
                    }
                    priorEnd = range.endExclusive
                }
            }
        }
    }
}

private fun identityPageKey(identity: ByteArray, pageIndex: Int): String {
    val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(identity)
    return "$encoded:$pageIndex"
}

private fun isValidResourcePath(path: String): Boolean {
    if (path.isBlank() || '\u0000' in path || '\\' in path || path.startsWith('/') || path.endsWith('/')) return false
    return path.split('/').all { segment ->
        segment.isNotEmpty() && segment != "." && segment != ".." &&
            segment.none { character -> character == '\r' || character == '\n' || character == '|' }
    }
}
