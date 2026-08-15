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
 * canonical reservation.  The page handle, evaluator graph and DEK are still
 * minted only after [AkenArtifactCommitment.reserve] has produced the final
 * commitment.  This keeps the pre-seal phase from inventing a reusable root or
 * serializing a plaintext/page-key catalog into a runtime artifact.
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
) : AutoCloseable {
    private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
    private var plaintextValue: ByteArray = plaintext.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(logicalIdentityValue.isNotEmpty()) { "AKEN VBC4 pending-page identity must not be empty" }
        require(plaintextValue.isNotEmpty()) { "AKEN VBC4 pending-page plaintext must not be empty" }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "AKEN VBC4 pending-page call-site proof length is invalid"
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
        logicalIdentityValue = ByteArray(0)
        plaintextValue = ByteArray(0)
        callSiteProofValue = ByteArray(0)
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
 * Pre-seal VBC4 layout reservation plus current-page native compiler inputs.
 *
 * This is the deliberately narrow S1 bridge between page planning and the
 * later native recompilation stage. It owns final page bytes, descriptors, and
 * per-page native locator inputs only while the build is active. It is never
 * injected as a Java runtime catalog and offers no `find`, `list`, arbitrary
 * resource decode, DEK getter, root-key getter, or page plaintext getter.
 */
internal class AkenVbc4FinalizationLayout private constructor(
    private val commitmentValue: AkenArtifactCommitment,
    private var finalEntriesValue: List<AkenVbc4FinalizationEntry>,
    private var emissionsValue: AkenVbc4PageEmissionSet?,
    private var nativeInputsValue: List<AkenNativePageLocatorCompileInput>,
) : AutoCloseable {
    @Volatile
    private var wiped: Boolean = false

    init {
        require(finalEntriesValue.isNotEmpty()) { "AKEN VBC4 finalization layout requires final entries" }
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
     * Rechecks the exact writer-equivalent artifact after a caller has emitted
     * the reserved bytes. The check covers canonical non-excluded bytes, root
     * shards, each page route/payload, each full-payload Merkle proof, and the
     * exact typed-native current-page binding. It remains build-only.
     */
    internal fun verifyWriterEquivalentArtifactForBuild(entries: Iterable<AkenArtifactEntry>): Boolean {
        if (wiped) return false
        val entriesByName = LinkedHashMap<String, AkenArtifactEntry>()
        val pages = ArrayList<VerifiedPage>()
        var artifactCommitment: ByteArray? = null
        var mesh: AkenIntegrityMesh? = null
        try {
            for (entry in entries) {
                if (entriesByName.put(entry.name, entry) != null) return false
            }
            if (!commitmentValue.matchesWriterEquivalentEntriesForBuild(entriesByName.values)) return false
            if (!commitmentValue.verifyRootShardsForBuild(entriesByName.values)) return false
            artifactCommitment = commitmentValue.copyBytes()

            val emittedPages = (emissionsValue ?: return false).pagesForBuild()
            if (emittedPages.size != nativeInputsValue.size) return false
            emittedPages.forEachIndexed { index, emission ->
                pages += verifyAndCapturePage(
                    emission = emission,
                    nativeInput = nativeInputsValue[index],
                    entriesByName = entriesByName,
                    artifactCommitment = checkNotNull(artifactCommitment),
                ) ?: return false
            }

            val leaves = pages.map { page -> AkenIntegrityMesh.Leaf(page.leafEncoding, page.payload) }
            mesh = AkenIntegrityMesh.build(leaves)
            return pages.all { page -> proofMatches(page.descriptor.proof, page.leafEncoding, checkNotNull(mesh), artifactCommitment) }
        } catch (_: IllegalArgumentException) {
            return false
        } catch (_: IllegalStateException) {
            return false
        } finally {
            pages.forEach { it.wipe() }
            artifactCommitment?.let { Arrays.fill(it, 0) }
        }
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        finalEntriesValue.forEach { it.wipe() }
        finalEntriesValue = emptyList()
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
         * Materializes a complete pre-seal page layout using a plan already
         * bound to [commitment] by the active VBC4 build context.
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
            rootShardRanges: Iterable<AkenRootShardRange> = emptyList(),
        ): AkenVbc4FinalizationLayout {
            val pages = ArrayList<AkenVbc4PendingPage>()
            val fixed = LinkedHashMap<String, ByteArray>()
            val pageBuffers = LinkedHashMap<String, ByteArray>()
            val expectedLengths = LinkedHashMap<String, Int>()
            val reservations = ArrayList<AkenCanonicalReservation>()
            val selfReferential = LinkedHashMap<String, MutableList<AkenCanonicalExclusionRange>>()
            val pageDefinitions = LinkedHashMap<String, AkenVbc4PendingPage>()
            val registeredPages = ArrayList<AkenBuildPlan.Page>()
            val requests = ArrayList<AkenVbc4PageEmissionRequest>()
            val compilerInputs = ArrayList<AkenNativePageLocatorCompileInput>()
            val finalEntries = ArrayList<AkenVbc4FinalizationEntry>()
            val rootRanges = rootShardRanges.toList()
            var emissions: AkenVbc4PageEmissionSet? = null
            var output: AkenVbc4FinalizationLayout? = null
            var planCommitment: ByteArray? = null
            var completed = false
            try {
                for (page in pendingPages) pages += page
                require(pages.isNotEmpty()) { "AKEN VBC4 finalization requires at least one pending page" }
                for (entry in fixedEntries) {
                    require(fixed.put(entry.name, entry.copyBytesForCommitment()) == null) {
                        "AKEN VBC4 finalization contains duplicate fixed entry: ${entry.name}"
                    }
                }

                planCommitment = plan.artifactCanonicalCommitment
                val suppliedCommitment = commitment.copyBytes()
                try {
                    require(MessageDigest.isEqual(planCommitment, suppliedCommitment)) {
                        "AKEN VBC4 finalization plan is not bound to its reserved artifact commitment"
                    }
                } finally {
                    Arrays.fill(suppliedCommitment, 0)
                }

                pages.forEach { page ->
                    require(page.resourcePath !in fixed) {
                        "AKEN VBC4 page path collides with a fixed final entry: ${page.resourcePath}"
                    }
                    require(pageDefinitions.put(page.identityPageKeyForBuild(), page) == null) {
                        "AKEN VBC4 finalization contains duplicate logical identity/page index"
                    }
                    val expectedLength = page.expectedStoredLength
                    val end = page.resourceOffset.toLong() + expectedLength.toLong()
                    require(end <= Int.MAX_VALUE.toLong()) { "AKEN VBC4 page reservation exceeds JVM array bounds" }
                    val existing = pageBuffers[page.resourcePath]
                    if (existing == null || existing.size < end.toInt()) {
                        val replacement = ByteArray(end.toInt())
                        existing?.copyInto(replacement)
                        existing?.let { Arrays.fill(it, 0) }
                        pageBuffers[page.resourcePath] = replacement
                    }
                    expectedLengths[page.identityPageKeyForBuild()] = expectedLength
                    selfReferential.getOrPut(page.resourcePath) { mutableListOf() } += AkenCanonicalExclusionRange(
                        entryName = page.resourcePath,
                        offset = page.resourceOffset,
                        length = expectedLength,
                        kind = AkenCanonicalExclusionKind.HighValuePayload,
                    )
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
                        "AKEN VBC4 finalization reservation does not reproduce the active artifact commitment"
                    }
                } finally {
                    Arrays.fill(reservedBytes, 0)
                    Arrays.fill(expectedBytes, 0)
                }

                pages.forEach { pending ->
                    val identity = pending.copyLogicalIdentityForBuild()
                    try {
                        val registered = plan.registerPage(
                            kind = AkenResourceKind.Vbc4Method,
                            identity = identity,
                            pageIndex = pending.pageIndex,
                            layoutVariant = pending.layoutVariant,
                            targetPageSize = pending.targetPageSize,
                        )
                        registeredPages += registered
                        requests += pending.toEmissionRequest(registered)
                    } finally {
                        Arrays.fill(identity, 0)
                    }
                }
                emissions = AkenVbc4PageEmitter.emitAndWipe(plan, requests)
                val outputPages = emissions.pagesForBuild()
                require(outputPages.size == pages.size) { "AKEN VBC4 finalization emitted an unexpected page count" }
                outputPages.forEach { emission ->
                    val identity = emission.copyLogicalIdentityForBuild()
                    val proof = emission.copyCallSiteProofForBuild()
                    try {
                        val key = identityPageKey(identity, emission.pageIndex)
                        val pending = pageDefinitions[key]
                            ?: error("AKEN VBC4 finalization emitted an unknown logical page")
                        require(emission.entryToken == pending.entryToken) { "AKEN VBC4 finalization entry-token binding drifted" }
                        val descriptorBytes = emission.copyDescriptorBytesForBuild()
                        try {
                            val descriptor = AkenRuntimePageDescriptor.decode(descriptorBytes)
                            require(descriptor.targetPageSize == pending.targetPageSize) {
                                "AKEN VBC4 finalization evaluator target size drifted from its block-cluster page"
                            }
                        } finally {
                            Arrays.fill(descriptorBytes, 0)
                        }
                        require(emission.resourcePath == pending.resourcePath && emission.resourceOffset == pending.resourceOffset) {
                            "AKEN VBC4 finalization route drifted from its reservation"
                        }
                        require(emission.storedLength == expectedLengths.getValue(key)) {
                            "AKEN VBC4 finalization payload length drifted from its reservation"
                        }
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
                            val buffer = checkNotNull(pageBuffers[emission.resourcePath])
                            payload.copyInto(buffer, destinationOffset = emission.resourceOffset)
                        } finally {
                            Arrays.fill(payload, 0)
                        }
                        compilerInputs += AkenNativePageLocatorCompileInput.fromVbc4Emission(emission)
                    } finally {
                        Arrays.fill(identity, 0)
                        Arrays.fill(proof, 0)
                    }
                }
                require(compilerInputs.size == outputPages.size) {
                    "AKEN VBC4 finalization did not create one native input per page"
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
                output = AkenVbc4FinalizationLayout(
                    commitmentValue = commitment,
                    finalEntriesValue = finalEntries,
                    emissionsValue = checkNotNull(emissions),
                    nativeInputsValue = compilerInputs,
                )
                require(output.verifyOwnedEntriesForBuild()) {
                    "AKEN VBC4 finalization did not verify its own writer-equivalent artifact"
                }
                completed = true
                return output
            } finally {
                // The page emitter owns/wipes the plan once materialization
                // begins. Calling wipe again is idempotent and covers failures
                // before that hand-off.
                plan.wipe()
                pages.forEach { it.wipe() }
                requests.forEach { it.wipe() }
                registeredPages.forEach { page ->
                    // Their plan owner has already wiped the authoritative page;
                    // no independent handle/DEK copy is retained here.
                    runCatching { page.handle.wipe() }
                }
                fixed.values.forEach { Arrays.fill(it, 0) }
                pageBuffers.values.forEach { Arrays.fill(it, 0) }
                planCommitment?.let { Arrays.fill(it, 0) }
                if (!completed) {
                    output?.wipe()
                    emissions?.wipe()
                    compilerInputs.forEach { it.wipe() }
                    finalEntries.forEach { it.wipe() }
                }
            }
        }

        /**
         * Computes the exact one-pass canonical commitment for a set of pending
         * VBC4 pages without consuming their plaintext owners. Callers use the
         * returned commitment to initialize [AkenBuildPlan], then hand the same
         * candidates to [materializeAndWipe].
         */
        @JvmSynthetic
        fun reserve(
            pendingPages: Iterable<AkenVbc4PendingPage>,
            fixedEntries: Iterable<AkenArtifactEntry>,
            rootShardRanges: Iterable<AkenRootShardRange> = emptyList(),
        ): AkenArtifactCommitment {
            val pages = ArrayList<AkenVbc4PendingPage>()
            val fixed = LinkedHashMap<String, ByteArray>()
            val pageBuffers = LinkedHashMap<String, ByteArray>()
            val selfReferential = LinkedHashMap<String, MutableList<AkenCanonicalExclusionRange>>()
            val definitions = HashSet<String>()
            val reservations = ArrayList<AkenCanonicalReservation>()
            val rootRanges = rootShardRanges.toList()
            try {
                for (page in pendingPages) pages += page
                require(pages.isNotEmpty()) { "AKEN VBC4 finalization requires at least one pending page" }
                for (entry in fixedEntries) {
                    require(fixed.put(entry.name, entry.copyBytesForCommitment()) == null) {
                        "AKEN VBC4 finalization contains duplicate fixed entry: ${entry.name}"
                    }
                }
                pages.forEach { page ->
                    require(page.resourcePath !in fixed) {
                        "AKEN VBC4 page path collides with a fixed final entry: ${page.resourcePath}"
                    }
                    require(definitions.add(page.identityPageKeyForBuild())) {
                        "AKEN VBC4 finalization contains duplicate logical identity/page index"
                    }
                    val end = page.resourceOffset.toLong() + page.expectedStoredLength.toLong()
                    require(end <= Int.MAX_VALUE.toLong()) { "AKEN VBC4 page reservation exceeds JVM array bounds" }
                    val existing = pageBuffers[page.resourcePath]
                    if (existing == null || existing.size < end.toInt()) {
                        val replacement = ByteArray(end.toInt())
                        existing?.copyInto(replacement)
                        existing?.let { Arrays.fill(it, 0) }
                        pageBuffers[page.resourcePath] = replacement
                    }
                    selfReferential.getOrPut(page.resourcePath) { mutableListOf() } += AkenCanonicalExclusionRange(
                        entryName = page.resourcePath,
                        offset = page.resourceOffset,
                        length = page.expectedStoredLength,
                        kind = AkenCanonicalExclusionKind.HighValuePayload,
                    )
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
