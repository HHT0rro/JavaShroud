package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.MessageDigest
import java.util.Arrays
import java.util.Base64

/**
 * Build-only ownership wrapper for the plaintext and call-site proof of one
 * already-registered AKEN page.
 *
 * The constructor takes defensive copies.  [AkenPageMaterializer] consumes and
 * wipes those copies, then wipes the owning [AkenBuildPlan].  This type has no
 * plaintext getter, no DEK getter, and no runtime decoding method.
 */
internal class AkenPageMaterializationInput private constructor(
    internal val page: AkenBuildPlan.Page,
    plaintext: ByteArray,
    val resourcePath: String,
    val resourceOffset: Int,
    callSiteProof: ByteArray,
) : AutoCloseable {
    private var plaintextValue: ByteArray = plaintext.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(plaintextValue.isNotEmpty()) { "AKEN materialization plaintext must not be empty" }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "AKEN materialization call-site proof length is invalid"
        }
        require(resourceOffset >= 0) { "AKEN materialization resource offset must be non-negative" }
    }

    val isWiped: Boolean
        get() = wiped

    internal fun copyPlaintextForBuild(): ByteArray {
        requireLive()
        return plaintextValue.copyOf()
    }

    internal fun copyCallSiteProofForBuild(): ByteArray {
        requireLive()
        return callSiteProofValue.copyOf()
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(plaintextValue, 0)
        Arrays.fill(callSiteProofValue, 0)
        plaintextValue = ByteArray(0)
        callSiteProofValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN materialization input has been wiped" }
    }

    companion object {
        private const val MAX_CALL_SITE_PROOF_SIZE = 4096

        fun create(
            page: AkenBuildPlan.Page,
            plaintext: ByteArray,
            resourcePath: String,
            resourceOffset: Int = 0,
            callSiteProof: ByteArray,
        ): AkenPageMaterializationInput = AkenPageMaterializationInput(
            page = page,
            plaintext = plaintext,
            resourcePath = resourcePath,
            resourceOffset = resourceOffset,
            callSiteProof = callSiteProof,
        )
    }
}

/**
 * One materialized encrypted page plus its page-local descriptor.
 *
 * The encrypted payload is exposed only as a build-only defensive copy for an
 * output emitter.  It cannot be decoded through this API.  Closing the page
 * wipes that stored payload and drops the descriptor reference.
 */
internal class AkenMaterializedPage private constructor(
    descriptor: AkenRuntimePageDescriptor,
    encodedPayload: ByteArray,
) : AutoCloseable {
    private var descriptorValue: AkenRuntimePageDescriptor? = descriptor
    private var encodedPayloadValue: ByteArray = encodedPayload.copyOf()

    @Volatile
    private var wiped: Boolean = false

    internal val descriptorForBuild: AkenRuntimePageDescriptor
        get() {
            requireLive()
            return descriptorValue ?: error("AKEN materialized page descriptor has been wiped")
        }

    internal val encodedLength: Int
        get() {
            requireLive()
            return encodedPayloadValue.size
        }

    val isWiped: Boolean
        get() = wiped

    internal fun copyEncodedPayloadForBuild(): ByteArray {
        requireLive()
        return encodedPayloadValue.copyOf()
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(encodedPayloadValue, 0)
        encodedPayloadValue = ByteArray(0)
        descriptorValue = null
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN materialized page has been wiped" }
    }

    companion object {
        internal fun create(
            descriptor: AkenRuntimePageDescriptor,
            encodedPayload: ByteArray,
        ): AkenMaterializedPage = AkenMaterializedPage(descriptor, encodedPayload)
    }
}

/**
 * Build-only materialization output.  It owns a full-payload Merkle mesh only
 * while an output emitter is consuming the individual page records.  There is
 * no serialized catalog, no runtime traversal method, no raw DEK export, and
 * no Java resource decoder.
 */
internal class AkenPageMaterialization private constructor(
    private var artifactCommitmentValue: ByteArray,
    private var meshValue: AkenIntegrityMesh?,
    private var pagesByLeafBinding: LinkedHashMap<String, AkenMaterializedPage>,
) : AutoCloseable {
    @Volatile
    private var wiped: Boolean = false

    val isWiped: Boolean
        get() = wiped

    /** Build-only emission order. This is never serialized as a runtime catalog. */
    internal fun pagesForBuild(): List<AkenMaterializedPage> {
        requireLive()
        return pagesByLeafBinding.values.toList()
    }

    internal fun copyMeshRootForBuild(): ByteArray {
        requireLive()
        return (meshValue ?: error("AKEN materialization mesh has been wiped")).root
    }

    /**
     * Validate a known generated descriptor/payload pair against the exact
     * materialized record and its full-payload Merkle proof. This is a
     * build-time integrity verification operation; it never decrypts [payload].
     */
    internal fun verifyPayloadForBuild(
        descriptor: AkenRuntimePageDescriptor,
        payload: ByteArray,
    ): Boolean {
        if (wiped) return false
        val leafEncoding = descriptor.route.leafIdentity.encode()
        try {
            val record = pagesByLeafBinding[leafKey(leafEncoding)] ?: return false
            val suppliedDescriptor = descriptor.encode()
            val expectedDescriptor = record.descriptorForBuild.encode()
            try {
                if (!MessageDigest.isEqual(suppliedDescriptor, expectedDescriptor)) return false

                val mesh = meshValue ?: return false
                val expectedProof = mesh.proofFor(leafEncoding) ?: return false
                val artifactCommitment = artifactCommitmentValue.copyOf()
                try {
                    if (!proofMatchesMesh(descriptor.proof, descriptor.route.leafIdentity, artifactCommitment, expectedProof)) {
                        return false
                    }
                    return mesh.verify(expectedProof, leafEncoding, payload)
                } finally {
                    Arrays.fill(artifactCommitment, 0)
                }
            } finally {
                Arrays.fill(suppliedDescriptor, 0)
                Arrays.fill(expectedDescriptor, 0)
            }
        } catch (_: IllegalArgumentException) {
            return false
        } catch (_: IllegalStateException) {
            return false
        } finally {
            Arrays.fill(leafEncoding, 0)
        }
    }

    internal fun verifyPageForBuild(page: AkenMaterializedPage): Boolean {
        if (wiped || page.isWiped) return false
        val payload = try {
            page.copyEncodedPayloadForBuild()
        } catch (_: IllegalStateException) {
            return false
        }
        return try {
            verifyPayloadForBuild(page.descriptorForBuild, payload)
        } catch (_: IllegalStateException) {
            false
        } finally {
            Arrays.fill(payload, 0)
        }
    }

    /**
     * Build-only final writer verification for a materialized AKEN output.
     *
     * The caller supplies the exact final JAR-entry byte view. This method first
     * verifies the one-pass canonical commitment using its declared zero ranges,
     * then separately checks commitment-derived root shards, and finally pulls
     * each current page from its declared physical route to verify the page-local
     * descriptor and full-payload Merkle proof. It has no resource traversal or
     * decoder API outside this build-only materialization owner.
     */
    internal fun verifyWriterEquivalentArtifactForBuild(
        commitment: AkenArtifactCommitment,
        entries: Iterable<AkenArtifactEntry>,
    ): Boolean {
        if (wiped) return false
        val entriesByName = LinkedHashMap<String, AkenArtifactEntry>()
        var storedCommitment: ByteArray? = null
        var suppliedCommitment: ByteArray? = null
        try {
            for (entry in entries) {
                if (entriesByName.put(entry.name, entry) != null) return false
            }
            storedCommitment = artifactCommitmentValue.copyOf()
            suppliedCommitment = commitment.copyBytes()
            if (!MessageDigest.isEqual(storedCommitment, suppliedCommitment)) return false
            if (!commitment.matchesWriterEquivalentEntriesForBuild(entriesByName.values)) return false
            if (!commitment.verifyRootShardsForBuild(entriesByName.values)) return false

            for (page in pagesByLeafBinding.values) {
                val descriptor = try {
                    page.descriptorForBuild
                } catch (_: IllegalStateException) {
                    return false
                }
                val route = descriptor.route
                val entry = entriesByName[route.resourcePath] ?: return false
                val entryBytes = entry.copyBytesForCommitment()
                var routedPayload: ByteArray? = null
                try {
                    val endExclusive = route.resourceOffset.toLong() + route.storedLength.toLong()
                    if (endExclusive > entryBytes.size.toLong()) return false
                    if (route.storedLength != page.encodedLength) return false
                    routedPayload = entryBytes.copyOfRange(route.resourceOffset, endExclusive.toInt())
                    if (!verifyPayloadForBuild(descriptor, routedPayload)) return false
                } finally {
                    routedPayload?.let { Arrays.fill(it, 0) }
                    Arrays.fill(entryBytes, 0)
                }
            }
            return true
        } catch (_: IllegalArgumentException) {
            return false
        } catch (_: IllegalStateException) {
            return false
        } finally {
            storedCommitment?.let { Arrays.fill(it, 0) }
            suppliedCommitment?.let { Arrays.fill(it, 0) }
        }
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        wiped = true
        pagesByLeafBinding.values.forEach { it.wipe() }
        pagesByLeafBinding.clear()
        meshValue = null
        Arrays.fill(artifactCommitmentValue, 0)
        artifactCommitmentValue = ByteArray(0)
    }

    private fun requireLive() {
        check(!wiped) { "AKEN page materialization has been wiped" }
    }

    private fun proofMatchesMesh(
        proof: AkenSealingProofMetadata,
        identity: AkenHighValueLeafIdentity,
        artifactCommitment: ByteArray,
        expected: AkenIntegrityMesh.MerkleProof,
    ): Boolean = proofMatchesExpectedMesh(proof, identity, artifactCommitment, expected)

    companion object {
        internal fun create(
            artifactCommitment: ByteArray,
            mesh: AkenIntegrityMesh,
            pages: LinkedHashMap<String, AkenMaterializedPage>,
        ): AkenPageMaterialization = AkenPageMaterialization(
            artifactCommitmentValue = artifactCommitment.copyOf(),
            meshValue = mesh,
            pagesByLeafBinding = LinkedHashMap(pages),
        )
    }
}

/**
 * Converts registered AKEN pages into page-local AEAD payloads, one full-payload
 * Merkle mesh, and one non-enumerable descriptor/proof record per page.
 *
 * This consumes [plan]: both every input's owned plaintext copy and the whole
 * build plan are wiped on success and failure. Descriptors retain page-local
 * route/proof metadata plus dispersed evaluator state, never a contiguous DEK
 * or a shared root key.
 */
internal object AkenPageMaterializer {
    fun materializeAndWipe(
        plan: AkenBuildPlan,
        inputs: Iterable<AkenPageMaterializationInput>,
    ): AkenPageMaterialization {
        // Snapshot under the owning try/finally.  A hostile or malformed
        // Iterable may throw while it is being consumed; every input already
        // obtained and the build authority must still be wiped in that case.
        val inputList = ArrayList<AkenPageMaterializationInput>()
        var artifactCommitment: ByteArray? = null
        var mesh: AkenIntegrityMesh? = null
        val drafts = ArrayList<PageDraft>()
        val outputPages = LinkedHashMap<String, AkenMaterializedPage>()
        var completed = false
        try {
            for (input in inputs) inputList += input
            require(inputList.isNotEmpty()) { "AKEN page materialization requires at least one input" }
            artifactCommitment = plan.artifactCanonicalCommitment
            val registeredPages = HashSet<String>()
            inputList.forEach { input ->
                val pageKey = pageKey(input.page)
                require(registeredPages.add(pageKey)) {
                    "AKEN page materialization contains the same registered page more than once"
                }
                drafts += draftFor(plan, input)
            }
            validatePhysicalRouting(drafts)

            mesh = buildMesh(drafts)

            drafts.forEach { draft ->
                val proofLeafEncoding = draft.copyLeafEncoding()
                val proof = try {
                    checkNotNull(mesh).proofFor(proofLeafEncoding)
                        ?: error("AKEN materialization mesh is missing its generated leaf proof")
                } finally {
                    Arrays.fill(proofLeafEncoding, 0)
                }
                val metadata = proofMetadataFor(
                    leafIdentity = draft.leafIdentity,
                    artifactCommitment = checkNotNull(artifactCommitment),
                    proof = proof,
                    callSiteProof = draft.copyCallSiteProof(),
                    codecVariant = draft.codecVariant,
                    layoutVariant = draft.layoutVariant,
                )
                val descriptor = descriptorFor(draft, metadata)
                validateGeneratedBinding(
                    plan = plan,
                    mesh = checkNotNull(mesh),
                    artifactCommitment = checkNotNull(artifactCommitment),
                    draft = draft,
                    descriptor = descriptor,
                    proof = proof,
                )
                val leafEncoding = draft.copyLeafEncoding()
                val key = try {
                    leafKey(leafEncoding)
                } finally {
                    Arrays.fill(leafEncoding, 0)
                }
                val payload = draft.copyEncodedPayload()
                try {
                    check(!outputPages.containsKey(key)) {
                        "AKEN materialization generated a duplicate leaf binding"
                    }
                    outputPages[key] = AkenMaterializedPage.create(descriptor, payload)
                } finally {
                    Arrays.fill(payload, 0)
                }
            }

            val result = AkenPageMaterialization.create(
                artifactCommitment = checkNotNull(artifactCommitment),
                mesh = checkNotNull(mesh),
                pages = outputPages,
            )
            completed = true
            return result
        } finally {
            inputList.forEach { it.wipe() }
            drafts.forEach { it.wipe() }
            artifactCommitment?.let { Arrays.fill(it, 0) }
            // The plan owns the DEKs and generated build graph. It must never
            // survive materialization as a reusable build authority.
            plan.wipe()
            if (!completed) outputPages.values.forEach { it.wipe() }
        }
    }

    private fun draftFor(
        plan: AkenBuildPlan,
        input: AkenPageMaterializationInput,
    ): PageDraft {
        val page = input.page
        val handle = page.handle
        val plaintext = input.copyPlaintextForBuild()
        try {
            val payload = plan.encodeForMaterialization(handle, plaintext)
            try {
                val logicalIdentity = page.logicalIdentity
                try {
                    val leafIdentity = AkenHighValueLeafIdentity.fromHandle(handle, logicalIdentity)
                    val leafEncoding = leafIdentity.encode()
                    try {
                        val callSiteProof = input.copyCallSiteProofForBuild()
                        try {
                            val route = AkenRoutingMetadata.fromHandle(
                                handle = handle,
                                logicalIdentity = logicalIdentity,
                                resourcePath = input.resourcePath,
                                resourceOffset = input.resourceOffset,
                                storedLength = payload.size,
                                codecVariant = page.codecVariant,
                                layoutVariant = page.layoutVariant,
                            )
                            return PageDraft(
                                handle = handle,
                                leafIdentity = leafIdentity,
                                logicalIdentity = logicalIdentity,
                                leafEncoding = leafEncoding,
                                encodedPayload = payload,
                                route = route,
                                targetPageSize = page.targetSize,
                                evaluatorPlan = runtimeEvaluatorPlanFor(page),
                                codecVariant = page.codecVariant,
                                layoutVariant = page.layoutVariant,
                                callSiteProof = callSiteProof,
                            )
                        } finally {
                            Arrays.fill(callSiteProof, 0)
                        }
                    } finally {
                        Arrays.fill(leafEncoding, 0)
                    }
                } finally {
                    Arrays.fill(logicalIdentity, 0)
                }
            } finally {
                Arrays.fill(payload, 0)
            }
        } finally {
            Arrays.fill(plaintext, 0)
        }
    }

    private fun descriptorFor(
        draft: PageDraft,
        metadata: AkenSealingProofMetadata,
    ): AkenRuntimePageDescriptor {
        val logicalIdentity = draft.copyLogicalIdentity()
        return try {
            AkenRuntimePageDescriptor.create(
                handle = draft.handle,
                logicalIdentity = logicalIdentity,
                route = draft.route,
                proof = metadata,
                targetPageSize = draft.targetPageSize,
                evaluatorPlan = draft.evaluatorPlan,
            )
        } finally {
            Arrays.fill(logicalIdentity, 0)
        }
    }

    private fun proofMetadataFor(
        leafIdentity: AkenHighValueLeafIdentity,
        artifactCommitment: ByteArray,
        proof: AkenIntegrityMesh.MerkleProof,
        callSiteProof: ByteArray,
        codecVariant: String,
        layoutVariant: String,
    ): AkenSealingProofMetadata {
        val root = proof.root
        val leaf = proof.leafDigest
        val siblings = proof.siblings
        try {
            return AkenSealingProofMetadata.create(
                leafIdentity = leafIdentity,
                artifactCommitment = artifactCommitment,
                meshRoot = root,
                leafDigest = leaf,
                siblings = siblings,
                siblingIsLeft = proof.siblingIsLeft,
                callSiteProof = callSiteProof,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
            )
        } finally {
            Arrays.fill(callSiteProof, 0)
            Arrays.fill(root, 0)
            Arrays.fill(leaf, 0)
            siblings.forEach { Arrays.fill(it, 0) }
        }
    }

    private fun validateGeneratedBinding(
        plan: AkenBuildPlan,
        mesh: AkenIntegrityMesh,
        artifactCommitment: ByteArray,
        draft: PageDraft,
        descriptor: AkenRuntimePageDescriptor,
        proof: AkenIntegrityMesh.MerkleProof,
    ) {
        val leafEncoding = draft.copyLeafEncoding()
        val payload = draft.copyEncodedPayload()
        val draftLogicalIdentity = draft.copyLogicalIdentity()
        val descriptorLogicalIdentity = descriptor.logicalIdentity
        val descriptorHandle = descriptor.handle
        val route = descriptor.route
        val descriptorProof = descriptor.proof
        val proofCommitment = descriptorProof.artifactCanonicalCommitment
        val descriptorCallSiteProof = descriptorProof.callSiteProof
        val expectedCallSiteProof = draft.copyCallSiteProof()
        val evaluatorPlan = descriptor.evaluatorPlan
        val evaluatorFingerprint = evaluatorPlan.fingerprint
        val routeFingerprint = route.evaluatorFingerprint
        val routeHandleEncoding = route.handleEncoding
        val routeLocatorToken = route.locatorToken
        try {
            require(MessageDigest.isEqual(descriptorLogicalIdentity, draftLogicalIdentity)) {
                "AKEN materialized descriptor does not bind the logical identity used for AEAD"
            }
            require(route.leafIdentity == draft.leafIdentity) {
                "AKEN materialized route does not bind the current leaf"
            }
            require(descriptorProof.leafIdentity == draft.leafIdentity) {
                "AKEN materialized proof does not bind the current leaf"
            }
            require(
                route.resourcePath == draft.route.resourcePath &&
                    route.resourceOffset == draft.route.resourceOffset &&
                    route.storedLength == draft.route.storedLength,
            ) {
                "AKEN materialized descriptor route does not bind the emitted payload range"
            }
            require(route.codecVariant == draft.codecVariant && route.layoutVariant == draft.layoutVariant) {
                "AKEN materialized route variants do not match the AEAD page context"
            }
            require(
                descriptorProof.codecVariant == draft.codecVariant &&
                    descriptorProof.layoutVariant == draft.layoutVariant,
            ) {
                "AKEN materialized proof variants do not match the AEAD page context"
            }
            require(MessageDigest.isEqual(descriptorCallSiteProof, expectedCallSiteProof)) {
                "AKEN materialized proof does not bind the generated call-site proof"
            }
            require(
                descriptor.matches(draft.handle) &&
                    descriptor.matches(descriptorHandle) &&
                    route.matches(draft.handle),
            ) {
                "AKEN materialized descriptor does not bind the generated handle"
            }
            require(MessageDigest.isEqual(proofCommitment, artifactCommitment)) {
                "AKEN materialized proof commitment does not match the build plan"
            }
            require(MessageDigest.isEqual(evaluatorFingerprint, routeFingerprint)) {
                "AKEN materialized evaluator fingerprint does not match the routed page"
            }
            require(
                evaluatorPlan.matchesPageBinding(
                    resourceKind = route.resourceKind,
                    logicalIdentity = descriptorLogicalIdentity,
                    pageIndex = route.pageIndex,
                    targetPageSize = descriptor.targetPageSize,
                    codecVariant = route.codecVariant,
                    layoutVariant = route.layoutVariant,
                    handleEncoding = routeHandleEncoding,
                    locatorToken = routeLocatorToken,
                ),
            ) {
                "AKEN materialized evaluator graph does not match the route/AAD binding"
            }
            require(proofMatchesExpectedMesh(descriptorProof, draft.leafIdentity, artifactCommitment, proof)) {
                "AKEN materialized descriptor proof does not match the generated Merkle path"
            }
            require(plan.verifyEncodedPayloadForMaterialization(draft.handle, payload)) {
                "AKEN materialized payload did not authenticate against its page-local AEAD binding"
            }
            require(mesh.verify(proof, leafEncoding, payload)) {
                "AKEN materialized payload did not verify against its full-payload Merkle proof"
            }
        } finally {
            Arrays.fill(leafEncoding, 0)
            Arrays.fill(payload, 0)
            Arrays.fill(draftLogicalIdentity, 0)
            Arrays.fill(descriptorLogicalIdentity, 0)
            Arrays.fill(proofCommitment, 0)
            Arrays.fill(descriptorCallSiteProof, 0)
            Arrays.fill(expectedCallSiteProof, 0)
            Arrays.fill(evaluatorFingerprint, 0)
            Arrays.fill(routeFingerprint, 0)
            Arrays.fill(routeHandleEncoding, 0)
            Arrays.fill(routeLocatorToken, 0)
            descriptorHandle.wipe()
        }
    }

    /**
     * This is build-only layout validation, not a runtime directory.  A single
     * physical entry may hold several pages, but two page payload byte ranges
     * must never collide or overlap inside that entry.
     */
    private fun validatePhysicalRouting(drafts: List<PageDraft>) {
        val ranges = ArrayList<PhysicalRange>(drafts.size)
        drafts.forEach { draft ->
            val payload = draft.copyEncodedPayload()
            try {
                val route = draft.route
                require(route.storedLength == payload.size) {
                    "AKEN materialized route length does not match its encrypted payload"
                }
                ranges += PhysicalRange(
                    resourcePath = route.resourcePath,
                    resourceOffset = route.resourceOffset,
                    endExclusive = route.resourceOffset.toLong() + route.storedLength.toLong(),
                )
            } finally {
                Arrays.fill(payload, 0)
            }
        }

        ranges.sortWith(compareBy<PhysicalRange> { it.resourcePath }.thenBy { it.resourceOffset }.thenBy { it.endExclusive })
        var previous: PhysicalRange? = null
        ranges.forEach { current ->
            val prior = previous
            if (prior != null && prior.resourcePath == current.resourcePath) {
                require(current.resourceOffset.toLong() >= prior.endExclusive) {
                    "AKEN materialized routes overlap in physical resource '${current.resourcePath}'"
                }
            }
            previous = current
        }
    }

    private fun buildMesh(drafts: List<PageDraft>): AkenIntegrityMesh {
        val leaves = ArrayList<AkenIntegrityMesh.Leaf>(drafts.size)
        try {
            drafts.forEach { draft ->
                val leafEncoding = draft.copyLeafEncoding()
                val payload = draft.copyEncodedPayload()
                try {
                    leaves += AkenIntegrityMesh.Leaf(leafEncoding, payload)
                } finally {
                    Arrays.fill(leafEncoding, 0)
                    Arrays.fill(payload, 0)
                }
            }
            return AkenIntegrityMesh.build(leaves)
        } finally {
            // Leaf values are only construction intermediates for the mesh. The
            // mesh itself retains digests/proofs, not plaintext or a DEK.
            leaves.clear()
        }
    }

    private fun runtimeEvaluatorPlanFor(page: AkenBuildPlan.Page): AkenRuntimeEvaluatorPlan {
        val evaluator = page.evaluatorPlan
        val fingerprint = evaluator.fingerprint
        return try {
            AkenRuntimeEvaluatorPlan.create(
                javaFragments = evaluator.javaFragments.map { fragment ->
                    runtimeFragment(AkenRuntimeEvaluatorRole.Java, fragment)
                },
                nativeFragments = evaluator.nativeFragments.map { fragment ->
                    runtimeFragment(AkenRuntimeEvaluatorRole.Native, fragment)
                },
                terminal = runtimeFragment(AkenRuntimeEvaluatorRole.Terminal, evaluator.terminal),
                fingerprint = fingerprint,
            )
        } finally {
            Arrays.fill(fingerprint, 0)
        }
    }

    private fun runtimeFragment(
        role: AkenRuntimeEvaluatorRole,
        fragment: AkenBuildPlan.EvaluatorFragment,
    ): AkenRuntimeEvaluatorFragment {
        val shape = fragment.shape
        val callToken = fragment.callToken
        val tablePermutation = fragment.tablePermutation
        return try {
            AkenRuntimeEvaluatorFragment.create(
                role = role,
                ordinal = fragment.ordinal,
                family = fragment.family,
                shape = shape,
                callToken = callToken,
                tablePermutation = tablePermutation,
            )
        } finally {
            Arrays.fill(shape, 0)
            Arrays.fill(callToken, 0)
            Arrays.fill(tablePermutation, 0)
        }
    }

    private fun pageKey(page: AkenBuildPlan.Page): String {
        val encoded = page.handle.encoded
        return try {
            Base64.getUrlEncoder().withoutPadding().encodeToString(encoded)
        } finally {
            Arrays.fill(encoded, 0)
        }
    }

    private class PageDraft(
        val handle: AkenHandle,
        val leafIdentity: AkenHighValueLeafIdentity,
        logicalIdentity: ByteArray,
        leafEncoding: ByteArray,
        encodedPayload: ByteArray,
        val route: AkenRoutingMetadata,
        val targetPageSize: Int,
        val evaluatorPlan: AkenRuntimeEvaluatorPlan,
        val codecVariant: String,
        val layoutVariant: String,
        callSiteProof: ByteArray,
    ) {
        private var logicalIdentityValue = logicalIdentity.copyOf()
        private var leafEncodingValue = leafEncoding.copyOf()
        private var encodedPayloadValue = encodedPayload.copyOf()
        private var callSiteProofValue = callSiteProof.copyOf()

        fun copyLogicalIdentity(): ByteArray = logicalIdentityValue.copyOf()

        fun copyLeafEncoding(): ByteArray = leafEncodingValue.copyOf()

        fun copyEncodedPayload(): ByteArray = encodedPayloadValue.copyOf()

        fun copyCallSiteProof(): ByteArray = callSiteProofValue.copyOf()

        fun wipe() {
            Arrays.fill(logicalIdentityValue, 0)
            Arrays.fill(leafEncodingValue, 0)
            Arrays.fill(encodedPayloadValue, 0)
            Arrays.fill(callSiteProofValue, 0)
            logicalIdentityValue = ByteArray(0)
            leafEncodingValue = ByteArray(0)
            encodedPayloadValue = ByteArray(0)
            callSiteProofValue = ByteArray(0)
        }
    }

    private data class PhysicalRange(
        val resourcePath: String,
        val resourceOffset: Int,
        val endExclusive: Long,
    )
}

private fun leafKey(leafEncoding: ByteArray): String =
    Base64.getUrlEncoder().withoutPadding().encodeToString(leafEncoding)

/**
 * Compare a serializable page proof with the exact build-only Merkle proof
 * without retaining any of its defensive-copy byte arrays.  Both construction
 * and later writer verification use this same comparison so descriptor proof
 * metadata cannot drift away from the payload mesh.
 */
private fun proofMatchesExpectedMesh(
    proof: AkenSealingProofMetadata,
    identity: AkenHighValueLeafIdentity,
    artifactCommitment: ByteArray,
    expected: AkenIntegrityMesh.MerkleProof,
): Boolean {
    if (proof.leafIdentity != identity) return false
    val proofCommitment = proof.artifactCanonicalCommitment
    val proofRoot = proof.merkleRoot
    val proofLeaf = proof.currentLeafDigest
    val expectedRoot = expected.root
    val expectedLeaf = expected.leafDigest
    val proofSiblings = proof.siblingDigests
    val expectedSiblings = expected.siblings
    try {
        if (!MessageDigest.isEqual(proofCommitment, artifactCommitment)) return false
        if (!MessageDigest.isEqual(proofRoot, expectedRoot)) return false
        if (!MessageDigest.isEqual(proofLeaf, expectedLeaf)) return false

        val directions = proof.siblingDirections
        val expectedDirections = expected.siblingIsLeft
        if (proofSiblings.size != expectedSiblings.size || directions != expectedDirections) return false
        return proofSiblings.indices.all { index ->
            MessageDigest.isEqual(proofSiblings[index], expectedSiblings[index])
        }
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
