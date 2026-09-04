package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.protection.concatBytes
import io.github.hht0rro.javashroud.transforms.protection.hkdfSha256
import io.github.hht0rro.javashroud.transforms.protection.qp.NativeVmSecretPack
import io.github.hht0rro.javashroud.transforms.protection.qp.NativeVmSecretPackDraft
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassPageCandidate
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassPageDescriptorSource
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassRouteAllocator
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassRouteReservation
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassRouteCandidateRef
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeSegmentCandidate
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeRouteAllocator
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeRouteReservation
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeRouteCandidateRef
import io.github.hht0rro.javashroud.transforms.protection.qp.QpTextPageCandidate
import io.github.hht0rro.javashroud.transforms.protection.qp.QpTextRouteAllocator
import io.github.hht0rro.javashroud.transforms.protection.qp.QpTextRouteReservation
import io.github.hht0rro.javashroud.transforms.protection.qp.QpTextRouteCandidateRef
import io.github.hht0rro.javashroud.transforms.protection.qp.QpFinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.qp.QpMethodCandidate
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPreSealRouteAllocator
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPreSealRouteReservation
import io.github.hht0rro.javashroud.transforms.protection.qp.QpRouteCandidateRef
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Shared Qp VM build context for one obfuscation run.
 *
 * Method resources are serialized before the native microkernel is recompiled,
 * so both phases must derive the same build-local root key from the same run
 * context. Root material is never kept as a repository or generated-native
 * constant; it stays build-local and is materialized only through the current
 * artifact-specific runtime binding flow.
 */
internal data class QpBuildContext(
    val masterKey: ByteArray,
    val nativeSeed: Long,
    val jarLayoutDigest: ByteArray,
    val runtimeResourceKey: ByteArray = generateRuntimeResourceKey(masterKey, jarLayoutDigest, nativeSeed),
    val runtimeKeyPartitions: RuntimeKeyPartitions = RuntimeKeyPartitions.generate(),
    val nativeVmProfile: NativeVmBuildProfile = NativeVmBuildProfile.fromBuildMaterial(nativeSeed, jarLayoutDigest),
    val productionBuildEvidence: CandidateProductionBuildEvidence = CandidateProductionBuildEvidence.disabled(nativeVmProfile),
    val maxHardening: Boolean = false,
    val nameSeed: ByteArray = ByteArray(io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.NAME_SEED_SIZE).also { java.security.SecureRandom().nextBytes(it) },
) {
    private var signedDebugMapDraft: io.github.hht0rro.javashroud.transforms.protection.hardening.SignedDebugMap.Draft? = null
    private val nativeSpecializationDigests = LinkedHashMap<String, ByteArray>()
    /** Build-only current-format Qp page/evaluator plan; never serialized into runtime output. */
    private var qpBuildPlan: QpBuildPlan? = null
    /**
     * Build-only native VM secret pack. Slot seeds feed the artifact-specific
     * specialization source only; they are never serialized into a descriptor,
     * catalog, or resource and never copied across scopes.
     */
    private var nativeVmSecretPackDraft: NativeVmSecretPackDraft? = null
    /**
     * Build-only Qp VM method snapshots captured by the current transform.
     * These are logical sources for a later page planner, not final routes,
     * descriptors, native records, or a runtime catalog.
     */
    private val qpMethodCandidates = LinkedHashMap<Long, QpMethodCandidate>()
    /**
     * Build-only pre-seal Qp VM layout. It owns final page geometry and native
     * current-page compiler records until recompilation/final sealing consumes
     * them; it is not a runtime page directory.
     */
    private var qpFinalizationLayout: QpFinalizationLayout? = null
    /** Build-only future container routes reserved before native recompilation. */
    private var qpPreSealRouteReservation: QpPreSealRouteReservation? = null
    /**
     * Build-only StringPage candidates captured after generated bootstraps
     * receive their own handle/proof bindings but before sealing chooses final
     * resource names. This is never copied into a scoped runtime context.
     */
    private val qpTextPageCandidates = LinkedHashMap<String, QpTextPageCandidate>()
    /** Build-only final StringPage routes reserved before page materialization. */
    private var qpTextRouteReservation: QpTextRouteReservation? = null
    /**
     * Build-only encrypted ClassPage candidates captured before sealing assigns
     * their final resource paths. They never enter scoped runtime contexts or
     * expose a build-wide class-page directory.
     */
    private val qpClassPageCandidates = LinkedHashMap<String, QpClassPageCandidate>()
    /**
     * Build-only class-local identity map used after page materialization to
     * construct one descriptor per encrypted class. It owns neither class
     * plaintext nor a final handle/proof and is never projected into runtime.
     */
    private val qpClassPageDescriptorSources =
        LinkedHashMap<String, List<QpClassPageDescriptorSource>>()
    /** Build-only final ClassPage routes reserved before page materialization. */
    private var qpClassRouteReservation: QpClassRouteReservation? = null
    /**
     * Build-only native shell/handler chunk sources captured before sealing
     * assigns final paths. They are never copied into a scoped runtime context
     * and do not expose a native payload catalog.
     */
    private val qpNativeSegmentCandidates = LinkedHashMap<String, QpNativeSegmentCandidate>()
    /** Build-only final NativeChunk routes reserved before page materialization. */
    private var qpNativeRouteReservation: QpNativeRouteReservation? = null

    init {
        require(nameSeed.size == io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.NAME_SEED_SIZE) { "nameSeed must be 16 bytes" }
        require(masterKey.size == QP_MASTER_KEY_SIZE) { "Qp VM master key must be 32 bytes" }
        require(jarLayoutDigest.size == QP_LAYOUT_DIGEST_SIZE) { "Qp VM layout digest must be 32 bytes" }
        require(runtimeResourceKey.size == QP_RUNTIME_RESOURCE_KEY_SIZE) { "Qp VM runtime resource key must be 32 bytes" }
    }

    fun copyMasterKey(): ByteArray = masterKey.copyOf()
    fun copyRuntimeResourceKey(): ByteArray = runtimeResourceKey.copyOf()
    fun copyNameSeed(): ByteArray = nameSeed.copyOf()
    fun publishSignedDebugMapDraft(draft: io.github.hht0rro.javashroud.transforms.protection.hardening.SignedDebugMap.Draft) {
        signedDebugMapDraft = draft
    }

    fun signedDebugMapDraftOrNull(): io.github.hht0rro.javashroud.transforms.protection.hardening.SignedDebugMap.Draft? =
        signedDebugMapDraft

    @Synchronized
    fun publishNativeSpecializationDigests(digests: Map<String, ByteArray>) {
        require(digests.isNotEmpty()) { "native specialization digest map must not be empty" }
        nativeSpecializationDigests.values.forEach { java.util.Arrays.fill(it, 0) }
        nativeSpecializationDigests.clear()
        for ((platform, digest) in digests) {
            require(digest.size == 32) { "native specialization digest must be 32 bytes" }
            require(digest.any { it != 0.toByte() }) { "native specialization digest must not be all-zero" }
            nativeSpecializationDigests[platform] = digest.copyOf()
        }
    }

    @Synchronized
    fun copyNativeSpecializationDigest(platform: String): ByteArray {
        val digest = nativeSpecializationDigests[platform]
            ?: error("native specialization digest for $platform is not published")
        if (digest.size != 32 || digest.all { it == 0.toByte() }) {
            error("native specialization digest for $platform is wiped")
        }
        return digest.copyOf()
    }

    private val nativeSealedPackBlobs = LinkedHashMap<String, ByteArray>()

    /** Sealed per-platform secret-pack blobs produced by the native compiler pass. */
    @Synchronized
    fun publishNativeSealedPackBlobs(blobs: Map<String, ByteArray>) {
        require(blobs.isNotEmpty()) { "sealed secret pack blob map must not be empty" }
        nativeSealedPackBlobs.values.forEach { java.util.Arrays.fill(it, 0) }
        nativeSealedPackBlobs.clear()
        frozenPackCryptoDomain?.let { java.util.Arrays.fill(it, 0) }
        frozenPackCryptoDomain = null
        for ((platform, blob) in blobs) {
            require(blob.isNotEmpty()) { "sealed secret pack blob for $platform is empty" }
            nativeSealedPackBlobs[platform] = blob.copyOf()
        }
    }

    @Synchronized
    fun copyNativeSealedPackBlob(platform: String): ByteArray {
        val blob = nativeSealedPackBlobs[platform]
            ?: error("sealed secret pack blob for $platform is not published")
        return blob.copyOf()
    }

    @Synchronized
    fun nativeSealedPackPlatforms(): Set<String> = nativeSealedPackBlobs.keys.toSet()

    /**
     * Return the scoped current-format Qp plan, creating it lazily from the artifact
     * commitment. The plan is build-only and is wiped with this context.
     *
     * A build context may represent only one canonical artifact. Reusing a live
     * plan with a different commitment would make pages authenticate against an
     * unrelated artifact representation, so reject it immediately instead of
     * deferring the mismatch to the final writer verification.
     */
    @Synchronized
    fun initializeQpBuildPlan(commitment: ByteArray): QpBuildPlan {
        require(commitment.size == QP_LAYOUT_DIGEST_SIZE) { "Qp artifact commitment must be 32 bytes" }
        val existing = qpBuildPlan
        if (existing != null && !existing.isWiped()) {
            val plannedCommitment = existing.artifactCanonicalCommitment
            try {
                require(java.security.MessageDigest.isEqual(plannedCommitment, commitment)) {
                    "Qp current-format build plan is already bound to a different artifact commitment"
                }
            } finally {
                java.util.Arrays.fill(plannedCommitment, 0)
            }
            return existing
        }
        return QpBuildPlan.create(commitment = commitment, secretPack = requireNativeVmSecretPackDraft())
            .also { qpBuildPlan = it }
    }

    /** Build-only secret-pack authority; created on first use, wiped with this context. */
    @Synchronized
    /** Whether this build carries a native secret-pack draft (survives plan wipe). */
    fun hasNativeVmSecretPackDraft(): Boolean = nativeVmSecretPackDraft != null

    @Volatile
    private var frozenPackCryptoDomain: ByteArray? = null

    /**
     * Freezes the pack crypto domain on first use. The layout-derived domain
     * drifts while pages reserve layout; every consumer that must agree with
     * the sealed pack (entry-token seals, bindings seal, directory seal, and
     * the pack plaintext itself) reads this frozen copy instead.
     */
    @Synchronized
    fun freezeOrCopyPackCryptoDomain(): ByteArray {
        frozenPackCryptoDomain?.let { return it.copyOf() }
        val fresh = io.github.hht0rro.javashroud.transforms.protection.QpInnerMaterial
            .copyCryptoDomainMaterial(this)
        frozenPackCryptoDomain = fresh.copyOf()
        return fresh
    }

    @Synchronized
    fun copyFrozenPackCryptoDomainOrNull(): ByteArray? = frozenPackCryptoDomain?.copyOf()

    fun requireNativeVmSecretPackDraft(): NativeVmSecretPackDraft {
        val existing = nativeVmSecretPackDraft
        if (existing != null) {
            return existing
        }
        val ikm = deriveSubKey("javashroud-qp-native-secret-pack-ikm-v4", QP_MASTER_KEY_SIZE)
        return try {
            NativeVmSecretPackDraft.create(NativeVmSecretPackDraft.Companion.derivePackRoot(ikm))
        } finally {
            java.util.Arrays.fill(ikm, 0)
        }.also { nativeVmSecretPackDraft = it }
    }

    /** One sealed copy for the specialization writer; the caller must wipe it. */
    @Synchronized
    fun withNativeVmSecretPackForSpecialization(block: (NativeVmSecretPack) -> Unit) {
        val draft = requireNativeVmSecretPackDraft()
        val sealed = draft.sealedCopyForSpecialization()
        try {
            block(sealed)
        } finally {
            sealed.wipe()
        }
    }

    @Synchronized
    fun qpBuildPlanOrNull(): QpBuildPlan? = qpBuildPlan?.takeUnless { it.isWiped() }

    @Synchronized
    fun requireQpBuildPlan(): QpBuildPlan = qpBuildPlanOrNull()
        ?: error("Qp current-format build plan is not initialized")

    /**
     * Atomically snapshots real Qp VM method programs for a later Qp page
     * planner. Callers retain ownership of [candidates]; this context copies
     * them and never exposes its internal instances to a callback.
     *
     * Candidates must be registered before an Qp build plan exists. A plan is
     * bound to final artifact material, whereas candidates still carry only
     * logical method inputs and must not be mistaken for finalized page state.
     */
    @Synchronized
    fun registerQpMethodCandidates(candidates: Iterable<QpMethodCandidate>) {
        require(qpBuildPlan?.isWiped() != false) {
            "Qp current-format method candidates must be registered before page-plan initialization"
        }
        require(qpFinalizationLayout?.isWiped != false) {
            "Qp current-format method candidates cannot be registered after finalization layout publication"
        }
        val incoming = candidates.toList()
        require(incoming.isNotEmpty()) { "Qp current-format method candidate batch must not be empty" }
        require(incoming.none { it.isWiped }) { "cannot register a wiped Qp current-format method candidate" }

        val incomingTokens = incoming.map { it.entryToken }
        require(incomingTokens.distinct().size == incomingTokens.size) {
            "Qp current-format method candidate batch contains duplicate entry tokens"
        }
        val incomingPaths = incoming.map { it.logicalMethod.logicalVmResourcePath }
        require(incomingPaths.distinct().size == incomingPaths.size) {
            "Qp current-format method candidate batch contains duplicate logical resource paths"
        }
        require(incomingTokens.none { it in qpMethodCandidates }) {
            "Qp current-format method candidate entry token is already registered"
        }
        require(incomingPaths.none { path -> qpMethodCandidates.values.any { it.logicalMethod.logicalVmResourcePath == path } }) {
            "Qp current-format method candidate logical resource path is already registered"
        }

        val snapshots = ArrayList<QpMethodCandidate>(incoming.size)
        try {
            incoming.forEach { candidate -> snapshots += candidate.copyForBuild() }
            snapshots.forEach { candidate ->
                check(qpMethodCandidates.put(candidate.entryToken, candidate) == null) {
                    "Qp current-format method candidate entry token is already registered"
                }
            }
        } catch (error: Throwable) {
            snapshots.forEach { candidate ->
                if (qpMethodCandidates[candidate.entryToken] === candidate) {
                    qpMethodCandidates.remove(candidate.entryToken)
                }
                candidate.wipe()
            }
            throw error
        }
    }

    /**
     * Gives a later build-only planner deep candidate copies. The copies are
     * invalidated and wiped immediately after [block] returns; runtime code
     * never receives this collection or an arbitrary resource lookup API.
     */
    fun <T> withQpMethodCandidatesForBuild(block: (List<QpMethodCandidate>) -> T): T {
        val snapshots = synchronized(this) {
            check(qpMethodCandidates.isNotEmpty()) { "Qp current-format method candidates are not initialized" }
            qpMethodCandidates.values.map { it.copyForBuild() }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { it.wipe() }
        }
    }

    /**
     * Gives the pre-seal routing stage a scoped projection of registered Qp VM
     * candidates. The projection contains only the entry token and logical VM
     * resource path, never the serialized program or another planner input.
     */
    fun <T> withQpRouteCandidateRefsForBuild(
        block: (List<QpRouteCandidateRef>) -> T,
    ): T {
        val snapshots = synchronized(this) {
            check(qpBuildPlan?.isWiped() != false) {
                "Qp current-format route candidates must be projected before page-plan initialization"
            }
            check(qpFinalizationLayout?.isWiped != false) {
                "Qp current-format route candidates cannot be projected after finalization layout publication"
            }
            check(qpMethodCandidates.isNotEmpty()) { "Qp current-format method candidates are not initialized" }
            qpMethodCandidates.values
                .sortedBy { candidate -> candidate.entryToken }
                .map { candidate ->
                    QpRouteCandidateRef.create(
                        entryToken = candidate.entryToken,
                        logicalVmResourcePath = candidate.logicalMethod.logicalVmResourcePath,
                    )
                }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { candidate -> candidate.wipe() }
        }
    }

    /**
     * Reserves the future page-container namespace for the registered Qp VM
     * methods. The reservation is build-only and is owned by this context until
     * the context is wiped; callers must not retain or wipe the returned owner.
     *
     * The allocator receives only scoped route candidate references, never the
     * serialized method program, page plaintext, evaluator state, or key
     * material. A context may publish at most one reservation.
     */
    @Synchronized
    fun reserveQpPreSealRoutes(
        occupiedEntryPaths: Set<String>,
        allocator: QpPreSealRouteAllocator,
    ): QpPreSealRouteReservation {
        require(qpBuildPlan?.isWiped() != false) {
            "Qp current-format pre-seal routes must be reserved before page-plan initialization"
        }
        require(qpFinalizationLayout?.isWiped != false) {
            "Qp current-format pre-seal routes cannot be reserved after finalization layout publication"
        }
        check(qpMethodCandidates.isNotEmpty()) {
            "Qp current-format method candidates are not initialized"
        }
        val existing = qpPreSealRouteReservation
        require(existing == null || existing.isWiped) {
            "Qp current-format pre-seal route reservation is already published"
        }
        val reservation = withQpRouteCandidateRefsForBuild { refs ->
            QpPreSealRouteReservation.reserve(
                candidateRefs = refs,
                occupiedEntryPaths = occupiedEntryPaths,
                allocator = allocator,
            )
        }
        qpPreSealRouteReservation = reservation
        return reservation
    }

    @Synchronized
    fun qpPreSealRouteReservationOrNull(): QpPreSealRouteReservation? =
        qpPreSealRouteReservation?.takeUnless { it.isWiped }

    @Synchronized
    fun requireQpPreSealRouteReservation(): QpPreSealRouteReservation =
        qpPreSealRouteReservation
            ?.takeUnless { it.isWiped }
            ?: error("Qp current-format pre-seal route reservation is not initialized")

    @Synchronized
    fun hasQpMethodCandidates(): Boolean = qpMethodCandidates.isNotEmpty()

    /**
     * Atomically snapshots StringPage sources for later pre-seal routing and
     * materialization. The context retains private copies only; generated
     * bytecode, runtime helpers, and scoped build copies do not receive this
     * plaintext collection or an enumerating lookup API.
     */
    @Synchronized
    fun registerQpTextPageCandidates(candidates: Iterable<QpTextPageCandidate>) {
        require(qpBuildPlan?.isWiped() != false) {
            "Qp StringPage candidates must be registered before page-plan initialization"
        }
        require(qpFinalizationLayout?.isWiped != false) {
            "Qp StringPage candidates cannot be registered after finalization layout publication"
        }
        val reservation = qpTextRouteReservation
        require(reservation == null || reservation.isWiped) {
            "Qp StringPage candidates cannot be registered after pre-seal route reservation"
        }
        val incoming = candidates.toList()
        require(incoming.isNotEmpty()) { "Qp StringPage candidate batch must not be empty" }
        require(incoming.none { it.isWiped }) { "cannot register a wiped Qp StringPage candidate" }

        val incomingKeys = incoming.map { it.identityPageKeyForBuild() }
        require(incomingKeys.distinct().size == incomingKeys.size) {
            "Qp StringPage candidate batch contains duplicate logical page identities"
        }
        require(incomingKeys.none { it in qpTextPageCandidates }) {
            "Qp StringPage candidate logical page identity is already registered"
        }

        val snapshots = ArrayList<Pair<String, QpTextPageCandidate>>(incoming.size)
        try {
            incoming.forEach { candidate ->
                snapshots += candidate.identityPageKeyForBuild() to candidate.copyForBuild()
            }
            snapshots.forEach { (identityPageKey, candidate) ->
                check(qpTextPageCandidates.put(identityPageKey, candidate) == null) {
                    "Qp StringPage candidate logical page identity is already registered"
                }
            }
        } catch (error: Throwable) {
            snapshots.forEach { (identityPageKey, candidate) ->
                if (qpTextPageCandidates[identityPageKey] === candidate) {
                    qpTextPageCandidates.remove(identityPageKey)
                }
                candidate.wipe()
            }
            throw error
        }
    }

    /**
     * Supplies deep, scoped StringPage candidate copies to the later
     * materializer. Every callback copy is wiped as the scope closes.
     */
    fun <T> withQpTextPageCandidatesForBuild(block: (List<QpTextPageCandidate>) -> T): T {
        val snapshots = synchronized(this) {
            check(qpTextPageCandidates.isNotEmpty()) { "Qp StringPage candidates are not initialized" }
            qpTextPageCandidates.values
                .sortedBy { it.identityPageKeyForBuild() }
                .map { it.copyForBuild() }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { it.wipe() }
        }
    }

    /**
     * Supplies sealing only the logical-page route key and logical binding
     * path. The projection excludes UTF-8 plaintext, handle bytes, proof,
     * layout data, and all evaluator inputs.
     */
    fun <T> withQpTextRouteCandidateRefsForBuild(
        block: (List<QpTextRouteCandidateRef>) -> T,
    ): T {
        val snapshots = synchronized(this) {
            check(qpBuildPlan?.isWiped() != false) {
                "Qp StringPage route candidates must be projected before page-plan initialization"
            }
            check(qpFinalizationLayout?.isWiped != false) {
                "Qp StringPage route candidates cannot be projected after finalization layout publication"
            }
            check(qpTextPageCandidates.isNotEmpty()) { "Qp StringPage candidates are not initialized" }
            qpTextPageCandidates.values
                .sortedBy { it.identityPageKeyForBuild() }
                .map { candidate ->
                    QpTextRouteCandidateRef.create(
                        identityPageKey = candidate.identityPageKeyForBuild(),
                        logicalBindingPath = candidate.logicalBindingPath,
                    )
                }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { it.wipe() }
        }
    }

    /**
     * Reserves one future resource path per registered StringPage. The route
     * reservation stays build-only and may be created only once before the
     * common Qp page plan is initialized.
     */
    @Synchronized
    fun reserveQpTextRoutes(
        occupiedEntryPaths: Set<String>,
        allocator: QpTextRouteAllocator,
    ): QpTextRouteReservation {
        require(qpBuildPlan?.isWiped() != false) {
            "Qp StringPage pre-seal routes must be reserved before page-plan initialization"
        }
        require(qpFinalizationLayout?.isWiped != false) {
            "Qp StringPage pre-seal routes cannot be reserved after finalization layout publication"
        }
        check(qpTextPageCandidates.isNotEmpty()) {
            "Qp StringPage candidates are not initialized"
        }
        val existing = qpTextRouteReservation
        require(existing == null || existing.isWiped) {
            "Qp StringPage pre-seal route reservation is already published"
        }
        val created = withQpTextRouteCandidateRefsForBuild { refs ->
            QpTextRouteReservation.reserve(
                candidateRefs = refs,
                occupiedEntryPaths = occupiedEntryPaths,
                allocator = allocator,
            )
        }
        qpTextRouteReservation = created
        return created
    }

    @Synchronized
    fun qpTextRouteReservationOrNull(): QpTextRouteReservation? =
        qpTextRouteReservation?.takeUnless { it.isWiped }

    @Synchronized
    fun requireQpTextRouteReservation(): QpTextRouteReservation =
        qpTextRouteReservation
            ?.takeUnless { it.isWiped }
            ?: error("Qp StringPage pre-seal route reservation is not initialized")

    @Synchronized
    fun hasQpTextPageCandidates(): Boolean = qpTextPageCandidates.isNotEmpty()


    /**
     * Atomically snapshots encrypted ClassPage sources for later pre-seal
     * routing and materialization. The context retains private copies only;
     * generated stubs and runtime helpers never receive this plaintext
     * collection or an enumerating lookup API.
     */
    @Synchronized
    fun registerQpClassPageCandidates(candidates: Iterable<QpClassPageCandidate>) {
        registerQpClassPageCandidatesInternal(
            internalName = null,
            candidates = candidates,
        )
    }

    /**
     * Registers every page for one encrypted class as an atomic build-only
     * batch. The class-local source map carries only logical identity and page
     * topology, so a later finalization callback can create exactly one
     * descriptor without turning the runtime into a catalog.
     */
    @Synchronized
    fun registerQpClassPageCandidatesForClass(
        internalName: String,
        candidates: Iterable<QpClassPageCandidate>,
    ) {
        registerQpClassPageCandidatesInternal(
            internalName = internalName,
            candidates = candidates,
        )
    }

    private fun registerQpClassPageCandidatesInternal(
        internalName: String?,
        candidates: Iterable<QpClassPageCandidate>,
    ) {
        require(qpBuildPlan?.isWiped() != false) {
            "Qp ClassPage candidates must be registered before page-plan initialization"
        }
        require(qpFinalizationLayout?.isWiped != false) {
            "Qp ClassPage candidates cannot be registered after finalization layout publication"
        }
        val reservation = qpClassRouteReservation
        require(reservation == null || reservation.isWiped) {
            "Qp ClassPage candidates cannot be registered after pre-seal route reservation"
        }
        val incoming = candidates.toList()
        require(incoming.isNotEmpty()) { "Qp ClassPage candidate batch must not be empty" }
        require(incoming.none { it.isWiped }) { "cannot register a wiped Qp ClassPage candidate" }

        val incomingKeys = incoming.map { it.identityPageKeyForBuild() }
        require(incomingKeys.distinct().size == incomingKeys.size) {
            "Qp ClassPage candidate batch contains duplicate logical page identities"
        }
        require(incomingKeys.none { it in qpClassPageCandidates }) {
            "Qp ClassPage candidate logical page identity is already registered"
        }

        val snapshots = ArrayList<Pair<String, QpClassPageCandidate>>(incoming.size)
        var descriptorSources: List<QpClassPageDescriptorSource>? = null
        var sourcesTransferred = false
        try {
            descriptorSources = internalName?.let { name ->
                require(!qpClassPageDescriptorSources.containsKey(name)) {
                    "Qp ClassPage descriptor sources are already registered for $name"
                }
                val sources = incoming
                    .map { candidate -> QpClassPageDescriptorSource.fromCandidate(name, candidate) }
                    .sortedBy { source -> source.pageIndex }
                try {
                    require(sources.map { source -> source.pageIndex } == sources.indices.toList()) {
                        "Qp ClassPage descriptor sources must use contiguous zero-based page indices"
                    }
                    require(
                        sources.map { source -> source.identityPageKeyForBuild() }.toSet() ==
                            incomingKeys.toSet(),
                    ) {
                        "Qp ClassPage descriptor sources drift from registered page candidates"
                    }
                    sources
                } catch (error: Throwable) {
                    sources.forEach { source -> source.wipe() }
                    throw error
                }
            }
            incoming.forEach { candidate ->
                snapshots += candidate.identityPageKeyForBuild() to candidate.copyForBuild()
            }
            snapshots.forEach { (identityPageKey, candidate) ->
                check(qpClassPageCandidates.put(identityPageKey, candidate) == null) {
                    "Qp ClassPage candidate logical page identity is already registered"
                }
            }
            if (internalName != null) {
                check(
                    qpClassPageDescriptorSources.put(
                        internalName,
                        checkNotNull(descriptorSources),
                    ) == null,
                ) {
                    "Qp ClassPage descriptor sources are already registered for $internalName"
                }
                sourcesTransferred = true
            }
        } catch (error: Throwable) {
            snapshots.forEach { (identityPageKey, candidate) ->
                if (qpClassPageCandidates[identityPageKey] === candidate) {
                    qpClassPageCandidates.remove(identityPageKey)
                }
                candidate.wipe()
            }
            if (internalName != null && qpClassPageDescriptorSources[internalName] === descriptorSources) {
                qpClassPageDescriptorSources.remove(internalName)
            }
            throw error
        } finally {
            if (!sourcesTransferred) {
                descriptorSources?.forEach { source -> source.wipe() }
            }
        }
    }

    /** Supplies deep, scoped ClassPage candidate copies to the later materializer. */
    fun <T> withQpClassPageCandidatesForBuild(block: (List<QpClassPageCandidate>) -> T): T {
        val snapshots = synchronized(this) {
            check(qpClassPageCandidates.isNotEmpty()) { "Qp ClassPage candidates are not initialized" }
            qpClassPageCandidates.values
                .sortedBy { it.identityPageKeyForBuild() }
                .map { it.copyForBuild() }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { it.wipe() }
        }
    }

    /**
     * Supplies only class-local logical page identities to the adjacent
     * descriptor emitter. Copies are callback-scoped and wiped before this
     * method returns; no Java runtime helper observes this build-only map.
     */
    fun <T> withQpClassPageDescriptorSourcesForBuild(
        block: (List<QpClassPageDescriptorSource>) -> T,
    ): T {
        val snapshots = synchronized(this) {
            check(qpClassPageDescriptorSources.isNotEmpty()) {
                "Qp ClassPage descriptor sources are not initialized"
            }
            qpClassPageDescriptorSources
                .asSequence()
                .flatMap { (_, sources) -> sources.asSequence() }
                .sortedWith(
                    compareBy<QpClassPageDescriptorSource> { source -> source.internalName }
                        .thenBy { source -> source.pageIndex },
                )
                .map { source -> source.copyForBuild() }
                .toList()
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { source -> source.wipe() }
        }
    }

    /**
     * Supplies sealing only the ClassPage logical identity key and logical
     * binding path; class bytes, handles, proofs, layout, and evaluator inputs
     * remain in build-only owners.
     */
    fun <T> withQpClassRouteCandidateRefsForBuild(
        block: (List<QpClassRouteCandidateRef>) -> T,
    ): T {
        val snapshots = synchronized(this) {
            check(qpBuildPlan?.isWiped() != false) {
                "Qp ClassPage route candidates must be projected before page-plan initialization"
            }
            check(qpFinalizationLayout?.isWiped != false) {
                "Qp ClassPage route candidates cannot be projected after finalization layout publication"
            }
            check(qpClassPageCandidates.isNotEmpty()) { "Qp ClassPage candidates are not initialized" }
            qpClassPageCandidates.values
                .sortedBy { it.identityPageKeyForBuild() }
                .map { candidate ->
                    QpClassRouteCandidateRef.create(
                        identityPageKey = candidate.identityPageKeyForBuild(),
                        logicalBindingPath = candidate.logicalBindingPath,
                    )
                }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { it.wipe() }
        }
    }

    /**
     * Reserves one final physical resource path per registered ClassPage before
     * the common Qp page plan is initialized.
     */
    @Synchronized
    fun reserveQpClassRoutes(
        occupiedEntryPaths: Set<String>,
        allocator: QpClassRouteAllocator,
    ): QpClassRouteReservation {
        require(qpBuildPlan?.isWiped() != false) {
            "Qp ClassPage pre-seal routes must be reserved before page-plan initialization"
        }
        require(qpFinalizationLayout?.isWiped != false) {
            "Qp ClassPage pre-seal routes cannot be reserved after finalization layout publication"
        }
        check(qpClassPageCandidates.isNotEmpty()) {
            "Qp ClassPage candidates are not initialized"
        }
        val existing = qpClassRouteReservation
        require(existing == null || existing.isWiped) {
            "Qp ClassPage pre-seal route reservation is already published"
        }
        val created = withQpClassRouteCandidateRefsForBuild { refs ->
            QpClassRouteReservation.reserve(
                candidateRefs = refs,
                occupiedEntryPaths = occupiedEntryPaths,
                allocator = allocator,
            )
        }
        qpClassRouteReservation = created
        return created
    }

    @Synchronized
    fun qpClassRouteReservationOrNull(): QpClassRouteReservation? =
        qpClassRouteReservation?.takeUnless { it.isWiped }

    @Synchronized
    fun requireQpClassRouteReservation(): QpClassRouteReservation =
        qpClassRouteReservation
            ?.takeUnless { it.isWiped }
            ?: error("Qp ClassPage pre-seal route reservation is not initialized")

    @Synchronized
    fun hasQpClassPageCandidates(): Boolean = qpClassPageCandidates.isNotEmpty()

    @Synchronized
    fun hasQpClassPageDescriptorSources(): Boolean = qpClassPageDescriptorSources.isNotEmpty()

    /**
     * Atomically snapshots native shell/handler chunk sources for later
     * pre-seal routing and materialization. The context retains private copies
     * only; Java runtime helpers receive neither these plaintext chunks nor an
     * enumerating native payload API.
     */
    @Synchronized
    fun registerQpNativeSegmentCandidates(candidates: Iterable<QpNativeSegmentCandidate>) {
        require(qpBuildPlan?.isWiped() != false) {
            "Qp NativeChunk candidates must be registered before page-plan initialization"
        }
        require(qpFinalizationLayout?.isWiped != false) {
            "Qp NativeChunk candidates cannot be registered after finalization layout publication"
        }
        val reservation = qpNativeRouteReservation
        require(reservation == null || reservation.isWiped) {
            "Qp NativeChunk candidates cannot be registered after pre-seal route reservation"
        }
        val incoming = candidates.toList()
        require(incoming.isNotEmpty()) { "Qp NativeChunk candidate batch must not be empty" }
        require(incoming.none { it.isWiped }) { "cannot register a wiped Qp NativeChunk candidate" }

        val incomingKeys = incoming.map { it.identityPageKeyForBuild() }
        require(incomingKeys.distinct().size == incomingKeys.size) {
            "Qp NativeChunk candidate batch contains duplicate logical page identities"
        }
        require(incomingKeys.none { it in qpNativeSegmentCandidates }) {
            "Qp NativeChunk candidate logical page identity is already registered"
        }

        val snapshots = ArrayList<Pair<String, QpNativeSegmentCandidate>>(incoming.size)
        try {
            incoming.forEach { candidate ->
                snapshots += candidate.identityPageKeyForBuild() to candidate.copyForBuild()
            }
            snapshots.forEach { (identityPageKey, candidate) ->
                check(qpNativeSegmentCandidates.put(identityPageKey, candidate) == null) {
                    "Qp NativeChunk candidate logical page identity is already registered"
                }
            }
        } catch (error: Throwable) {
            snapshots.forEach { (identityPageKey, candidate) ->
                if (qpNativeSegmentCandidates[identityPageKey] === candidate) {
                    qpNativeSegmentCandidates.remove(identityPageKey)
                }
                candidate.wipe()
            }
            throw error
        }
    }

    /** Supplies deep, scoped NativeChunk copies to the later materializer. */
    fun <T> withQpNativeSegmentCandidatesForBuild(block: (List<QpNativeSegmentCandidate>) -> T): T {
        val snapshots = synchronized(this) {
            check(qpNativeSegmentCandidates.isNotEmpty()) { "Qp NativeChunk candidates are not initialized" }
            qpNativeSegmentCandidates.values
                .sortedBy { it.identityPageKeyForBuild() }
                .map { it.copyForBuild() }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { it.wipe() }
        }
    }

    /**
     * Supplies sealing only the NativeChunk logical page identity and binding
     * path. Chunk plaintext, handles, proofs, layout data, and evaluator inputs
     * remain build-only.
     */
    fun <T> withQpNativeRouteCandidateRefsForBuild(
        block: (List<QpNativeRouteCandidateRef>) -> T,
    ): T {
        val snapshots = synchronized(this) {
            check(qpBuildPlan?.isWiped() != false) {
                "Qp NativeChunk route candidates must be projected before page-plan initialization"
            }
            check(qpFinalizationLayout?.isWiped != false) {
                "Qp NativeChunk route candidates cannot be projected after finalization layout publication"
            }
            check(qpNativeSegmentCandidates.isNotEmpty()) { "Qp NativeChunk candidates are not initialized" }
            qpNativeSegmentCandidates.values
                .sortedBy { it.identityPageKeyForBuild() }
                .map { candidate ->
                    QpNativeRouteCandidateRef.create(
                        identityPageKey = candidate.identityPageKeyForBuild(),
                        logicalBindingPath = candidate.logicalBindingPath,
                    )
                }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { it.wipe() }
        }
    }

    /**
     * Reserves one final physical resource path per registered NativeChunk
     * before the common Qp page plan is initialized.
     */
    @Synchronized
    fun reserveQpNativeRoutes(
        occupiedEntryPaths: Set<String>,
        allocator: QpNativeRouteAllocator,
    ): QpNativeRouteReservation {
        require(qpBuildPlan?.isWiped() != false) {
            "Qp NativeChunk pre-seal routes must be reserved before page-plan initialization"
        }
        require(qpFinalizationLayout?.isWiped != false) {
            "Qp NativeChunk pre-seal routes cannot be reserved after finalization layout publication"
        }
        check(qpNativeSegmentCandidates.isNotEmpty()) {
            "Qp NativeChunk candidates are not initialized"
        }
        val existing = qpNativeRouteReservation
        require(existing == null || existing.isWiped) {
            "Qp NativeChunk pre-seal route reservation is already published"
        }
        val created = withQpNativeRouteCandidateRefsForBuild { refs ->
            QpNativeRouteReservation.reserve(
                candidateRefs = refs,
                occupiedEntryPaths = occupiedEntryPaths,
                allocator = allocator,
            )
        }
        qpNativeRouteReservation = created
        return created
    }

    @Synchronized
    fun qpNativeRouteReservationOrNull(): QpNativeRouteReservation? =
        qpNativeRouteReservation?.takeUnless { it.isWiped }

    @Synchronized
    fun requireQpNativeRouteReservation(): QpNativeRouteReservation =
        qpNativeRouteReservation
            ?.takeUnless { it.isWiped }
            ?: error("Qp NativeChunk pre-seal route reservation is not initialized")

    @Synchronized
    fun hasQpNativeSegmentCandidates(): Boolean = qpNativeSegmentCandidates.isNotEmpty()

    /**
     * Publishes the one build-only page layout produced by consuming the scoped
     * Qp plan. A live plan and a finalized layout must never coexist: the
     * former contains build authority, while the latter contains only encrypted
     * page/output records for native compilation and final-writer verification.
     */
    @Synchronized
    fun publishQpFinalizationLayout(layout: QpFinalizationLayout) {
        require(!layout.isWiped) { "cannot publish a wiped Qp current-format finalization layout" }
        require(qpBuildPlan?.isWiped() != false) {
            "Qp current-format finalization requires the scoped build plan to be consumed first"
        }
        val existing = qpFinalizationLayout
        require(existing == null || existing.isWiped) {
            "Qp current-format finalization layout is already published for this build context"
        }
        qpFinalizationLayout = layout
    }

    @Synchronized
    fun qpFinalizationLayoutOrNull(): QpFinalizationLayout? =
        qpFinalizationLayout?.takeUnless { it.isWiped }

    @Synchronized
    fun requireQpFinalizationLayout(): QpFinalizationLayout =
        qpFinalizationLayoutOrNull()
            ?: error("Qp current-format finalization layout is not initialized")

    /**
     * Narrow native compiler bridge. The callback receives fresh bounded
     * current-page record copies and they are wiped by the layout after it
     * returns; this context never exposes a runtime traversal or a key array.
     */
    @Synchronized
    fun <T> withQpLocatorRecordsForBuild(block: (List<ByteArray>) -> T): T =
        requireQpFinalizationLayout().withNativeLocatorRecordsForBuild(block)

    /**
     * Derive a build-local sub key from the per-build runtime resource root key
     * using HKDF-SHA256 (RFC 5869). The runtime resource key is the IKM, [label]
     * is the extract salt, and [info] entries are concatenated into the expand
     * info. This is the single shared derivation skeleton reused by every pass
     * that needs build-local key material, so Kotlin (build) and the Java/native
     * runtime recompute byte-for-byte identical keys from the same root.
     */
    fun deriveSubKey(label: String, length: Int, vararg info: ByteArray): ByteArray {
        val ikm = runtimeKeyPartitions.copyAnchorKey()
        return try {
            hkdfSha256(
                ikm = ikm,
                salt = label.toByteArray(Charsets.US_ASCII),
                info = concatBytes(info),
                length = length,
            )
        } finally {
            java.util.Arrays.fill(ikm, 0)
        }
    }

    /** Build-local Qp VM inner key hierarchy; no public compatibility root is used. */
    fun deriveVmBuildKey(): ByteArray = QpInnerMaterial.deriveVmBuildKey(this)

    /** Stable per-method leaf; [methodIdentity] is the canonical call-gate binding. */
    fun deriveVmMethodKey(methodIdentity: ByteArray, methodNonce: ByteArray): ByteArray {
        require(methodIdentity.isNotEmpty()) { "Qp VM VM method identity must not be empty" }
        require(methodNonce.size == QP_VM_METHOD_NONCE_SIZE) {
            "Qp VM VM method nonce must be $QP_VM_METHOD_NONCE_SIZE bytes"
        }
        val buildKey = deriveVmBuildKey()
        return try {
            hkdfSha256(
                ikm = buildKey,
                salt = QP_VM_METHOD_KEY_DOMAIN,
                info = concatBytes(arrayOf(methodIdentity, methodNonce)),
                length = QP_VM_DOMAIN_KEY_SIZE,
            )
        } finally {
            java.util.Arrays.fill(buildKey, 0)
        }
    }

    /** Per-process/per-method runtime leaf. It is never used for stored Qp VM MACs. */
    fun deriveVmRuntimeSessionLeaf(
        startupNonce: ByteArray,
        methodIdentity: ByteArray,
        methodNonce: ByteArray,
    ): ByteArray {
        require(startupNonce.size == QP_VM_STARTUP_NONCE_SIZE) {
            "Qp VM VM startup nonce must be $QP_VM_STARTUP_NONCE_SIZE bytes"
        }
        val methodKey = deriveVmMethodKey(methodIdentity, methodNonce)
        return try {
            hkdfSha256(
                ikm = methodKey,
                salt = QP_VM_SESSION_KEY_DOMAIN,
                info = startupNonce,
                length = QP_VM_DOMAIN_KEY_SIZE,
            )
        } finally {
            java.util.Arrays.fill(methodKey, 0)
        }
    }

    @Synchronized
    fun scopedCopy(): QpBuildContext = copy(
        masterKey = masterKey.copyOf(),
        jarLayoutDigest = jarLayoutDigest.copyOf(),
        runtimeResourceKey = runtimeResourceKey.copyOf(),
        nameSeed = nameSeed.copyOf(),
        runtimeKeyPartitions = runtimeKeyPartitions.deepCopy(),
        productionBuildEvidence = productionBuildEvidence,
    ).also { copy ->
        if (nativeSpecializationDigests.isNotEmpty()) {
            copy.publishNativeSpecializationDigests(
                nativeSpecializationDigests.mapValues { (_, digest) -> digest.copyOf() },
            )
        }
        // Candidate sources and pre-seal route reservations are intentionally
        // not copied across scopes; either copy could outlive the candidate
        // namespace and plaintext ownership it binds.
        // Qp plan state and the native secret pack are intentionally not
        // copied: each scoped build gets an independent page graph and secret
        // slots, and both are wiped on scope exit.
    }

    @Synchronized
    fun wipe() {
        java.util.Arrays.fill(masterKey, 0)
        java.util.Arrays.fill(jarLayoutDigest, 0)
        java.util.Arrays.fill(runtimeResourceKey, 0)
        java.util.Arrays.fill(nameSeed, 0)
        runtimeKeyPartitions.wipe()
        signedDebugMapDraft = null
        nativeSpecializationDigests.values.forEach { java.util.Arrays.fill(it, 0) }
        nativeSpecializationDigests.clear()
        nativeSealedPackBlobs.values.forEach { java.util.Arrays.fill(it, 0) }
        nativeSealedPackBlobs.clear()
        qpMethodCandidates.values.forEach { it.wipe() }
        qpMethodCandidates.clear()
        qpTextPageCandidates.values.forEach { it.wipe() }
        qpTextPageCandidates.clear()
        qpClassPageCandidates.values.forEach { it.wipe() }
        qpClassPageCandidates.clear()
        qpClassPageDescriptorSources.values.flatten().forEach { it.wipe() }
        qpClassPageDescriptorSources.clear()
        qpNativeSegmentCandidates.values.forEach { it.wipe() }
        qpNativeSegmentCandidates.clear()
        qpBuildPlan?.wipe()
        qpBuildPlan = null
        nativeVmSecretPackDraft?.wipe()
        nativeVmSecretPackDraft = null
        qpFinalizationLayout?.wipe()
        qpFinalizationLayout = null
        qpPreSealRouteReservation?.wipe()
        qpPreSealRouteReservation = null
        qpTextRouteReservation?.wipe()
        qpTextRouteReservation = null
        qpClassRouteReservation?.wipe()
        qpClassRouteReservation = null
        qpNativeRouteReservation?.wipe()
        qpNativeRouteReservation = null
    }
}

internal data class NativeVmBuildProfile(
    val parserRowProfile: Int,
    val operandAccessProfile: Int,
) {
    init {
        require(parserRowProfile in 0..2) { "native VM parser row profile must be in 0..2" }
        require(operandAccessProfile in 0..2) { "native VM operand access profile must be in 0..2" }
    }

    val authenticatedId: Int
        get() = parserRowProfile or (operandAccessProfile shl 8)

    companion object {
        fun fromBuildMaterial(nativeSeed: Long, jarLayoutDigest: ByteArray): NativeVmBuildProfile {
            require(jarLayoutDigest.size == QP_LAYOUT_DIGEST_SIZE) { "Qp VM layout digest must be 32 bytes" }
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("javashroud-native-vm-profile-v1".toByteArray(Charsets.US_ASCII))
            digest.update(longBytes(nativeSeed))
            digest.update(jarLayoutDigest)
            val material = digest.digest()
            return NativeVmBuildProfile(
                parserRowProfile = (material[0].toInt() and 0xFF) % 3,
                operandAccessProfile = (material[1].toInt() and 0xFF) % 3,
            )
        }
    }
}

internal const val QP_MASTER_KEY_SIZE = 32
internal const val QP_LAYOUT_DIGEST_SIZE = 32
internal const val QP_RUNTIME_RESOURCE_KEY_SIZE = 32
internal const val QP_VM_DOMAIN_KEY_SIZE = 32
internal const val QP_VM_METHOD_NONCE_SIZE = 16
internal const val QP_VM_STARTUP_NONCE_SIZE = 32
internal val QP_VM_BUILD_KEY_DOMAIN = "javashroud-qp-vm-build-key-v3".toByteArray(Charsets.US_ASCII)
internal val QP_VM_METHOD_KEY_DOMAIN = "javashroud-qp-vm-method-key-v1".toByteArray(Charsets.US_ASCII)
internal val QP_VM_SESSION_KEY_DOMAIN = "javashroud-qp-vm-session-key-v1".toByteArray(Charsets.US_ASCII)

private val explicitRunContext = ThreadLocal<QpBuildContext?>()

/**
 * Class-scoped access to the active build context. The top-level compatibility
 * helper below delegates here, and native recompilation uses this explicit
 * access surface.
 */
internal object QpBuildContexts {
    fun requireCurrent(): QpBuildContext = explicitRunContext.get()
        ?: error("Qp VM build context is not initialized")
}

internal fun <T> withQpBuildContext(context: QpBuildContext, block: () -> T): T {
    val previous = explicitRunContext.get()
    val scoped = context.scopedCopy()
    explicitRunContext.set(scoped)
    return try {
        block()
    } finally {
        scoped.wipe()
        if (previous == null) explicitRunContext.remove() else explicitRunContext.set(previous)
    }
}

internal fun currentQpBuildContextOrNull(): QpBuildContext? = explicitRunContext.get()

internal fun requireQpBuildContext(): QpBuildContext = QpBuildContexts.requireCurrent()

internal fun defaultQpBuildContext(): QpBuildContext = generateStandaloneQpBuildContext()

internal fun buildQpBuildContext(config: ObfuscationConfig, artifact: BytecodeArtifact): QpBuildContext {
    val layoutDigest = jarLayoutDigest(artifact)
    val seedDigest = MessageDigest.getInstance("SHA-256")
    seedDigest.update(config.inputJarPath.toByteArray(Charsets.UTF_8))
    seedDigest.update(0)
    seedDigest.update(config.outputJarPath.toByteArray(Charsets.UTF_8))
    seedDigest.update(0)
    seedDigest.update(layoutDigest)
    for (pass in config.passes.sortedBy { it.id }) {
        seedDigest.update(pass.id.toByteArray(Charsets.UTF_8))
        seedDigest.update(if (pass.enabled) 1 else 0)
        val seedNode = pass.params["seed"]
        if (seedNode != null) seedDigest.update(seedNode.toString().toByteArray(Charsets.UTF_8))
    }
    val seedBytes = seedDigest.digest()
    val randomSeedBytes = ByteArray(Long.SIZE_BYTES)
    SecureRandom().nextBytes(randomSeedBytes)
    val nativeSeed = readLong(seedBytes, 0) xor readLong(seedBytes, 8) xor readLong(randomSeedBytes, 0)
    val masterKey = MaxBuildSecurityPlan.withProductionBuildLeaf(
        inputDigest = layoutDigest,
        configurationDigest = seedBytes,
    ) { buildLeaf ->
        generateMasterKey(layoutDigest, nativeSeed, buildLeaf)
    }
    val profile = NativeVmBuildProfile.fromBuildMaterial(nativeSeed, layoutDigest)
    return QpBuildContext(
        masterKey = masterKey,
        nativeSeed = nativeSeed,
        jarLayoutDigest = layoutDigest,
        runtimeResourceKey = generateRuntimeResourceKey(masterKey, layoutDigest, nativeSeed),
        runtimeKeyPartitions = RuntimeKeyPartitions.generate(),
        nativeVmProfile = profile,
        productionBuildEvidence = CandidateProductionBuildEvidence.forConfig(config, profile),
        maxHardening = config.passes.any { pass ->
            pass.enabled && pass.id == "jni-microkernel-loader" &&
                pass.params["nativePackingLevel"]?.asText() == "max-hardening"
        },
    )
}

private fun generateStandaloneQpBuildContext(): QpBuildContext {
    val random = SecureRandom()
    val layoutDigest = ByteArray(QP_LAYOUT_DIGEST_SIZE)
    random.nextBytes(layoutDigest)
    val seedBytes = ByteArray(Long.SIZE_BYTES)
    random.nextBytes(seedBytes)
    val nativeSeed = readLong(seedBytes, 0)
    val masterKey = generateMasterKey(layoutDigest, nativeSeed)
    return QpBuildContext(
        masterKey = masterKey,
        nativeSeed = nativeSeed,
        jarLayoutDigest = layoutDigest,
        runtimeResourceKey = generateRuntimeResourceKey(masterKey, layoutDigest, nativeSeed),
        runtimeKeyPartitions = RuntimeKeyPartitions.generate(),
    )
}

private fun generateMasterKey(
    layoutDigest: ByteArray,
    nativeSeed: Long,
    buildAuthority: ByteArray = ByteArray(0),
): ByteArray {
    val random = SecureRandom()
    val entropy = ByteArray(64)
    random.nextBytes(entropy)
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("javashroud-qp-build-root".toByteArray(Charsets.US_ASCII))
    digest.update(longBytes(nativeSeed))
    digest.update(layoutDigest)
    digest.update(buildAuthority)
    digest.update(entropy)
    return digest.digest()
}

internal fun generateRuntimeResourceKey(masterKey: ByteArray, layoutDigest: ByteArray, nativeSeed: Long): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("javashroud-qp-runtime-resource".toByteArray(Charsets.US_ASCII))
    digest.update(longBytes(nativeSeed))
    digest.update(layoutDigest)
    digest.update(masterKey)
    return digest.digest()
}

private fun jarLayoutDigest(artifact: BytecodeArtifact): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    for (classArtifact in artifact.classArtifacts.sortedBy { it.entryName }) {
        digest.update(1)
        digest.update(classArtifact.entryName.toByteArray(Charsets.UTF_8))
        digest.update(0)
        digest.update(intBytes(classArtifact.bytes.size))
        digest.update(MessageDigest.getInstance("SHA-256").digest(classArtifact.bytes))
    }
    for (entry in artifact.jarEntries.sortedBy { it.name }) {
        digest.update(2)
        digest.update(entry.name.toByteArray(Charsets.UTF_8))
        digest.update(0)
        digest.update(intBytes(entry.bytes.size))
        digest.update(MessageDigest.getInstance("SHA-256").digest(entry.bytes))
    }
    return digest.digest()
}

private fun readLong(bytes: ByteArray, offset: Int): Long {
    var value = 0L
    for (index in 0 until Long.SIZE_BYTES) {
        value = (value shl 8) or (bytes[offset + index].toLong() and 0xFFL)
    }
    return value
}

private fun longBytes(value: Long): ByteArray = ByteArray(Long.SIZE_BYTES) { index ->
    ((value ushr ((Long.SIZE_BYTES - 1 - index) * 8)) and 0xFF).toByte()
}

internal const val QP_DERIVE_LABEL_CLASS_ENCRYPTION = "javashroud-qp-class-encryption-v1"

/**
 * HKDF-SHA256 (RFC 5869): extract-then-expand. Shared by every build-local key
 * derivation so the engine never invents its own enumerable KDF.
 */
internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    require(length in 1..(255 * 32)) { "HKDF-SHA256 output length out of range: $length" }
    val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
    val output = ByteArray(length)
    var produced = 0
    var counter = 1
    var previous = ByteArray(0)
    while (produced < length) {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"))
        mac.update(previous)
        mac.update(info)
        mac.update(counter.toByte())
        previous = mac.doFinal()
        val take = minOf(previous.size, length - produced)
        System.arraycopy(previous, 0, output, produced, take)
        produced += take
        counter++
    }
    java.util.Arrays.fill(prk, 0)
    java.util.Arrays.fill(previous, 0)
    return output
}

private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(javax.crypto.spec.SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
    return mac.doFinal(data)
}

internal fun concatBytes(parts: Array<out ByteArray>): ByteArray {
    val total = parts.sumOf { it.size }
    val out = ByteArray(total)
    var offset = 0
    for (part in parts) {
        System.arraycopy(part, 0, out, offset, part.size)
        offset += part.size
    }
    return out
}

private fun intBytes(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xFF).toByte(),
    ((value ushr 16) and 0xFF).toByte(),
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte(),
)
