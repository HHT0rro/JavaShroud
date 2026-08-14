package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4MethodCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4RouteCandidateRef
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Shared VBC4 build context for one obfuscation run.
 *
 * Method resources are serialized before the native microkernel is recompiled,
 * so both phases must derive the same build-local root key from the same run
 * context. Root material is never kept as a repository or generated-native
 * constant; it is sealed into boot.dat and materialized only in runtime memory.
 */
internal data class Vbc4BuildContext(
    val masterKey: ByteArray,
    val nativeSeed: Long,
    val jarLayoutDigest: ByteArray,
    val runtimeResourceKey: ByteArray = generateRuntimeResourceKey(masterKey, jarLayoutDigest, nativeSeed),
    val runtimeKeyPartitions: RuntimeKeyPartitions = RuntimeKeyPartitions.generate(),
    val nativeVmProfile: NativeVmBuildProfile = NativeVmBuildProfile.fromBuildMaterial(nativeSeed, jarLayoutDigest),
    val productionBuildEvidence: CandidateProductionBuildEvidence = CandidateProductionBuildEvidence.disabled(nativeVmProfile),
    val maxHardening: Boolean = false,
) {
    private var runtimeVmCatalogPlan: RuntimeVmCatalogPlan? = null
    /** Build-only AKEN v4 page/evaluator plan; never serialized into runtime output. */
    private var akenBuildPlan: AkenBuildPlan? = null
    /**
     * Build-only VBC4 method snapshots captured after legacy emission succeeds.
     * These are logical sources for a later page planner, not final routes,
     * descriptors, native records, or a runtime catalog.
     */
    private val akenVbc4MethodCandidates = LinkedHashMap<Long, AkenVbc4MethodCandidate>()
    /**
     * Build-only pre-seal VBC4 layout. It owns final page geometry and native
     * current-page compiler records until recompilation/final sealing consumes
     * them; it is not a runtime page directory.
     */
    private var akenVbc4FinalizationLayout: AkenVbc4FinalizationLayout? = null
    private var bootSecretSnapshot: ByteArray? = null
    private var bootSidecarBindingSnapshot: ByteArray? = null

    init {
        require(masterKey.size == VBC4_MASTER_KEY_SIZE) { "VBC4 master key must be 32 bytes" }
        require(jarLayoutDigest.size == VBC4_LAYOUT_DIGEST_SIZE) { "VBC4 layout digest must be 32 bytes" }
        require(runtimeResourceKey.size == VBC4_RUNTIME_RESOURCE_KEY_SIZE) { "VBC4 runtime resource key must be 32 bytes" }
    }

    fun copyMasterKey(): ByteArray = masterKey.copyOf()
    fun copyRuntimeResourceKey(): ByteArray = runtimeResourceKey.copyOf()
    fun publishRuntimeVmCatalogPlan(plan: RuntimeVmCatalogPlan) {
        runtimeVmCatalogPlan = plan
    }

    fun runtimeVmCatalogPlanOrNull(): RuntimeVmCatalogPlan? = runtimeVmCatalogPlan

    /**
     * Return the scoped AKEN v4 plan, creating it lazily from the artifact
     * commitment. The plan is build-only and is wiped with this context.
     *
     * A build context may represent only one canonical artifact. Reusing a live
     * plan with a different commitment would make pages authenticate against an
     * unrelated artifact representation, so reject it immediately instead of
     * deferring the mismatch to the final writer verification.
     */
    @Synchronized
    fun initializeAkenBuildPlan(commitment: ByteArray): AkenBuildPlan {
        require(commitment.size == VBC4_LAYOUT_DIGEST_SIZE) { "AKEN artifact commitment must be 32 bytes" }
        val existing = akenBuildPlan
        if (existing != null && !existing.isWiped()) {
            val plannedCommitment = existing.artifactCanonicalCommitment
            try {
                require(java.security.MessageDigest.isEqual(plannedCommitment, commitment)) {
                    "AKEN v4 build plan is already bound to a different artifact commitment"
                }
            } finally {
                java.util.Arrays.fill(plannedCommitment, 0)
            }
            return existing
        }
        return AkenBuildPlan.create(commitment = commitment).also { akenBuildPlan = it }
    }

    @Synchronized
    fun akenBuildPlanOrNull(): AkenBuildPlan? = akenBuildPlan?.takeUnless { it.isWiped() }

    @Synchronized
    fun requireAkenBuildPlan(): AkenBuildPlan = akenBuildPlanOrNull()
        ?: error("AKEN v4 build plan is not initialized")

    /**
     * Atomically snapshots real VBC4 method programs for a later AKEN page
     * planner. Callers retain ownership of [candidates]; this context copies
     * them and never exposes its internal instances to a callback.
     *
     * Candidates must be registered before an AKEN build plan exists. A plan is
     * bound to final artifact material, whereas candidates still carry only
     * logical method inputs and must not be mistaken for finalized page state.
     */
    @Synchronized
    fun registerAkenVbc4MethodCandidates(candidates: Iterable<AkenVbc4MethodCandidate>) {
        require(akenBuildPlan?.isWiped() != false) {
            "AKEN VBC4 method candidates must be registered before page-plan initialization"
        }
        require(akenVbc4FinalizationLayout?.isWiped != false) {
            "AKEN VBC4 method candidates cannot be registered after finalization layout publication"
        }
        val incoming = candidates.toList()
        require(incoming.isNotEmpty()) { "AKEN VBC4 method candidate batch must not be empty" }
        require(incoming.none { it.isWiped }) { "cannot register a wiped AKEN VBC4 method candidate" }

        val incomingTokens = incoming.map { it.entryToken }
        require(incomingTokens.distinct().size == incomingTokens.size) {
            "AKEN VBC4 method candidate batch contains duplicate entry tokens"
        }
        val incomingPaths = incoming.map { it.logicalMethod.logicalVmResourcePath }
        require(incomingPaths.distinct().size == incomingPaths.size) {
            "AKEN VBC4 method candidate batch contains duplicate logical resource paths"
        }
        require(incomingTokens.none { it in akenVbc4MethodCandidates }) {
            "AKEN VBC4 method candidate entry token is already registered"
        }
        require(incomingPaths.none { path -> akenVbc4MethodCandidates.values.any { it.logicalMethod.logicalVmResourcePath == path } }) {
            "AKEN VBC4 method candidate logical resource path is already registered"
        }

        val snapshots = ArrayList<AkenVbc4MethodCandidate>(incoming.size)
        try {
            incoming.forEach { candidate -> snapshots += candidate.copyForBuild() }
            snapshots.forEach { candidate ->
                check(akenVbc4MethodCandidates.put(candidate.entryToken, candidate) == null) {
                    "AKEN VBC4 method candidate entry token is already registered"
                }
            }
        } catch (error: Throwable) {
            snapshots.forEach { candidate ->
                if (akenVbc4MethodCandidates[candidate.entryToken] === candidate) {
                    akenVbc4MethodCandidates.remove(candidate.entryToken)
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
    fun <T> withAkenVbc4MethodCandidatesForBuild(block: (List<AkenVbc4MethodCandidate>) -> T): T {
        val snapshots = synchronized(this) {
            check(akenVbc4MethodCandidates.isNotEmpty()) { "AKEN VBC4 method candidates are not initialized" }
            akenVbc4MethodCandidates.values.map { it.copyForBuild() }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { it.wipe() }
        }
    }

    /**
     * Gives the pre-seal routing stage a scoped projection of registered VBC4
     * candidates. The projection contains only the entry token and logical VM
     * resource path, never the serialized program or another planner input.
     */
    fun <T> withAkenVbc4RouteCandidateRefsForBuild(
        block: (List<AkenVbc4RouteCandidateRef>) -> T,
    ): T {
        val snapshots = synchronized(this) {
            check(akenBuildPlan?.isWiped() != false) {
                "AKEN VBC4 route candidates must be projected before page-plan initialization"
            }
            check(akenVbc4FinalizationLayout?.isWiped != false) {
                "AKEN VBC4 route candidates cannot be projected after finalization layout publication"
            }
            check(akenVbc4MethodCandidates.isNotEmpty()) { "AKEN VBC4 method candidates are not initialized" }
            akenVbc4MethodCandidates.values
                .sortedBy { candidate -> candidate.entryToken }
                .map { candidate ->
                    AkenVbc4RouteCandidateRef.create(
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
     * Publishes the one build-only page layout produced by consuming the scoped
     * AKEN plan. A live plan and a finalized layout must never coexist: the
     * former contains build authority, while the latter contains only encrypted
     * page/output records for native compilation and final-writer verification.
     */
    @Synchronized
    fun publishAkenVbc4FinalizationLayout(layout: AkenVbc4FinalizationLayout) {
        require(!layout.isWiped) { "cannot publish a wiped AKEN VBC4 finalization layout" }
        require(akenBuildPlan?.isWiped() != false) {
            "AKEN VBC4 finalization requires the scoped build plan to be consumed first"
        }
        val existing = akenVbc4FinalizationLayout
        require(existing == null || existing.isWiped) {
            "AKEN VBC4 finalization layout is already published for this build context"
        }
        akenVbc4FinalizationLayout = layout
    }

    @Synchronized
    fun akenVbc4FinalizationLayoutOrNull(): AkenVbc4FinalizationLayout? =
        akenVbc4FinalizationLayout?.takeUnless { it.isWiped }

    @Synchronized
    fun requireAkenVbc4FinalizationLayout(): AkenVbc4FinalizationLayout =
        akenVbc4FinalizationLayoutOrNull()
            ?: error("AKEN VBC4 finalization layout is not initialized")

    /**
     * Narrow native compiler bridge. The callback receives fresh bounded
     * current-page record copies and they are wiped by the layout after it
     * returns; this context never exposes a runtime traversal or a key array.
     */
    @Synchronized
    fun <T> withAkenNativeLocatorRecordsForBuild(block: (List<ByteArray>) -> T): T =
        requireAkenVbc4FinalizationLayout().withNativeLocatorRecordsForBuild(block)

    fun vmManifestProtocol(): Vbc4ManifestProtocol {
        if (!maxHardening) return Vbc4ManifestProtocol(magic = "VBC4S", version = "1")
        val token = deriveSubKey("javashroud-vbc4-manifest-token-v2", 8, jarLayoutDigest)
        return try {
            Vbc4ManifestProtocol(
                magic = "H" + token.joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) },
                version = "2",
            )
        } finally {
            java.util.Arrays.fill(token, 0)
        }
    }

    @Synchronized
    fun copyBootSecretForBuild(): ByteArray {
        val snapshot = bootSecretSnapshot ?: NativeKernelShellPacker.requireBootSecretForBuild().also {
            bootSecretSnapshot = it
        }
        return snapshot.copyOf()
    }

    @Synchronized
    fun copyBootSidecarBindingForBuild(): ByteArray {
        val snapshot = bootSidecarBindingSnapshot ?: BootKekSidecar.requireArtifactBindingForBuild().also {
            bootSidecarBindingSnapshot = it
        }
        return snapshot.copyOf()
    }

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

    /** Stable per-build VM authority; runtime session material is derived from this root. */
    fun deriveVmBuildKey(): ByteArray = hkdfSha256(
        ikm = masterKey,
        salt = VBC4_VM_BUILD_KEY_DOMAIN,
        info = jarLayoutDigest,
        length = VBC4_VM_DOMAIN_KEY_SIZE,
    )

    /** Stable per-method leaf; [methodIdentity] is the canonical call-gate binding. */
    fun deriveVmMethodKey(methodIdentity: ByteArray, methodNonce: ByteArray): ByteArray {
        require(methodIdentity.isNotEmpty()) { "VBC4 VM method identity must not be empty" }
        require(methodNonce.size == VBC4_VM_METHOD_NONCE_SIZE) {
            "VBC4 VM method nonce must be $VBC4_VM_METHOD_NONCE_SIZE bytes"
        }
        val buildKey = deriveVmBuildKey()
        return try {
            hkdfSha256(
                ikm = buildKey,
                salt = VBC4_VM_METHOD_KEY_DOMAIN,
                info = concatBytes(arrayOf(methodIdentity, methodNonce)),
                length = VBC4_VM_DOMAIN_KEY_SIZE,
            )
        } finally {
            java.util.Arrays.fill(buildKey, 0)
        }
    }

    /** Per-process/per-method runtime leaf. It is never used for stored VBC4 MACs. */
    fun deriveVmRuntimeSessionLeaf(
        startupNonce: ByteArray,
        methodIdentity: ByteArray,
        methodNonce: ByteArray,
    ): ByteArray {
        require(startupNonce.size == VBC4_VM_STARTUP_NONCE_SIZE) {
            "VBC4 VM startup nonce must be $VBC4_VM_STARTUP_NONCE_SIZE bytes"
        }
        val methodKey = deriveVmMethodKey(methodIdentity, methodNonce)
        return try {
            hkdfSha256(
                ikm = methodKey,
                salt = VBC4_VM_SESSION_KEY_DOMAIN,
                info = startupNonce,
                length = VBC4_VM_DOMAIN_KEY_SIZE,
            )
        } finally {
            java.util.Arrays.fill(methodKey, 0)
        }
    }

    @Synchronized
    fun scopedCopy(): Vbc4BuildContext = copy(
        masterKey = masterKey.copyOf(),
        jarLayoutDigest = jarLayoutDigest.copyOf(),
        runtimeResourceKey = runtimeResourceKey.copyOf(),
        runtimeKeyPartitions = runtimeKeyPartitions.deepCopy(),
        productionBuildEvidence = productionBuildEvidence,
    ).also { copy ->
        copy.runtimeVmCatalogPlan = runtimeVmCatalogPlan
        copy.bootSecretSnapshot = bootSecretSnapshot?.copyOf()
        copy.bootSidecarBindingSnapshot = bootSidecarBindingSnapshot?.copyOf()
        // AKEN plan state is intentionally not copied: each scoped build gets
        // an independent page/evaluator graph and wipes it on scope exit.
    }

    @Synchronized
    fun wipe() {
        java.util.Arrays.fill(masterKey, 0)
        java.util.Arrays.fill(jarLayoutDigest, 0)
        java.util.Arrays.fill(runtimeResourceKey, 0)
        runtimeKeyPartitions.wipe()
        bootSecretSnapshot?.let { java.util.Arrays.fill(it, 0) }
        bootSidecarBindingSnapshot?.let { java.util.Arrays.fill(it, 0) }
        bootSecretSnapshot = null
        bootSidecarBindingSnapshot = null
        runtimeVmCatalogPlan = null
        akenVbc4MethodCandidates.values.forEach { it.wipe() }
        akenVbc4MethodCandidates.clear()
        akenBuildPlan?.wipe()
        akenBuildPlan = null
        akenVbc4FinalizationLayout?.wipe()
        akenVbc4FinalizationLayout = null
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
            require(jarLayoutDigest.size == VBC4_LAYOUT_DIGEST_SIZE) { "VBC4 layout digest must be 32 bytes" }
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

internal data class Vbc4ManifestProtocol(
    val magic: String,
    val version: String,
) {
    val prefix: String
        get() = "$magic|$version|"
}

internal const val VBC4_MASTER_KEY_SIZE = 32
internal const val VBC4_LAYOUT_DIGEST_SIZE = 32
internal const val VBC4_RUNTIME_RESOURCE_KEY_SIZE = 32
internal const val VBC4_VM_DOMAIN_KEY_SIZE = 32
internal const val VBC4_VM_METHOD_NONCE_SIZE = 16
internal const val VBC4_VM_STARTUP_NONCE_SIZE = 32
internal val VBC4_VM_BUILD_KEY_DOMAIN = "javashroud-vbc4-vm-build-key-v1".toByteArray(Charsets.US_ASCII)
internal val VBC4_VM_METHOD_KEY_DOMAIN = "javashroud-vbc4-vm-method-key-v1".toByteArray(Charsets.US_ASCII)
internal val VBC4_VM_SESSION_KEY_DOMAIN = "javashroud-vbc4-vm-session-key-v1".toByteArray(Charsets.US_ASCII)

private val explicitRunContext = ThreadLocal<Vbc4BuildContext?>()

/**
 * Class-scoped access to the active build context. The top-level compatibility
 * helper below delegates here, and native recompilation uses this explicit
 * access surface.
 */
internal object Vbc4BuildContexts {
    fun requireCurrent(): Vbc4BuildContext = explicitRunContext.get()
        ?: error("VBC4 build context is not initialized")
}

internal fun <T> withVbc4BuildContext(context: Vbc4BuildContext, block: () -> T): T {
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

internal fun currentVbc4BuildContextOrNull(): Vbc4BuildContext? = explicitRunContext.get()

internal fun requireVbc4BuildContext(): Vbc4BuildContext = Vbc4BuildContexts.requireCurrent()

internal fun defaultVbc4BuildContext(): Vbc4BuildContext = generateStandaloneVbc4BuildContext()

internal fun buildVbc4BuildContext(config: ObfuscationConfig, artifact: BytecodeArtifact): Vbc4BuildContext {
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
    return Vbc4BuildContext(
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

private fun generateStandaloneVbc4BuildContext(): Vbc4BuildContext {
    val random = SecureRandom()
    val layoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE)
    random.nextBytes(layoutDigest)
    val seedBytes = ByteArray(Long.SIZE_BYTES)
    random.nextBytes(seedBytes)
    val nativeSeed = readLong(seedBytes, 0)
    val masterKey = generateMasterKey(layoutDigest, nativeSeed)
    return Vbc4BuildContext(
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
    digest.update("javashroud-vbc4-build-root".toByteArray(Charsets.US_ASCII))
    digest.update(longBytes(nativeSeed))
    digest.update(layoutDigest)
    digest.update(buildAuthority)
    digest.update(entropy)
    return digest.digest()
}

internal fun generateRuntimeResourceKey(masterKey: ByteArray, layoutDigest: ByteArray, nativeSeed: Long): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("javashroud-vbc4-runtime-resource".toByteArray(Charsets.US_ASCII))
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

internal const val VBC4_DERIVE_LABEL_CLASS_ENCRYPTION = "javashroud-vbc4-jse-class-v1"

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
