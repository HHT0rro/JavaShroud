package io.github.hht0rro.javashroud.transforms.protection.qp

import io.github.hht0rro.javashroud.transforms.protection.concatBytes
import io.github.hht0rro.javashroud.transforms.protection.hkdfSha256
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Build-only secret material for the per-artifact native VM specialization.
 *
 * Every high-value page receives one secret slot. The slot seed never enters a
 * descriptor, catalog, or generated resource; it is emitted once as sharded
 * literals into the artifact-specific Rust specialization source and wiped from
 * the JVM after the native recompilation finishes. The runtime page key is
 * derived from structured binary inputs
 * (`preNativeCommitment + secretSlot + pageIdentity + pageNonce +
 * nativeIdentity`) with HKDF-SHA256; there is no public string-concatenation
 * derivation and no evaluator fragment material to recover.
 */
internal const val QP_SECRET_PACK_MAX_SLOTS: Int = 4096
internal const val QP_SECRET_PACK_SEED_SIZE: Int = 32

private val SECRET_PACK_ROOT_DOMAIN = "javashroud-qp-secret-pack-root-v4".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_SLOT_DOMAIN = "javashroud-qp-secret-slot-v4".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_COMMITMENT_DOMAIN = "javashroud-qp-secret-commitment-v4".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_PAGE_KEY_DOMAIN = "javashroud-qp-page-key-v4".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_NATIVE_IDENTITY_DOMAIN = "javashroud-qp-native-identity-v4".toByteArray(Charsets.US_ASCII)

/** One allocated secret slot; the seed is owned by the surrounding draft. */
internal class NativeVmPageSlot internal constructor(
    val slotId: Int,
    seed: ByteArray,
) : AutoCloseable {
    private var seedValue = seed.copyOf()

    @Volatile
    private var wiped = false

    internal val isWiped: Boolean
        get() = wiped

    /** One-time copy for the native specialization writer. */
    internal fun copySeedForSpecialization(): ByteArray {
        check(!wiped) { "Qp native secret slot has been wiped" }
        return seedValue.copyOf()
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(seedValue, 0)
        seedValue = ByteArray(0)
        wiped = true
    }
}

/**
 * One-shot sealed snapshot handed to the native compiler pass. The source
 * draft stays with the build context; this copy is wiped by the compiler pass
 * after the specialization source has been written.
 */
internal class NativeVmSecretPack private constructor(
    private val slotsValue: List<NativeVmPageSlot>,
    private val nativeIdentityValue: ByteArray,
) : AutoCloseable {
    @Volatile
    private var wiped = false

    val isWiped: Boolean
        get() = wiped

    val slotCount: Int
        get() {
            requireLive()
            return slotsValue.size
        }

    val nativeIdentity: ByteArray
        get() {
            requireLive()
            return nativeIdentityValue.copyOf()
        }

    internal fun slotsForSpecialization(): List<NativeVmPageSlot> {
        requireLive()
        return slotsValue
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        slotsValue.forEach { it.wipe() }
        Arrays.fill(nativeIdentityValue, 0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "Qp native secret pack has been wiped" }
    }

    internal companion object {
        internal fun create(slots: List<Pair<Int, ByteArray>>, nativeIdentity: ByteArray): NativeVmSecretPack {
            require(nativeIdentity.size == QP_SECRET_PACK_SEED_SIZE) {
                "Qp native identity must be ${QP_SECRET_PACK_SEED_SIZE} bytes"
            }
            return NativeVmSecretPack(
                slotsValue = slots.map { (slotId, seed) -> NativeVmPageSlot(slotId, seed) },
                nativeIdentityValue = nativeIdentity.copyOf(),
            )
        }
    }
}

/**
 * Build-only allocator and derivation authority for the per-artifact native
 * secret pack. Created lazily by the owning [QpBuildContext]; wiped with it.
 */
internal class NativeVmSecretPackDraft private constructor(
    private val packRoot: ByteArray,
) {
    private val slotSeeds = LinkedHashMap<Int, ByteArray>()
    private var nativeIdentityValue: ByteArray = ByteArray(0)

    @Volatile
    private var wiped = false

    val slotCount: Int
        get() {
            requireLive()
            return slotSeeds.size
        }

    init {
        require(packRoot.size == QP_SECRET_PACK_SEED_SIZE) {
            "Qp native secret pack root must be ${QP_SECRET_PACK_SEED_SIZE} bytes"
        }
        nativeIdentityValue = hkdfSha256(
            ikm = packRoot,
            salt = SECRET_PACK_NATIVE_IDENTITY_DOMAIN,
            info = ByteArray(0),
            length = QP_SECRET_PACK_SEED_SIZE,
        )
    }

    /** Allocates the next secret slot for one registered page. */
    @Synchronized
    fun registerSlot(): Int {
        requireLive()
        val slotId = slotSeeds.size
        require(slotId < QP_SECRET_PACK_MAX_SLOTS) {
            "Qp native secret pack slot space is exhausted"
        }
        val seed = hkdfSha256(
            ikm = packRoot,
            salt = SECRET_PACK_SLOT_DOMAIN,
            info = u32be(slotId),
            length = QP_SECRET_PACK_SEED_SIZE,
        )
        slotSeeds[slotId] = seed
        return slotId
    }

    /**
     * Derives the page DEK from structured binary inputs only. All inputs are
     * reconstructible at runtime by the native specialization: the slot seed
     * lives in the generated binary, the remaining inputs travel in the page
     * frame and descriptor.
     */
    fun pageKey(
        slotId: Int,
        resourceKind: QpResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
        locatorToken: ByteArray,
        pageNonce: ByteArray,
        preNativeCommitment: ByteArray,
    ): ByteArray {
        requireLive()
        val seed = synchronized(this) {
            slotSeeds[slotId] ?: throw IllegalArgumentException("Qp secret slot is not registered")
        }
        require(encodedHandle.size == QpHandle.ENCODED_HANDLE_SIZE) {
            "Qp secret page key handle size is invalid"
        }
        require(locatorToken.size == QpHandle.LOCATOR_TOKEN_SIZE) {
            "Qp secret page key locator size is invalid"
        }
        require(pageNonce.size == QpPageCodec.NONCE_SIZE) {
            "Qp secret page key nonce size is invalid"
        }
        require(preNativeCommitment.size == QP_SECRET_PACK_SEED_SIZE) {
            "Qp pre-native commitment must be ${QP_SECRET_PACK_SEED_SIZE} bytes"
        }
        // The slot seed is owned by the draft; only the derived key escapes.
        return hkdfSha256(
            ikm = seed,
            salt = SECRET_PACK_PAGE_KEY_DOMAIN,
            info = concatBytes(
                arrayOf(
                        preNativeCommitment,
                        u32be(slotId),
                        byteArrayOf(resourceKind.id.toByte()),
                        u32be(pageIndex),
                    encodedHandle,
                    locatorToken,
                    pageNonce,
                    copyNativeIdentity(),
                ),
            ),
            length = QP_SECRET_PACK_SEED_SIZE,
        )
    }

    /** Key commitment for one derived page key; verified by the native open path. */
    fun keyCommitment(slotId: Int, pageKey: ByteArray): ByteArray {
        requireLive()
        val seed = synchronized(this) {
            slotSeeds[slotId] ?: throw IllegalArgumentException("Qp secret slot is not registered")
        }
        var commitmentKey: ByteArray? = null
        return try {
            commitmentKey = hkdfSha256(
                ikm = seed,
                salt = SECRET_PACK_COMMITMENT_DOMAIN,
                info = ByteArray(0),
                length = QP_SECRET_PACK_SEED_SIZE,
            )
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(checkNotNull(commitmentKey), "HmacSHA256"))
            mac.doFinal(pageKey)
        } finally {
            commitmentKey?.let { Arrays.fill(it, 0) }
        }
    }

    @Synchronized
    fun copyNativeIdentity(): ByteArray {
        requireLive()
        return nativeIdentityValue.copyOf()
    }

    /**
     * One sealed copy for the specialization writer; the draft stays live.
     *
     * Zero slots is valid for loader-only or CFG-evidence compiles: the native
     * identity and dialect corpus still bind the binary, and page open stays
     * fail-closed until a later artifact actually registers slots.
     */
    @Synchronized
    fun sealedCopyForSpecialization(): NativeVmSecretPack {
        requireLive()
        return NativeVmSecretPack.create(
            slots = slotSeeds.map { (slotId, seed) -> slotId to seed.copyOf() },
            nativeIdentity = nativeIdentityValue,
        )
    }

    @Synchronized
    fun wipe() {
        if (wiped) return
        slotSeeds.values.forEach { Arrays.fill(it, 0) }
        slotSeeds.clear()
        Arrays.fill(nativeIdentityValue, 0)
        nativeIdentityValue = ByteArray(0)
        Arrays.fill(packRoot, 0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "Qp native secret pack draft has been wiped" }
    }

    internal companion object {
        internal fun create(packRoot: ByteArray): NativeVmSecretPackDraft =
            NativeVmSecretPackDraft(packRoot.copyOf())

        internal fun derivePackRoot(ikm: ByteArray): ByteArray = hkdfSha256(
            ikm = ikm,
            salt = SECRET_PACK_ROOT_DOMAIN,
            info = ByteArray(0),
            length = QP_SECRET_PACK_SEED_SIZE,
        )
    }
}

/**
 * Sharded, compile-only projection of one sealed [NativeVmSecretPack].
 *
 * Every slot seed is split into a randomized count of XOR shards so the
 * generated Rust source never contains a contiguous 32-byte secret array.
 * The shards are wiped as soon as the specialization source has been written.
 */
internal class NativeSecretPackLiterals private constructor(
    private val nativeIdentityValue: ByteArray,
    private val slotShardGroups: List<Pair<Int, List<ByteArray>>>,
) {
    val slotCount: Int
        get() = slotShardGroups.size

    val nativeIdentity: ByteArray
        get() = nativeIdentityValue.copyOf()

    /** Slot id of the [index]-th literal group. */
    fun slotIdAt(index: Int): Int = slotShardGroups[index].first

    fun shardCountAt(index: Int): Int = slotShardGroups[index].second.size

    fun shardAt(slotIndex: Int, shardIndex: Int): ByteArray =
        slotShardGroups[slotIndex].second[shardIndex].copyOf()

    /**
     * Deterministic commitment over the combined seeds. It is folded into the
     * native specialization digest so the published digest binds the exact
     * secret material embedded in the binary.
     */
    fun commitment(): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(SECRET_PACK_LITERAL_COMMITMENT_DOMAIN)
        digest.update(nativeIdentityValue)
        slotShardGroups.sortedBy { it.first }.forEach { (slotId, shards) ->
            val combined = shards.reduce { acc, shard -> acc.mapIndexed { i, b -> (b.toInt() xor shard[i].toInt()).toByte() }.toByteArray() }
            try {
                digest.update(u32be(slotId))
                digest.update(combined)
            } finally {
                Arrays.fill(combined, 0)
            }
        }
        return digest.digest()
    }

    fun wipe() {
        Arrays.fill(nativeIdentityValue, 0)
        slotShardGroups.forEach { (_, shards) -> shards.forEach { Arrays.fill(it, 0) } }
    }

    internal companion object {
        private val SECRET_PACK_LITERAL_COMMITMENT_DOMAIN =
            "javashroud-qp-secret-pack-commitment-v4".toByteArray(Charsets.US_ASCII)

        internal fun prepare(pack: NativeVmSecretPack, random: java.util.Random): NativeSecretPackLiterals {
            val groups = ArrayList<Pair<Int, List<ByteArray>>>(pack.slotCount)
            try {
                for (index in 0 until pack.slotCount) {
                    val slot = pack.slotsForSpecialization()[index]
                    val seed = slot.copySeedForSpecialization()
                    val combined = ArrayList<ByteArray>()
                    try {
                        val shardCount = 2 + random.nextInt(3)
                        repeat(shardCount - 1) {
                            val shard = ByteArray(QP_SECRET_PACK_SEED_SIZE)
                            random.nextBytes(shard)
                            combined += shard
                        }
                        val tail = seed.mapIndexed { i, b ->
                            (b.toInt() xor combined.fold(0) { acc, shard -> acc xor shard[i].toInt() }).toByte()
                        }.toByteArray()
                        combined += tail
                        combined.shuffle(java.util.Random(random.nextLong()))
                        groups += slot.slotId to combined
                    } finally {
                        Arrays.fill(seed, 0)
                    }
                }
                return NativeSecretPackLiterals(
                    nativeIdentityValue = pack.nativeIdentity,
                    slotShardGroups = groups,
                )
            } catch (error: Throwable) {
                groups.forEach { (_, shards) -> shards.forEach { Arrays.fill(it, 0) } }
                throw error
            }
        }
    }
}

private fun u32be(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xFF).toByte(),
    ((value ushr 16) and 0xFF).toByte(),
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte(),
)
