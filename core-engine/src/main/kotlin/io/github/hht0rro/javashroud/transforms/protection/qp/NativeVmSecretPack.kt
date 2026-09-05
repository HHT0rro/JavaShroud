package io.github.hht0rro.javashroud.transforms.protection.qp

import io.github.hht0rro.javashroud.transforms.protection.concatBytes
import io.github.hht0rro.javashroud.transforms.protection.hkdfSha256
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Build-only secret material for the per-artifact native VM specialization.
 *
 * Every high-value page receives one secret slot. The slot seed never enters a
 * descriptor, catalog, or generated resource; it is emitted once as wrapped
 * literals into the artifact-specific Rust specialization source and wiped from
 * the JVM after the native recompilation finishes. Slot seeds travel only
 * inside an AEAD wrap reconstructed from MBA immediates. The runtime page key is
 * derived from structured binary inputs
 * (`preNativeCommitment + secretSlot + pageIdentity + pageNonce +
 * nativeIdentity`) with HKDF-SHA256; there is no public string-concatenation
 * derivation and no evaluator fragment material to recover.
 */
internal const val QP_SECRET_PACK_MAX_SLOTS: Int = 4096
internal const val QP_SECRET_PACK_SEED_SIZE: Int = 32

private val SECRET_PACK_ROOT_DOMAIN = "javashroud-qp-secret-pack-root-v6".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_SLOT_DOMAIN = "javashroud-qp-secret-slot-v6".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_COMMITMENT_DOMAIN = "javashroud-qp-secret-commitment-v6".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_PAGE_KEY_DOMAIN = "javashroud-qp-page-key-v6".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_NATIVE_IDENTITY_DOMAIN = "javashroud-qp-native-identity-v6".toByteArray(Charsets.US_ASCII)
internal val SECRET_PACK_WRAP_AAD = "javashroud-qp-secret-wrap-v6".toByteArray(Charsets.US_ASCII)
internal val IMAGE_MEASUREMENT_MAGIC: ByteArray = byteArrayOf(
    'J'.code.toByte(),
    'S'.code.toByte(),
    'I'.code.toByte(),
    'M'.code.toByte(),
    0x01,
    'v'.code.toByte(),
    '6'.code.toByte(),
    0,
)

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
    private val slotKindsValue: Map<Int, Int>,
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

    /** Resource kind a slot was first derived for; sealing shards requires it. */
    internal fun kindOfSlot(slotId: Int): Int {
        requireLive()
        return requireNotNull(slotKindsValue[slotId]) {
            "Qp secret slot $slotId has no bound resource kind"
        }
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
        internal fun create(
            slots: List<Pair<Int, ByteArray>>,
            slotKinds: Map<Int, Int>,
            nativeIdentity: ByteArray,
        ): NativeVmSecretPack {
            require(nativeIdentity.size == QP_SECRET_PACK_SEED_SIZE) {
                "Qp native identity must be ${QP_SECRET_PACK_SEED_SIZE} bytes"
            }
            return NativeVmSecretPack(
                slotsValue = slots.map { (slotId, seed) -> NativeVmPageSlot(slotId, seed) },
                slotKindsValue = slotKinds.toMap(),
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
    private val slotKinds = HashMap<Int, Int>()
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
        synchronized(this) { slotKinds.putIfAbsent(slotId, resourceKind.id) }
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
            slotKinds = slotKinds,
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

internal data class MbaWord(val multiplier: Int, val factor: Int, val addend: Int)

/**
 * Compile-only AEAD projection of one sealed [NativeVmSecretPack] (v6).
 *
 * The pack is split into five independently wrapped shards — a root shard
 * (identity, slot count, VM crypto domain, layout digest) plus one shard per
 * resource kind. Shard wrap keys are `HMAC(cmKey, image commitment)`: the
 * commitment is only known after the compiled native artifact has been
 * measured and patched, so sealing happens post-compile and the sealed blob
 * ships as catalog data instead of a native source constant. Runtime shard
 * keys mix the commitment through a volatile read and can therefore never be
 * constant-folded into a contiguous static window.
 */
internal class NativeSecretPackLiterals private constructor(
    private val nativeIdentityValue: ByteArray,
    private val shardsValue: List<ShardMaterial>,
    private val slotIdsValue: IntArray,
    private val packCommitmentValue: ByteArray,
    private val maskRMasterValue: ByteArray,
) {
    /** One shard: static half key, MBA projection, and plaintext until sealed. */
    internal class ShardMaterial(
        val kind: Int,
        val cmKey: ByteArray,
        val plaintext: ByteArray,
        val mbaWords: List<MbaWord>,
    )

    val slotCount: Int
        get() = slotIdsValue.size

    val nativeIdentity: ByteArray
        get() = nativeIdentityValue.copyOf()

    val mbaWords: List<MbaWord>
        get() = shardsValue[MEASUREMENT_SHARD_INDEX].mbaWords

    /** MBA projection of every shard, in emission order (root first). */
    fun shardMbaWords(): List<List<MbaWord>> =
        shardsValue.map { shard -> shard.mbaWords }

    /** Effective shard count including the root shard. */
    fun shardCount(): Int = shardsValue.size

    /** Static mask master shared by every shard mask derivation. */
    fun maskRMaster(): ByteArray = maskRMasterValue.copyOf()

    /** Static half key of shard [index], in emission order (root first). */
    fun cmKeyAt(index: Int): ByteArray = shardsValue[index].cmKey.copyOf()

    /** Static half of the QpMethod shard; keys the image measurement commitment. */
    internal val measurementKey: ByteArray
        get() = shardsValue[MEASUREMENT_SHARD_INDEX].cmKey.copyOf()

    /** Build-known domain-separated commitment mixed into the specialization digest. */
    fun commitment(): ByteArray = packCommitmentValue.copyOf()

    private val sealedBlobs = LinkedHashMap<String, ByteArray>()

    @Volatile
    private var wiped = false

    /**
     * Seals every shard under `HMAC(cmKey, imageCommitment)` and caches the
     * packed blob for one compiled platform artifact. Idempotent per platform.
     */
    @Synchronized
    fun sealForPlatform(platform: String, imageCommitment: ByteArray): ByteArray {
        requireLive()
        require(imageCommitment.size == QP_SECRET_PACK_SEED_SIZE) {
            "Qp image commitment must be ${QP_SECRET_PACK_SEED_SIZE} bytes"
        }
        sealedBlobs[platform]?.let { return it.copyOf() }
        val random = java.security.SecureRandom()
        val mac = Mac.getInstance("HmacSHA256")
        val out = java.io.ByteArrayOutputStream()
        try {
            out.write(SEALED_PACK_MAGIC)
            out.write(u16be(shardsValue.size))
            for (shard in shardsValue) {
                mac.init(SecretKeySpec(shard.cmKey, "HmacSHA256"))
                val shardKey = mac.doFinal(imageCommitment)
                val nonce = ByteArray(QpPageCodec.NONCE_SIZE)
                random.nextBytes(nonce)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(shardKey, "AES"),
                    GCMParameterSpec(QpPageCodec.GCM_TAG_SIZE * 8, nonce),
                )
                cipher.updateAAD(SECRET_PACK_WRAP_AAD)
                val sealed = cipher.doFinal(shard.plaintext)
                out.write(byteArrayOf(shard.kind.toByte(), 0))
                out.write(u16be(nonce.size))
                out.write(u32be(sealed.size))
                out.write(nonce)
                out.write(sealed)
                Arrays.fill(shardKey, 0)
                Arrays.fill(sealed, 0)
            }
            val blob = out.toByteArray()
            sealedBlobs[platform] = blob
            return blob.copyOf()
        } finally {
            out.reset()
        }
    }

    /** Sealed blob per compiled platform; empty until [sealForPlatform] ran. */
    @Synchronized
    fun blobByPlatform(): Map<String, ByteArray> =
        sealedBlobs.mapValues { (_, blob) -> blob.copyOf() }

    fun wipe() {
        if (wiped) return
        shardsValue.forEach { shard ->
            Arrays.fill(shard.cmKey, 0)
            Arrays.fill(shard.plaintext, 0)
        }
        Arrays.fill(nativeIdentityValue, 0)
        sealedBlobs.values.forEach { Arrays.fill(it, 0) }
        sealedBlobs.clear()
        Arrays.fill(packCommitmentValue, 0)
        Arrays.fill(maskRMasterValue, 0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "Qp native secret pack literals have been wiped" }
    }

    internal companion object {
        private val SECRET_PACK_LITERAL_COMMITMENT_DOMAIN =
            "javashroud-qp-secret-pack-commitment-v6".toByteArray(Charsets.US_ASCII)
        private val SEALED_PACK_MAGIC = byteArrayOf(0x6A, 0)
        private const val MEASUREMENT_SHARD_INDEX = 1
        private const val SHARD_KIND_ROOT = 0

        /** Method slots per shard bucket; bounds the blast radius of one shard. */
        private const val METHOD_BUCKET_SLOTS = 16

        internal fun prepare(
            pack: NativeVmSecretPack,
            random: java.util.Random,
            cryptoDomain: ByteArray,
            layoutDigest: ByteArray,
        ): NativeSecretPackLiterals {
            require(cryptoDomain.size == QP_SECRET_PACK_SEED_SIZE) { "Qp crypto domain must be 32 bytes" }
            require(layoutDigest.size == QP_SECRET_PACK_SEED_SIZE) { "Qp layout digest must be 32 bytes" }
            val slots = pack.slotsForSpecialization()
            val slotIds = IntArray(pack.slotCount)
            val byKind = LinkedHashMap<Int, MutableList<Pair<Int, ByteArray>>>()
            try {
                val identity = pack.nativeIdentity
                for ((index, slot) in slots.withIndex()) {
                    val slotId = slot.slotId
                    slotIds[index] = slotId
                    val seed = slot.copySeedForSpecialization()
                    byKind.getOrPut(pack.kindOfSlot(slotId)) { ArrayList() } += slotId to seed
                }
                // Fixed shard order: root, then method buckets (16 slots each,
                // capping the blast radius of any single shard break), then the
                // remaining kinds one shard each.
                val rootPlain = ArrayList<Byte>(QP_SECRET_PACK_SEED_SIZE * 4)
                identity.forEach { rootPlain += it }
                u32be(pack.slotCount).forEach { rootPlain += it }
                cryptoDomain.forEach { rootPlain += it }
                layoutDigest.forEach { rootPlain += it }
                val shards = ArrayList<ShardMaterial>()
                shards += ShardMaterial(
                    kind = SHARD_KIND_ROOT,
                    cmKey = newCmKey(random),
                    plaintext = rootPlain.toByteArray(),
                    mbaWords = emptyList(),
                )
                for (kind in 1..4) {
                    val entries = byKind[kind].orEmpty().sortedBy { it.first }
                    val buckets = if (kind == QpResourceKind.QpMethod.id) {
                        entries.chunked(METHOD_BUCKET_SLOTS)
                    } else {
                        listOf(entries)
                    }
                    for (bucket in buckets) {
                        val plain = ArrayList<Byte>(5 + bucket.size * (4 + QP_SECRET_PACK_SEED_SIZE))
                        plain += kind.toByte()
                        u32be(bucket.size).forEach { plain += it }
                        for ((slotId, seed) in bucket) {
                            u32be(slotId).forEach { plain += it }
                            seed.forEach { plain += it }
                        }
                        shards += ShardMaterial(
                            kind = kind,
                            cmKey = newCmKey(random),
                            plaintext = plain.toByteArray(),
                            mbaWords = emptyList(),
                        )
                    }
                }
                for (index in shards.indices) {
                    val shard = shards[index]
                    shards[index] = ShardMaterial(
                        kind = shard.kind,
                        cmKey = shard.cmKey,
                        plaintext = shard.plaintext,
                        mbaWords = mbaWordsFor(shard.cmKey, random),
                    )
                }
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                digest.update(SECRET_PACK_LITERAL_COMMITMENT_DOMAIN)
                digest.update(identity)
                digest.update(u32be(pack.slotCount))
                for ((slotId, seed) in byKind.values.flatten().sortedBy { it.first }) {
                    digest.update(u32be(slotId))
                    digest.update(seed)
                }
                digest.update(cryptoDomain)
                digest.update(layoutDigest)
                val commitment = digest.digest()
                Arrays.fill(identity, 0)
                val maskRMaster = ByteArray(QP_SECRET_PACK_SEED_SIZE)
                random.nextBytes(maskRMaster)
                return NativeSecretPackLiterals(
                    nativeIdentityValue = pack.nativeIdentity,
                    shardsValue = shards,
                    slotIdsValue = slotIds,
                    packCommitmentValue = commitment,
                    maskRMasterValue = maskRMaster,
                )
            } finally {
                byKind.values.forEach { entries -> entries.forEach { (_, seed) -> Arrays.fill(seed, 0) } }
            }
        }

        private fun newCmKey(random: java.util.Random): ByteArray {
            val key = ByteArray(QP_SECRET_PACK_SEED_SIZE)
            random.nextBytes(key)
            return key
        }

        private fun mbaWordsFor(cmKey: ByteArray, random: java.util.Random): List<MbaWord> {
            val words = ArrayList<MbaWord>(8)
            for (index in 0 until 8) {
                val offset = index * 4
                val word = ((cmKey[offset].toInt() and 0xFF) shl 24) or
                    ((cmKey[offset + 1].toInt() and 0xFF) shl 16) or
                    ((cmKey[offset + 2].toInt() and 0xFF) shl 8) or
                    (cmKey[offset + 3].toInt() and 0xFF)
                var multiplier = random.nextInt()
                if (multiplier == 0) multiplier = 1
                var factor = random.nextInt()
                if (factor == 0) factor = 3
                val addend = word - multiplier * factor
                words += MbaWord(multiplier, factor, addend)
            }
            return words
        }
    }
}

private fun u16be(value: Int): ByteArray = byteArrayOf(
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte(),
)

private fun u32be(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xFF).toByte(),
    ((value ushr 16) and 0xFF).toByte(),
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte(),
)

internal object NativeImageMeasurement {
    private const val PE_RELOC_DIRECTORY = 5
    private const val PE_IAT_DIRECTORY = 12
    private const val ELF_SHT_REL = 9
    private const val ELF_SHT_RELA = 4

    internal fun digest(bytes: ByteArray): ByteArray {
        val working = bytes.copyOf()
        try {
            // File-backed measurement: ASLR does not rewrite the on-disk image, so
            // reloc/IAT ranges stay in the digest. Only the commitment slot is
            // hashed as zeros so it can be patched after compile.
            zeroCommitmentSlot(working)
            zeroShardMaskRegion(working)
            return java.security.MessageDigest.getInstance("SHA-256").digest(working)
        } finally {
            Arrays.fill(working, 0)
        }
    }

    private fun zeroShardMaskRegion(bytes: ByteArray) {
        // The .jsmk rows are patched with the commitment after this digest is
        // taken; the runtime zeroes the same region, so both sides must hash
        // it as zeros or the measurement will never verify.
        val range = locateSectionRange(bytes, ".jsmk") ?: return
        val offset = range.first
        val size = range.second
        if (offset < 0 || size <= 0 || offset + size > bytes.size) return
        for (index in offset until offset + size) {
            bytes[index] = 0
        }
    }

    internal fun hmacCommitment(wrapKey: ByteArray, digest: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(wrapKey, "HmacSHA256"))
        return mac.doFinal(digest)
    }

    internal fun locateMeasurementSlot(bytes: ByteArray): Int {
        locateJsmsSection(bytes)?.let { offset ->
            require(offset >= 0 && offset + IMAGE_MEASUREMENT_MAGIC.size + 32 <= bytes.size) {
                "Qp image measurement section is truncated"
            }
            val magic = IMAGE_MEASUREMENT_MAGIC
            for (index in magic.indices) {
                require(bytes[offset + index] == magic[index]) { "Qp image measurement section magic is invalid" }
            }
            return offset
        }
        locateUniqueMagic(bytes)?.let { return it }
        return locateZeroedSlot(bytes)
    }

    /** A single magic occurrence anywhere in the image is the slot regardless of slot content. */
    private fun locateUniqueMagic(bytes: ByteArray): Int? {
        val magic = IMAGE_MEASUREMENT_MAGIC
        if (bytes.size < magic.size + 32) return null
        val limit = bytes.size - magic.size - 32
        var found = -1
        var count = 0
        for (index in 0..limit) {
            var match = true
            for (offset in magic.indices) {
                if (bytes[index + offset] != magic[offset]) {
                    match = false
                    break
                }
            }
            if (!match) continue
            count += 1
            found = index
        }
        return if (count == 1) found else null
    }

    internal fun locateZeroedSlot(bytes: ByteArray): Int {
        val magic = IMAGE_MEASUREMENT_MAGIC
        if (bytes.size < magic.size + 32) {
            throw IllegalArgumentException("Qp native artifact is too small for image measurement")
        }
        var found = -1
        val limit = bytes.size - magic.size - 32
        for (index in 0..limit) {
            var match = true
            for (offset in magic.indices) {
                if (bytes[index + offset] != magic[offset]) {
                    match = false
                    break
                }
            }
            if (!match) continue
            var zeros = true
            for (offset in 0 until 32) {
                if (bytes[index + magic.size + offset] != 0.toByte()) {
                    zeros = false
                    break
                }
            }
            if (!zeros) continue
            require(found < 0) { "Qp image measurement magic must be unique" }
            found = index
        }
        require(found >= 0) { "Qp image measurement magic is missing" }
        return found
    }

    private fun zeroCommitmentSlot(bytes: ByteArray) {
        val magic = IMAGE_MEASUREMENT_MAGIC
        if (bytes.size < magic.size + 32) {
            throw IllegalArgumentException("Qp native artifact is too small for image measurement")
        }
        val found = locateMeasurementSlot(bytes)
        val commitmentStart = found + magic.size
        for (offset in 0 until 32) {
            bytes[commitmentStart + offset] = 0
        }
    }

    /**
     * Locates a named PE/ELF section, returning its raw file offset and size.
     * Used for the .jsmk shard-key mask region, which is patched with the
     * image commitment after the measurement slot has been filled.
     */
    internal fun locateSectionRange(bytes: ByteArray, name: String): Pair<Int, Int>? {
        if (isPe64(bytes)) return locatePeSectionRange(bytes, name)
        if (isElf64(bytes)) return locateElfSectionRange(bytes, name)
        return null
    }

    private fun locatePeSectionRange(bytes: ByteArray, name: String): Pair<Int, Int>? {
        val peOffset = readU32(bytes, 0x3C)
        val optionalSize = readU16(bytes, peOffset + 20)
        val sectionCount = readU16(bytes, peOffset + 6)
        if (optionalSize < 112 || sectionCount !in 1..96) return null
        val sectionTable = peOffset + 24 + optionalSize
        val expected = ByteArray(8)
        name.toByteArray(Charsets.US_ASCII).copyInto(expected, endIndex = minOf(name.length, 8))
        for (index in 0 until sectionCount) {
            val section = sectionTable + index * 40
            if (section + 40 > bytes.size) return null
            var match = true
            for (offset in 0 until 8) {
                if (bytes[section + offset] != expected[offset]) {
                    match = false
                    break
                }
            }
            if (!match) continue
            val rawSize = readU32(bytes, section + 16)
            val rawOffset = readU32(bytes, section + 20)
            if (rawOffset < 0 || rawSize <= 0 || rawOffset + rawSize > bytes.size) continue
            return rawOffset to rawSize
        }
        return null
    }

    private fun locateElfSectionRange(bytes: ByteArray, name: String): Pair<Int, Int>? {
        val sectionOffset = readU64Long(bytes, 0x28)
        val sectionEntrySize = readU16(bytes, 0x3A)
        val sectionCount = readU16(bytes, 0x3C)
        val nameIndex = readU16(bytes, 0x3E)
        if (sectionOffset <= 0 || sectionEntrySize < 64 || sectionCount !in 1..1024) return null
        if (nameIndex !in 0 until sectionCount) return null
        val nameSection = sectionOffset + nameIndex.toLong() * sectionEntrySize.toLong()
        if (nameSection + 64 > bytes.size) return null
        val nameTableOffset = readU64Long(bytes, nameSection.toInt() + 24)
        val nameTableSize = readU64Long(bytes, nameSection.toInt() + 32)
        if (nameTableOffset <= 0 || nameTableSize <= 0) return null
        val needle = name.toByteArray(Charsets.US_ASCII)
        for (index in 0 until sectionCount) {
            val section = sectionOffset + index.toLong() * sectionEntrySize.toLong()
            if (section + 64 > bytes.size) return null
            val nameOff = readU32(bytes, section.toInt()).toLong() and 0xFFFFFFFFL
            if (!elfNameEquals(bytes, nameTableOffset, nameTableSize, nameOff, needle)) continue
            val fileOffset = readU64Long(bytes, section.toInt() + 24)
            val size = readU64Long(bytes, section.toInt() + 32)
            if (fileOffset <= 0 || size <= 0 || fileOffset + size > bytes.size) continue
            return fileOffset.toInt() to size.toInt()
        }
        return null
    }

    /**
     * Commitment-chains the shard key halves: each 32-byte row of the .jsmk
     * region is XORed with the patched image commitment, so the effective
     * shard key only exists after a volatile runtime read.
     */
    /**
     * Commitment-chains the shard key halves by content: each pre-mask row
     * (cm ^ R) is located in the image and XORed in place with the patched
     * image commitment. Section-header location is deliberately avoided -
     * linkers may home or alias custom sections, and the runtime reads the
     * array by symbol address, so the patch must follow the content.
     */
    internal fun patchShardKeyMask(
        bytes: ByteArray,
        commitment: ByteArray,
        shardCount: Int,
        maskedRows: List<ByteArray>,
    ): Boolean {
        if (shardCount <= 0) return true
        if (maskedRows.size != shardCount) return false
        // The patch must land inside the .jsmk section: the runtime reads the
        // array by symbol address, so a content match outside the section would
        // modify unrelated bytes and leave the real keys unchained.
        val section = locateSectionRange(bytes, ".jsmk") ?: return false
        val secOffset = section.first
        val secSize = section.second
        if (secSize < shardCount * 32) return false
        for (row in maskedRows) {
            var found = -1
            outer@ for (i in 0..secSize - 32) {
                for (j in 0 until 32) {
                    if (bytes[secOffset + i + j] != row[j]) continue@outer
                }
                found = secOffset + i
                break
            }
            if (found < 0) return false
            for (j in 0 until 32) {
                bytes[found + j] = ((bytes[found + j].toInt() xor commitment[j % 32].toInt()) and 0xFF).toByte()
            }
        }
        return true
    }

    private fun indexOfBytes(bytes: ByteArray, needle: ByteArray): Int? {
        if (needle.isEmpty() || bytes.size < needle.size) return null
        outer@ for (i in 0..bytes.size - needle.size) {
            for (j in needle.indices) {
                if (bytes[i + j] != needle[j]) continue@outer
            }
            return i
        }
        return null
    }
    /** Derives the per-shard mask; must byte-match the runtime shard_mask_r. */
    internal fun shardMask(maskRMaster: ByteArray, shard: Int): ByteArray {
        val mask = ByteArray(32)
        for (j in 0 until 32) {
            mask[j] = (maskRMaster[(j + 7 * shard + 3) % 32].toInt() xor shard).toByte()
        }
        return mask
    }

    private fun locateJsmsSection(bytes: ByteArray): Int? {
        if (isPe64(bytes)) return locatePeSection(bytes, ".jsms")
        if (isElf64(bytes)) return locateElfSection(bytes, ".jsms")
        return null
    }

    private fun locatePeSection(bytes: ByteArray, name: String): Int? {
        val peOffset = readU32(bytes, 0x3C)
        val optionalSize = readU16(bytes, peOffset + 20)
        val sectionCount = readU16(bytes, peOffset + 6)
        if (optionalSize < 112 || sectionCount !in 1..96) return null
        val sectionTable = peOffset + 24 + optionalSize
        val expected = ByteArray(8)
        name.toByteArray(Charsets.US_ASCII).copyInto(expected, endIndex = minOf(name.length, 8))
        for (index in 0 until sectionCount) {
            val section = sectionTable + index * 40
            if (section + 40 > bytes.size) return null
            var match = true
            for (offset in 0 until 8) {
                if (bytes[section + offset] != expected[offset]) {
                    match = false
                    break
                }
            }
            if (!match) continue
            val rawSize = readU32(bytes, section + 16)
            val rawOffset = readU32(bytes, section + 20)
            if (rawOffset < 0 || rawSize < IMAGE_MEASUREMENT_MAGIC.size + 32) continue
            if (rawOffset + rawSize > bytes.size) continue
            return scanSlotInRange(bytes, rawOffset, rawSize)
        }
        return null
    }

    private fun locateElfSection(bytes: ByteArray, name: String): Int? {
        val sectionOffset = readU64Long(bytes, 0x28)
        val sectionEntrySize = readU16(bytes, 0x3A)
        val sectionCount = readU16(bytes, 0x3C)
        val nameIndex = readU16(bytes, 0x3E)
        if (sectionOffset <= 0L || sectionEntrySize < 64 || sectionCount !in 1..1024) return null
        if (nameIndex !in 0 until sectionCount) return null
        val nameSection = sectionOffset + nameIndex.toLong() * sectionEntrySize.toLong()
        if (nameSection + 64 > bytes.size) return null
        val nameTableOffset = readU64Long(bytes, nameSection.toInt() + 24)
        val nameTableSize = readU64Long(bytes, nameSection.toInt() + 32)
        if (nameTableOffset <= 0L || nameTableSize <= 0L) return null
        val needle = name.toByteArray(Charsets.US_ASCII)
        for (index in 0 until sectionCount) {
            val section = sectionOffset + index.toLong() * sectionEntrySize.toLong()
            if (section + 64 > bytes.size) return null
            val nameOff = readU32(bytes, section.toInt()).toLong() and 0xFFFFFFFFL
            if (!elfNameEquals(bytes, nameTableOffset, nameTableSize, nameOff, needle)) continue
            val fileOffset = readU64Long(bytes, section.toInt() + 24)
            val size = readU64Long(bytes, section.toInt() + 32)
            if (fileOffset <= 0L || size < IMAGE_MEASUREMENT_MAGIC.size + 32L) continue
            if (fileOffset + size > bytes.size) continue
            return scanSlotInRange(bytes, fileOffset.toInt(), size.toInt())
        }
        return null
    }

    private fun scanSlotInRange(bytes: ByteArray, start: Int, size: Int): Int? {
        val magic = IMAGE_MEASUREMENT_MAGIC
        if (size < magic.size + 32) return null
        val limit = start + size - magic.size - 32
        for (index in start..limit) {
            var match = true
            for (offset in magic.indices) {
                if (bytes[index + offset] != magic[offset]) {
                    match = false
                    break
                }
            }
            if (match) return index
        }
        return null
    }

    private fun elfNameEquals(bytes: ByteArray, tableOffset: Long, tableSize: Long, nameOff: Long, needle: ByteArray): Boolean {
        if (nameOff < 0L || nameOff >= tableSize) return false
        val start = tableOffset + nameOff
        if (start + needle.size + 1 > bytes.size) return false
        for (index in needle.indices) {
            if (bytes[start.toInt() + index] != needle[index]) return false
        }
        return bytes[start.toInt() + needle.size].toInt() == 0
    }

    private fun isPe64(bytes: ByteArray): Boolean {
        if (bytes.size < 0x40 || bytes[0] != 'M'.code.toByte() || bytes[1] != 'Z'.code.toByte()) return false
        val peOffset = readU32(bytes, 0x3C)
        if (peOffset < 0 || peOffset + 24 + 112 > bytes.size) return false
        if (bytes[peOffset] != 'P'.code.toByte() || bytes[peOffset + 1] != 'E'.code.toByte()) return false
        if (bytes[peOffset + 2].toInt() != 0 || bytes[peOffset + 3].toInt() != 0) return false
        return readU16(bytes, peOffset + 4) == 0x8664 && readU16(bytes, peOffset + 24) == 0x20B
    }

    private fun isElf64(bytes: ByteArray): Boolean =
        bytes.size >= 64 &&
            bytes[0] == 0x7F.toByte() &&
            bytes[1] == 'E'.code.toByte() &&
            bytes[2] == 'L'.code.toByte() &&
            bytes[3] == 'F'.code.toByte() &&
            bytes[4].toInt() == 2 &&
            bytes[5].toInt() == 1

    private fun zeroPeRelocAndIat(bytes: ByteArray) {
        val peOffset = readU32(bytes, 0x3C)
        val optionalSize = readU16(bytes, peOffset + 20)
        val optionalOffset = peOffset + 24
        val sectionCount = readU16(bytes, peOffset + 6)
        if (optionalSize < 112 || sectionCount !in 1..96) return
        val directoryOffset = optionalOffset + 112
        val numberOfRvaAndSizes = if (optionalSize >= 112 + 4) readU32(bytes, optionalOffset + 108) else 0
        val sectionTable = optionalOffset + optionalSize
        zeroPeDirectory(bytes, directoryOffset, numberOfRvaAndSizes, PE_RELOC_DIRECTORY, sectionTable, sectionCount)
        zeroPeDirectory(bytes, directoryOffset, numberOfRvaAndSizes, PE_IAT_DIRECTORY, sectionTable, sectionCount)
    }

    private fun zeroPeDirectory(
        bytes: ByteArray,
        directoryOffset: Int,
        numberOfRvaAndSizes: Int,
        index: Int,
        sectionTable: Int,
        sectionCount: Int,
    ) {
        if (index >= numberOfRvaAndSizes) return
        val entry = directoryOffset + index * 8
        if (entry + 8 > bytes.size) return
        val rva = readU32(bytes, entry)
        val size = readU32(bytes, entry + 4)
        if (rva == 0 || size == 0) return
        val fileOffset = rvaToFileOffset(bytes, sectionTable, sectionCount, rva) ?: return
        zeroRange(bytes, fileOffset, size)
    }

    private fun rvaToFileOffset(bytes: ByteArray, sectionTable: Int, sectionCount: Int, rva: Int): Int? {
        for (index in 0 until sectionCount) {
            val section = sectionTable + index * 40
            if (section + 40 > bytes.size) return null
            val virtualSize = readU32(bytes, section + 8)
            val virtualAddress = readU32(bytes, section + 12)
            val rawSize = readU32(bytes, section + 16)
            val rawOffset = readU32(bytes, section + 20)
            val span = unsignedMax(virtualSize, rawSize)
            if (Integer.compareUnsigned(rva, virtualAddress) >= 0 &&
                Integer.compareUnsigned(rva - virtualAddress, span) < 0
            ) {
                val offset = rawOffset + (rva - virtualAddress)
                if (offset < 0 || offset >= bytes.size) return null
                return offset
            }
        }
        return null
    }

    private fun unsignedMax(left: Int, right: Int): Int =
        if (Integer.compareUnsigned(left, right) >= 0) left else right

    private fun zeroElfRelocations(bytes: ByteArray) {
        val sectionOffset = readU64(bytes, 0x28)
        val sectionEntrySize = readU16(bytes, 0x3A)
        val sectionCount = readU16(bytes, 0x3C)
        if (sectionOffset <= 0 || sectionEntrySize < 64 || sectionCount !in 1..1024) return
        for (index in 0 until sectionCount) {
            val section = sectionOffset + index.toLong() * sectionEntrySize.toLong()
            if (section < 0 || section + 64 > bytes.size) return
            val type = readU32(bytes, section.toInt() + 4)
            if (type != ELF_SHT_REL && type != ELF_SHT_RELA) continue
            val fileOffset = readU64(bytes, section.toInt() + 24)
            val size = readU64(bytes, section.toInt() + 32)
            if (fileOffset <= 0 || size <= 0) continue
            zeroRange(bytes, fileOffset, size)
        }
    }

    private fun zeroRange(bytes: ByteArray, offset: Int, size: Int) {
        if (offset < 0 || size <= 0) return
        val end = offset.toLong() + size.toLong()
        if (end > bytes.size) return
        for (index in offset until offset + size) {
            bytes[index] = 0
        }
    }

    private fun readU16(bytes: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 2 > bytes.size) return 0
        return (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)
    }

    private fun readU32(bytes: ByteArray, offset: Int): Int {
        if (offset < 0 || offset + 4 > bytes.size) return 0
        return (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun readU64(bytes: ByteArray, offset: Int): Int {
        val value = readU64Long(bytes, offset)
        if (value <= 0L || value > Int.MAX_VALUE) return 0
        return value.toInt()
    }

    private fun readU64Long(bytes: ByteArray, offset: Int): Long {
        if (offset < 0 || offset + 8 > bytes.size) return 0L
        val low = readU32(bytes, offset).toLong() and 0xFFFFFFFFL
        val high = readU32(bytes, offset + 4).toLong() and 0xFFFFFFFFL
        return (high shl 32) or low
    }
}
