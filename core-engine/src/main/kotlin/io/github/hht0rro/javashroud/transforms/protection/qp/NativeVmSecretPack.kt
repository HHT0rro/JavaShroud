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

private val SECRET_PACK_ROOT_DOMAIN = "javashroud-qp-secret-pack-root-v5".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_SLOT_DOMAIN = "javashroud-qp-secret-slot-v5".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_COMMITMENT_DOMAIN = "javashroud-qp-secret-commitment-v5".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_PAGE_KEY_DOMAIN = "javashroud-qp-page-key-v5".toByteArray(Charsets.US_ASCII)
private val SECRET_PACK_NATIVE_IDENTITY_DOMAIN = "javashroud-qp-native-identity-v5".toByteArray(Charsets.US_ASCII)
internal val SECRET_PACK_WRAP_AAD = "javashroud-qp-secret-wrap-v5".toByteArray(Charsets.US_ASCII)
internal val IMAGE_MEASUREMENT_MAGIC: ByteArray = byteArrayOf(
    'J'.code.toByte(),
    'S'.code.toByte(),
    'I'.code.toByte(),
    'M'.code.toByte(),
    0x01,
    'v'.code.toByte(),
    '5'.code.toByte(),
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

internal data class MbaWord(val multiplier: Int, val factor: Int, val addend: Int)

/**
 * Compile-only AEAD projection of one sealed [NativeVmSecretPack].
 *
 * Slot seeds, VM crypto domain, and layout digest are sealed with a random
 * wrap key. The wrap key is emitted only as eight MBA immediates so the
 * generated source never contains a contiguous 32-byte secret array.
 */
internal class NativeSecretPackLiterals private constructor(
    private val nativeIdentityValue: ByteArray,
    private val wrapKeyValue: ByteArray,
    private val nonceValue: ByteArray,
    private val wrappedValue: ByteArray,
    private val mbaWordsValue: List<MbaWord>,
    private val slotIdsValue: IntArray,
    private val commitmentValue: ByteArray,
) {
    val slotCount: Int
        get() = slotIdsValue.size

    val nativeIdentity: ByteArray
        get() = nativeIdentityValue.copyOf()

    val wrapKey: ByteArray
        get() = wrapKeyValue.copyOf()

    val nonce: ByteArray
        get() = nonceValue.copyOf()

    val wrapped: ByteArray
        get() = wrappedValue.copyOf()

    val mbaWords: List<MbaWord>
        get() = mbaWordsValue

    fun slotIdAt(index: Int): Int = slotIdsValue[index]

    fun commitment(): ByteArray = commitmentValue.copyOf()

    fun wipe() {
        Arrays.fill(nativeIdentityValue, 0)
        Arrays.fill(wrapKeyValue, 0)
        Arrays.fill(nonceValue, 0)
        Arrays.fill(wrappedValue, 0)
        Arrays.fill(commitmentValue, 0)
    }

    internal companion object {
        private val SECRET_PACK_LITERAL_COMMITMENT_DOMAIN =
            "javashroud-qp-secret-pack-commitment-v5".toByteArray(Charsets.US_ASCII)

        internal fun prepare(
            pack: NativeVmSecretPack,
            random: java.util.Random,
            cryptoDomain: ByteArray,
            layoutDigest: ByteArray,
        ): NativeSecretPackLiterals {
            require(cryptoDomain.size == QP_SECRET_PACK_SEED_SIZE) { "Qp crypto domain must be 32 bytes" }
            require(layoutDigest.size == QP_SECRET_PACK_SEED_SIZE) { "Qp layout digest must be 32 bytes" }
            val wrapKey = ByteArray(QP_SECRET_PACK_SEED_SIZE)
            val nonce = ByteArray(QpPageCodec.NONCE_SIZE)
            random.nextBytes(wrapKey)
            random.nextBytes(nonce)
            val slotIds = IntArray(pack.slotCount)
            val seeds = ArrayList<ByteArray>(pack.slotCount)
            val plaintext = ArrayList<Byte>()
            try {
                val identity = pack.nativeIdentity
                identity.forEach { plaintext += it }
                u32be(pack.slotCount).forEach { plaintext += it }
                for (index in 0 until pack.slotCount) {
                    val slot = pack.slotsForSpecialization()[index]
                    slotIds[index] = slot.slotId
                    val seed = slot.copySeedForSpecialization()
                    seeds += seed
                    u32be(slot.slotId).forEach { plaintext += it }
                    seed.forEach { plaintext += it }
                }
                cryptoDomain.forEach { plaintext += it }
                layoutDigest.forEach { plaintext += it }
                val plainBytes = plaintext.toByteArray()
                val wrapped = try {
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(
                        Cipher.ENCRYPT_MODE,
                        SecretKeySpec(wrapKey, "AES"),
                        GCMParameterSpec(QpPageCodec.GCM_TAG_SIZE * 8, nonce),
                    )
                    cipher.updateAAD(SECRET_PACK_WRAP_AAD)
                    cipher.doFinal(plainBytes)
                } finally {
                    Arrays.fill(plainBytes, 0)
                }
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                digest.update(SECRET_PACK_LITERAL_COMMITMENT_DOMAIN)
                digest.update(identity)
                digest.update(u32be(pack.slotCount))
                for (index in 0 until pack.slotCount) {
                    digest.update(u32be(slotIds[index]))
                    digest.update(seeds[index])
                }
                digest.update(cryptoDomain)
                digest.update(layoutDigest)
                val commitment = digest.digest()
                Arrays.fill(identity, 0)
                return NativeSecretPackLiterals(
                    nativeIdentityValue = pack.nativeIdentity,
                    wrapKeyValue = wrapKey,
                    nonceValue = nonce,
                    wrappedValue = wrapped,
                    mbaWordsValue = mbaWordsFor(wrapKey, random),
                    slotIdsValue = slotIds,
                    commitmentValue = commitment,
                )
            } catch (error: Throwable) {
                Arrays.fill(wrapKey, 0)
                Arrays.fill(nonce, 0)
                throw error
            } finally {
                seeds.forEach { Arrays.fill(it, 0) }
            }
        }

        private fun mbaWordsFor(wrapKey: ByteArray, random: java.util.Random): List<MbaWord> {
            val words = ArrayList<MbaWord>(8)
            for (index in 0 until 8) {
                val offset = index * 4
                val word = ((wrapKey[offset].toInt() and 0xFF) shl 24) or
                    ((wrapKey[offset + 1].toInt() and 0xFF) shl 16) or
                    ((wrapKey[offset + 2].toInt() and 0xFF) shl 8) or
                    (wrapKey[offset + 3].toInt() and 0xFF)
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
            return java.security.MessageDigest.getInstance("SHA-256").digest(working)
        } finally {
            Arrays.fill(working, 0)
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
