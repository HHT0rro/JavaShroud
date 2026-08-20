package io.github.hht0rro.javashroud.transforms.protection.aken

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays

/**
 * One final artifact entry in AKEN v4's build-only canonical representation.
 *
 * The entry makes a defensive copy of its bytes. It represents final output
 * data only; it does not retain or expose any page DEK.
 */
class AkenArtifactEntry(
    val name: String,
    bytes: ByteArray,
) {
    private val bytesValue = bytes.copyOf()

    init {
        require(name.isNotEmpty() && '\u0000' !in name) {
            "AKEN artifact entry name must be non-empty and NUL-free"
        }
    }

    val byteSize: Int
        get() = bytesValue.size

    fun copyBytes(): ByteArray = bytesValue.copyOf()

    internal fun copyBytesForCommitment(): ByteArray = bytesValue.copyOf()
}

/**
 * A root-commitment shard range in one final entry. The interval is
 * `[offset, offset + length)`. The range is zeroed during canonical hashing,
 * then populated with a deterministic, non-secret shard derived from the
 * canonical commitment itself.
 */
data class AkenRootShardRange(
    val entryName: String,
    val offset: Int,
    val length: Int,
) {
    init {
        require(entryName.isNotEmpty() && '\u0000' !in entryName) {
            "AKEN root shard entry name must be non-empty and NUL-free"
        }
        require(offset >= 0) { "AKEN root shard offset must be non-negative" }
        require(length > 0) { "AKEN root shard length must be positive" }
    }

    internal val endExclusive: Long
        get() = offset.toLong() + length.toLong()
}

/**
 * The only byte classes which may be zeroed in the canonical artifact view.
 *
 * [HighValuePayload] covers the complete physical bytes of one AKEN page. It
 * breaks `canonical commitment -> AEAD AAD -> encrypted page -> canonical
 * commitment` without making those bytes unauthenticated: the page remains a
 * full-payload [AkenIntegrityMesh] leaf.
 *
 * [PerPageDescriptor] is reserved for a future emitted page descriptor/proof
 * record. Such a record contains the commitment and Merkle data, therefore it
 * must be explicitly declared as self-referential before it is written. This
 * enum deliberately has no generic "other" value.
 */
enum class AkenCanonicalExclusionKind(
    internal val framingId: Int,
) {
    HighValuePayload(2),
    PerPageDescriptor(3),
}

/**
 * One declared self-referential byte interval in a final writer-equivalent
 * entry. The interval is `[offset, offset + length)`.
 *
 * The range geometry and [kind] are part of the canonical digest framing. This
 * means an emitter cannot move, grow, shrink, or reinterpret an exclusion
 * without changing the artifact commitment.
 */
data class AkenCanonicalExclusionRange(
    val entryName: String,
    val offset: Int,
    val length: Int,
    val kind: AkenCanonicalExclusionKind,
) {
    init {
        require(entryName.isNotEmpty() && '\u0000' !in entryName) {
            "AKEN canonical exclusion entry name must be non-empty and NUL-free"
        }
        require(offset >= 0) { "AKEN canonical exclusion offset must be non-negative" }
        require(length > 0) { "AKEN canonical exclusion length must be positive" }
    }

    internal val endExclusive: Long
        get() = offset.toLong() + length.toLong()
}

/**
 * Complete pre-sealing reservation for one final writer entry.
 *
 * [canonicalBytes] must contain the final bytes for every non-excluded span;
 * bytes inside declared root-shard and self-referential ranges are ignored by
 * [AkenArtifactCommitment.reserve] and may therefore remain zero placeholders.
 * The final writer must emit exactly [entryLength] bytes under [entryName].
 * This value is build-only and is not a runtime catalog.
 */
class AkenCanonicalReservation(
    val entryName: String,
    canonicalBytes: ByteArray,
    val rootShardRanges: List<AkenRootShardRange> = emptyList(),
    val selfReferentialRanges: List<AkenCanonicalExclusionRange> = emptyList(),
) {
    private val canonicalBytesValue = canonicalBytes.copyOf()

    init {
        require(entryName.isNotEmpty() && '\u0000' !in entryName) {
            "AKEN canonical reservation entry name must be non-empty and NUL-free"
        }
        require(rootShardRanges.all { it.entryName == entryName }) {
            "AKEN canonical reservation root shard entry name mismatch"
        }
        require(selfReferentialRanges.all { it.entryName == entryName }) {
            "AKEN canonical reservation exclusion entry name mismatch"
        }
    }

    val entryLength: Int
        get() = canonicalBytesValue.size

    /** Defensive-copy view for tests and writer-equivalent build verification. */
    fun copyCanonicalBytes(): ByteArray = canonicalBytesValue.copyOf()

    internal fun copyCanonicalBytesForBuild(): ByteArray = canonicalBytesValue.copyOf()
}

/**
 * SHA-256 over a writer-equivalent, sorted stable `(name, bytes)` entry set.
 *
 * AKEN v4 computes this value exactly once, before encrypting a high-value
 * page. The writer reserves exact final entry names, lengths, and ranges for
 * every self-referential page payload/descriptor and every root shard. Hashing
 * replaces only those declared ranges with zeroes; all other final bytes remain
 * covered. The final page payload is authenticated separately by the page's
 * Merkle leaf, while root shards are checked against their deterministic
 * commitment-derived encoding.
 *
 * There is no temporary JAR digest, no fixed-point/convergence loop, and no
 * boot/root-key fallback in this protocol. A caller must use the same declared
 * geometry when it later verifies final writer-equivalent entries.
 */
class AkenArtifactCommitment private constructor(
    digest: ByteArray,
    rootShardRanges: List<AkenRootShardRange>,
    selfReferentialRanges: List<AkenCanonicalExclusionRange>,
) {
    private val digestValue = digest.copyOf()
    private val rootShardRangesValue = rootShardRanges.toList()
    private val selfReferentialRangesValue = selfReferentialRanges.toList()

    init {
        require(digestValue.size == DIGEST_SIZE) { "AKEN artifact commitment must be 32 bytes" }
    }

    val bytes: ByteArray
        get() = digestValue.copyOf()

    val rootShardRanges: List<AkenRootShardRange>
        get() = rootShardRangesValue.toList()

    /** Declared non-root self-referential ranges; never a runtime resource catalog. */
    val selfReferentialRanges: List<AkenCanonicalExclusionRange>
        get() = selfReferentialRangesValue.toList()

    fun copyBytes(): ByteArray = digestValue.copyOf()

    /**
     * Build-only writer-equivalent check. Page-payload bytes may differ because
     * they are deliberately zeroed for the canonical view; non-excluded bytes
     * and all exclusion geometry must still reproduce this commitment.
     */
    internal fun matchesWriterEquivalentEntriesForBuild(entries: Iterable<AkenArtifactEntry>): Boolean {
        return try {
            val recomputed = compute(
                entries = entries,
                rootShardRanges = rootShardRangesValue,
                selfReferentialRanges = selfReferentialRangesValue,
            )
            val candidate = recomputed.copyBytes()
            try {
                MessageDigest.isEqual(digestValue, candidate)
            } finally {
                Arrays.fill(candidate, 0)
            }
        } catch (_: IllegalArgumentException) {
            false
        } catch (_: IllegalStateException) {
            false
        }
    }

    /**
     * Build-only material for one already-declared root shard. It is public
     * integrity material, not a DEK or a hidden key. The later native evaluator
     * may distribute this value through its generated fragments.
     */
    internal fun copyExpectedRootShardBytesForBuild(range: AkenRootShardRange): ByteArray {
        val rangeIndex = rootShardRangesValue.indexOf(range)
        require(rangeIndex >= 0) { "AKEN root shard range is not declared by this commitment" }
        return deriveRootShard(range, rangeIndex)
    }

    /**
     * Check that every emitted root shard matches the canonical commitment.
     * Root-shard bytes are excluded from the commitment to avoid a self-hash
     * loop, so this independent check is required in addition to
     * [matchesWriterEquivalentEntriesForBuild].
     */
    internal fun verifyRootShardsForBuild(entries: Iterable<AkenArtifactEntry>): Boolean {
        if (rootShardRangesValue.isEmpty()) return true
        val entriesByName = LinkedHashMap<String, AkenArtifactEntry>()
        return try {
            entries.forEach { entry ->
                if (entriesByName.put(entry.name, entry) != null) return false
            }
            rootShardRangesValue.forEachIndexed { index, range ->
                val entry = entriesByName[range.entryName] ?: return false
                val bytes = entry.copyBytesForCommitment()
                val expected = deriveRootShard(range, index)
                try {
                    if (range.endExclusive > bytes.size.toLong()) return false
                    if (!constantTimeEquals(bytes, range.offset, expected)) return false
                } finally {
                    Arrays.fill(bytes, 0)
                    Arrays.fill(expected, 0)
                }
            }
            true
        } catch (_: IllegalArgumentException) {
            false
        } catch (_: IllegalStateException) {
            false
        }
    }

    override fun equals(other: Any?): Boolean =
        other is AkenArtifactCommitment &&
            Arrays.equals(digestValue, other.digestValue) &&
            rootShardRangesValue == other.rootShardRangesValue &&
            selfReferentialRangesValue == other.selfReferentialRangesValue

    override fun hashCode(): Int {
        var result = digestValue.contentHashCode()
        result = 31 * result + rootShardRangesValue.hashCode()
        return 31 * result + selfReferentialRangesValue.hashCode()
    }

    override fun toString(): String = "AkenArtifactCommitment(sha256)"

    private fun deriveRootShard(range: AkenRootShardRange, rangeIndex: Int): ByteArray {
        val output = ByteArray(range.length)
        var offset = 0
        var blockIndex = 0
        try {
            while (offset < output.size) {
                val digest = MessageDigest.getInstance("SHA-256")
                digest.update(ROOT_SHARD_DOMAIN)
                digest.update(digestValue)
                updateInt(digest, rangeIndex)
                updateString(digest, range.entryName)
                updateLong(digest, range.offset.toLong())
                updateLong(digest, range.length.toLong())
                updateInt(digest, blockIndex++)
                val block = digest.digest()
                try {
                    val count = minOf(block.size, output.size - offset)
                    block.copyInto(output, destinationOffset = offset, endIndex = count)
                    offset += count
                } finally {
                    Arrays.fill(block, 0)
                }
            }
            return output
        } catch (error: Throwable) {
            Arrays.fill(output, 0)
            throw error
        }
    }

    companion object {
        const val DIGEST_SIZE: Int = 32

        private const val CANONICALIZATION_VERSION = 2
        private const val ROOT_SHARD_FRAMING_ID = 1
        private const val ZERO_BLOCK_SIZE = 1024
        private val DOMAIN = "AKEN-v4-artifact-canonical-commitment".toByteArray(StandardCharsets.US_ASCII)
        private val ROOT_SHARD_DOMAIN = "AKEN-v4-root-shard-material".toByteArray(StandardCharsets.US_ASCII)

        /**
         * Compute the one-pass canonical commitment from final writer-equivalent
         * entries. [selfReferentialRanges] must reserve complete page payloads
         * and any separately emitted commitment/mesh-bearing descriptor bytes.
         */
        /**
         * One-pass pre-sealing API for a writer which already knows its final
         * entry names, entry lengths, page routes, descriptor lengths, and root
         * shard positions, but has not generated the self-referential bytes yet.
         *
         * Each [AkenCanonicalReservation] supplies the final entry size plus all
         * excluded ranges in that entry. Its byte array is intentionally zero
         * filled because those ranges are zeroed by [compute] anyway. The writer
         * must later call [matchesWriterEquivalentEntriesForBuild] with actual
         * final bytes and [verifyRootShardsForBuild] after filling root shards.
         */
        fun reserve(
            entries: Iterable<AkenCanonicalReservation>,
        ): AkenArtifactCommitment {
            val reservations = entries.toList()
            val placeholders = ArrayList<AkenArtifactEntry>(reservations.size)
            try {
                reservations.forEach { reservation ->
                    val bytes = reservation.copyCanonicalBytesForBuild()
                    try {
                        placeholders += AkenArtifactEntry(reservation.entryName, bytes)
                    } finally {
                        Arrays.fill(bytes, 0)
                    }
                }
                return compute(
                    entries = placeholders,
                    rootShardRanges = reservations.flatMap { it.rootShardRanges },
                    selfReferentialRanges = reservations.flatMap { it.selfReferentialRanges },
                )
            } finally {
                placeholders.forEach { entry ->
                    val bytes = entry.copyBytesForCommitment()
                    Arrays.fill(bytes, 0)
                }
            }
        }

        fun compute(
            entries: Iterable<AkenArtifactEntry>,
            rootShardRanges: Iterable<AkenRootShardRange> = emptyList(),
            selfReferentialRanges: Iterable<AkenCanonicalExclusionRange> = emptyList(),
        ): AkenArtifactCommitment {
            val entriesByName = linkedMapOf<String, AkenArtifactEntry>()
            entries.forEach { entry ->
                require(entriesByName.put(entry.name, entry) == null) {
                    "AKEN artifact commitment rejects duplicate entry name: ${entry.name}"
                }
            }
            val normalizedRootShards = normalizeRootShardRanges(entriesByName, rootShardRanges.toList())
            val normalizedSelfReferential = normalizeSelfReferentialRanges(
                entriesByName,
                selfReferentialRanges.toList(),
            )
            val zeroedRanges = normalizeZeroedRanges(
                entriesByName = entriesByName,
                rootShardRanges = normalizedRootShards,
                selfReferentialRanges = normalizedSelfReferential,
            )
            val rangesByEntry = zeroedRanges.groupBy { it.entryName }
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(DOMAIN)
            updateInt(digest, CANONICALIZATION_VERSION)
            updateInt(digest, entriesByName.size)
            updateInt(digest, zeroedRanges.size)
            zeroedRanges.forEach { range ->
                updateInt(digest, range.framingId)
                updateString(digest, range.entryName)
                updateLong(digest, range.offset.toLong())
                updateLong(digest, range.length.toLong())
            }
            entriesByName.values.sortedBy { it.name }.forEach { entry ->
                val bytes = entry.copyBytesForCommitment()
                try {
                    updateString(digest, entry.name)
                    updateLong(digest, bytes.size.toLong())
                    updateZeroedBytes(digest, bytes, rangesByEntry[entry.name].orEmpty())
                } finally {
                    Arrays.fill(bytes, 0)
                }
            }
            return AkenArtifactCommitment(
                digest = digest.digest(),
                rootShardRanges = normalizedRootShards,
                selfReferentialRanges = normalizedSelfReferential,
            )
        }

        private fun normalizeRootShardRanges(
            entriesByName: Map<String, AkenArtifactEntry>,
            ranges: List<AkenRootShardRange>,
        ): List<AkenRootShardRange> {
            val sorted = ranges.sortedWith(
                compareBy<AkenRootShardRange>({ it.entryName }, { it.offset }, { it.length }),
            )
            var previous: AkenRootShardRange? = null
            sorted.forEach { range ->
                val entry = entriesByName[range.entryName]
                    ?: throw IllegalArgumentException("AKEN root shard range references missing entry: ${range.entryName}")
                require(range.endExclusive <= entry.byteSize.toLong()) {
                    "AKEN root shard range exceeds entry bounds: ${range.entryName}@${range.offset}+${range.length}"
                }
                val prior = previous
                if (prior != null && prior.entryName == range.entryName) {
                    require(prior.endExclusive <= range.offset.toLong()) {
                        "AKEN root shard ranges must not overlap in entry: ${range.entryName}"
                    }
                }
                previous = range
            }
            return sorted
        }

        private fun normalizeSelfReferentialRanges(
            entriesByName: Map<String, AkenArtifactEntry>,
            ranges: List<AkenCanonicalExclusionRange>,
        ): List<AkenCanonicalExclusionRange> {
            val sorted = ranges.sortedWith(
                compareBy<AkenCanonicalExclusionRange>(
                    { it.entryName },
                    { it.offset },
                    { it.length },
                    { it.kind.framingId },
                ),
            )
            var previous: AkenCanonicalExclusionRange? = null
            sorted.forEach { range ->
                val entry = entriesByName[range.entryName]
                    ?: throw IllegalArgumentException(
                        "AKEN canonical exclusion references missing entry: ${range.entryName}",
                    )
                require(range.endExclusive <= entry.byteSize.toLong()) {
                    "AKEN canonical exclusion exceeds entry bounds: " +
                        "${range.entryName}@${range.offset}+${range.length}"
                }
                val prior = previous
                if (prior != null && prior.entryName == range.entryName) {
                    require(prior.endExclusive <= range.offset.toLong()) {
                        "AKEN canonical exclusions must not overlap in entry: ${range.entryName}"
                    }
                }
                previous = range
            }
            return sorted
        }

        private fun normalizeZeroedRanges(
            entriesByName: Map<String, AkenArtifactEntry>,
            rootShardRanges: List<AkenRootShardRange>,
            selfReferentialRanges: List<AkenCanonicalExclusionRange>,
        ): List<CanonicalZeroRange> {
            val ranges = ArrayList<CanonicalZeroRange>(rootShardRanges.size + selfReferentialRanges.size)
            rootShardRanges.forEach { range ->
                ranges += CanonicalZeroRange(
                    entryName = range.entryName,
                    offset = range.offset,
                    length = range.length,
                    framingId = ROOT_SHARD_FRAMING_ID,
                )
            }
            selfReferentialRanges.forEach { range ->
                ranges += CanonicalZeroRange(
                    entryName = range.entryName,
                    offset = range.offset,
                    length = range.length,
                    framingId = range.kind.framingId,
                )
            }
            val sorted = ranges.sortedWith(
                compareBy<CanonicalZeroRange>({ it.entryName }, { it.offset }, { it.length }, { it.framingId }),
            )
            var previous: CanonicalZeroRange? = null
            sorted.forEach { range ->
                val entry = entriesByName[range.entryName]
                    ?: throw IllegalArgumentException("AKEN canonical zero range references missing entry: ${range.entryName}")
                require(range.endExclusive <= entry.byteSize.toLong()) {
                    "AKEN canonical zero range exceeds entry bounds: ${range.entryName}@${range.offset}+${range.length}"
                }
                val prior = previous
                if (prior != null && prior.entryName == range.entryName) {
                    require(prior.endExclusive <= range.offset.toLong()) {
                        "AKEN root shard and self-referential ranges must not overlap in entry: ${range.entryName}"
                    }
                }
                previous = range
            }
            return sorted
        }

        private fun updateZeroedBytes(
            digest: MessageDigest,
            bytes: ByteArray,
            ranges: List<CanonicalZeroRange>,
        ) {
            var cursor = 0
            ranges.forEach { range ->
                if (cursor < range.offset) digest.update(bytes, cursor, range.offset - cursor)
                updateZeroes(digest, range.length)
                cursor = range.endExclusive.toInt()
            }
            if (cursor < bytes.size) digest.update(bytes, cursor, bytes.size - cursor)
        }

        private fun updateZeroes(digest: MessageDigest, length: Int) {
            val zeroes = ByteArray(minOf(length, ZERO_BLOCK_SIZE))
            try {
                var remaining = length
                while (remaining > 0) {
                    val count = minOf(remaining, zeroes.size)
                    digest.update(zeroes, 0, count)
                    remaining -= count
                }
            } finally {
                Arrays.fill(zeroes, 0)
            }
        }

        private fun updateString(digest: MessageDigest, value: String) {
            val bytes = value.toByteArray(StandardCharsets.UTF_8)
            try {
                updateInt(digest, bytes.size)
                digest.update(bytes)
            } finally {
                Arrays.fill(bytes, 0)
            }
        }

        private fun updateInt(digest: MessageDigest, value: Int) {
            digest.update((value ushr 24).toByte())
            digest.update((value ushr 16).toByte())
            digest.update((value ushr 8).toByte())
            digest.update(value.toByte())
        }

        private fun updateLong(digest: MessageDigest, value: Long) {
            for (shift in 56 downTo 0 step 8) digest.update((value ushr shift).toByte())
        }

        private fun constantTimeEquals(source: ByteArray, offset: Int, expected: ByteArray): Boolean {
            if (offset < 0 || offset + expected.size > source.size) return false
            var difference = 0
            expected.indices.forEach { index ->
                difference = difference or ((source[offset + index].toInt() xor expected[index].toInt()) and 0xFF)
            }
            return difference == 0
        }

        private data class CanonicalZeroRange(
            val entryName: String,
            val offset: Int,
            val length: Int,
            val framingId: Int,
        ) {
            val endExclusive: Long
                get() = offset.toLong() + length.toLong()
        }
    }
}

/**
 * Identity of exactly one high-value page.  It contains only the current page
 * binding and provides no catalog/traversal API.
 */
class AkenHighValueLeafIdentity private constructor(
    val resourceKind: AkenResourceKind,
    val pageIndex: Int,
    handleEncoding: ByteArray,
    locatorToken: ByteArray,
    evaluatorFingerprint: ByteArray,
    logicalIdentity: ByteArray,
) {
    private val handleEncodingValue = handleEncoding.copyOf()
    private val locatorTokenValue = locatorToken.copyOf()
    private val evaluatorFingerprintValue = evaluatorFingerprint.copyOf()
    private val logicalIdentityValue = logicalIdentity.copyOf()

    init {
        require(pageIndex >= 0) { "AKEN leaf page index must be non-negative" }
        require(handleEncodingValue.size == AkenHandle.ENCODED_HANDLE_SIZE) { "AKEN leaf handle length is invalid" }
        require(locatorTokenValue.size == AkenHandle.LOCATOR_TOKEN_SIZE) { "AKEN leaf locator length is invalid" }
        require(evaluatorFingerprintValue.size == AkenHandle.FINGERPRINT_SIZE) { "AKEN leaf fingerprint length is invalid" }
        require(logicalIdentityValue.isNotEmpty() && logicalIdentityValue.size <= MAX_LOGICAL_IDENTITY_SIZE) {
            "AKEN leaf logical identity length is invalid"
        }
    }

    val handleEncoding: ByteArray
        get() = handleEncodingValue.copyOf()

    val locatorToken: ByteArray
        get() = locatorTokenValue.copyOf()

    val evaluatorFingerprint: ByteArray
        get() = evaluatorFingerprintValue.copyOf()

    val logicalIdentity: ByteArray
        get() = logicalIdentityValue.copyOf()

    fun encode(): ByteArray = ByteArrayOutputStream().use { out ->
        out.write(resourceKind.id)
        writeInt(out, pageIndex)
        out.write(handleEncodingValue)
        out.write(locatorTokenValue)
        out.write(evaluatorFingerprintValue)
        writeFramed(out, logicalIdentityValue)
        out.toByteArray()
    }

    fun matches(handle: AkenHandle): Boolean {
        var encoded: ByteArray? = null
        var locator: ByteArray? = null
        var fingerprint: ByteArray? = null
        return try {
            encoded = handle.encoded
            locator = handle.locatorToken
            fingerprint = handle.evaluatorPlanFingerprint
            handle.resourceKind == resourceKind &&
                handle.pageIndex == pageIndex &&
                Arrays.equals(encoded, handleEncodingValue) &&
                Arrays.equals(locator, locatorTokenValue) &&
                Arrays.equals(fingerprint, evaluatorFingerprintValue)
        } catch (_: IllegalStateException) {
            false
        } finally {
            encoded?.let { Arrays.fill(it, 0) }
            locator?.let { Arrays.fill(it, 0) }
            fingerprint?.let { Arrays.fill(it, 0) }
        }
    }

    override fun equals(other: Any?): Boolean =
        other is AkenHighValueLeafIdentity &&
            resourceKind == other.resourceKind && pageIndex == other.pageIndex &&
            Arrays.equals(handleEncodingValue, other.handleEncodingValue) &&
            Arrays.equals(locatorTokenValue, other.locatorTokenValue) &&
            Arrays.equals(evaluatorFingerprintValue, other.evaluatorFingerprintValue) &&
            Arrays.equals(logicalIdentityValue, other.logicalIdentityValue)

    override fun hashCode(): Int {
        var result = resourceKind.hashCode()
        result = 31 * result + pageIndex
        result = 31 * result + handleEncodingValue.contentHashCode()
        result = 31 * result + locatorTokenValue.contentHashCode()
        result = 31 * result + evaluatorFingerprintValue.contentHashCode()
        return 31 * result + logicalIdentityValue.contentHashCode()
    }

    override fun toString(): String = "AkenHighValueLeafIdentity(kind=${resourceKind.logicalName}, page=$pageIndex)"

    companion object {
        private const val MAX_LOGICAL_IDENTITY_SIZE = 64 * 1024

        fun fromHandle(handle: AkenHandle, logicalIdentity: ByteArray): AkenHighValueLeafIdentity {
            var encoded: ByteArray? = null
            var locator: ByteArray? = null
            var fingerprint: ByteArray? = null
            return try {
                encoded = handle.encoded
                locator = handle.locatorToken
                fingerprint = handle.evaluatorPlanFingerprint
                of(
                    resourceKind = handle.resourceKind,
                    pageIndex = handle.pageIndex,
                    handleEncoding = checkNotNull(encoded),
                    locatorToken = checkNotNull(locator),
                    evaluatorFingerprint = checkNotNull(fingerprint),
                    logicalIdentity = logicalIdentity,
                )
            } finally {
                encoded?.let { Arrays.fill(it, 0) }
                locator?.let { Arrays.fill(it, 0) }
                fingerprint?.let { Arrays.fill(it, 0) }
            }
        }

        fun of(
            resourceKind: AkenResourceKind,
            pageIndex: Int,
            handleEncoding: ByteArray,
            locatorToken: ByteArray,
            evaluatorFingerprint: ByteArray,
            logicalIdentity: ByteArray,
        ): AkenHighValueLeafIdentity = AkenHighValueLeafIdentity(
            resourceKind, pageIndex, handleEncoding, locatorToken, evaluatorFingerprint, logicalIdentity,
        )

        fun decode(encoded: ByteArray): AkenHighValueLeafIdentity {
            val reader = AkenMetadataReader(encoded)
            val kind = AkenResourceKind.fromId(reader.readUnsignedByte("AKEN leaf resource kind"))
                ?: throw IllegalArgumentException("unknown AKEN leaf resource kind")
            val page = reader.readInt("AKEN leaf page index")
            val handle = reader.readFixed(AkenHandle.ENCODED_HANDLE_SIZE, "AKEN leaf handle")
            val locator = reader.readFixed(AkenHandle.LOCATOR_TOKEN_SIZE, "AKEN leaf locator")
            val fingerprint = reader.readFixed(AkenHandle.FINGERPRINT_SIZE, "AKEN leaf fingerprint")
            val logical = reader.readFramed(MAX_LOGICAL_IDENTITY_SIZE, "AKEN leaf logical identity", allowEmpty = false)
            return try {
                reader.requireFullyRead("AKEN leaf identity")
                of(kind, page, handle, locator, fingerprint, logical)
            } finally {
                Arrays.fill(handle, 0)
                Arrays.fill(locator, 0)
                Arrays.fill(fingerprint, 0)
                Arrays.fill(logical, 0)
            }
        }
    }
}

/** Serializable per-page integrity/call-site metadata; never a central directory. */
class AkenSealingProofMetadata private constructor(
    val leafIdentity: AkenHighValueLeafIdentity,
    artifactCommitment: ByteArray,
    meshRoot: ByteArray,
    leafDigest: ByteArray,
    siblings: List<ByteArray>,
    siblingIsLeft: List<Boolean>,
    callSiteProof: ByteArray,
    val codecVariant: String,
    val layoutVariant: String,
) {
    private val artifactCommitmentValue = artifactCommitment.copyOf()
    private val meshRootValue = meshRoot.copyOf()
    private val leafDigestValue = leafDigest.copyOf()
    private val siblingsValue = siblings.map { it.copyOf() }
    private val siblingIsLeftValue = siblingIsLeft.toList()
    private val callSiteProofValue = callSiteProof.copyOf()

    init {
        require(artifactCommitmentValue.size == AkenArtifactCommitment.DIGEST_SIZE) { "AKEN proof commitment length is invalid" }
        require(meshRootValue.size == AkenArtifactCommitment.DIGEST_SIZE) { "AKEN proof root length is invalid" }
        require(leafDigestValue.size == AkenArtifactCommitment.DIGEST_SIZE) { "AKEN proof leaf length is invalid" }
        require(siblingsValue.size == siblingIsLeftValue.size && siblingsValue.size <= MAX_MERKLE_DEPTH) {
            "AKEN proof sibling count is invalid"
        }
        require(siblingsValue.all { it.size == AkenArtifactCommitment.DIGEST_SIZE }) {
            "AKEN proof sibling length is invalid"
        }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "AKEN call-site proof length is invalid"
        }
        validateVariant(codecVariant, "codec")
        validateVariant(layoutVariant, "layout")
    }

    val artifactCanonicalCommitment: ByteArray
        get() = artifactCommitmentValue.copyOf()
    val merkleRoot: ByteArray
        get() = meshRootValue.copyOf()
    val currentLeafDigest: ByteArray
        get() = leafDigestValue.copyOf()
    val siblingDigests: List<ByteArray>
        get() = siblingsValue.map { it.copyOf() }
    val siblingDirections: List<Boolean>
        get() = siblingIsLeftValue.toList()
    val callSiteProof: ByteArray
        get() = callSiteProofValue.copyOf()

    fun encode(): ByteArray = ByteArrayOutputStream().use { out ->
        val identity = leafIdentity.encode()
        try {
            writeFramed(out, identity)
        } finally {
            Arrays.fill(identity, 0)
        }
        out.write(artifactCommitmentValue)
        out.write(meshRootValue)
        out.write(leafDigestValue)
        writeInt(out, siblingsValue.size)
        siblingsValue.indices.forEach { index ->
            out.write(siblingsValue[index])
            out.write(if (siblingIsLeftValue[index]) 1 else 0)
        }
        writeFramed(out, callSiteProofValue)
        writeString(out, codecVariant)
        writeString(out, layoutVariant)
        out.toByteArray()
    }

    companion object {
        private const val MAX_MERKLE_DEPTH = 64
        private const val MAX_CALL_SITE_PROOF_SIZE = 4096
        private const val MAX_VARIANT_SIZE = 256

        fun create(
            leafIdentity: AkenHighValueLeafIdentity,
            artifactCommitment: ByteArray,
            meshRoot: ByteArray,
            leafDigest: ByteArray,
            siblings: List<ByteArray>,
            siblingIsLeft: List<Boolean>,
            callSiteProof: ByteArray,
            codecVariant: String,
            layoutVariant: String,
        ): AkenSealingProofMetadata = AkenSealingProofMetadata(
            leafIdentity, artifactCommitment, meshRoot, leafDigest, siblings, siblingIsLeft,
            callSiteProof, codecVariant, layoutVariant,
        )

        fun decode(encoded: ByteArray): AkenSealingProofMetadata {
            val reader = AkenMetadataReader(encoded)
            var identityBytes: ByteArray? = null
            var commitment: ByteArray? = null
            var root: ByteArray? = null
            var leaf: ByteArray? = null
            var callSiteProof: ByteArray? = null
            val siblings = ArrayList<ByteArray>()
            return try {
                identityBytes = reader.readFramed(MAX_LEAF_IDENTITY_ENCODING_SIZE, "AKEN proof leaf identity", allowEmpty = false)
                val identity = AkenHighValueLeafIdentity.decode(checkNotNull(identityBytes))
                commitment = reader.readFixed(AkenArtifactCommitment.DIGEST_SIZE, "AKEN proof commitment")
                root = reader.readFixed(AkenArtifactCommitment.DIGEST_SIZE, "AKEN proof root")
                leaf = reader.readFixed(AkenArtifactCommitment.DIGEST_SIZE, "AKEN proof leaf")
                val siblingCount = reader.readInt("AKEN proof sibling count")
                require(siblingCount in 0..MAX_MERKLE_DEPTH) { "AKEN proof sibling count is invalid" }
                val directions = ArrayList<Boolean>(siblingCount)
                repeat(siblingCount) {
                    siblings += reader.readFixed(AkenArtifactCommitment.DIGEST_SIZE, "AKEN proof sibling")
                    directions += when (reader.readUnsignedByte("AKEN proof direction")) {
                        0 -> false
                        1 -> true
                        else -> throw IllegalArgumentException("AKEN proof direction is invalid")
                    }
                }
                callSiteProof = reader.readFramed(MAX_CALL_SITE_PROOF_SIZE, "AKEN call-site proof", allowEmpty = false)
                val codec = reader.readString(MAX_VARIANT_SIZE, "AKEN codec variant")
                val layout = reader.readString(MAX_VARIANT_SIZE, "AKEN layout variant")
                reader.requireFullyRead("AKEN proof")
                create(
                    identity,
                    checkNotNull(commitment),
                    checkNotNull(root),
                    checkNotNull(leaf),
                    siblings,
                    directions,
                    checkNotNull(callSiteProof),
                    codec,
                    layout,
                )
            } finally {
                identityBytes?.let { Arrays.fill(it, 0) }
                commitment?.let { Arrays.fill(it, 0) }
                root?.let { Arrays.fill(it, 0) }
                leaf?.let { Arrays.fill(it, 0) }
                callSiteProof?.let { Arrays.fill(it, 0) }
                siblings.forEach { Arrays.fill(it, 0) }
            }
        }

        private fun validateVariant(value: String, label: String) {
            require(value.isNotBlank() && '\u0000' !in value && value.toByteArray(StandardCharsets.UTF_8).size <= MAX_VARIANT_SIZE) {
                "AKEN $label variant is invalid"
            }
        }
    }
}

/** Immutable per-handle route metadata.  It contains no DEK or sibling-page data. */
class AkenRoutingMetadata private constructor(
    val leafIdentity: AkenHighValueLeafIdentity,
    val resourcePath: String,
    val resourceOffset: Int,
    val storedLength: Int,
    val codecVariant: String,
    val layoutVariant: String,
    val logicalBindingPath: String,
) {
    init {
        require(resourceOffset >= 0 && storedLength > 0) { "AKEN route bounds are invalid" }
        requireNormalizedPath(resourcePath, "AKEN route path")
        requireNormalizedPath(logicalBindingPath, "AKEN logical binding path")
        require(codecVariant.isNotBlank() && layoutVariant.isNotBlank()) { "AKEN route variants must be non-blank" }
    }

    val resourceKind: AkenResourceKind
        get() = leafIdentity.resourceKind
    val pageIndex: Int
        get() = leafIdentity.pageIndex
    val handleEncoding: ByteArray
        get() = leafIdentity.handleEncoding
    val locatorToken: ByteArray
        get() = leafIdentity.locatorToken
    val evaluatorFingerprint: ByteArray
        get() = leafIdentity.evaluatorFingerprint

    fun matches(handle: AkenHandle): Boolean = leafIdentity.matches(handle)

    fun encode(): ByteArray = ByteArrayOutputStream().use { out ->
        val identity = leafIdentity.encode()
        try {
            writeFramed(out, identity)
        } finally {
            Arrays.fill(identity, 0)
        }
        writeString(out, resourcePath)
        writeInt(out, resourceOffset)
        writeInt(out, storedLength)
        writeString(out, codecVariant)
        writeString(out, layoutVariant)
        writeString(out, logicalBindingPath)
        out.toByteArray()
    }

    companion object {
        private const val MAX_RESOURCE_PATH_SIZE = 4096
        private const val MAX_VARIANT_SIZE = 256

        fun fromHandle(
            handle: AkenHandle,
            logicalIdentity: ByteArray,
            resourcePath: String,
            resourceOffset: Int,
            storedLength: Int,
            codecVariant: String,
            layoutVariant: String,
            logicalBindingPath: String = resourcePath,
        ): AkenRoutingMetadata = AkenRoutingMetadata(
            AkenHighValueLeafIdentity.fromHandle(handle, logicalIdentity), resourcePath,
            resourceOffset, storedLength, codecVariant, layoutVariant, logicalBindingPath,
        )

        fun decode(encoded: ByteArray): AkenRoutingMetadata {
            val reader = AkenMetadataReader(encoded)
            val identityBytes = reader.readFramed(MAX_LEAF_IDENTITY_ENCODING_SIZE, "AKEN route identity", allowEmpty = false)
            return try {
                val identity = AkenHighValueLeafIdentity.decode(identityBytes)
                val path = reader.readString(MAX_RESOURCE_PATH_SIZE, "AKEN route path")
                val offset = reader.readInt("AKEN route offset")
                val length = reader.readInt("AKEN route length")
                val codec = reader.readString(MAX_VARIANT_SIZE, "AKEN route codec")
                val layout = reader.readString(MAX_VARIANT_SIZE, "AKEN route layout")
                val logicalBindingPath = reader.readString(MAX_RESOURCE_PATH_SIZE, "AKEN logical binding path")
                reader.requireFullyRead("AKEN route")
                AkenRoutingMetadata(identity, path, offset, length, codec, layout, logicalBindingPath)
            } finally {
                Arrays.fill(identityBytes, 0)
            }
        }

        private fun requireNormalizedPath(value: String, label: String) {
            require(value.isNotBlank() && '\u0000' !in value && '\\' !in value) { "$label is invalid" }
            require(
                !value.startsWith('/') &&
                    !value.endsWith('/') &&
                    value.split('/').none { it.isEmpty() || it == "." || it == ".." },
            ) { "$label must be a normalized relative entry name" }
        }
    }
}

/** Build-time factory facade; all returned values are per-handle metadata only. */
object AkenSealingMetadata {
    fun leafIdentity(handle: AkenHandle, logicalIdentity: ByteArray): AkenHighValueLeafIdentity =
        AkenHighValueLeafIdentity.fromHandle(handle, logicalIdentity)

    fun routingFor(
        handle: AkenHandle,
        logicalIdentity: ByteArray,
        resourcePath: String,
        resourceOffset: Int,
        storedLength: Int,
        codecVariant: String,
        layoutVariant: String,
        logicalBindingPath: String = resourcePath,
    ): AkenRoutingMetadata = AkenRoutingMetadata.fromHandle(
        handle, logicalIdentity, resourcePath, resourceOffset, storedLength, codecVariant, layoutVariant,
        logicalBindingPath,
    )
}

private const val MAX_LEAF_IDENTITY_ENCODING_SIZE = 96 * 1024

private fun writeInt(out: ByteArrayOutputStream, value: Int) {
    out.write((value ushr 24) and 0xFF)
    out.write((value ushr 16) and 0xFF)
    out.write((value ushr 8) and 0xFF)
    out.write(value and 0xFF)
}

private fun writeFramed(out: ByteArrayOutputStream, value: ByteArray) {
    writeInt(out, value.size)
    out.write(value)
}

private fun writeString(out: ByteArrayOutputStream, value: String) {
    val bytes = value.toByteArray(StandardCharsets.UTF_8)
    try {
        writeFramed(out, bytes)
    } finally {
        Arrays.fill(bytes, 0)
    }
}

private class AkenMetadataReader(private val bytes: ByteArray) {
    private var offset: Int = 0

    fun readUnsignedByte(label: String): Int {
        requireRemaining(1, label)
        return bytes[offset++].toInt() and 0xFF
    }

    fun readInt(label: String): Int {
        requireRemaining(Int.SIZE_BYTES, label)
        val value =
            ((bytes[offset].toInt() and 0xFF) shl 24) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
                (bytes[offset + 3].toInt() and 0xFF)
        offset += Int.SIZE_BYTES
        return value
    }

    fun readFixed(length: Int, label: String): ByteArray {
        require(length >= 0) { "AKEN metadata fixed length must be non-negative" }
        requireRemaining(length, label)
        return bytes.copyOfRange(offset, offset + length).also { offset += length }
    }

    fun readFramed(maximumLength: Int, label: String, allowEmpty: Boolean = true): ByteArray {
        val length = readInt("$label length")
        require(length >= 0 && length <= maximumLength && (allowEmpty || length > 0)) {
            "$label length is invalid"
        }
        return readFixed(length, label)
    }

    fun readString(maximumLength: Int, label: String): String {
        val value = readFramed(maximumLength, label, allowEmpty = false)
        return try {
            String(value, StandardCharsets.UTF_8)
        } finally {
            Arrays.fill(value, 0)
        }
    }

    fun requireFullyRead(label: String) {
        require(offset == bytes.size) { "$label contains trailing bytes" }
    }

    private fun requireRemaining(length: Int, label: String) {
        require(length >= 0 && length <= bytes.size - offset) { "$label is truncated" }
    }
}
