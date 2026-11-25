package io.github.hht0rro.javashroud.transforms.protection.qp

import java.security.SecureRandom
import java.util.Arrays

/**
 * Build-only physical Qp VM block clustering.
 *
 * The Qp VM stream already stores each logical block in its own authenticated,
 * compressed physical frame. This planner parses only the public outer frame
 * geometry, then groups contiguous physical block frames without inspecting or
 * decoding any encrypted payload. It deliberately does not retain program
 * bytes, logical identity bytes, a page handle, a DEK, or a native locator
 * record.
 */
internal object QpBlockClusterPlanner {
    private val QP_RETIRED_MAGIC = byteArrayOf(0x56, 0x42, 0x43, 0x35)
    private const val QP_NONCE_BYTES = 16
    private const val QP_DIALECT_COMMITMENT_BYTES = 32
    private const val QP_WRAPPED_SEED_BYTES = 16
    private const val QP_BLOCK_INDEX_ENTRY_BYTES = 10
    private const val QP_BLOCK_FRAME_HEADER_BYTES = 12
    private const val QP_AUTH_TAG_BYTES = 32

    private val supportedTargetSizes = setOf(512, 768, 1024, 1536, 2048)

    /**
     * Uses a build CSPRNG to select a target independently for every output
     * cluster. The target is only a packing preference: an oversized physical
     * Qp VM block remains one intact singleton cluster.
     */
    fun plan(
        candidate: QpMethodCandidate,
        random: SecureRandom = SecureRandom(),
    ): QpBlockClusterPlan = plan(candidate) { _ ->
        supportedTargetSizes.elementAt(random.nextInt(supportedTargetSizes.size))
    }

    /**
     * Testable build-only form of [plan]. The selector is called once per page
     * ordinal and must return one of the Qp VM target sizes.
     */
    internal fun plan(
        candidate: QpMethodCandidate,
        targetSizeForPage: (pageIndex: Int) -> Int,
    ): QpBlockClusterPlan {
        val serializedProgram = candidate.copySerializedProgramForBuild()
        try {
            val frame = parseFrame(serializedProgram)
            val clusters = cluster(frame.blocks, targetSizeForPage)
            return QpBlockClusterPlan.create(
                entryToken = candidate.entryToken,
                logicalVmResourcePath = candidate.logicalMethod.logicalVmResourcePath,
                serializedLength = serializedProgram.size,
                blockRegionStart = frame.blockRegionStart,
                blockRegionEndExclusive = frame.blockRegionEndExclusive,
                clusters = clusters,
            )
        } finally {
            Arrays.fill(serializedProgram, 0)
        }
    }

    internal fun isSupportedTargetSize(value: Int): Boolean = value in supportedTargetSizes

    private fun cluster(
        blocks: List<ParsedBlock>,
        targetSizeForPage: (pageIndex: Int) -> Int,
    ): List<QpBlockCluster> {
        require(blocks.isNotEmpty()) { "Qp current-format block clustering requires at least one physical block" }
        val output = ArrayList<QpBlockCluster>()
        var nextBlockOrdinal = 0
        var pageIndex = 0
        while (nextBlockOrdinal < blocks.size) {
            val targetSize = targetSizeForPage(pageIndex)
            require(isSupportedTargetSize(targetSize)) {
                "Qp current-format page target size '$targetSize' is unsupported"
            }
            val firstBlockOrdinal = nextBlockOrdinal
            val start = blocks[firstBlockOrdinal].encodedStart
            var endExclusive = start
            while (nextBlockOrdinal < blocks.size) {
                val next = blocks[nextBlockOrdinal]
                val candidateEndExclusive = next.encodedEndExclusive
                val candidateLength = candidateEndExclusive - start
                if (nextBlockOrdinal > firstBlockOrdinal && candidateLength > targetSize) {
                    break
                }
                endExclusive = candidateEndExclusive
                nextBlockOrdinal++
                if (candidateLength >= targetSize) {
                    break
                }
            }
            output += QpBlockCluster(
                pageIndex = pageIndex,
                targetSize = targetSize,
                firstStorageBlockOrdinal = firstBlockOrdinal,
                lastStorageBlockOrdinal = nextBlockOrdinal - 1,
                encodedStart = start,
                encodedEndExclusive = endExclusive,
            )
            pageIndex++
        }
        return output
    }

    private fun parseFrame(bytes: ByteArray): ParsedFrame {
        val cursor = Cursor(bytes)
        val expectedMagic = derivedVmMagic()
        val actualMagic = ByteArray(4) { cursor.readU1("magic").toByte() }
        try {
            require(!actualMagic.contentEquals(QP_RETIRED_MAGIC)) { "retired VM magic is rejected" }
            require(actualMagic.contentEquals(expectedMagic)) { "VM block planner expected current derived magic" }
        } finally {
            java.util.Arrays.fill(expectedMagic, 0)
            java.util.Arrays.fill(actualMagic, 0)
        }
        // The current Qp VM frame has no version field between magic and nonce.
        // Keep this grammar single-format so the planner cannot accept retired
        // container layouts.
        cursor.skip(QP_NONCE_BYTES, "nonce")
        cursor.skip(QP_DIALECT_COMMITMENT_BYTES, "dialect commitment")
        cursor.readU4("key id")
        cursor.skip(QP_WRAPPED_SEED_BYTES, "wrapped seed")
        cursor.readU2("flags")
        val blockCount = cursor.readU2("block count")
        require(blockCount > 0) { "Qp current-format block planner requires at least one block" }
        val constantPoolPlainLength = cursor.readLength("constant-pool plain length")
        require(constantPoolPlainLength > 0) {
            "Qp current-format block planner found an empty constant-pool section"
        }
        val constantPoolEncryptedLength = cursor.readLength("constant-pool encrypted length")
        require(constantPoolEncryptedLength > 0) {
            "Qp current-format block planner found an empty encrypted constant-pool section"
        }
        cursor.skip(constantPoolEncryptedLength, "constant-pool encrypted bytes")

        val index = ArrayList<BlockIndexEntry>(blockCount)
        val blockIds = HashSet<Int>(blockCount)
        repeat(blockCount) { ordinal ->
            val blockId = cursor.readU2("block index[$ordinal] id")
            require(blockIds.add(blockId)) { "Qp current-format block planner found a duplicate block id" }
            cursor.readU4("block index[$ordinal] entry token")
            cursor.readU4("block index[$ordinal] dispatch token")
            index += BlockIndexEntry(blockId)
        }

        val blockRegionStart = cursor.position
        val blocks = ArrayList<ParsedBlock>(blockCount)
        index.forEachIndexed { ordinal, indexEntry ->
            val encodedStart = cursor.position
            val plainLength = cursor.readLength("block[$ordinal] plain length")
            val storedLength = cursor.readLength("block[$ordinal] stored length")
            val encryptedLength = cursor.readLength("block[$ordinal] encrypted length")
            require(plainLength > 0) { "Qp current-format block planner found an empty physical block" }
            require(storedLength > 0) { "Qp current-format block planner found an empty stored block" }
            require(encryptedLength > 0) { "Qp current-format block planner found an empty encrypted block" }
            require(storedLength == encryptedLength) {
                "Qp current-format block planner found a non-length-preserving physical block cipher"
            }
            cursor.skip(encryptedLength, "block[$ordinal] encrypted bytes")
            blocks += ParsedBlock(
                storageOrdinal = ordinal,
                blockId = indexEntry.blockId,
                encodedStart = encodedStart,
                encodedEndExclusive = cursor.position,
            )
        }
        val blockRegionEndExclusive = cursor.position

        cursor.readLength("exception plain length")
        val exceptionStoredLength = cursor.readLength("exception stored length")
        val exceptionEncryptedLength = cursor.readLength("exception encrypted length")
        require(exceptionStoredLength == exceptionEncryptedLength) {
            "Qp current-format block planner found a non-length-preserving exception cipher"
        }
        cursor.skip(exceptionEncryptedLength, "exception encrypted bytes")
        val paddingLength = cursor.readLength("padding length")
        cursor.skip(paddingLength, "padding bytes")
        cursor.skip(QP_AUTH_TAG_BYTES, "authentication tag")
        require(cursor.remaining == 0) { "Qp current-format block planner found trailing frame bytes" }
        return ParsedFrame(
            blockRegionStart = blockRegionStart,
            blockRegionEndExclusive = blockRegionEndExclusive,
            blocks = blocks,
        )
    }

    private data class BlockIndexEntry(
        val blockId: Int,
    )

    private data class ParsedBlock(
        val storageOrdinal: Int,
        val blockId: Int,
        val encodedStart: Int,
        val encodedEndExclusive: Int,
    )

    private data class ParsedFrame(
        val blockRegionStart: Int,
        val blockRegionEndExclusive: Int,
        val blocks: List<ParsedBlock>,
    )

    private class Cursor(
        private val bytes: ByteArray,
    ) {
        var position: Int = 0
            private set

        val remaining: Int
            get() = bytes.size - position

        fun readU1(label: String): Int {
            requireAvailable(1, label)
            return bytes[position++].toInt() and 0xFF
        }

        fun readU2(label: String): Int =
            (readU1("$label[0]") shl 8) or readU1("$label[1]")

        fun readU4(label: String): Long =
            (readU1("$label[0]").toLong() shl 24) or
                (readU1("$label[1]").toLong() shl 16) or
                (readU1("$label[2]").toLong() shl 8) or
                readU1("$label[3]").toLong()

        fun readLength(label: String): Int {
            val value = readU4(label)
            require(value <= Int.MAX_VALUE.toLong()) { "Qp current-format $label exceeds JVM bounds" }
            return value.toInt()
        }

        fun skip(length: Int, label: String) {
            require(length >= 0) { "Qp current-format $label has a negative length" }
            requireAvailable(length, label)
            position += length
        }

        private fun requireAvailable(length: Int, label: String) {
            require(length <= remaining) { "Qp current-format frame is truncated while reading $label" }
        }
    }
}

/**
 * One page-sized contiguous physical block range. Block ordinals use Qp VM's
 * diversified physical storage order; they are not a runtime directory.
 */
internal data class QpBlockCluster(
    val pageIndex: Int,
    val targetSize: Int,
    val firstStorageBlockOrdinal: Int,
    val lastStorageBlockOrdinal: Int,
    val encodedStart: Int,
    val encodedEndExclusive: Int,
) {
    init {
        require(pageIndex >= 0) { "Qp current-format block-cluster page index must be non-negative" }
        require(QpBlockClusterPlanner.isSupportedTargetSize(targetSize)) {
            "Qp current-format block-cluster target size is unsupported"
        }
        require(firstStorageBlockOrdinal >= 0 && lastStorageBlockOrdinal >= firstStorageBlockOrdinal) {
            "Qp current-format block-cluster storage ordinals are invalid"
        }
        require(encodedStart >= 0 && encodedEndExclusive > encodedStart) {
            "Qp current-format block-cluster encoded range is invalid"
        }
    }

    val encodedLength: Int
        get() = encodedEndExclusive - encodedStart
}

/**
 * Non-secret, build-only page geometry derived from one serialized Qp VM method.
 * It contains only physical block boundaries and the logical routing identity;
 * callers must separately own/wipe any plaintext they later slice on these
 * boundaries.
 */
internal class QpBlockClusterPlan private constructor(
    val entryToken: Long,
    val logicalVmResourcePath: String,
    val serializedLength: Int,
    val blockRegionStart: Int,
    val blockRegionEndExclusive: Int,
    clusters: List<QpBlockCluster>,
) {
    val clusters: List<QpBlockCluster> = clusters.toList()

    init {
        require(logicalVmResourcePath.isNotBlank()) { "Qp current-format block-cluster plan logical path is blank" }
        require(serializedLength > 0) { "Qp current-format block-cluster plan serialized length is invalid" }
        require(blockRegionStart >= 0 && blockRegionEndExclusive > blockRegionStart && blockRegionEndExclusive <= serializedLength) {
            "Qp current-format block-cluster plan block region is invalid"
        }
        require(this.clusters.isNotEmpty()) { "Qp current-format block-cluster plan has no clusters" }
        var expectedPageIndex = 0
        var expectedBlockOrdinal = 0
        var expectedEncodedStart = blockRegionStart
        this.clusters.forEach { cluster ->
            require(cluster.pageIndex == expectedPageIndex++) { "Qp current-format block-cluster page indices are not contiguous" }
            require(cluster.firstStorageBlockOrdinal == expectedBlockOrdinal) {
                "Qp current-format block-cluster storage ordinals are not contiguous"
            }
            expectedBlockOrdinal = cluster.lastStorageBlockOrdinal + 1
            require(cluster.encodedStart == expectedEncodedStart) {
                "Qp current-format block-cluster encoded ranges are not contiguous"
            }
            expectedEncodedStart = cluster.encodedEndExclusive
        }
        require(expectedEncodedStart == blockRegionEndExclusive) {
            "Qp current-format block-cluster ranges do not cover the full physical block region"
        }
    }

    companion object {
        internal fun create(
            entryToken: Long,
            logicalVmResourcePath: String,
            serializedLength: Int,
            blockRegionStart: Int,
            blockRegionEndExclusive: Int,
            clusters: List<QpBlockCluster>,
        ): QpBlockClusterPlan = QpBlockClusterPlan(
            entryToken = entryToken,
            logicalVmResourcePath = logicalVmResourcePath,
            serializedLength = serializedLength,
            blockRegionStart = blockRegionStart,
            blockRegionEndExclusive = blockRegionEndExclusive,
            clusters = clusters,
        )
    }
}
