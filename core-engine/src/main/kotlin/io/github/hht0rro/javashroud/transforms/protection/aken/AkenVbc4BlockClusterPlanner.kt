package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.SecureRandom
import java.util.Arrays

/**
 * Build-only physical VBC4 block clustering.
 *
 * The VBC4 stream already stores each logical block in its own authenticated,
 * compressed physical frame. This planner parses only the public outer frame
 * geometry, then groups contiguous physical block frames without inspecting or
 * decoding any encrypted payload. It deliberately does not retain program
 * bytes, logical identity bytes, a page handle, a DEK, or a native locator
 * record.
 */
internal object AkenVbc4BlockClusterPlanner {
    private const val VBC4_VERSION = 4
    private const val VBC4_NONCE_BYTES = 16
    private const val VBC4_WRAPPED_SEED_BYTES = 16
    private const val VBC4_BLOCK_INDEX_ENTRY_BYTES = 10
    private const val VBC4_BLOCK_FRAME_HEADER_BYTES = 12
    private const val VBC4_AUTH_TAG_BYTES = 32
    private const val VBC4_AUTH_TAG_LENGTH_MARKER = 32

    private val supportedTargetSizes = setOf(512, 768, 1024, 1536, 2048)

    /**
     * Uses a build CSPRNG to select a target independently for every output
     * cluster. The target is only a packing preference: an oversized physical
     * VBC4 block remains one intact singleton cluster.
     */
    fun plan(
        candidate: AkenVbc4MethodCandidate,
        random: SecureRandom = SecureRandom(),
    ): AkenVbc4BlockClusterPlan = plan(candidate) { _ ->
        supportedTargetSizes.elementAt(random.nextInt(supportedTargetSizes.size))
    }

    /**
     * Testable build-only form of [plan]. The selector is called once per page
     * ordinal and must return one of the VBC4 target sizes.
     */
    internal fun plan(
        candidate: AkenVbc4MethodCandidate,
        targetSizeForPage: (pageIndex: Int) -> Int,
    ): AkenVbc4BlockClusterPlan {
        val serializedProgram = candidate.copySerializedProgramForBuild()
        try {
            val frame = parseFrame(serializedProgram)
            val clusters = cluster(frame.blocks, targetSizeForPage)
            return AkenVbc4BlockClusterPlan.create(
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
    ): List<AkenVbc4BlockCluster> {
        require(blocks.isNotEmpty()) { "AKEN VBC4 block clustering requires at least one physical block" }
        val output = ArrayList<AkenVbc4BlockCluster>()
        var nextBlockOrdinal = 0
        var pageIndex = 0
        while (nextBlockOrdinal < blocks.size) {
            val targetSize = targetSizeForPage(pageIndex)
            require(isSupportedTargetSize(targetSize)) {
                "AKEN VBC4 page target size '$targetSize' is unsupported"
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
            output += AkenVbc4BlockCluster(
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
        require(cursor.readU1("magic[0]") == 'V'.code) { "AKEN VBC4 block planner expected VBC4 magic" }
        require(cursor.readU1("magic[1]") == 'B'.code) { "AKEN VBC4 block planner expected VBC4 magic" }
        require(cursor.readU1("magic[2]") == 'C'.code) { "AKEN VBC4 block planner expected VBC4 magic" }
        require(cursor.readU1("magic[3]") == '4'.code) { "AKEN VBC4 block planner expected VBC4 magic" }
        require(cursor.readU2("version") == VBC4_VERSION) { "AKEN VBC4 block planner expected VBC4 version $VBC4_VERSION" }
        cursor.skip(VBC4_NONCE_BYTES, "nonce")
        cursor.readU4("key id")
        cursor.skip(VBC4_WRAPPED_SEED_BYTES, "wrapped seed")
        cursor.readU2("flags")
        val blockCount = cursor.readU2("block count")
        require(blockCount > 0) { "AKEN VBC4 block planner requires at least one block" }
        cursor.readU4("constant-pool plain length")
        val constantPoolEncryptedLength = cursor.readLength("constant-pool encrypted length")
        cursor.skip(constantPoolEncryptedLength, "constant-pool encrypted bytes")

        val index = ArrayList<BlockIndexEntry>(blockCount)
        val blockIds = HashSet<Int>(blockCount)
        repeat(blockCount) { ordinal ->
            val blockId = cursor.readU2("block index[$ordinal] id")
            require(blockIds.add(blockId)) { "AKEN VBC4 block planner found a duplicate block id" }
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
            require(plainLength > 0) { "AKEN VBC4 block planner found an empty physical block" }
            require(storedLength > 0) { "AKEN VBC4 block planner found an empty stored block" }
            require(encryptedLength > 0) { "AKEN VBC4 block planner found an empty encrypted block" }
            cursor.skip(encryptedLength, "block[$ordinal] encrypted bytes")
            blocks += ParsedBlock(
                storageOrdinal = ordinal,
                blockId = indexEntry.blockId,
                encodedStart = encodedStart,
                encodedEndExclusive = cursor.position,
            )
        }
        val blockRegionEndExclusive = cursor.position

        cursor.readU4("exception plain length")
        cursor.readU4("exception stored length")
        val exceptionEncryptedLength = cursor.readLength("exception encrypted length")
        cursor.skip(exceptionEncryptedLength, "exception encrypted bytes")
        val paddingLength = cursor.readLength("padding length")
        cursor.skip(paddingLength, "padding bytes")
        cursor.skip(VBC4_AUTH_TAG_BYTES, "authentication tag")
        require(cursor.readU1("authentication tag length") == VBC4_AUTH_TAG_LENGTH_MARKER) {
            "AKEN VBC4 block planner found an invalid authentication-tag length marker"
        }
        require(cursor.remaining == 0) { "AKEN VBC4 block planner found trailing frame bytes" }
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
            require(value <= Int.MAX_VALUE.toLong()) { "AKEN VBC4 $label exceeds JVM bounds" }
            return value.toInt()
        }

        fun skip(length: Int, label: String) {
            require(length >= 0) { "AKEN VBC4 $label has a negative length" }
            requireAvailable(length, label)
            position += length
        }

        private fun requireAvailable(length: Int, label: String) {
            require(length <= remaining) { "AKEN VBC4 frame is truncated while reading $label" }
        }
    }
}

/**
 * One page-sized contiguous physical block range. Block ordinals use VBC4's
 * diversified physical storage order; they are not a runtime directory.
 */
internal data class AkenVbc4BlockCluster(
    val pageIndex: Int,
    val targetSize: Int,
    val firstStorageBlockOrdinal: Int,
    val lastStorageBlockOrdinal: Int,
    val encodedStart: Int,
    val encodedEndExclusive: Int,
) {
    init {
        require(pageIndex >= 0) { "AKEN VBC4 block-cluster page index must be non-negative" }
        require(AkenVbc4BlockClusterPlanner.isSupportedTargetSize(targetSize)) {
            "AKEN VBC4 block-cluster target size is unsupported"
        }
        require(firstStorageBlockOrdinal >= 0 && lastStorageBlockOrdinal >= firstStorageBlockOrdinal) {
            "AKEN VBC4 block-cluster storage ordinals are invalid"
        }
        require(encodedStart >= 0 && encodedEndExclusive > encodedStart) {
            "AKEN VBC4 block-cluster encoded range is invalid"
        }
    }

    val encodedLength: Int
        get() = encodedEndExclusive - encodedStart
}

/**
 * Non-secret, build-only page geometry derived from one serialized VBC4 method.
 * It contains only physical block boundaries and the logical routing identity;
 * callers must separately own/wipe any plaintext they later slice on these
 * boundaries.
 */
internal class AkenVbc4BlockClusterPlan private constructor(
    val entryToken: Long,
    val logicalVmResourcePath: String,
    val serializedLength: Int,
    val blockRegionStart: Int,
    val blockRegionEndExclusive: Int,
    clusters: List<AkenVbc4BlockCluster>,
) {
    val clusters: List<AkenVbc4BlockCluster> = clusters.toList()

    init {
        require(logicalVmResourcePath.isNotBlank()) { "AKEN VBC4 block-cluster plan logical path is blank" }
        require(serializedLength > 0) { "AKEN VBC4 block-cluster plan serialized length is invalid" }
        require(blockRegionStart >= 0 && blockRegionEndExclusive > blockRegionStart && blockRegionEndExclusive <= serializedLength) {
            "AKEN VBC4 block-cluster plan block region is invalid"
        }
        require(this.clusters.isNotEmpty()) { "AKEN VBC4 block-cluster plan has no clusters" }
        var expectedPageIndex = 0
        var expectedBlockOrdinal = 0
        var expectedEncodedStart = blockRegionStart
        this.clusters.forEach { cluster ->
            require(cluster.pageIndex == expectedPageIndex++) { "AKEN VBC4 block-cluster page indices are not contiguous" }
            require(cluster.firstStorageBlockOrdinal == expectedBlockOrdinal) {
                "AKEN VBC4 block-cluster storage ordinals are not contiguous"
            }
            expectedBlockOrdinal = cluster.lastStorageBlockOrdinal + 1
            require(cluster.encodedStart == expectedEncodedStart) {
                "AKEN VBC4 block-cluster encoded ranges are not contiguous"
            }
            expectedEncodedStart = cluster.encodedEndExclusive
        }
        require(expectedEncodedStart == blockRegionEndExclusive) {
            "AKEN VBC4 block-cluster ranges do not cover the full physical block region"
        }
    }

    companion object {
        internal fun create(
            entryToken: Long,
            logicalVmResourcePath: String,
            serializedLength: Int,
            blockRegionStart: Int,
            blockRegionEndExclusive: Int,
            clusters: List<AkenVbc4BlockCluster>,
        ): AkenVbc4BlockClusterPlan = AkenVbc4BlockClusterPlan(
            entryToken = entryToken,
            logicalVmResourcePath = logicalVmResourcePath,
            serializedLength = serializedLength,
            blockRegionStart = blockRegionStart,
            blockRegionEndExclusive = blockRegionEndExclusive,
            clusters = clusters,
        )
    }
}
