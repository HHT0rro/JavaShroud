package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.SecureRandom
import java.security.MessageDigest
import java.util.Arrays

/**
 * Converts one build-only serialized VBC4 method candidate into contiguous
 * pending AKEN pages for one already-reserved container route.
 *
 * VBC4's public outer frame is divided without decrypting its constant pool,
 * physical block payloads, or exception payload. The first page owns the
 * method-frame prefix through its first physical block cluster; middle pages
 * own only complete physical block clusters; the final page owns its final
 * cluster plus the authenticated frame suffix. Concatenating the pending-page
 * plaintexts in page-index order therefore reproduces the original VBC4
 * serialization byte-for-byte, while no physical block is split.
 *
 * This is a build-only hand-off. It neither writes an artifact entry nor
 * initializes an AKEN build plan, emits a native locator, changes a runtime
 * dispatcher, or exposes a runtime page enumeration API.
 */
internal object AkenVbc4PendingPagePlanner {
    /**
     * Uses a build CSPRNG for independent VBC4 physical-block target selection
     * and for each pending page's AKEN frame variant.
     *
     * [callSiteProofForPage] transfers ownership of every returned byte array
     * to this method. Each array is copied into the pending page and cleared
     * before this method advances to the next page.
     */
    fun partitionAndWipe(
        candidate: AkenVbc4MethodCandidate,
        route: AkenVbc4PreSealRoute,
        callSiteProofForPage: (pageIndex: Int) -> ByteArray,
        random: SecureRandom = SecureRandom(),
    ): AkenVbc4PendingPageBatch =
        try {
            partition(
                candidate = candidate,
                route = route,
                blockPlan = AkenVbc4BlockClusterPlanner.plan(candidate, random),
                callSiteProofForPage = callSiteProofForPage,
                random = random,
            )
        } finally {
            candidate.wipe()
        }

    /**
     * Testable form of [partitionAndWipe] with explicit per-page VBC4 target
     * selection. Production callers should use the CSPRNG-selected overload.
     */
    internal fun partitionAndWipe(
        candidate: AkenVbc4MethodCandidate,
        route: AkenVbc4PreSealRoute,
        callSiteProofForPage: (pageIndex: Int) -> ByteArray,
        targetSizeForPage: (pageIndex: Int) -> Int,
        random: SecureRandom = SecureRandom(),
    ): AkenVbc4PendingPageBatch =
        try {
            partition(
                candidate = candidate,
                route = route,
                blockPlan = AkenVbc4BlockClusterPlanner.plan(candidate, targetSizeForPage),
                callSiteProofForPage = callSiteProofForPage,
                random = random,
            )
        } finally {
            candidate.wipe()
        }

    private fun partition(
        candidate: AkenVbc4MethodCandidate,
        route: AkenVbc4PreSealRoute,
        blockPlan: AkenVbc4BlockClusterPlan,
        callSiteProofForPage: (pageIndex: Int) -> ByteArray,
        random: SecureRandom,
    ): AkenVbc4PendingPageBatch {
        require(candidate.entryToken == route.entryToken) {
            "AKEN VBC4 pending-page route entry token does not match its candidate"
        }
        require(candidate.logicalMethod.logicalVmResourcePath == route.logicalVmResourcePath) {
            "AKEN VBC4 pending-page route logical resource path does not match its candidate"
        }
        require(blockPlan.entryToken == candidate.entryToken) {
            "AKEN VBC4 block-cluster plan entry token does not match its candidate"
        }
        require(blockPlan.logicalVmResourcePath == candidate.logicalMethod.logicalVmResourcePath) {
            "AKEN VBC4 block-cluster plan logical resource path does not match its candidate"
        }

        var serializedProgram: ByteArray? = null
        var logicalIdentity: ByteArray? = null
        val pendingPages = ArrayList<AkenVbc4PendingPage>(blockPlan.clusters.size)
        val partitions = ArrayList<AkenVbc4PagePartition>(blockPlan.clusters.size)
        var completed = false
        try {
            serializedProgram = candidate.copySerializedProgramForBuild()
            logicalIdentity = candidate.copyLogicalIdentityForBuild()
            val source = checkNotNull(serializedProgram)
            require(source.size == blockPlan.serializedLength) {
                "AKEN VBC4 block-cluster plan serialized length drifted from its candidate"
            }

            var expectedSerializedStart = 0
            var nextResourceOffset = 0
            blockPlan.clusters.forEachIndexed { ordinal, cluster ->
                require(cluster.pageIndex == ordinal) {
                    "AKEN VBC4 block-cluster page indices are not contiguous"
                }
                require(
                    cluster.encodedStart >= blockPlan.blockRegionStart &&
                        cluster.encodedEndExclusive <= blockPlan.blockRegionEndExclusive,
                ) {
                    "AKEN VBC4 block-cluster range is outside its physical block region"
                }

                val serializedStart = if (ordinal == 0) 0 else cluster.encodedStart
                val serializedEndExclusive = if (ordinal == blockPlan.clusters.lastIndex) {
                    source.size
                } else {
                    cluster.encodedEndExclusive
                }
                require(serializedStart == expectedSerializedStart) {
                    "AKEN VBC4 pending-page slices are not contiguous"
                }
                require(serializedEndExclusive > serializedStart && serializedEndExclusive <= source.size) {
                    "AKEN VBC4 pending-page slice is outside its serialized method"
                }
                val prefixLength = cluster.encodedStart - serializedStart
                val suffixLength = serializedEndExclusive - cluster.encodedEndExclusive
                require(prefixLength >= 0 && suffixLength >= 0) {
                    "AKEN VBC4 pending-page frame ownership is invalid"
                }

                val partition = AkenVbc4PagePartition(
                    pageIndex = cluster.pageIndex,
                    targetSize = cluster.targetSize,
                    firstStorageBlockOrdinal = cluster.firstStorageBlockOrdinal,
                    lastStorageBlockOrdinal = cluster.lastStorageBlockOrdinal,
                    encodedBlockStart = cluster.encodedStart,
                    encodedBlockEndExclusive = cluster.encodedEndExclusive,
                    serializedStart = serializedStart,
                    serializedEndExclusive = serializedEndExclusive,
                    framePrefixLength = prefixLength,
                    frameSuffixLength = suffixLength,
                )
                var pagePlaintext: ByteArray? = null
                var derivedCallSiteProof: ByteArray? = null
                var callSiteProof: ByteArray? = null
                var encodedHandleOverride: ByteArray? = null
                try {
                    pagePlaintext = source.copyOfRange(serializedStart, serializedEndExclusive)
                    derivedCallSiteProof = callSiteProofForPage(cluster.pageIndex)
                    if (cluster.pageIndex == 0 && candidate.hasPageZeroDispatchBindingForBuild) {
                        encodedHandleOverride = candidate.copyPageZeroEncodedHandleForBuild()
                        callSiteProof = candidate.copyPageZeroCallSiteProofForBuild()
                        require(
                            MessageDigest.isEqual(
                                checkNotNull(derivedCallSiteProof),
                                checkNotNull(callSiteProof),
                            ),
                        ) {
                            "AKEN VBC4 page-zero dispatch proof drifted from the pending page proof"
                        }
                    } else {
                        callSiteProof = derivedCallSiteProof
                        derivedCallSiteProof = null
                    }
                    val pending = AkenVbc4PendingPage.create(
                        entryToken = candidate.entryToken,
                        logicalIdentity = checkNotNull(logicalIdentity),
                        plaintext = pagePlaintext,
                        resourcePath = route.futureContainerPath,
                        resourceOffset = nextResourceOffset,
                        pageIndex = cluster.pageIndex,
                        callSiteProof = callSiteProof,
                        targetPageSize = partition.targetSize,
                        random = random,
                        logicalBindingPath = route.logicalVmResourcePath,
                        encodedHandleOverride = encodedHandleOverride,
                    )
                    pendingPages += pending
                    val nextOffset = nextResourceOffset.toLong() + pending.expectedStoredLength.toLong()
                    require(nextOffset <= Int.MAX_VALUE.toLong()) {
                        "AKEN VBC4 pending-page container exceeds JVM bounds"
                    }
                    nextResourceOffset = nextOffset.toInt()
                    partitions += partition
                } finally {
                    pagePlaintext?.let { Arrays.fill(it, 0) }
                    derivedCallSiteProof?.let { Arrays.fill(it, 0) }
                    callSiteProof?.let { Arrays.fill(it, 0) }
                    encodedHandleOverride?.let { Arrays.fill(it, 0) }
                }
                expectedSerializedStart = serializedEndExclusive
            }
            require(expectedSerializedStart == source.size) {
                "AKEN VBC4 pending-page slices do not cover the serialized method"
            }
            return AkenVbc4PendingPageBatch.create(
                entryToken = candidate.entryToken,
                resourcePath = route.futureContainerPath,
                serializedLength = source.size,
                partitions = partitions,
                pages = pendingPages,
            ).also {
                completed = true
            }
        } finally {
            serializedProgram?.let { Arrays.fill(it, 0) }
            logicalIdentity?.let { Arrays.fill(it, 0) }
            if (!completed) {
                pendingPages.forEach { it.wipe() }
            }
        }
    }
}

/**
 * Build-only metadata for one serialized VBC4 slice. The structure describes
 * ownership of public outer-frame bytes only; it never retains the bytes,
 * page plaintext, DEK, handle, descriptor, locator record, evaluator graph,
 * or final artifact commitment.
 */
internal data class AkenVbc4PagePartition(
    val pageIndex: Int,
    val targetSize: Int,
    val firstStorageBlockOrdinal: Int,
    val lastStorageBlockOrdinal: Int,
    val encodedBlockStart: Int,
    val encodedBlockEndExclusive: Int,
    val serializedStart: Int,
    val serializedEndExclusive: Int,
    val framePrefixLength: Int,
    val frameSuffixLength: Int,
) {
    init {
        require(pageIndex >= 0) { "AKEN VBC4 page partition index must be non-negative" }
        require(AkenVbc4BlockClusterPlanner.isSupportedTargetSize(targetSize)) {
            "AKEN VBC4 page partition target size is unsupported"
        }
        require(firstStorageBlockOrdinal >= 0 && lastStorageBlockOrdinal >= firstStorageBlockOrdinal) {
            "AKEN VBC4 page partition storage ordinals are invalid"
        }
        require(encodedBlockStart >= 0 && encodedBlockEndExclusive > encodedBlockStart) {
            "AKEN VBC4 page partition physical block range is invalid"
        }
        require(serializedStart >= 0 && serializedEndExclusive > serializedStart) {
            "AKEN VBC4 page partition serialized range is invalid"
        }
        require(
            encodedBlockStart == serializedStart + framePrefixLength &&
                encodedBlockEndExclusive + frameSuffixLength == serializedEndExclusive,
        ) {
            "AKEN VBC4 page partition frame ownership does not close around its block cluster"
        }
    }

    val physicalBlockLength: Int
        get() = encodedBlockEndExclusive - encodedBlockStart

    val plaintextLength: Int
        get() = serializedEndExclusive - serializedStart
}

/**
 * Short-lived owner for all pending pages of one VBC4 method container.
 *
 * The batch exposes only non-secret partition geometry until it is consumed.
 * [consumePendingPagesForBuild] transfers the private pending pages to one
 * adjacent build callback and wipes every page immediately after that callback
 * returns, including when the callback fails. This deliberately prevents a
 * build-stage page list from becoming a reusable runtime catalog.
 */
internal class AkenVbc4PendingPageBatch private constructor(
    private var entryTokenValue: Long,
    private var resourcePathValue: String,
    private var serializedLengthValue: Int,
    partitions: List<AkenVbc4PagePartition>,
    pages: List<AkenVbc4PendingPage>,
) : AutoCloseable {
    private var partitionsValue: List<AkenVbc4PagePartition> = partitions.toList()
    private var pagesValue: List<AkenVbc4PendingPage> = pages.toList()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(resourcePathValue.isNotBlank()) { "AKEN VBC4 pending-page batch resource path is blank" }
        require(serializedLengthValue > 0) { "AKEN VBC4 pending-page batch serialized length is invalid" }
        require(partitionsValue.isNotEmpty() && partitionsValue.size == pagesValue.size) {
            "AKEN VBC4 pending-page batch page count is invalid"
        }
        validateOwnership()
    }

    val isWiped: Boolean
        get() = wiped

    val entryToken: Long
        get() {
            requireLive()
            return entryTokenValue
        }

    val resourcePath: String
        get() {
            requireLive()
            return resourcePathValue
        }

    /** Build-only immutable copy of the VBC4 ownership geometry. */
    fun partitionsForBuild(): List<AkenVbc4PagePartition> {
        requireLive()
        return partitionsValue.toList()
    }

    /**
     * Supplies the private pending pages to exactly one adjacent build stage.
     * The supplied list is invalidated at callback exit and must not escape.
     */
    fun <T> consumePendingPagesForBuild(block: (List<AkenVbc4PendingPage>) -> T): T {
        val pages = synchronized(this) {
            requireLive()
            val snapshot = pagesValue
            pagesValue = emptyList()
            partitionsValue = emptyList()
            entryTokenValue = 0L
            resourcePathValue = ""
            serializedLengthValue = 0
            wiped = true
            snapshot
        }
        try {
            return block(pages.toList())
        } finally {
            pages.forEach { it.wipe() }
        }
    }

    override fun close() = wipe()

    @Synchronized
    fun wipe() {
        if (wiped) return
        pagesValue.forEach { it.wipe() }
        pagesValue = emptyList()
        partitionsValue = emptyList()
        entryTokenValue = 0L
        resourcePathValue = ""
        serializedLengthValue = 0
        wiped = true
    }

    private fun validateOwnership() {
        var expectedPageIndex = 0
        var expectedSerializedStart = 0
        var expectedResourceOffset = 0
        partitionsValue.indices.forEach { index ->
            val partition = partitionsValue[index]
            val page = pagesValue[index]
            require(partition.pageIndex == expectedPageIndex++) {
                "AKEN VBC4 pending-page batch page indices are not contiguous"
            }
            require(partition.serializedStart == expectedSerializedStart) {
                "AKEN VBC4 pending-page batch serialized ranges are not contiguous"
            }
            expectedSerializedStart = partition.serializedEndExclusive
            require(page.entryToken == entryTokenValue) {
                "AKEN VBC4 pending-page batch entry-token binding drifted"
            }
            require(page.resourcePath == resourcePathValue) {
                "AKEN VBC4 pending-page batch resource path binding drifted"
            }
            require(page.pageIndex == partition.pageIndex) {
                "AKEN VBC4 pending-page batch page index binding drifted"
            }
            require(page.resourceOffset == expectedResourceOffset) {
                "AKEN VBC4 pending-page batch physical page offsets are not contiguous"
            }
            val nextOffset = expectedResourceOffset.toLong() + page.expectedStoredLength.toLong()
            require(nextOffset <= Int.MAX_VALUE.toLong()) {
                "AKEN VBC4 pending-page batch container exceeds JVM bounds"
            }
            expectedResourceOffset = nextOffset.toInt()
        }
        require(expectedSerializedStart == serializedLengthValue) {
            "AKEN VBC4 pending-page batch does not cover its serialized method"
        }
    }

    private fun requireLive() {
        check(!wiped) { "AKEN VBC4 pending-page batch has been wiped" }
    }

    companion object {
        internal fun create(
            entryToken: Long,
            resourcePath: String,
            serializedLength: Int,
            partitions: List<AkenVbc4PagePartition>,
            pages: List<AkenVbc4PendingPage>,
        ): AkenVbc4PendingPageBatch =
            AkenVbc4PendingPageBatch(
                entryTokenValue = entryToken,
                resourcePathValue = resourcePath,
                serializedLengthValue = serializedLength,
                partitions = partitions,
                pages = pages,
            )
    }
}
