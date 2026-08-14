package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimePageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4LogicalMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4MethodCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPagePlanner
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PreSealRoute
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AkenVbc4PendingPagePlannerTest {
    @Test
    fun partitions_one_vbc4_method_into_contiguous_container_pages_and_wipes_every_owner() {
        val program = framedVbc4(
            blockIds = listOf(10, 20, 30, 40, 50),
            encryptedPayloadLengths = listOf(288, 168, 588, 88, 188),
        )
        val entryToken = 0x4A4B_454E_0000_0C10L
        val logicalPath = "META-INF/vbc4/pending-page-fixture.bin"
        val candidate = candidate(entryToken, logicalPath, program)
        val route = AkenVbc4PreSealRoute.create(
            entryToken = entryToken,
            logicalVmResourcePath = logicalPath,
            futureContainerPath = "META-INF/.aken/vbc4/container-pending-page.bin",
        )
        var proofRequests = 0
        val pageReferences = ArrayList<AkenVbc4PendingPage>()
        try {
            val batch = AkenVbc4PendingPagePlanner.partitionAndWipe(
                candidate = candidate,
                route = route,
                callSiteProofForPage = { pageIndex ->
                    assertEquals(proofRequests, pageIndex)
                    proofRequests++
                    ByteArray(33) { index -> (pageIndex * 37 + index * 11 + 3).toByte() }
                },
                targetSizeForPage = { 512 },
                random = DeterministicSecureRandom(0x1357),
            )

            assertTrue(candidate.isWiped)
            assertEquals(entryToken, batch.entryToken)
            assertEquals("META-INF/.aken/vbc4/container-pending-page.bin", batch.resourcePath)
            val partitions = batch.partitionsForBuild()
            assertEquals(3, partitions.size)
            assertEquals(listOf(0, 1, 2), partitions.map { it.pageIndex })
            assertEquals(listOf(0, 2, 3), partitions.map { it.firstStorageBlockOrdinal })
            assertEquals(listOf(1, 2, 4), partitions.map { it.lastStorageBlockOrdinal })
            assertEquals(listOf(480, 600, 300), partitions.map { it.physicalBlockLength })
            assertEquals(listOf(108, 0, 0), partitions.map { it.framePrefixLength })
            assertEquals(listOf(0, 0, 49), partitions.map { it.frameSuffixLength })
            assertEquals(listOf(588, 600, 349), partitions.map { it.plaintextLength })
            assertEquals(3, proofRequests)

            batch.consumePendingPagesForBuild { pages ->
                pageReferences += pages
                assertEquals(listOf(0, 1, 2), pages.map { it.pageIndex })
                assertTrue(pages.all { it.entryToken == entryToken })
                assertTrue(pages.all { it.resourcePath == route.futureContainerPath })
                assertEquals(partitions.map { it.targetSize }, pages.map { it.targetPageSize })
                var expectedOffset = 0
                pages.forEach { page ->
                    assertEquals(expectedOffset, page.resourceOffset)
                    expectedOffset += page.expectedStoredLength
                }

                val plaintexts = pages.map { it.copyPlaintextForBuild() }
                try {
                    val reconstructed = plaintexts.fold(ByteArray(0)) { output, page ->
                        output + page
                    }
                    try {
                        assertContentEquals(program, reconstructed)
                    } finally {
                        Arrays.fill(reconstructed, 0)
                    }
                } finally {
                    plaintexts.forEach { Arrays.fill(it, 0) }
                }
            }

            assertTrue(batch.isWiped)
            assertTrue(pageReferences.all { it.isWiped })
            assertFailsWith<IllegalStateException> {
                batch.partitionsForBuild()
            }
        } finally {
            candidate.wipe()
            route.wipe()
            Arrays.fill(program, 0)
        }
    }

    @Test
    fun rejects_a_route_for_another_vbc4_method_and_wipes_the_candidate() {
        val program = framedVbc4(
            blockIds = listOf(1),
            encryptedPayloadLengths = listOf(100),
        )
        val candidate = candidate(
            entryToken = 0x4A4B_454E_0000_0D10L,
            logicalPath = "META-INF/vbc4/route-mismatch.bin",
            program = program,
        )
        val route = AkenVbc4PreSealRoute.create(
            entryToken = 0x4A4B_454E_0000_0D11L,
            logicalVmResourcePath = "META-INF/vbc4/route-mismatch.bin",
            futureContainerPath = "META-INF/.aken/vbc4/route-mismatch.bin",
        )
        try {
            assertFailsWith<IllegalArgumentException> {
                AkenVbc4PendingPagePlanner.partitionAndWipe(
                    candidate = candidate,
                    route = route,
                    callSiteProofForPage = { byteArrayOf(1) },
                    targetSizeForPage = { 512 },
                    random = DeterministicSecureRandom(0x2468),
                )
            }
            assertTrue(candidate.isWiped)
            assertTrue(!route.futureContainerPath.isBlank())
        } finally {
            candidate.wipe()
            route.wipe()
            Arrays.fill(program, 0)
        }
    }

    @Test
    fun propagates_block_cluster_targets_into_finalized_runtime_descriptors() {
        val program = framedVbc4(
            blockIds = listOf(10, 20, 30, 40, 50),
            encryptedPayloadLengths = listOf(288, 168, 588, 88, 188),
        )
        val entryToken = 0x4A4B_454E_0000_0E10L
        val route = AkenVbc4PreSealRoute.create(
            entryToken = entryToken,
            logicalVmResourcePath = "META-INF/vbc4/target-propagation.bin",
            futureContainerPath = "META-INF/.aken/vbc4/target-propagation-container.bin",
        )
        val candidate = candidate(entryToken, route.logicalVmResourcePath, program)
        val expectedTargets = listOf(512, 768, 1024)
        var layout: AkenVbc4FinalizationLayout? = null
        try {
            val batch = AkenVbc4PendingPagePlanner.partitionAndWipe(
                candidate = candidate,
                route = route,
                callSiteProofForPage = { pageIndex ->
                    ByteArray(37) { index -> (pageIndex * 41 + index * 7 + 5).toByte() }
                },
                targetSizeForPage = { pageIndex -> expectedTargets[pageIndex] },
                random = DeterministicSecureRandom(0x4F4B),
            )
            assertTrue(candidate.isWiped)
            val partitions = batch.partitionsForBuild()
            assertEquals(expectedTargets, partitions.map { it.targetSize })

            batch.consumePendingPagesForBuild { pages ->
                assertEquals(expectedTargets, pages.map { it.targetPageSize })
                assertEquals(List(pages.size) { route.futureContainerPath }, pages.map { it.resourcePath })
                var expectedOffset = 0
                pages.forEach { page ->
                    assertEquals(expectedOffset, page.resourceOffset)
                    expectedOffset += page.expectedStoredLength
                }

                val commitment = AkenVbc4FinalizationLayout.reserve(
                    pendingPages = pages,
                    fixedEntries = emptyList(),
                )
                val commitmentBytes = commitment.copyBytes()
                val plan = try {
                    AkenBuildPlan.create(commitmentBytes, FirstSizeSecureRandom())
                } finally {
                    Arrays.fill(commitmentBytes, 0)
                }
                layout = AkenVbc4FinalizationLayout.materializeAndWipe(
                    plan = plan,
                    commitment = commitment,
                    pendingPages = pages,
                    fixedEntries = emptyList(),
                )
                assertTrue(plan.isWiped())
            }

            val finalized = checkNotNull(layout)
            finalized.withNativeLocatorRecordsForBuild { records ->
                val descriptors = records
                    .map(::descriptorFromNativeLocatorRecord)
                    .sortedBy { it.pageIndex }
                assertEquals(listOf(0, 1, 2), descriptors.map { it.pageIndex })
                assertEquals(expectedTargets, descriptors.map { it.targetPageSize })
                assertEquals(
                    List(descriptors.size) { route.futureContainerPath },
                    descriptors.map { it.route.resourcePath },
                )
            }
            assertTrue(finalized.verifyWriterEquivalentArtifactForBuild(artifactEntriesFor(finalized)))
            assertTrue(batch.isWiped)
        } finally {
            layout?.wipe()
            candidate.wipe()
            route.wipe()
            Arrays.fill(program, 0)
        }
    }

    private fun candidate(
        entryToken: Long,
        logicalPath: String,
        program: ByteArray,
    ): AkenVbc4MethodCandidate {
        val identity = ByteArray(32) { index -> (index * 13 + 7).toByte() }
        val logicalMethod = AkenVbc4LogicalMethodIdentity.create(
            dispatchClassToken = "fixture/PendingPage",
            dispatchMethodToken = "dispatch",
            descriptor = "()V",
            logicalVmResourcePath = logicalPath,
        )
        return try {
            AkenVbc4MethodCandidate.create(
                entryToken = entryToken,
                logicalMethod = logicalMethod,
                logicalIdentity = identity,
                serializedProgram = program,
            )
        } finally {
            Arrays.fill(identity, 0)
        }
    }

    private fun framedVbc4(
        blockIds: List<Int>,
        encryptedPayloadLengths: List<Int>,
    ): ByteArray {
        require(blockIds.isNotEmpty() && blockIds.size == encryptedPayloadLengths.size)
        val out = ByteArrayOutputStream()
        out.write("VBC4".encodeToByteArray())
        writeU2(out, 4)
        out.write(ByteArray(16))
        writeU4(out, 0xAABBCCDDL)
        out.write(ByteArray(16))
        writeU2(out, 0)
        writeU2(out, blockIds.size)
        writeU4(out, 0)
        writeU4(out, 4)
        out.write(byteArrayOf(1, 2, 3, 4))
        blockIds.forEachIndexed { ordinal, blockId ->
            writeU2(out, blockId)
            writeU4(out, ordinal.toLong() + 1)
            writeU4(out, ordinal.toLong() + 101)
        }
        encryptedPayloadLengths.forEachIndexed { ordinal, encryptedLength ->
            require(encryptedLength > 0)
            writeU4(out, encryptedLength.toLong())
            writeU4(out, encryptedLength.toLong())
            writeU4(out, encryptedLength.toLong())
            out.write(ByteArray(encryptedLength) { index -> (ordinal * 17 + index).toByte() })
        }
        writeU4(out, 0)
        writeU4(out, 0)
        writeU4(out, 0)
        writeU4(out, 0)
        out.write(ByteArray(32))
        out.write(32)
        return out.toByteArray()
    }

    private fun writeU2(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU4(out: ByteArrayOutputStream, value: Long) {
        require(value in 0L..0xFFFF_FFFFL)
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }

    private fun artifactEntriesFor(layout: AkenVbc4FinalizationLayout): List<AkenArtifactEntry> =
        layout.entriesForBuild().map { entry ->
            val bytes = entry.copyBytesForBuild()
            try {
                AkenArtifactEntry(entry.name, bytes)
            } finally {
                Arrays.fill(bytes, 0)
            }
        }

    private fun descriptorFromNativeLocatorRecord(record: ByteArray): AkenRuntimePageDescriptor {
        require(record.size >= 1 + Long.SIZE_BYTES + 1 + Int.SIZE_BYTES + 32) {
            "AKEN native locator record is too short for a descriptor"
        }
        require((record[0].toInt() and 0xFF) == 1) {
            "unexpected AKEN native locator record version"
        }
        var cursor = 1 + Long.SIZE_BYTES + 1 + Int.SIZE_BYTES

        fun readFrame(label: String): ByteArray {
            require(cursor + Int.SIZE_BYTES <= record.size) {
                "AKEN native locator $label frame length is truncated"
            }
            val length =
                ((record[cursor++].toInt() and 0xFF) shl 24) or
                    ((record[cursor++].toInt() and 0xFF) shl 16) or
                    ((record[cursor++].toInt() and 0xFF) shl 8) or
                    (record[cursor++].toInt() and 0xFF)
            require(length >= 0 && length <= record.size - cursor) {
                "AKEN native locator $label frame length is invalid"
            }
            val endExclusive = cursor + length
            return record.copyOfRange(cursor, endExclusive).also {
                cursor = endExclusive
            }
        }

        var handle: ByteArray? = null
        var envelope: ByteArray? = null
        var descriptorBytes: ByteArray? = null
        var route: ByteArray? = null
        try {
            handle = readFrame("handle")
            envelope = readFrame("envelope")
            descriptorBytes = readFrame("descriptor")
            route = readFrame("route")
            require(cursor + 32 == record.size) {
                "AKEN native locator record binding length is invalid"
            }
            return AkenRuntimePageDescriptor.decode(checkNotNull(descriptorBytes))
        } finally {
            handle?.let { Arrays.fill(it, 0) }
            envelope?.let { Arrays.fill(it, 0) }
            descriptorBytes?.let { Arrays.fill(it, 0) }
            route?.let { Arrays.fill(it, 0) }
        }
    }

    private class FirstSizeSecureRandom : SecureRandom() {
        private var state: Int = 0x4A4B_454E

        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { index ->
                state = state * 1_103_515_245 + 12_345
                bytes[index] = (state ushr 16).toByte()
            }
        }

        override fun nextInt(bound: Int): Int {
            require(bound > 0)
            return 0
        }

        override fun nextBoolean(): Boolean = false
    }

    private class DeterministicSecureRandom(seed: Int) : SecureRandom() {
        private var state: Int = seed

        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { index ->
                state = state * 1_103_515_245 + 12_345
                bytes[index] = (state ushr 16).toByte()
            }
        }

        override fun nextInt(bound: Int): Int {
            require(bound > 0)
            state = state * 1_664_525 + 1_013_904_223
            return (state ushr 1).mod(bound)
        }

        override fun nextBoolean(): Boolean {
            state = state * 22_695_477 + 1
            return state < 0
        }
    }
}
