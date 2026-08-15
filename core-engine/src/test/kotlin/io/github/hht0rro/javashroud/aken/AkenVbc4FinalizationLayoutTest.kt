package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRootShardRange
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4DispatchBinding
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenVbc4FinalizationLayoutTest {
    @Test
    fun reserves_final_geometry_materializes_independent_pages_and_binds_native_compile_records() {
        val helperBytes = ByteArray(96) { index -> (index * 13 + 7).toByte() }
        val rootShard = AkenRootShardRange(
            entryName = "io/example/Helper.class",
            offset = 17,
            length = AkenArtifactCommitment.DIGEST_SIZE,
        )
        helperBytes.fill(0, rootShard.offset, rootShard.offset + rootShard.length)
        val fixedEntries = listOf(AkenArtifactEntry("io/example/Helper.class", helperBytes))
        helperBytes.fill(0)

        val identity0 = "fixture:aken-finalization:first".encodeToByteArray()
        val plain0 = "first finalized VBC4 page".encodeToByteArray()
        val proof0 = ByteArray(41) { index -> (index * 17 + 3).toByte() }
        val page0 = try {
            AkenVbc4PendingPage.create(
                entryToken = 0x4A4B_454E_0000_1010L,
                logicalIdentity = identity0,
                plaintext = plain0,
                resourcePath = "META-INF/.aken/vbc4/shared-page.bin",
                pageIndex = 0,
                callSiteProof = proof0,
                random = SecureRandom(),
            )
        } finally {
            Arrays.fill(identity0, 0)
            Arrays.fill(plain0, 0)
            Arrays.fill(proof0, 0)
        }
        val secondOffset = page0.expectedStoredLength + 19
        val identity1 = "fixture:aken-finalization:second".encodeToByteArray()
        val plain1 = "second finalized VBC4 page with a separate identity".encodeToByteArray()
        val proof1 = ByteArray(67) { index -> (index * 29 + 11).toByte() }
        val page1 = try {
            AkenVbc4PendingPage.create(
                entryToken = 0x4A4B_454E_0000_2020L,
                logicalIdentity = identity1,
                plaintext = plain1,
                resourcePath = "META-INF/.aken/vbc4/shared-page.bin",
                resourceOffset = secondOffset,
                pageIndex = 0,
                callSiteProof = proof1,
                random = SecureRandom(),
            )
        } finally {
            Arrays.fill(identity1, 0)
            Arrays.fill(plain1, 0)
            Arrays.fill(proof1, 0)
        }

        val commitment = AkenVbc4FinalizationLayout.reserve(
            pendingPages = listOf(page0, page1),
            fixedEntries = fixedEntries,
            rootShardRanges = listOf(rootShard),
        )
        val commitmentBytes = commitment.copyBytes()
        val plan = AkenBuildPlan.create(commitmentBytes, SecureRandom())
        Arrays.fill(commitmentBytes, 0)

        val layout = AkenVbc4FinalizationLayout.materializeAndWipe(
            plan = plan,
            commitment = commitment,
            pendingPages = listOf(page0, page1),
            fixedEntries = fixedEntries,
            rootShardRanges = listOf(rootShard),
        )
        try {
            assertTrue(plan.isWiped())
            assertTrue(page0.isWiped)
            assertTrue(page1.isWiped)
            assertTrue(layout.verifyWriterEquivalentArtifactForBuild(artifactEntries(layout)))

            val helperEntry = layout.entriesForBuild().single { it.name == rootShard.entryName }
            val helperFinal = helperEntry.copyBytesForBuild()
            val expectedShard = commitment.copyExpectedRootShardBytesForBuild(rootShard)
            val observedShard = helperFinal.copyOfRange(rootShard.offset, rootShard.offset + rootShard.length)
            try {
                assertTrue(MessageDigest.isEqual(observedShard, expectedShard))
            } finally {
                Arrays.fill(helperFinal, 0)
                Arrays.fill(expectedShard, 0)
                Arrays.fill(observedShard, 0)
            }

            var nativeRecordCount = 0
            var originalNativeRecordByte = 0.toByte()
            layout.withNativeLocatorRecordsForBuild { records ->
                nativeRecordCount = records.size
                assertEquals(2, records.size)
                assertTrue(records.all { record -> record.isNotEmpty() })
                originalNativeRecordByte = records.first()[0]
                records.first()[0] = (records.first()[0].toInt() xor 0x5A).toByte()
            }
            assertEquals(2, nativeRecordCount)
            layout.withNativeLocatorRecordsForBuild { records ->
                assertEquals(2, records.size)
                assertEquals(originalNativeRecordByte, records.first()[0])
            }

            var retainedDispatchBindings: List<AkenVbc4DispatchBinding> = emptyList()
            layout.withPageZeroDispatchBindingsForBuild { bindings ->
                retainedDispatchBindings = bindings.toList()
                assertEquals(2, bindings.size)
                assertEquals(
                    setOf(0x4A4B_454E_0000_1010L, 0x4A4B_454E_0000_2020L),
                    bindings.mapTo(linkedSetOf()) { binding -> binding.entryToken },
                )
                bindings.forEach { binding ->
                    val handle = binding.copyEncodedHandleForBuild()
                    val proof = binding.copyCallSiteProofForBuild()
                    val logicalIdentity = binding.copyLogicalIdentityForBuild()
                    try {
                        assertEquals(0, binding.pageIndex)
                        assertTrue(logicalIdentity.isNotEmpty())
                        assertTrue(
                            binding.matchesForBuild(
                                entryToken = binding.entryToken,
                                encodedHandle = handle,
                                pageIndex = 0,
                                callSiteProof = proof,
                            ),
                        )
                        handle[0] = (handle[0].toInt() xor 0x55).toByte()
                        assertFalse(
                            binding.matchesForBuild(
                                entryToken = binding.entryToken,
                                encodedHandle = handle,
                                pageIndex = 0,
                                callSiteProof = proof,
                            ),
                        )
                    } finally {
                        Arrays.fill(handle, 0)
                        Arrays.fill(proof, 0)
                        Arrays.fill(logicalIdentity, 0)
                    }
                }
            }
            assertTrue(retainedDispatchBindings.all { binding -> binding.isWiped })
            assertFailsWith<IllegalStateException> {
                retainedDispatchBindings.first().copyEncodedHandleForBuild()
            }
            layout.withPageZeroDispatchBindingsForBuild { bindings ->
                assertEquals(2, bindings.size)
                assertTrue(bindings.none { binding -> binding.isWiped })
            }

            val payloadTampered = artifactEntries(layout) { name, bytes ->
                if (name == page1.resourcePath) {
                    bytes[page1.resourceOffset + 3] = (bytes[page1.resourceOffset + 3].toInt() xor 0x44).toByte()
                }
            }
            assertFalse(layout.verifyWriterEquivalentArtifactForBuild(payloadTampered))

            val rootTampered = artifactEntries(layout) { name, bytes ->
                if (name == rootShard.entryName) {
                    bytes[rootShard.offset] = (bytes[rootShard.offset].toInt() xor 0x01).toByte()
                }
            }
            assertFalse(layout.verifyWriterEquivalentArtifactForBuild(rootTampered))

            layout.wipe()
            assertTrue(layout.isWiped)
            assertFailsWith<IllegalStateException> { layout.entriesForBuild() }
            assertFailsWith<IllegalStateException> { layout.withNativeLocatorRecordsForBuild { } }
            assertFailsWith<IllegalStateException> { layout.withPageZeroDispatchBindingsForBuild { } }
        } finally {
            layout.wipe()
        }
    }

    @Test
    fun finalization_rejects_overlapping_physical_page_ranges_before_plan_materialization() {
        val identity0 = "fixture:aken-finalization:overlap-0".encodeToByteArray()
        val identity1 = "fixture:aken-finalization:overlap-1".encodeToByteArray()
        val plain = "overlap page payload".encodeToByteArray()
        val proof = byteArrayOf(1, 2, 3, 4)
        val page0 = AkenVbc4PendingPage.create(
            entryToken = 1L,
            logicalIdentity = identity0,
            plaintext = plain,
            resourcePath = "META-INF/.aken/vbc4/overlap.bin",
            pageIndex = 0,
            callSiteProof = proof,
            random = SecureRandom(),
        )
        val page1 = AkenVbc4PendingPage.create(
            entryToken = 2L,
            logicalIdentity = identity1,
            plaintext = plain,
            resourcePath = "META-INF/.aken/vbc4/overlap.bin",
            resourceOffset = page0.expectedStoredLength - 1,
            pageIndex = 0,
            callSiteProof = proof,
            random = SecureRandom(),
        )
        try {
            assertFailsWith<IllegalArgumentException> {
                AkenVbc4FinalizationLayout.reserve(
                    pendingPages = listOf(page0, page1),
                    fixedEntries = emptyList(),
                )
            }
            assertFalse(page0.isWiped)
            assertFalse(page1.isWiped)
        } finally {
            page0.wipe()
            page1.wipe()
            Arrays.fill(identity0, 0)
            Arrays.fill(identity1, 0)
            Arrays.fill(plain, 0)
            Arrays.fill(proof, 0)
        }
    }

    private fun artifactEntries(
        layout: AkenVbc4FinalizationLayout,
        mutate: (String, ByteArray) -> Unit = { _, _ -> },
    ): List<AkenArtifactEntry> = layout.entriesForBuild().map { entry ->
        val bytes = entry.copyBytesForBuild()
        try {
            mutate(entry.name, bytes)
            AkenArtifactEntry(entry.name, bytes)
        } finally {
            Arrays.fill(bytes, 0)
        }
    }
}
