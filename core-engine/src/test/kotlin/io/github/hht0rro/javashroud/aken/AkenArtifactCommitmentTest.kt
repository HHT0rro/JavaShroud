package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenCanonicalExclusionKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenCanonicalExclusionRange
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenCanonicalReservation
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHighValueLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRootShardRange
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRoutingMetadata
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenSealingProofMetadata
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenArtifactCommitmentTest {
    @Test
    fun canonicalCommitmentSortsEntriesAndZerosOnlyDeclaredRootShards() {
        val first = AkenArtifactCommitment.compute(
            entries = listOf(
                AkenArtifactEntry("z.bin", byteArrayOf(8, 7, 6)),
                AkenArtifactEntry("a.bin", byteArrayOf(1, 2, 3, 4)),
            ),
            rootShardRanges = listOf(AkenRootShardRange("a.bin", offset = 1, length = 2)),
        )
        val sameExceptShard = AkenArtifactCommitment.compute(
            entries = listOf(
                AkenArtifactEntry("a.bin", byteArrayOf(1, 99, 100, 4)),
                AkenArtifactEntry("z.bin", byteArrayOf(8, 7, 6)),
            ),
            rootShardRanges = listOf(AkenRootShardRange("a.bin", offset = 1, length = 2)),
        )
        val changedOutsideShard = AkenArtifactCommitment.compute(
            entries = listOf(
                AkenArtifactEntry("a.bin", byteArrayOf(2, 99, 100, 4)),
                AkenArtifactEntry("z.bin", byteArrayOf(8, 7, 6)),
            ),
            rootShardRanges = listOf(AkenRootShardRange("a.bin", offset = 1, length = 2)),
        )

        assertContentEquals(first.bytes, sameExceptShard.bytes)
        assertFalse(first.bytes.contentEquals(changedOutsideShard.bytes))

        val plan = AkenBuildPlan.create(first.bytes)
        try {
            assertContentEquals(first.bytes, plan.artifactCanonicalCommitment)
        } finally {
            plan.close()
        }
    }

    @Test
    fun onePassReservationExcludesOnlyDeclaredAkenPayloadAndDescriptorBytes() {
        val payloadRange = AkenCanonicalExclusionRange(
            entryName = "META-INF/.aken/p/vm.bin",
            offset = 5,
            length = 11,
            kind = AkenCanonicalExclusionKind.HighValuePayload,
        )
        val descriptorRange = AkenCanonicalExclusionRange(
            entryName = "META-INF/.aken/d/vm.desc",
            offset = 3,
            length = 9,
            kind = AkenCanonicalExclusionKind.PerPageDescriptor,
        )
        val payloadPlaceholder = byteArrayOf(1, 2, 3, 4, 5) + ByteArray(11) + byteArrayOf(6, 7, 8)
        val descriptorPlaceholder = byteArrayOf(9, 10, 11) + ByteArray(9) + byteArrayOf(12, 13)
        val helperBytes = byteArrayOf(21, 22, 23, 24)
        val commitment = AkenArtifactCommitment.reserve(
            entries = listOf(
                AkenCanonicalReservation(
                    entryName = "META-INF/.aken/p/vm.bin",
                    canonicalBytes = payloadPlaceholder,
                    selfReferentialRanges = listOf(payloadRange),
                ),
                AkenCanonicalReservation(
                    entryName = "META-INF/.aken/d/vm.desc",
                    canonicalBytes = descriptorPlaceholder,
                    selfReferentialRanges = listOf(descriptorRange),
                ),
                AkenCanonicalReservation(
                    entryName = "io/example/Helper.class",
                    canonicalBytes = helperBytes,
                ),
            ),
        )
        val finalPayload = payloadPlaceholder.copyOf().also { bytes ->
            for (index in payloadRange.offset until payloadRange.offset + payloadRange.length) {
                bytes[index] = (0x41 + index).toByte()
            }
        }
        val finalDescriptor = descriptorPlaceholder.copyOf().also { bytes ->
            for (index in descriptorRange.offset until descriptorRange.offset + descriptorRange.length) {
                bytes[index] = (0x61 + index).toByte()
            }
        }
        try {
            assertTrue(
                commitment.matchesWriterEquivalentEntriesForBuild(
                    listOf(
                        AkenArtifactEntry("META-INF/.aken/p/vm.bin", finalPayload),
                        AkenArtifactEntry("META-INF/.aken/d/vm.desc", finalDescriptor),
                        AkenArtifactEntry("io/example/Helper.class", helperBytes),
                    ),
                ),
            )

            finalPayload[payloadRange.offset - 1] = (finalPayload[payloadRange.offset - 1].toInt() xor 0x55).toByte()
            assertFalse(
                commitment.matchesWriterEquivalentEntriesForBuild(
                    listOf(
                        AkenArtifactEntry("META-INF/.aken/p/vm.bin", finalPayload),
                        AkenArtifactEntry("META-INF/.aken/d/vm.desc", finalDescriptor),
                        AkenArtifactEntry("io/example/Helper.class", helperBytes),
                    ),
                ),
            )
        } finally {
            finalPayload.fill(0)
            finalDescriptor.fill(0)
            payloadPlaceholder.fill(0)
            descriptorPlaceholder.fill(0)
            helperBytes.fill(0)
        }
    }

    @Test
    fun rootShardsAreOnePassDerivedAndVerifiedSeparatelyFromCanonicalBytes() {
        val rootRange = AkenRootShardRange("io/example/Helper.class", offset = 2, length = 48)
        val excludedPayload = AkenCanonicalExclusionRange(
            entryName = "META-INF/.aken/p/page.bin",
            offset = 0,
            length = 32,
            kind = AkenCanonicalExclusionKind.HighValuePayload,
        )
        val helperPlaceholder = ByteArray(64) { index -> (0x20 + index).toByte() }
        helperPlaceholder.fill(0, rootRange.offset, rootRange.offset + rootRange.length)
        val payloadPlaceholder = ByteArray(32)
        val commitment = AkenArtifactCommitment.reserve(
            listOf(
                AkenCanonicalReservation(
                    entryName = "io/example/Helper.class",
                    canonicalBytes = helperPlaceholder,
                    rootShardRanges = listOf(rootRange),
                ),
                AkenCanonicalReservation(
                    entryName = "META-INF/.aken/p/page.bin",
                    canonicalBytes = payloadPlaceholder,
                    selfReferentialRanges = listOf(excludedPayload),
                ),
            ),
        )
        val helperFinal = helperPlaceholder.copyOf()
        val payloadFinal = ByteArray(32) { index -> (0x70 + index).toByte() }
        val expectedShard = commitment.copyExpectedRootShardBytesForBuild(rootRange)
        try {
            assertEquals(rootRange.length, expectedShard.size)
            expectedShard.copyInto(helperFinal, rootRange.offset)
            val finalEntries = listOf(
                AkenArtifactEntry("io/example/Helper.class", helperFinal),
                AkenArtifactEntry("META-INF/.aken/p/page.bin", payloadFinal),
            )
            assertTrue(commitment.matchesWriterEquivalentEntriesForBuild(finalEntries))
            assertTrue(commitment.verifyRootShardsForBuild(finalEntries))

            helperFinal[rootRange.offset] = (helperFinal[rootRange.offset].toInt() xor 0x01).toByte()
            val tampered = listOf(
                AkenArtifactEntry("io/example/Helper.class", helperFinal),
                AkenArtifactEntry("META-INF/.aken/p/page.bin", payloadFinal),
            )
            assertTrue(commitment.matchesWriterEquivalentEntriesForBuild(tampered))
            assertFalse(commitment.verifyRootShardsForBuild(tampered))
        } finally {
            helperPlaceholder.fill(0)
            payloadPlaceholder.fill(0)
            helperFinal.fill(0)
            payloadFinal.fill(0)
            expectedShard.fill(0)
        }
    }

    @Test
    fun canonicalProtocolRejectsOverlappingOrUndeclaredExclusionGeometry() {
        val entry = AkenArtifactEntry("META-INF/.aken/p/page.bin", ByteArray(32))
        val payload = AkenCanonicalExclusionRange(
            "META-INF/.aken/p/page.bin",
            4,
            16,
            AkenCanonicalExclusionKind.HighValuePayload,
        )
        val descriptorOverlap = AkenCanonicalExclusionRange(
            "META-INF/.aken/p/page.bin",
            12,
            8,
            AkenCanonicalExclusionKind.PerPageDescriptor,
        )

        assertFailsWith<IllegalArgumentException> {
            AkenArtifactCommitment.compute(
                entries = listOf(entry),
                selfReferentialRanges = listOf(payload, descriptorOverlap),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AkenArtifactCommitment.reserve(
                listOf(
                    AkenCanonicalReservation(
                        entryName = "META-INF/.aken/p/page.bin",
                        canonicalBytes = ByteArray(32),
                        selfReferentialRanges = listOf(
                            AkenCanonicalExclusionRange(
                                "META-INF/.aken/other.bin",
                                0,
                                4,
                                AkenCanonicalExclusionKind.HighValuePayload,
                            ),
                        ),
                    ),
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AkenArtifactCommitment.compute(
                entries = listOf(entry),
                rootShardRanges = listOf(
                    AkenRootShardRange(
                        entryName = "META-INF/.aken/p/page.bin",
                        offset = 6,
                        length = 8,
                    ),
                ),
                selfReferentialRanges = listOf(payload),
            )
        }
    }

    @Test
    fun canonicalCommitmentRejectsInvalidOrAmbiguousShardLayout() {
        val entries = listOf(AkenArtifactEntry("a.bin", byteArrayOf(1, 2, 3, 4)))

        assertFailsWith<IllegalArgumentException> {
            AkenArtifactCommitment.compute(entries, listOf(AkenRootShardRange("missing.bin", 0, 1)))
        }
        assertFailsWith<IllegalArgumentException> {
            AkenArtifactCommitment.compute(entries, listOf(AkenRootShardRange("a.bin", 3, 2)))
        }
        assertFailsWith<IllegalArgumentException> {
            AkenArtifactCommitment.compute(
                entries,
                listOf(AkenRootShardRange("a.bin", 0, 2), AkenRootShardRange("a.bin", 1, 2)),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            AkenArtifactCommitment.compute(
                listOf(AkenArtifactEntry("a.bin", byteArrayOf(1)), AkenArtifactEntry("a.bin", byteArrayOf(2))),
            )
        }
    }

    @Test
    fun perHandleRouteAndProofRoundTripWithoutDekOrCatalog() {
        val plan = AkenBuildPlan.create(ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { it.toByte() })
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.Vbc4Method,
                identity = "owner#method()V".toByteArray(),
                pageIndex = 2,
            )
            val leaf = AkenHighValueLeafIdentity.fromHandle(page.handle, page.logicalIdentity)
            val decodedLeaf = AkenHighValueLeafIdentity.decode(leaf.encode())
            assertEquals(leaf, decodedLeaf)
            assertTrue(decodedLeaf.matches(page.handle))

            val route = AkenRoutingMetadata.fromHandle(
                handle = page.handle,
                logicalIdentity = page.logicalIdentity,
                resourcePath = "META-INF/.aken/r/page.bin",
                resourceOffset = 32,
                storedLength = 96,
                codecVariant = page.codecVariant,
                layoutVariant = page.layoutVariant,
            )
            val decodedRoute = AkenRoutingMetadata.decode(route.encode())
            assertEquals(route.resourcePath, decodedRoute.resourcePath)
            assertEquals(route.resourceOffset, decodedRoute.resourceOffset)
            assertEquals(route.storedLength, decodedRoute.storedLength)
            assertTrue(decodedRoute.matches(page.handle))

            val proof = AkenSealingProofMetadata.create(
                leafIdentity = leaf,
                artifactCommitment = plan.artifactCanonicalCommitment,
                meshRoot = ByteArray(32) { 4 },
                leafDigest = ByteArray(32) { 5 },
                siblings = listOf(ByteArray(32) { 6 }),
                siblingIsLeft = listOf(true),
                callSiteProof = byteArrayOf(7, 8, 9),
                codecVariant = page.codecVariant,
                layoutVariant = page.layoutVariant,
            )
            val decodedProof = AkenSealingProofMetadata.decode(proof.encode())
            assertEquals(proof.leafIdentity, decodedProof.leafIdentity)
            assertContentEquals(proof.artifactCanonicalCommitment, decodedProof.artifactCanonicalCommitment)
            assertContentEquals(proof.merkleRoot, decodedProof.merkleRoot)
            assertContentEquals(proof.currentLeafDigest, decodedProof.currentLeafDigest)
            assertContentEquals(proof.callSiteProof, decodedProof.callSiteProof)

            val malformedHeader = route.encode().also { it[0] = (it[0].toInt() xor 1).toByte() }
            assertFailsWith<IllegalArgumentException> { AkenRoutingMetadata.decode(malformedHeader) }
        } finally {
            plan.close()
        }
    }
}
