package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.qp.QpResourceKind
import io.github.hht0rro.javashroud.transforms.protection.qp.QpRouteMetadata
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.qp.QpProofMetadata
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class QpPageDescriptorTest {
    private val commitment = ByteArray(QpArtifactCommitment.DIGEST_SIZE) { index ->
        (index * 13 + 5).toByte()
    }

    @Test
    fun descriptor_round_trips_one_compact_locator_without_key_material() {
        val plan = QpBuildPlan.create(commitment, testSecretPackDraft(), DeterministicSecureRandom(701))
        try {
            val page = plan.registerPage(
                kind = QpResourceKind.QpMethod,
                identity = "fixture:runtime:descriptor".encodeToByteArray(),
                pageIndex = 4,
            )
            val descriptor = descriptorFor(plan, page)
            val encoded = descriptor.encode()
            try {
                val decoded = QpPageDescriptor.decode(encoded)
                assertEquals(page.resourceKind, decoded.resourceKind)
                assertEquals(page.pageIndex, decoded.pageIndex)
                assertEquals(page.targetSize, decoded.targetPageSize)
                assertEquals(page.secretSlot, decoded.secretSlot)
                assertContentEquals(page.logicalIdentity, decoded.logicalIdentity)
                assertEquals(descriptor.route.resourcePath, decoded.route.resourcePath)
                assertEquals(descriptor.route.resourceOffset, decoded.route.resourceOffset)
                assertEquals(descriptor.route.storedLength, decoded.route.storedLength)
                assertEquals(descriptor.route.logicalBindingPath, decoded.route.logicalBindingPath)
                assertContentEquals(descriptor.proof.callSiteProof, decoded.proof.callSiteProof)
                assertContentEquals(
                    page.handle.keyCommitmentFingerprint,
                    decoded.handle.keyCommitmentFingerprint,
                )
                assertTrue(decoded.matches(page.handle))
                assertTrue(decoded.matches(decoded.handle))
                // The compact encoding is small and carries no evaluator or
                // DEK material: version, framed route, framed proof, size, slot.
                assertEquals(3, encoded[0].toInt() and 0xFF)
                val routeLen = routeLength(encoded)
                val proofStart = 5 + routeLen
                val proofLen = ((encoded[proofStart].toInt() and 0xFF) shl 24) or
                    ((encoded[proofStart + 1].toInt() and 0xFF) shl 16) or
                    ((encoded[proofStart + 2].toInt() and 0xFF) shl 8) or
                    (encoded[proofStart + 3].toInt() and 0xFF)
                assertEquals(
                    encoded.size,
                    1 + 4 + routeLen + 4 + proofLen + 4 + 4,
                )
            } finally {
                encoded.fill(0)
            }
        } finally {
            plan.wipe()
        }
    }

    @Test
    fun descriptor_is_defensive_and_rejects_mismatched_page_or_slot_metadata() {
        val plan = QpBuildPlan.create(commitment, testSecretPackDraft(), DeterministicSecureRandom(811))
        try {
            val page = plan.registerPage(
                kind = QpResourceKind.StringPage,
                identity = "fixture:runtime:one".encodeToByteArray(),
                pageIndex = 1,
            )
            val other = plan.registerPage(
                kind = QpResourceKind.StringPage,
                identity = "fixture:runtime:two".encodeToByteArray(),
                pageIndex = 1,
            )
            val descriptor = descriptorFor(plan, page)

            val identityCopy = descriptor.logicalIdentity
            val expectedIdentity = identityCopy.copyOf()
            try {
                identityCopy.fill(0x31.toByte())
                assertContentEquals(expectedIdentity, descriptor.logicalIdentity)
            } finally {
                identityCopy.fill(0)
                expectedIdentity.fill(0)
            }

            val mismatchedRoute = QpRouteMetadata.fromHandle(
                handle = other.handle,
                logicalIdentity = other.logicalIdentity,
                resourcePath = "META-INF/.qp/runtime/other.bin",
                resourceOffset = 11,
                storedLength = 71,
                codecVariant = other.codecVariant,
                layoutVariant = other.layoutVariant,
            )
            assertFailsWith<IllegalArgumentException> {
                QpPageDescriptor.create(
                    handle = page.handle,
                    logicalIdentity = page.logicalIdentity,
                    route = mismatchedRoute,
                    proof = proofFor(plan, page),
                    targetPageSize = page.targetSize,
                    secretSlot = page.secretSlot,
                )
            }

            assertFailsWith<IllegalArgumentException> {
                QpPageDescriptor.create(
                    handle = page.handle,
                    logicalIdentity = page.logicalIdentity,
                    route = routeFor(page),
                    proof = proofFor(plan, page),
                    targetPageSize = page.targetSize,
                    secretSlot = -1,
                )
            }
        } finally {
            plan.wipe()
        }
    }

    @Test
    fun descriptor_parse_rejects_invalid_version_lengths_and_trailing_bytes() {
        val plan = QpBuildPlan.create(commitment, testSecretPackDraft(), DeterministicSecureRandom(919))
        try {
            val page = plan.registerPage(
                kind = QpResourceKind.NativeChunk,
                identity = "fixture:runtime:strict".encodeToByteArray(),
                pageIndex = 0,
            )
            val encoded = descriptorFor(plan, page).encode()
            val badVersion = encoded.copyOf().also { it[0] = 99.toByte() }
            val retiredInlineVersion = encoded.copyOf().also { it[0] = 2.toByte() }
            val badRouteLength = encoded.copyOf().also {
                it[1] = 0x7F
                it[2] = 0xFF.toByte()
                it[3] = 0xFF.toByte()
                it[4] = 0xFF.toByte()
            }
            val trailing = encoded.copyOf(encoded.size + 1).also { it[it.lastIndex] = 0x7E }
            try {
                assertFailsWith<IllegalArgumentException> { QpPageDescriptor.decode(badVersion) }
                assertFailsWith<IllegalArgumentException> { QpPageDescriptor.decode(retiredInlineVersion) }
                assertFailsWith<IllegalArgumentException> { QpPageDescriptor.decode(badRouteLength) }
                assertFailsWith<IllegalArgumentException> { QpPageDescriptor.decode(trailing) }
            } finally {
                encoded.fill(0)
                badVersion.fill(0)
                retiredInlineVersion.fill(0)
                badRouteLength.fill(0)
                trailing.fill(0)
            }

        } finally {
            plan.wipe()
        }
    }

    private fun descriptorFor(plan: QpBuildPlan, page: QpBuildPlan.Page): QpPageDescriptor {
        val route = routeFor(page)
        val proof = proofFor(plan, page)
        return QpPageDescriptor.create(
            handle = page.handle,
            logicalIdentity = page.logicalIdentity,
            route = route,
            proof = proof,
            targetPageSize = page.targetSize,
            secretSlot = page.secretSlot,
        )
    }

    private fun routeFor(page: QpBuildPlan.Page): QpRouteMetadata = QpRouteMetadata.fromHandle(
        handle = page.handle,
        logicalIdentity = page.logicalIdentity,
        resourcePath = "META-INF/.qp/runtime/" + page.resourceKind.id + "-" + page.pageIndex + ".bin",
        resourceOffset = 17,
        storedLength = 113,
        codecVariant = page.codecVariant,
        layoutVariant = page.layoutVariant,
        logicalBindingPath = "META-INF/qp/logical-binding-${page.pageIndex}.bin",
    )

    private fun proofFor(plan: QpBuildPlan, page: QpBuildPlan.Page): QpProofMetadata {
        val leaf = QpLeafIdentity.fromHandle(page.handle, page.logicalIdentity)
        return QpProofMetadata.create(
            leafIdentity = leaf,
            artifactCommitment = plan.artifactCanonicalCommitment,
            meshRoot = ByteArray(32) { 0x41 },
            leafDigest = ByteArray(32) { 0x42 },
            siblings = listOf(ByteArray(32) { 0x43 }),
            siblingIsLeft = listOf(true),
            callSiteProof = byteArrayOf(0x10, 0x20, 0x30),
            codecVariant = page.codecVariant,
            layoutVariant = page.layoutVariant,
        )
    }

    private fun routeLength(encoded: ByteArray): Int =
        ((encoded[1].toInt() and 0xFF) shl 24) or
            ((encoded[2].toInt() and 0xFF) shl 16) or
            ((encoded[3].toInt() and 0xFF) shl 8) or
            (encoded[4].toInt() and 0xFF)

    private class DeterministicSecureRandom(seed: Int) : SecureRandom() {
        private var state = seed

        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { index -> bytes[index] = nextValue().toByte() }
        }

        override fun nextInt(bound: Int): Int {
            require(bound > 0)
            return Math.floorMod(nextValue(), bound)
        }

        override fun nextBoolean(): Boolean = (nextValue() and 1) == 0

        private fun nextValue(): Int {
            state = state * 1_103_515_245 + 12_345
            return state
        }
    }
}
