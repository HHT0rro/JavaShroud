package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageEnvelope
import io.github.hht0rro.javashroud.transforms.protection.qp.QpResourceKind
import io.github.hht0rro.javashroud.transforms.protection.qp.QpRouteMetadata
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.qp.QpProofMetadata
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpPageEnvelopeTest {
    @Test
    fun compact_envelope_round_trips_strictly_and_binds_only_its_current_page() {
        val fixture = fixture(seed = 1_213, callSiteProof = byteArrayOf(0x11, 0x22, 0x33, 0x44))
        var envelope: QpPageEnvelope? = null
        var parsed: QpPageEnvelope? = null
        var encoded: ByteArray? = null
        var tampered: ByteArray? = null
        var trailing: ByteArray? = null
        var legacyForm: ByteArray? = null
        var handleEncoding: ByteArray? = null
        var expectedDescriptor: ByteArray? = null
        try {
            envelope = QpPageEnvelope.create(
                entryToken = 0x0102_0304_0506_0708L,
                handle = fixture.handle,
                descriptor = fixture.descriptor,
                rawCallSiteProof = fixture.callSiteProof,
            )
            assertTrue(envelope.encodedSize <= QpPageEnvelope.MAX_ENCODED_SIZE)
            assertTrue(envelope.matchesDescriptor(fixture.descriptor))

            handleEncoding = fixture.handle.encoded
            assertTrue(
                envelope.matchesCurrentPage(
                    entryToken = 0x0102_0304_0506_0708L,
                    encodedHandle = handleEncoding,
                    pageIndex = fixture.descriptor.pageIndex,
                    rawCallSiteProof = fixture.callSiteProof,
                    descriptor = fixture.descriptor,
                ),
            )

            encoded = envelope.encode()
            assertEquals(envelope.encodedSize, encoded.size)
            assertTrue(encoded.size <= QpPageEnvelope.MAX_ENCODED_SIZE)
            parsed = QpPageEnvelope.decode(encoded)
            assertTrue(parsed.matchesDescriptor(fixture.descriptor))
            assertTrue(
                parsed.matchesTypedBridgeRequest(
                    entryToken = 0x0102_0304_0506_0708L,
                    encodedHandle = handleEncoding,
                    pageIndex = fixture.descriptor.pageIndex,
                    rawCallSiteProof = fixture.callSiteProof,
                ),
            )
            assertFalse(
                parsed.matchesTypedBridgeRequest(
                    entryToken = 0x0102_0304_0506_0708L,
                    encodedHandle = handleEncoding,
                    pageIndex = fixture.descriptor.pageIndex,
                    rawCallSiteProof = encoded,
                ),
                "the native locator envelope cannot replace the typed JNI raw proof argument",
            )

            // The compact locator carries only fixed-size bindings; the
            // descriptor encoding itself never travels inline.
            expectedDescriptor = fixture.descriptor.encode()
            assertEquals(ENVELOPE_FIXED_SIZE, encoded.size)
            assertTrue(encoded.size < expectedDescriptor.size)

            val mutableCopy = parsed.copyEncodedHandleForCurrentPage()
            val retainedCopy = parsed.copyEncodedHandleForCurrentPage()
            try {
                mutableCopy[0] = (mutableCopy[0].toInt() xor 0x5A).toByte()
                assertFalse(mutableCopy.contentEquals(retainedCopy))
                assertTrue(
                    parsed.matchesTypedBridgeRequest(
                        entryToken = 0x0102_0304_0506_0708L,
                        encodedHandle = retainedCopy,
                        pageIndex = fixture.descriptor.pageIndex,
                        rawCallSiteProof = fixture.callSiteProof,
                    ),
                )
                assertFalse(
                    parsed.matchesTypedBridgeRequest(
                        entryToken = 0x0102_0304_0506_0708L,
                        encodedHandle = mutableCopy,
                        pageIndex = fixture.descriptor.pageIndex,
                        rawCallSiteProof = fixture.callSiteProof,
                    ),
                )
            } finally {
                Arrays.fill(mutableCopy, 0)
                Arrays.fill(retainedCopy, 0)
            }

            tampered = encoded.copyOf()
            tampered[tampered.lastIndex] = (tampered[tampered.lastIndex].toInt() xor 0x3D).toByte()
            assertFailsWith<IllegalArgumentException> { QpPageEnvelope.decode(tampered) }

            trailing = encoded + 0x66
            assertFailsWith<IllegalArgumentException> { QpPageEnvelope.decode(trailing) }

            // Legacy inline (1) and retired compact (2) forms fail closed.
            legacyForm = encoded.copyOf().also { it[0] = 1 }
            assertFailsWith<IllegalArgumentException> { QpPageEnvelope.decode(legacyForm) }
            legacyForm = encoded.copyOf().also { it[0] = 2 }
            assertFailsWith<IllegalArgumentException> { QpPageEnvelope.decode(legacyForm) }
            legacyForm = encoded.copyOf().also { it[0] = 4 }
            assertFailsWith<IllegalArgumentException> { QpPageEnvelope.decode(legacyForm) }

            val wrongProof = fixture.callSiteProof.copyOf()
            try {
                wrongProof[0] = (wrongProof[0].toInt() xor 0x17).toByte()
                assertFailsWith<IllegalArgumentException> {
                    QpPageEnvelope.create(
                        entryToken = 0x0102_0304_0506_0708L,
                        handle = fixture.handle,
                        descriptor = fixture.descriptor,
                        rawCallSiteProof = wrongProof,
                    )
                }
            } finally {
                Arrays.fill(wrongProof, 0)
            }

            parsed.wipe()
            assertTrue(parsed.isWiped)
            assertFalse(
                parsed.matchesTypedBridgeRequest(
                    entryToken = 0x0102_0304_0506_0708L,
                    encodedHandle = handleEncoding,
                    pageIndex = fixture.descriptor.pageIndex,
                    rawCallSiteProof = fixture.callSiteProof,
                ),
            )
            assertFailsWith<IllegalStateException> { parsed.encode() }
            assertFailsWith<IllegalStateException> { parsed.copyEncodedHandleForCurrentPage() }
        } finally {
            parsed?.wipe()
            envelope?.wipe()
            encoded?.let { Arrays.fill(it, 0) }
            tampered?.let { Arrays.fill(it, 0) }
            trailing?.let { Arrays.fill(it, 0) }
            legacyForm?.let { Arrays.fill(it, 0) }
            handleEncoding?.let { Arrays.fill(it, 0) }
            expectedDescriptor?.let { Arrays.fill(it, 0) }
            fixture.wipe()
        }
    }

    @Test
    fun maximum_legal_call_site_proof_stays_within_the_bounded_locator_record() {
        val proof = ByteArray(4096) { index -> (index * 31 + 7).toByte() }
        val fixture = fixture(seed = 1_307, callSiteProof = proof)
        Arrays.fill(proof, 0)
        var envelope: QpPageEnvelope? = null
        var parsed: QpPageEnvelope? = null
        var encoded: ByteArray? = null
        var handleEncoding: ByteArray? = null
        var artifactCommitment: ByteArray? = null
        try {
            envelope = QpPageEnvelope.create(
                entryToken = -0x0102_0304_0506_0708L,
                handle = fixture.handle,
                descriptor = fixture.descriptor,
                rawCallSiteProof = fixture.callSiteProof,
            )
            encoded = envelope.encode()
            assertEquals(envelope.encodedSize, encoded.size)
            assertEquals(ENVELOPE_FIXED_SIZE, encoded.size)
            assertTrue(encoded.size <= QpPageEnvelope.MAX_ENCODED_SIZE)

            parsed = QpPageEnvelope.decode(encoded)
            handleEncoding = fixture.handle.encoded
            assertTrue(
                parsed.matchesCurrentPage(
                    entryToken = -0x0102_0304_0506_0708L,
                    encodedHandle = handleEncoding,
                    pageIndex = fixture.descriptor.pageIndex,
                    rawCallSiteProof = fixture.callSiteProof,
                    descriptor = fixture.descriptor,
                ),
            )

            val changedProof = fixture.callSiteProof.copyOf()
            try {
                changedProof[changedProof.lastIndex] = (changedProof.lastIndex xor 0x54).toByte()
                assertFalse(
                    parsed.matchesTypedBridgeRequest(
                        entryToken = -0x0102_0304_0506_0708L,
                        encodedHandle = handleEncoding,
                        pageIndex = fixture.descriptor.pageIndex,
                        rawCallSiteProof = changedProof,
                    ),
                )
            } finally {
                Arrays.fill(changedProof, 0)
            }

            artifactCommitment = parsed.copyArtifactCommitmentForCurrentPage()
            val retainedCommitment = parsed.copyArtifactCommitmentForCurrentPage()
            try {
                artifactCommitment[0] = (artifactCommitment[0].toInt() xor 0x28).toByte()
                assertFalse(artifactCommitment.contentEquals(retainedCommitment))
            } finally {
                Arrays.fill(retainedCommitment, 0)
            }
        } finally {
            parsed?.wipe()
            envelope?.wipe()
            encoded?.let { Arrays.fill(it, 0) }
            handleEncoding?.let { Arrays.fill(it, 0) }
            artifactCommitment?.let { Arrays.fill(it, 0) }
            fixture.wipe()
        }
    }

    private fun fixture(seed: Int, callSiteProof: ByteArray): Fixture {
        val commitment = ByteArray(QpArtifactCommitment.DIGEST_SIZE) { index -> (seed + index * 19).toByte() }
        val plan = QpBuildPlan.create(commitment, testSecretPackDraft(), DeterministicSecureRandom(seed))
        var page: QpBuildPlan.Page? = null
        var copiedProof: ByteArray? = null
        try {
            page = plan.registerPage(
                kind = QpResourceKind.QpMethod,
                identity = "fixture:native-page-envelope:$seed".encodeToByteArray(),
                pageIndex = 2,
            )
            copiedProof = callSiteProof.copyOf()
            val route = QpRouteMetadata.fromHandle(
                handle = page.handle,
                logicalIdentity = page.logicalIdentity,
                resourcePath = "META-INF/.qp/envelope/" + page.resourceKind.id + "-" + page.pageIndex + ".bin",
                resourceOffset = 17,
                storedLength = 511,
                codecVariant = page.codecVariant,
                layoutVariant = page.layoutVariant,
            )
            val proof = proofFor(
                handle = page.handle,
                identity = page.logicalIdentity,
                artifactCommitment = commitment,
                callSiteProof = checkNotNull(copiedProof),
                codecVariant = page.codecVariant,
                layoutVariant = page.layoutVariant,
            )
            val descriptor = QpPageDescriptor.create(
                handle = page.handle,
                logicalIdentity = page.logicalIdentity,
                route = route,
                proof = proof,
                targetPageSize = page.targetSize,
                secretSlot = page.secretSlot,
            )
            return Fixture(page.handle, descriptor, checkNotNull(copiedProof), plan).also {
                page = null
                copiedProof = null
            }
        } finally {
            Arrays.fill(commitment, 0)
            copiedProof?.let { Arrays.fill(it, 0) }
            page?.wipe()
            if (page != null) plan.wipe()
        }
    }

    private fun proofFor(
        handle: QpHandle,
        identity: ByteArray,
        artifactCommitment: ByteArray,
        callSiteProof: ByteArray,
        codecVariant: String,
        layoutVariant: String,
    ): QpProofMetadata {
        val meshRoot = ByteArray(QpArtifactCommitment.DIGEST_SIZE) { 0x31 }
        val leafDigest = ByteArray(QpArtifactCommitment.DIGEST_SIZE) { 0x42 }
        val sibling = ByteArray(QpArtifactCommitment.DIGEST_SIZE) { 0x53 }
        try {
            return QpProofMetadata.create(
                leafIdentity = QpLeafIdentity.fromHandle(handle, identity),
                artifactCommitment = artifactCommitment,
                meshRoot = meshRoot,
                leafDigest = leafDigest,
                siblings = listOf(sibling),
                siblingIsLeft = listOf(true),
                callSiteProof = callSiteProof,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
            )
        } finally {
            Arrays.fill(meshRoot, 0)
            Arrays.fill(leafDigest, 0)
            Arrays.fill(sibling, 0)
        }
    }

    private class Fixture(
        val handle: QpHandle,
        val descriptor: QpPageDescriptor,
        val callSiteProof: ByteArray,
        private val plan: QpBuildPlan,
    ) {
        fun wipe() {
            Arrays.fill(callSiteProof, 0)
            handle.wipe()
            plan.wipe()
        }
    }

    private class DeterministicSecureRandom(seed: Int) : java.security.SecureRandom() {
        private var state = seed

        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { index -> bytes[index] = nextValue().toByte() }
        }

        override fun nextInt(bound: Int): Int {
            require(bound > 0)
            return Math.floorMod(nextValue(), bound)
        }

        private fun nextValue(): Int {
            state = state * 1_103_515_245 + 12_345
            return state
        }
    }

    private companion object {
        /** form + entry token + kind + index + handle + locator + commitment + 5 bindings. */
        private const val ENVELOPE_FIXED_SIZE: Int =
            1 + Long.SIZE_BYTES + 1 + Int.SIZE_BYTES + 24 + 16 + 32 + 32 + 32 + 32 + 32 + 32
    }
}
