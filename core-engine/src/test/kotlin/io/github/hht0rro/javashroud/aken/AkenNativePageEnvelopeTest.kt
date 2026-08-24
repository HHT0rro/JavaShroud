package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHighValueLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativePageEnvelope
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRoutingMetadata
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimePageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenSealingProofMetadata
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AkenNativePageEnvelopeTest {
    @Test
    fun inline_envelope_round_trips_strictly_and_binds_only_its_current_page() {
        val fixture = fixture(seed = 1_213, callSiteProof = byteArrayOf(0x11, 0x22, 0x33, 0x44))
        var envelope: AkenNativePageEnvelope? = null
        var parsed: AkenNativePageEnvelope? = null
        var encoded: ByteArray? = null
        var tampered: ByteArray? = null
        var trailing: ByteArray? = null
        var handleEncoding: ByteArray? = null
        var inline: ByteArray? = null
        var expectedDescriptor: ByteArray? = null
        try {
            envelope = AkenNativePageEnvelope.create(
                entryToken = 0x0102_0304_0506_0708L,
                handle = fixture.handle,
                descriptor = fixture.descriptor,
                rawCallSiteProof = fixture.callSiteProof,
            )
            assertTrue(envelope.hasInlineDescriptor)
            assertTrue(envelope.encodedSize <= AkenNativePageEnvelope.MAX_ENCODED_SIZE)
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
            assertTrue(encoded.size <= AkenNativePageEnvelope.MAX_ENCODED_SIZE)
            parsed = AkenNativePageEnvelope.decode(encoded)
            assertTrue(parsed.hasInlineDescriptor)
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

            inline = parsed.copyInlineDescriptorEncodingForCurrentPage()
            expectedDescriptor = fixture.descriptor.encode()
            assertContentEquals(expectedDescriptor, checkNotNull(inline))

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
            assertFailsWith<IllegalArgumentException> { AkenNativePageEnvelope.decode(tampered) }

            trailing = encoded + 0x66
            assertFailsWith<IllegalArgumentException> { AkenNativePageEnvelope.decode(trailing) }

            val wrongProof = fixture.callSiteProof.copyOf()
            try {
                wrongProof[0] = (wrongProof[0].toInt() xor 0x17).toByte()
                assertFailsWith<IllegalArgumentException> {
                    AkenNativePageEnvelope.create(
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
            handleEncoding?.let { Arrays.fill(it, 0) }
            inline?.let { Arrays.fill(it, 0) }
            expectedDescriptor?.let { Arrays.fill(it, 0) }
            fixture.wipe()
        }
    }

    @Test
    fun maximum_legal_call_site_proof_uses_compact_descriptor_binding_and_stays_within_bounded_locator_record_limit() {
        val proof = ByteArray(4096) { index -> (index * 31 + 7).toByte() }
        val fixture = fixture(seed = 1_307, callSiteProof = proof)
        Arrays.fill(proof, 0)
        var envelope: AkenNativePageEnvelope? = null
        var parsed: AkenNativePageEnvelope? = null
        var encoded: ByteArray? = null
        var rawDescriptor: ByteArray? = null
        var handleEncoding: ByteArray? = null
        var artifactCommitment: ByteArray? = null
        try {
            rawDescriptor = fixture.descriptor.encode()
            assertTrue(
                rawDescriptor.size > AkenNativePageEnvelope.MAX_ENCODED_SIZE,
                "the existing descriptor encoding exceeds the typed JNI proof slot at the legal 4096-byte proof maximum",
            )

            envelope = AkenNativePageEnvelope.create(
                entryToken = -0x0102_0304_0506_0708L,
                handle = fixture.handle,
                descriptor = fixture.descriptor,
                rawCallSiteProof = fixture.callSiteProof,
            )
            assertFalse(envelope.hasInlineDescriptor)
            assertNull(envelope.copyInlineDescriptorEncodingForCurrentPage())
            encoded = envelope.encode()
            assertEquals(envelope.encodedSize, encoded.size)
            assertTrue(encoded.size <= AkenNativePageEnvelope.MAX_ENCODED_SIZE)
            assertTrue(encoded.size < rawDescriptor.size)

            parsed = AkenNativePageEnvelope.decode(encoded)
            assertFalse(parsed.hasInlineDescriptor)
            assertNull(parsed.copyInlineDescriptorEncodingForCurrentPage())
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
            rawDescriptor?.let { Arrays.fill(it, 0) }
            handleEncoding?.let { Arrays.fill(it, 0) }
            artifactCommitment?.let { Arrays.fill(it, 0) }
            fixture.wipe()
        }
    }

    private fun fixture(seed: Int, callSiteProof: ByteArray): Fixture {
        val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (seed + index * 19).toByte() }
        val plan = AkenBuildPlan.create(commitment, DeterministicSecureRandom(seed))
        var page: AkenBuildPlan.Page? = null
        var copiedProof: ByteArray? = null
        try {
            page = plan.registerPage(
                kind = AkenResourceKind.Vbc4Method,
                identity = "fixture:native-page-envelope:$seed".encodeToByteArray(),
                pageIndex = 2,
            )
            copiedProof = callSiteProof.copyOf()
            val route = AkenRoutingMetadata.fromHandle(
                handle = page.handle,
                logicalIdentity = page.logicalIdentity,
                resourcePath = "META-INF/.aken/envelope/" + page.resourceKind.id + "-" + page.pageIndex + ".bin",
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
            val fingerprint = page.evaluatorPlan.fingerprint
            val evaluatorPlan = try {
                AkenRuntimeEvaluatorPlan.createBound(
                    page.evaluatorPlan.boundPlanForRuntime(route, proof.callSiteProof),
                    fingerprint,
                )
            } finally {
                fingerprint.fill(0)
            }
            val descriptor = AkenRuntimePageDescriptor.create(
                handle = page.handle,
                logicalIdentity = page.logicalIdentity,
                route = route,
                proof = proof,
                targetPageSize = page.targetSize,
                evaluatorPlan = evaluatorPlan,
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
        handle: AkenHandle,
        identity: ByteArray,
        artifactCommitment: ByteArray,
        callSiteProof: ByteArray,
        codecVariant: String,
        layoutVariant: String,
    ): AkenSealingProofMetadata {
        val meshRoot = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { 0x31 }
        val leafDigest = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { 0x42 }
        val sibling = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { 0x53 }
        try {
            return AkenSealingProofMetadata.create(
                leafIdentity = AkenHighValueLeafIdentity.fromHandle(handle, identity),
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
        val handle: AkenHandle,
        val descriptor: AkenRuntimePageDescriptor,
        val callSiteProof: ByteArray,
        private val plan: AkenBuildPlan,
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
}
