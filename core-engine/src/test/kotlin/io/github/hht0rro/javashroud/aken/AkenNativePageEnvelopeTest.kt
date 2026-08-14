package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHighValueLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativePageEnvelope
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRoutingMetadata
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorFragment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorRole
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
        val kind = AkenResourceKind.Vbc4Method
        val pageIndex = 2
        val targetPageSize = 512
        val codecVariant = AkenResourceCodec.CANONICAL_CODEC_VARIANT
        val layoutVariant = "aken4-frame1:fixture:12:8:head:AAAAAAAAAAA"
        val logicalIdentity = "fixture:native-page-envelope:$seed".encodeToByteArray()
        val handleEncoding = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (seed + index * 17).toByte() }
        val locatorToken = ByteArray(AkenHandle.LOCATOR_TOKEN_SIZE) { index -> (seed * 3 + index * 11).toByte() }
        val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (seed + index * 19).toByte() }
        val javaFragments = List(3) { ordinal -> runtimeFragment(AkenRuntimeEvaluatorRole.Java, ordinal, seed) }
        val nativeFragments = List(3) { index -> runtimeFragment(AkenRuntimeEvaluatorRole.Native, index + 3, seed) }
        val terminal = runtimeFragment(AkenRuntimeEvaluatorRole.Terminal, 6, seed)
        var fingerprint: ByteArray? = null
        var handle: AkenHandle? = null
        var copiedProof: ByteArray? = null
        try {
            fingerprint = AkenRuntimeEvaluatorPlan.computeFingerprint(
                resourceKind = kind,
                logicalIdentity = logicalIdentity,
                pageIndex = pageIndex,
                targetPageSize = targetPageSize,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
                handleEncoding = handleEncoding,
                locatorToken = locatorToken,
                javaFragments = javaFragments,
                nativeFragments = nativeFragments,
                terminal = terminal,
            )
            val evaluatorPlan = AkenRuntimeEvaluatorPlan.create(
                javaFragments = javaFragments,
                nativeFragments = nativeFragments,
                terminal = terminal,
                fingerprint = checkNotNull(fingerprint),
            )
            handle = AkenHandle.create(
                resourceKind = kind,
                pageIndex = pageIndex,
                encoded = handleEncoding,
                locatorToken = locatorToken,
                evaluatorFingerprint = checkNotNull(fingerprint),
            )
            copiedProof = callSiteProof.copyOf()
            val route = AkenRoutingMetadata.fromHandle(
                handle = checkNotNull(handle),
                logicalIdentity = logicalIdentity,
                resourcePath = "META-INF/.aken/envelope/" + kind.id + "-" + pageIndex + ".bin",
                resourceOffset = 17,
                storedLength = 511,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
            )
            val proof = proofFor(
                handle = checkNotNull(handle),
                identity = logicalIdentity,
                artifactCommitment = commitment,
                callSiteProof = checkNotNull(copiedProof),
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
            )
            val descriptor = AkenRuntimePageDescriptor.create(
                handle = checkNotNull(handle),
                logicalIdentity = logicalIdentity,
                route = route,
                proof = proof,
                targetPageSize = targetPageSize,
                evaluatorPlan = evaluatorPlan,
            )
            return Fixture(checkNotNull(handle), descriptor, checkNotNull(copiedProof)).also {
                handle = null
                copiedProof = null
            }
        } finally {
            Arrays.fill(logicalIdentity, 0)
            Arrays.fill(handleEncoding, 0)
            Arrays.fill(locatorToken, 0)
            Arrays.fill(commitment, 0)
            fingerprint?.let { Arrays.fill(it, 0) }
            copiedProof?.let { Arrays.fill(it, 0) }
            handle?.wipe()
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

    private fun runtimeFragment(
        role: AkenRuntimeEvaluatorRole,
        ordinal: Int,
        seed: Int,
    ): AkenRuntimeEvaluatorFragment {
        val shape = ByteArray(65) { index -> (seed + role.id * 41 + ordinal * 17 + index).toByte() }
        val callToken = ByteArray(32) { index -> (seed * 3 + role.id * 23 + ordinal * 13 + index).toByte() }
        val tablePermutation = IntArray(32) { index -> (index + ordinal) and 31 }
        try {
            shape[0] = 1
            return AkenRuntimeEvaluatorFragment.create(
                role = role,
                ordinal = ordinal,
                family = (seed + ordinal * 5) and 0x0F,
                shape = shape,
                callToken = callToken,
                tablePermutation = tablePermutation,
            )
        } finally {
            Arrays.fill(shape, 0)
            Arrays.fill(callToken, 0)
            Arrays.fill(tablePermutation, 0)
        }
    }

    private class Fixture(
        val handle: AkenHandle,
        val descriptor: AkenRuntimePageDescriptor,
        val callSiteProof: ByteArray,
    ) {
        fun wipe() {
            Arrays.fill(callSiteProof, 0)
            handle.wipe()
        }
    }
}
