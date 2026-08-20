package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkHandlerDescriptor
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenNativeChunkHandlerDescriptorTest {
    @Test
    fun loader_attestation_descriptor_binds_one_identity_handle_and_proof() {
        val identity = ByteArray(AkenNativeChunkHandlerDescriptor.IDENTITY_SIZE) { index -> (index * 37 + 5).toByte() }
        val handle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 29 + 7).toByte() }
        val proof = ByteArray(AkenNativeChunkHandlerDescriptor.CALL_SITE_PROOF_SIZE) { index -> (index * 23 + 11).toByte() }
        val nonce = ByteArray(AkenNativeChunkHandlerDescriptor.NONCE_SIZE) { index -> (index * 19 + 13).toByte() }
        var descriptor: ByteArray? = null
        var tampered: ByteArray? = null
        var wrongProof: ByteArray? = null
        try {
            descriptor = AkenNativeChunkHandlerDescriptor.createLoaderAttestation(
                logicalIdentity = identity,
                encodedHandle = handle,
                callSiteProof = proof,
                nonce = nonce,
            )
            assertEquals(AkenNativeChunkHandlerDescriptor.ENCODED_SIZE, checkNotNull(descriptor).size)
            assertTrue(
                AkenNativeChunkHandlerDescriptor.isLoaderAttestationForBuild(
                    encoded = checkNotNull(descriptor),
                    logicalIdentity = identity,
                    encodedHandle = handle,
                    callSiteProof = proof,
                ),
            )

            tampered = checkNotNull(descriptor).copyOf()
            tampered[128] = (tampered[128].toInt() xor 0x5A).toByte()
            assertFalse(
                AkenNativeChunkHandlerDescriptor.isLoaderAttestationForBuild(
                    encoded = checkNotNull(tampered),
                    logicalIdentity = identity,
                    encodedHandle = handle,
                    callSiteProof = proof,
                ),
            )

            wrongProof = proof.copyOf()
            wrongProof[wrongProof.lastIndex] = (wrongProof.last().toInt() xor 0x39).toByte()
            assertFalse(
                AkenNativeChunkHandlerDescriptor.isLoaderAttestationForBuild(
                    encoded = checkNotNull(descriptor),
                    logicalIdentity = identity,
                    encodedHandle = handle,
                    callSiteProof = checkNotNull(wrongProof),
                ),
            )
        } finally {
            descriptor?.let { Arrays.fill(it, 0) }
            tampered?.let { Arrays.fill(it, 0) }
            wrongProof?.let { Arrays.fill(it, 0) }
            Arrays.fill(identity, 0)
            Arrays.fill(handle, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(nonce, 0)
        }
    }
}
