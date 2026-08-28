package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeHandlerDescriptor
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpNativeHandlerDescriptorTest {
    @Test
    fun loader_attestation_descriptor_binds_one_identity_handle_and_proof() {
        val identity = ByteArray(QpNativeHandlerDescriptor.IDENTITY_SIZE) { index -> (index * 37 + 5).toByte() }
        val handle = ByteArray(QpHandle.ENCODED_HANDLE_SIZE) { index -> (index * 29 + 7).toByte() }
        val proof = ByteArray(QpNativeHandlerDescriptor.CALL_SITE_PROOF_SIZE) { index -> (index * 23 + 11).toByte() }
        val nonce = ByteArray(QpNativeHandlerDescriptor.NONCE_SIZE) { index -> (index * 19 + 13).toByte() }
        var descriptor: ByteArray? = null
        var tampered: ByteArray? = null
        var wrongProof: ByteArray? = null
        try {
            descriptor = QpNativeHandlerDescriptor.createLoaderAttestation(
                logicalIdentity = identity,
                encodedHandle = handle,
                callSiteProof = proof,
                nonce = nonce,
            )
            assertEquals(QpNativeHandlerDescriptor.ENCODED_SIZE, checkNotNull(descriptor).size)
            assertTrue(
                QpNativeHandlerDescriptor.isLoaderAttestationForBuild(
                    encoded = checkNotNull(descriptor),
                    logicalIdentity = identity,
                    encodedHandle = handle,
                    callSiteProof = proof,
                ),
            )

            tampered = checkNotNull(descriptor).copyOf()
            tampered[128] = (tampered[128].toInt() xor 0x5A).toByte()
            assertFalse(
                QpNativeHandlerDescriptor.isLoaderAttestationForBuild(
                    encoded = checkNotNull(tampered),
                    logicalIdentity = identity,
                    encodedHandle = handle,
                    callSiteProof = proof,
                ),
            )

            wrongProof = proof.copyOf()
            wrongProof[wrongProof.lastIndex] = (wrongProof.last().toInt() xor 0x39).toByte()
            assertFalse(
                QpNativeHandlerDescriptor.isLoaderAttestationForBuild(
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
