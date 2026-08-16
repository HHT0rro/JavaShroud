package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPageMaterialization
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPageMaterializer
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPendingClassPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenTypedPageEntryToken
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AkenPendingClassPageTest {
    @Test
    fun pending_class_page_preserves_its_preassigned_handle_proof_frame_and_route_through_materialization() {
        val identity = "fixture:pending-string:identity".encodeToByteArray()
        val plaintext = "AKEN ClassPage: UTF-8 ☃".encodeToByteArray()
        val proof = ByteArray(41) { index -> (index * 17 + 5).toByte() }
        val handle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 23 + 9).toByte() }
        val expectedIdentity = identity.copyOf()
        val expectedPlaintext = plaintext.copyOf()
        val expectedProof = proof.copyOf()
        val expectedHandle = handle.copyOf()
        val resourcePath = "META-INF/.aken/class/pending-fixture.bin"
        val logicalBindingPath = "META-INF/.logical/class/pending-fixture.bin"
        val plan = newPlan()
        var pending: AkenPendingClassPage? = null
        var materialization: AkenPageMaterialization? = null
        try {
            pending = AkenPendingClassPage.create(
                logicalIdentity = identity,
                plaintext = plaintext,
                resourcePath = resourcePath,
                pageIndex = 2,
                callSiteProof = proof,
                encodedHandle = handle,
                resourceOffset = 0,
                targetPageSize = 1024,
                logicalBindingPath = logicalBindingPath,
            )
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(handle, 0)

            val copiedIdentity = pending.copyLogicalIdentityForBuild()
            val copiedPlaintext = pending.copyPlaintextForBuild()
            val copiedProof = pending.copyCallSiteProofForBuild()
            val copiedHandle = pending.copyEncodedHandleForBuild()
            try {
                assertContentEquals(expectedIdentity, copiedIdentity)
                assertContentEquals(expectedPlaintext, copiedPlaintext)
                assertContentEquals(expectedProof, copiedProof)
                assertContentEquals(expectedHandle, copiedHandle)
            } finally {
                Arrays.fill(copiedIdentity, 0)
                Arrays.fill(copiedPlaintext, 0)
                Arrays.fill(copiedProof, 0)
                Arrays.fill(copiedHandle, 0)
            }

            val expectedStoredLength = pending.expectedStoredLength
            val input = pending.toMaterializationInput(plan)
            assertFalse(pending.isWiped)

            materialization = AkenPageMaterializer.materializeAndWipe(plan, listOf(input))
            assertTrue(plan.isWiped())
            assertTrue(input.isWiped)

            val descriptor = materialization.pagesForBuild().single().descriptorForBuild
            val descriptorHandle = descriptor.handle
            val descriptorEncoding = descriptorHandle.encoded
            val descriptorIdentity = descriptor.logicalIdentity
            val descriptorProof = descriptor.proof.callSiteProof
            try {
                assertEquals(AkenResourceKind.EncryptedClassPage, descriptor.resourceKind)
                assertEquals(2, descriptor.pageIndex)
                assertEquals(1024, descriptor.targetPageSize)
                assertEquals(resourcePath, descriptor.route.resourcePath)
                assertEquals(logicalBindingPath, descriptor.route.logicalBindingPath)
                assertEquals(expectedStoredLength, descriptor.route.storedLength)
                assertContentEquals(expectedIdentity, descriptorIdentity)
                assertContentEquals(expectedProof, descriptorProof)
                assertContentEquals(expectedHandle, descriptorEncoding)
                assertEquals(
                    AkenTypedPageEntryToken.derive(
                        resourceKind = AkenResourceKind.EncryptedClassPage,
                        pageIndex = 2,
                        encodedHandle = expectedHandle,
                    ),
                    AkenTypedPageEntryToken.derive(
                        resourceKind = descriptor.resourceKind,
                        pageIndex = descriptor.pageIndex,
                        encodedHandle = descriptorEncoding,
                    ),
                )
            } finally {
                Arrays.fill(descriptorEncoding, 0)
                Arrays.fill(descriptorIdentity, 0)
                Arrays.fill(descriptorProof, 0)
                descriptorHandle.wipe()
            }

            val otherIdentity = "fixture:pending-string:other".encodeToByteArray()
            val otherPlaintext = "another page".encodeToByteArray()
            val otherProof = expectedProof.copyOf()
            val otherHandle = expectedHandle.copyOf()
            val other = try {
                AkenPendingClassPage.create(
                    logicalIdentity = otherIdentity,
                    plaintext = otherPlaintext,
                    resourcePath = "META-INF/.aken/class/pending-fixture-other.bin",
                    pageIndex = 2,
                    callSiteProof = otherProof,
                    encodedHandle = otherHandle,
                    targetPageSize = 1024,
                    logicalBindingPath = "META-INF/.logical/class/pending-fixture-other.bin",
                )
            } finally {
                Arrays.fill(otherIdentity, 0)
                Arrays.fill(otherPlaintext, 0)
                Arrays.fill(otherProof, 0)
                Arrays.fill(otherHandle, 0)
            }
            try {
                assertNotEquals(pending.identityPageKeyForBuild(), other.identityPageKeyForBuild())
            } finally {
                other.wipe()
            }
        } finally {
            materialization?.wipe()
            pending?.wipe()
            plan.wipe()
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(handle, 0)
            Arrays.fill(expectedIdentity, 0)
            Arrays.fill(expectedPlaintext, 0)
            Arrays.fill(expectedProof, 0)
            Arrays.fill(expectedHandle, 0)
        }
    }

    @Test
    fun malformed_pending_class_page_inputs_fail_closed_before_build_plan_registration() {
        val validIdentity = "fixture:pending-string:invalid".encodeToByteArray()
        val validPlaintext = "non-empty".encodeToByteArray()
        val validProof = byteArrayOf(0x11)
        val validHandle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index + 7).toByte() }
        try {
            assertFailsWith<IllegalArgumentException> {
                AkenPendingClassPage.create(
                    logicalIdentity = validIdentity,
                    plaintext = validPlaintext,
                    resourcePath = "META-INF/.aken/class/invalid.bin",
                    pageIndex = 0,
                    callSiteProof = validProof,
                    encodedHandle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE - 1),
                    targetPageSize = 512,
                    logicalBindingPath = "META-INF/.logical/class/invalid.bin",
                )
            }
            assertFailsWith<IllegalArgumentException> {
                AkenPendingClassPage.create(
                    logicalIdentity = validIdentity,
                    plaintext = validPlaintext,
                    resourcePath = "META-INF/.aken/class/invalid.bin",
                    pageIndex = 0,
                    callSiteProof = ByteArray(0),
                    encodedHandle = validHandle,
                    targetPageSize = 512,
                    logicalBindingPath = "META-INF/.logical/class/invalid.bin",
                )
            }
            assertFailsWith<IllegalArgumentException> {
                AkenPendingClassPage.create(
                    logicalIdentity = validIdentity,
                    plaintext = validPlaintext,
                    resourcePath = "META-INF/.aken/class/invalid.bin",
                    pageIndex = 0,
                    callSiteProof = validProof,
                    encodedHandle = validHandle,
                    targetPageSize = 513,
                    logicalBindingPath = "META-INF/.logical/class/invalid.bin",
                )
            }
            assertFailsWith<IllegalArgumentException> {
                AkenPendingClassPage.create(
                    logicalIdentity = validIdentity,
                    plaintext = ByteArray(0),
                    resourcePath = "META-INF/.aken/class/invalid.bin",
                    pageIndex = 0,
                    callSiteProof = validProof,
                    encodedHandle = validHandle,
                    targetPageSize = 512,
                    logicalBindingPath = "META-INF/.logical/class/invalid.bin",
                )
            }
        } finally {
            Arrays.fill(validIdentity, 0)
            Arrays.fill(validPlaintext, 0)
            Arrays.fill(validProof, 0)
            Arrays.fill(validHandle, 0)
        }
    }

    @Test
    fun wipe_invalidates_build_copies_and_prevents_repeat_materialization_input_creation() {
        val pending = AkenPendingClassPage.create(
            logicalIdentity = "fixture:pending-string:wipe".encodeToByteArray(),
            plaintext = "erase owned buffers".encodeToByteArray(),
            resourcePath = "META-INF/.aken/class/wipe.bin",
            pageIndex = 0,
            callSiteProof = byteArrayOf(0x21, 0x22),
            encodedHandle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 3 + 1).toByte() },
            targetPageSize = 512,
            logicalBindingPath = "META-INF/.logical/class/wipe.bin",
        )
        val plan = newPlan()
        try {
            pending.wipe()
            assertTrue(pending.isWiped)
            assertFailsWith<IllegalStateException> { pending.copyPlaintextForBuild() }
            assertFailsWith<IllegalStateException> { pending.copyCallSiteProofForBuild() }
            assertFailsWith<IllegalStateException> { pending.copyEncodedHandleForBuild() }
            assertFailsWith<IllegalStateException> { pending.identityPageKeyForBuild() }
            assertFailsWith<IllegalStateException> { pending.toMaterializationInput(plan) }
        } finally {
            pending.wipe()
            plan.wipe()
        }
    }

    private fun newPlan(): AkenBuildPlan {
        val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (index * 29 + 3).toByte() }
        return try {
            AkenBuildPlan.create(commitment, SecureRandom())
        } finally {
            Arrays.fill(commitment, 0)
        }
    }
}
