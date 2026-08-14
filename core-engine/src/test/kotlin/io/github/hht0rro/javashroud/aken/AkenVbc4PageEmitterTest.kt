package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimePageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PageEmissionRequest
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PageEmitter
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenVbc4PageEmitterTest {
    @Test
    fun emits_independent_pages_for_one_vbc4_method_and_wipes_every_owner() {
        val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index ->
            (index * 31 + 9).toByte()
        }
        val methodIdentity = "fixture:aken-vbc4-emitter:method".encodeToByteArray()
        val expectedIdentity = methodIdentity.copyOf()
        val expectedProofs = listOf(
            byteArrayOf(0x11, 0x12, 0x13),
            byteArrayOf(0x21, 0x22, 0x23),
        )
        val plan = AkenBuildPlan.create(commitment, SecureRandom())
        commitment.fill(0)
        val page0 = plan.registerPage(AkenResourceKind.Vbc4Method, methodIdentity, pageIndex = 0)
        val page1 = plan.registerPage(AkenResourceKind.Vbc4Method, methodIdentity, pageIndex = 1)
        methodIdentity.fill(0)

        val request0 = requestFor(
            page = page0,
            identity = expectedIdentity,
            plaintext = "first VBC4 page".encodeToByteArray(),
            resourcePath = "META-INF/.aken/vbc4/method-0.bin",
            callSiteProof = expectedProofs[0],
        )
        val request1 = requestFor(
            page = page1,
            identity = expectedIdentity,
            plaintext = "second VBC4 page".encodeToByteArray(),
            resourcePath = "META-INF/.aken/vbc4/method-1.bin",
            callSiteProof = expectedProofs[1],
        )

        val output = AkenVbc4PageEmitter.emitAndWipe(plan, listOf(request0, request1))
        try {
            assertTrue(plan.isWiped())
            assertTrue(request0.isWiped)
            assertTrue(request1.isWiped)

            val pages = output.pagesForBuild().sortedBy { it.pageIndex }
            assertEquals(listOf(0, 1), pages.map { it.pageIndex })
            assertEquals(
                listOf("META-INF/.aken/vbc4/method-0.bin", "META-INF/.aken/vbc4/method-1.bin"),
                pages.map { it.resourcePath },
            )
            assertTrue(pages.all { it.storedLength > 0 })

            pages.forEachIndexed { index, page ->
                val descriptorBytes = page.copyDescriptorBytesForBuild()
                val payload = page.copyEncryptedPayloadForBuild()
                val logicalIdentity = page.copyLogicalIdentityForBuild()
                val callSiteProof = page.copyCallSiteProofForBuild()
                val handle = page.copyHandleForBuild()
                try {
                    val descriptor = AkenRuntimePageDescriptor.decode(descriptorBytes)
                    assertEquals(AkenResourceKind.Vbc4Method, descriptor.resourceKind)
                    assertEquals(index, descriptor.pageIndex)
                    assertEquals(page.resourcePath, descriptor.route.resourcePath)
                    assertEquals(page.resourceOffset, descriptor.route.resourceOffset)
                    assertEquals(page.storedLength, descriptor.route.storedLength)
                    assertTrue(descriptor.matches(handle))
                    assertTrue(logicalIdentity.contentEquals(expectedIdentity))
                    assertTrue(callSiteProof.contentEquals(expectedProofs[index]))
                    assertEquals(page.storedLength, payload.size)

                    payload[payload.lastIndex] = (payload[payload.lastIndex].toInt() xor 0x5A).toByte()
                    logicalIdentity[0] = (logicalIdentity[0].toInt() xor 0x55).toByte()
                    callSiteProof[0] = (callSiteProof[0].toInt() xor 0x33).toByte()
                    val retainedPayload = page.copyEncryptedPayloadForBuild()
                    val retainedIdentity = page.copyLogicalIdentityForBuild()
                    val retainedCallSiteProof = page.copyCallSiteProofForBuild()
                    try {
                        assertFalse(payload.contentEquals(retainedPayload))
                        assertTrue(retainedIdentity.contentEquals(expectedIdentity))
                        assertTrue(retainedCallSiteProof.contentEquals(expectedProofs[index]))
                    } finally {
                        Arrays.fill(retainedPayload, 0)
                        Arrays.fill(retainedIdentity, 0)
                        Arrays.fill(retainedCallSiteProof, 0)
                    }
                } finally {
                    Arrays.fill(descriptorBytes, 0)
                    Arrays.fill(payload, 0)
                    Arrays.fill(logicalIdentity, 0)
                    Arrays.fill(callSiteProof, 0)
                    handle.wipe()
                }
            }

            val meshRoot = output.copyMeshRootForBuild()
            try {
                assertEquals(AkenArtifactCommitment.DIGEST_SIZE, meshRoot.size)
            } finally {
                Arrays.fill(meshRoot, 0)
            }

            output.wipe()
            assertTrue(output.isWiped)
            assertTrue(pages.all { it.isWiped })
            assertFailsWith<IllegalStateException> { output.pagesForBuild() }
            assertFailsWith<IllegalStateException> { pages.first().copyDescriptorBytesForBuild() }
        } finally {
            output.wipe()
            Arrays.fill(expectedIdentity, 0)
            expectedProofs.forEach { Arrays.fill(it, 0) }
        }
    }

    private fun requestFor(
        page: AkenBuildPlan.Page,
        identity: ByteArray,
        plaintext: ByteArray,
        resourcePath: String,
        callSiteProof: ByteArray,
    ): AkenVbc4PageEmissionRequest = try {
        AkenVbc4PageEmissionRequest.create(
            page = page,
            logicalIdentity = identity,
            plaintext = plaintext,
            resourcePath = resourcePath,
            callSiteProof = callSiteProof,
        )
    } finally {
        Arrays.fill(plaintext, 0)
    }
}
