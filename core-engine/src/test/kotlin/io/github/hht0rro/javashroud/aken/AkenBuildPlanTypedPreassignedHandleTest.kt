package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPageMaterialization
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPageMaterializationInput
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPageMaterializer
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenTypedPageEntryToken
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AkenBuildPlanTypedPreassignedHandleTest {
    @Test
    fun preassigned_string_page_handle_survives_materialization_and_derives_its_exact_typed_entry_token() {
        val expectedHandle = handleFor(0x41)
        val pageIndex = 3
        val plan = newPlan()
        var materialization: AkenPageMaterialization? = null
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.StringPage,
                identity = "fixture:typed-preassigned:string".encodeToByteArray(),
                pageIndex = pageIndex,
                targetPageSize = 128,
                encodedHandleOverride = expectedHandle,
            )
            val registeredHandle = page.handle.encoded
            try {
                assertContentEquals(expectedHandle, registeredHandle)
            } finally {
                Arrays.fill(registeredHandle, 0)
            }

            val plaintext = "typed page fixture".encodeToByteArray()
            val proof = byteArrayOf(0x31, 0x32, 0x33, 0x34)
            val input = try {
                AkenPageMaterializationInput.create(
                    page = page,
                    plaintext = plaintext,
                    resourcePath = "META-INF/.aken/string/typed-preassigned.bin",
                    resourceOffset = 0,
                    callSiteProof = proof,
                    logicalBindingPath = "fixture:typed-preassigned:string",
                )
            } finally {
                Arrays.fill(plaintext, 0)
                Arrays.fill(proof, 0)
            }

            materialization = AkenPageMaterializer.materializeAndWipe(plan, listOf(input))
            assertTrue(plan.isWiped())
            assertTrue(input.isWiped)

            val descriptor = materialization.pagesForBuild().single().descriptorForBuild
            val descriptorHandle = descriptor.handle
            val descriptorEncoding = descriptorHandle.encoded
            try {
                assertEquals(AkenResourceKind.StringPage, descriptor.resourceKind)
                assertEquals(pageIndex, descriptor.pageIndex)
                assertContentEquals(expectedHandle, descriptorEncoding)
                assertEquals(
                    AkenTypedPageEntryToken.derive(
                        resourceKind = AkenResourceKind.StringPage,
                        pageIndex = pageIndex,
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
                descriptorHandle.wipe()
            }
        } finally {
            materialization?.wipe()
            plan.wipe()
            Arrays.fill(expectedHandle, 0)
        }
    }

    @Test
    fun duplicate_preassigned_handle_is_rejected_across_typed_pages_without_invalidating_the_first_page() {
        val sharedHandle = handleFor(0x52)
        val plan = newPlan()
        try {
            val first = plan.registerPage(
                kind = AkenResourceKind.StringPage,
                identity = "fixture:typed-preassigned:first".encodeToByteArray(),
                pageIndex = 0,
                targetPageSize = 128,
                encodedHandleOverride = sharedHandle,
            )

            assertFailsWith<IllegalArgumentException> {
                plan.registerPage(
                    kind = AkenResourceKind.EncryptedClassPage,
                    identity = "fixture:typed-preassigned:second".encodeToByteArray(),
                    pageIndex = 0,
                    targetPageSize = 512,
                    encodedHandleOverride = sharedHandle,
                )
            }

            val retainedFirstHandle = first.handle.encoded
            try {
                assertContentEquals(sharedHandle, retainedFirstHandle)
            } finally {
                Arrays.fill(retainedFirstHandle, 0)
            }
        } finally {
            plan.wipe()
            Arrays.fill(sharedHandle, 0)
        }
    }

    @Test
    fun malformed_typed_preassigned_handle_fails_closed_without_reserving_its_page_identity() {
        val malformedHandle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE - 1) { index -> (index * 7 + 3).toByte() }
        val expectedHandle = handleFor(0x63)
        val identity = "fixture:typed-preassigned:retry".encodeToByteArray()
        val plan = newPlan()
        try {
            assertFailsWith<IllegalArgumentException> {
                plan.registerPage(
                    kind = AkenResourceKind.StringPage,
                    identity = identity,
                    pageIndex = 2,
                    targetPageSize = 192,
                    encodedHandleOverride = malformedHandle,
                )
            }

            val retry = plan.registerPage(
                kind = AkenResourceKind.StringPage,
                identity = identity,
                pageIndex = 2,
                targetPageSize = 192,
                encodedHandleOverride = expectedHandle,
            )
            val retryHandle = retry.handle.encoded
            try {
                assertContentEquals(expectedHandle, retryHandle)
            } finally {
                Arrays.fill(retryHandle, 0)
            }
        } finally {
            plan.wipe()
            Arrays.fill(malformedHandle, 0)
            Arrays.fill(expectedHandle, 0)
            Arrays.fill(identity, 0)
        }
    }

    @Test
    fun vbc4_page_zero_preassigned_handle_remains_accepted() {
        val expectedHandle = handleFor(0x74)
        val plan = newPlan()
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.Vbc4Method,
                identity = "fixture:typed-preassigned:vbc4".encodeToByteArray(),
                pageIndex = 0,
                targetPageSize = 512,
                encodedHandleOverride = expectedHandle,
            )
            val registeredHandle = page.handle.encoded
            try {
                assertContentEquals(expectedHandle, registeredHandle)
            } finally {
                Arrays.fill(registeredHandle, 0)
            }
        } finally {
            plan.wipe()
            Arrays.fill(expectedHandle, 0)
        }
    }

    private fun newPlan(): AkenBuildPlan {
        val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (index * 17 + 11).toByte() }
        return try {
            AkenBuildPlan.create(commitment, SecureRandom())
        } finally {
            Arrays.fill(commitment, 0)
        }
    }

    private fun handleFor(seed: Int): ByteArray =
        ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (seed + index * 13).toByte() }
}
