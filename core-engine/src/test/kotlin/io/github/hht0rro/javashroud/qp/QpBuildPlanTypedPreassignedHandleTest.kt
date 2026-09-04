package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageMaterialization
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageMaterializationInput
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageMaterializer
import io.github.hht0rro.javashroud.transforms.protection.qp.QpResourceKind
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageEntryToken
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class QpBuildPlanTypedPreassignedHandleTest {
    @Test
    fun preassigned_string_page_handle_survives_materialization_and_derives_its_exact_typed_entry_token() {
        val expectedHandle = handleFor(0x41)
        val pageIndex = 3
        val plan = newPlan()
        var materialization: QpPageMaterialization? = null
        try {
            val page = plan.registerPage(
                kind = QpResourceKind.StringPage,
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
                QpPageMaterializationInput.create(
                    page = page,
                    plaintext = plaintext,
                    resourcePath = "META-INF/.qp/string/typed-preassigned.bin",
                    resourceOffset = 0,
                    callSiteProof = proof,
                    logicalBindingPath = "fixture:typed-preassigned:string",
                )
            } finally {
                Arrays.fill(plaintext, 0)
                Arrays.fill(proof, 0)
            }

            materialization = QpPageMaterializer.materializeAndWipe(plan, listOf(input))
            assertTrue(plan.isWiped())
            assertTrue(input.isWiped)

            val descriptor = materialization.pagesForBuild().single().descriptorForBuild
            val descriptorHandle = descriptor.handle
            val descriptorEncoding = descriptorHandle.encoded
            try {
                assertEquals(QpResourceKind.StringPage, descriptor.resourceKind)
                assertEquals(pageIndex, descriptor.pageIndex)
                assertContentEquals(expectedHandle, descriptorEncoding)
                assertEquals(
                    QpPageEntryToken.derive(
                        resourceKind = QpResourceKind.StringPage,
                        pageIndex = pageIndex,
                        encodedHandle = expectedHandle,
                    ),
                    QpPageEntryToken.derive(
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
                kind = QpResourceKind.StringPage,
                identity = "fixture:typed-preassigned:first".encodeToByteArray(),
                pageIndex = 0,
                targetPageSize = 128,
                encodedHandleOverride = sharedHandle,
            )

            assertFailsWith<IllegalArgumentException> {
                plan.registerPage(
                    kind = QpResourceKind.EncryptedClassPage,
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
        val malformedHandle = ByteArray(QpHandle.ENCODED_HANDLE_SIZE - 1) { index -> (index * 7 + 3).toByte() }
        val expectedHandle = handleFor(0x63)
        val identity = "fixture:typed-preassigned:retry".encodeToByteArray()
        val plan = newPlan()
        try {
            assertFailsWith<IllegalArgumentException> {
                plan.registerPage(
                    kind = QpResourceKind.StringPage,
                    identity = identity,
                    pageIndex = 2,
                    targetPageSize = 192,
                    encodedHandleOverride = malformedHandle,
                )
            }

            val retry = plan.registerPage(
                kind = QpResourceKind.StringPage,
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
    fun native_page_zero_preassigned_handle_remains_accepted() {
        val expectedHandle = handleFor(0x74)
        val plan = newPlan()
        try {
            val page = plan.registerPage(
                kind = QpResourceKind.QpMethod,
                identity = "fixture:typed-preassigned:qp".encodeToByteArray(),
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

    private fun newPlan(): QpBuildPlan {
        val commitment = ByteArray(QpArtifactCommitment.DIGEST_SIZE) { index -> (index * 17 + 11).toByte() }
        return try {
            QpBuildPlan.create(commitment, testSecretPackDraft(), SecureRandom())
        } finally {
            Arrays.fill(commitment, 0)
        }
    }

    private fun handleFor(seed: Int): ByteArray =
        ByteArray(QpHandle.ENCODED_HANDLE_SIZE) { index -> (seed + index * 13).toByte() }
}
