package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassPageBinding
import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingClassPage
import io.github.hht0rro.javashroud.transforms.protection.qp.QpFinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingPage
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpUnifiedClassPageFinalizationTest {
    @Test
    fun native_and_class_pages_share_one_finalization_mesh_and_native_record_owner() {
        val vmIdentity = "fixture:unified-finalization:qp".encodeToByteArray()
        val vmPlaintext = "qp page in a unified Qp materialization".encodeToByteArray()
        val vmProof = ByteArray(37) { index -> (index * 11 + 3).toByte() }
        val stringIdentity = "fixture:unified-finalization:class".encodeToByteArray()
        val stringPlaintext = "typed class page in the same Qp materialization".encodeToByteArray()
        val stringProof = ByteArray(43) { index -> (index * 13 + 5).toByte() }
        val stringHandle = ByteArray(QpHandle.ENCODED_HANDLE_SIZE) { index -> (index * 17 + 7).toByte() }

        val vmPage = try {
            QpPendingPage.create(
                entryToken = 0x414B_454E_0000_3001L,
                logicalIdentity = vmIdentity,
                plaintext = vmPlaintext,
                resourcePath = "META-INF/.qp/qp/unified.bin",
                pageIndex = 0,
                callSiteProof = vmProof,
                random = SecureRandom(),
            )
        } finally {
            Arrays.fill(vmIdentity, 0)
            Arrays.fill(vmPlaintext, 0)
            Arrays.fill(vmProof, 0)
        }
        val stringPage = try {
            QpPendingClassPage.create(
                logicalIdentity = stringIdentity,
                plaintext = stringPlaintext,
                resourcePath = "META-INF/.qp/class/unified.bin",
                pageIndex = 0,
                callSiteProof = stringProof,
                encodedHandle = stringHandle,
                targetPageSize = 512,
            )
        } finally {
            Arrays.fill(stringIdentity, 0)
            Arrays.fill(stringPlaintext, 0)
            Arrays.fill(stringProof, 0)
            Arrays.fill(stringHandle, 0)
        }

        var layout: QpFinalizationLayout? = null
        try {
            val commitment = QpFinalizationLayout.reserve(
                pendingPages = listOf(vmPage),
                pendingClassPages = listOf(stringPage),
                fixedEntries = emptyList(),
            )
            val commitmentBytes = commitment.copyBytes()
            val plan = try {
                QpBuildPlan.create(commitmentBytes, testSecretPackDraft(), SecureRandom())
            } finally {
                Arrays.fill(commitmentBytes, 0)
            }

            layout = QpFinalizationLayout.materializeAndWipe(
                plan = plan,
                commitment = commitment,
                pendingPages = listOf(vmPage),
                pendingClassPages = listOf(stringPage),
                fixedEntries = emptyList(),
                pageStateBindingLayoutDigest = ByteArray(32) { index -> (index * 19 + 9).toByte() },
            )
            assertTrue(plan.isWiped())
            assertTrue(vmPage.isWiped)
            assertTrue(stringPage.isWiped)

            val finalized = checkNotNull(layout)
            assertEquals(
                setOf("META-INF/.qp/qp/unified.bin", "META-INF/.qp/class/unified.bin"),
                finalized.entriesForBuild().mapTo(linkedSetOf()) { entry -> entry.name },
            )
            assertTrue(finalized.verifyWriterEquivalentArtifactForBuild(artifactEntries(finalized)))

            finalized.withNativeLocatorRecordsForBuild { records ->
                assertEquals(2, records.size)
                assertTrue(records.all { record -> record.isNotEmpty() })
            }
            finalized.withPageZeroDispatchBindingsForBuild { bindings ->
                assertEquals(1, bindings.size)
                assertEquals(0x414B_454E_0000_3001L, bindings.single().entryToken)
            }
            var retainedClassBindings: List<QpClassPageBinding> = emptyList()
            finalized.withClassPageBindingsForBuild { bindings ->
                assertEquals(1, bindings.size)
                val binding = bindings.single()
                retainedClassBindings = bindings.toList()
                val identity = binding.copyLogicalIdentityForBuild()
                val handle = binding.copyEncodedHandleForBuild()
                val proof = binding.copyCallSiteProofForBuild()
                try {
                    assertEquals(0, binding.pageIndex)
                    assertTrue(identity.isNotEmpty())
                    assertTrue(
                        binding.matchesForBuild(
                            pageIndex = 0,
                            logicalIdentity = identity,
                            encodedHandle = handle,
                            callSiteProof = proof,
                        ),
                    )
                    handle[0] = (handle[0].toInt() xor 0x5A).toByte()
                    assertFalse(
                        binding.matchesForBuild(
                            pageIndex = 0,
                            logicalIdentity = identity,
                            encodedHandle = handle,
                            callSiteProof = proof,
                        ),
                    )
                } finally {
                    Arrays.fill(identity, 0)
                    Arrays.fill(handle, 0)
                    Arrays.fill(proof, 0)
                }
            }
            assertTrue(retainedClassBindings.all { binding -> binding.isWiped })
            assertFailsWith<IllegalStateException> {
                retainedClassBindings.single().copyEncodedHandleForBuild()
            }

            val tamperedClassPage = artifactEntries(finalized) { name, bytes ->
                if (name == "META-INF/.qp/class/unified.bin") {
                    bytes[3] = (bytes[3].toInt() xor 0x5A).toByte()
                }
            }
            assertFalse(finalized.verifyWriterEquivalentArtifactForBuild(tamperedClassPage))
        } finally {
            layout?.wipe()
            vmPage.wipe()
            stringPage.wipe()
        }
    }

    private fun artifactEntries(
        layout: QpFinalizationLayout,
        mutate: (String, ByteArray) -> Unit = { _, _ -> },
    ): List<QpArtifactEntry> = layout.entriesForBuild().map { entry ->
        val bytes = entry.copyBytesForBuild()
        try {
            mutate(entry.name, bytes)
            QpArtifactEntry(entry.name, bytes)
        } finally {
            Arrays.fill(bytes, 0)
        }
    }
}
