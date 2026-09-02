package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingTextPage
import io.github.hht0rro.javashroud.transforms.protection.qp.QpFinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingPage
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpUnifiedStringPageFinalizationTest {
    @Test
    fun native_and_string_pages_share_one_finalization_mesh_and_native_record_owner() {
        val vmIdentity = "fixture:unified-finalization:qp".encodeToByteArray()
        val vmPlaintext = "qp page in a unified Qp materialization".encodeToByteArray()
        val vmProof = ByteArray(37) { index -> (index * 11 + 3).toByte() }
        val stringIdentity = "fixture:unified-finalization:string".encodeToByteArray()
        val stringPlaintext = "typed string page in the same Qp materialization".encodeToByteArray()
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
            QpPendingTextPage.create(
                logicalIdentity = stringIdentity,
                plaintext = stringPlaintext,
                resourcePath = "META-INF/.qp/string/unified.bin",
                pageIndex = 0,
                callSiteProof = stringProof,
                encodedHandle = stringHandle,
                targetPageSize = 128,
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
                pendingStringPages = listOf(stringPage),
                fixedEntries = emptyList(),
            )
            val commitmentBytes = commitment.copyBytes()
            val plan = try {
                QpBuildPlan.create(commitmentBytes, SecureRandom())
            } finally {
                Arrays.fill(commitmentBytes, 0)
            }

            layout = QpFinalizationLayout.materializeAndWipe(
                plan = plan,
                commitment = commitment,
                pendingPages = listOf(vmPage),
                pendingStringPages = listOf(stringPage),
                fixedEntries = emptyList(),
                pageStateBindingLayoutDigest = ByteArray(32) { index -> (index * 19 + 9).toByte() },
            )
            assertTrue(plan.isWiped())
            assertTrue(vmPage.isWiped)
            assertTrue(stringPage.isWiped)

            val finalized = checkNotNull(layout)
            assertEquals(
                setOf("META-INF/.qp/qp/unified.bin", "META-INF/.qp/string/unified.bin"),
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

            val tamperedStringPage = artifactEntries(finalized) { name, bytes ->
                if (name == "META-INF/.qp/string/unified.bin") {
                    bytes[3] = (bytes[3].toInt() xor 0x5A).toByte()
                }
            }
            assertFalse(finalized.verifyWriterEquivalentArtifactForBuild(tamperedStringPage))
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
