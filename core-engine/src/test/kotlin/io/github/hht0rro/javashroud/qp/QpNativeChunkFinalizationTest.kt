package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingNativeSegment
import io.github.hht0rro.javashroud.transforms.protection.qp.QpFinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingPage
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpNativeChunkFinalizationTest {
    @Test
    fun vbc4_and_native_chunks_share_one_finalization_mesh_and_native_record_owner() {
        val vbc4Identity = "fixture:unified-finalization:qp".encodeToByteArray()
        val vbc4Plaintext = "qp page in a unified AKEN materialization".encodeToByteArray()
        val vbc4Proof = ByteArray(37) { index -> (index * 11 + 3).toByte() }
        val nativeIdentity = "fixture:unified-finalization:native".encodeToByteArray()
        val nativePlaintext = "native handler chunk in the same AKEN materialization".encodeToByteArray()
        val nativeProof = ByteArray(43) { index -> (index * 13 + 5).toByte() }
        val nativeHandle = ByteArray(QpHandle.ENCODED_HANDLE_SIZE) { index -> (index * 17 + 7).toByte() }

        val vbc4Page = try {
            QpPendingPage.create(
                entryToken = 0x414B_454E_0000_3001L,
                logicalIdentity = vbc4Identity,
                plaintext = vbc4Plaintext,
                resourcePath = "META-INF/.qp/qp/unified.bin",
                pageIndex = 0,
                callSiteProof = vbc4Proof,
                random = SecureRandom(),
            )
        } finally {
            Arrays.fill(vbc4Identity, 0)
            Arrays.fill(vbc4Plaintext, 0)
            Arrays.fill(vbc4Proof, 0)
        }
        val nativeChunk = try {
            QpPendingNativeSegment.create(
                logicalIdentity = nativeIdentity,
                plaintext = nativePlaintext,
                resourcePath = "META-INF/.qp/native/unified.bin",
                pageIndex = 0,
                callSiteProof = nativeProof,
                encodedHandle = nativeHandle,
                targetPageSize = 1024,
            )
        } finally {
            Arrays.fill(nativeIdentity, 0)
            Arrays.fill(nativePlaintext, 0)
            Arrays.fill(nativeProof, 0)
            Arrays.fill(nativeHandle, 0)
        }

        var layout: QpFinalizationLayout? = null
        try {
            val commitment = QpFinalizationLayout.reserve(
                pendingPages = listOf(vbc4Page),
                pendingNativeChunks = listOf(nativeChunk),
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
                pendingPages = listOf(vbc4Page),
                pendingNativeChunks = listOf(nativeChunk),
                fixedEntries = emptyList(),
                vbc4StateBindingLayoutDigest = ByteArray(32) { index -> (index * 19 + 9).toByte() },
            )
            assertTrue(plan.isWiped())
            assertTrue(vbc4Page.isWiped)
            assertTrue(nativeChunk.isWiped)

            val finalized = checkNotNull(layout)
            assertEquals(
                setOf(
                    "META-INF/.qp/qp/unified.bin",
                    "META-INF/.qp/native/unified.bin",
                ),
                finalized.entriesForBuild().mapTo(linkedSetOf()) { entry -> entry.name },
            )
            assertTrue(finalized.verifyWriterEquivalentArtifactForBuild(artifactEntries(finalized)))

            finalized.withNativeLocatorRecordsForBuild { records ->
                assertEquals(2, records.size)
                assertTrue(records.all { record -> record.isNotEmpty() })
            }

            val tamperedNativeChunk = artifactEntries(finalized) { name, bytes ->
                if (name == "META-INF/.qp/native/unified.bin") {
                    bytes[3] = (bytes[3].toInt() xor 0x5A).toByte()
                }
            }
            assertFalse(finalized.verifyWriterEquivalentArtifactForBuild(tamperedNativeChunk))
        } finally {
            layout?.wipe()
            vbc4Page.wipe()
            nativeChunk.wipe()
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
