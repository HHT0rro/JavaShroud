package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPendingClassPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenUnifiedClassPageFinalizationTest {
    @Test
    fun vbc4_and_class_pages_share_one_finalization_mesh_and_native_record_owner() {
        val vbc4Identity = "fixture:unified-finalization:vbc4".encodeToByteArray()
        val vbc4Plaintext = "vbc4 page in a unified AKEN materialization".encodeToByteArray()
        val vbc4Proof = ByteArray(37) { index -> (index * 11 + 3).toByte() }
        val stringIdentity = "fixture:unified-finalization:class".encodeToByteArray()
        val stringPlaintext = "typed class page in the same AKEN materialization".encodeToByteArray()
        val stringProof = ByteArray(43) { index -> (index * 13 + 5).toByte() }
        val stringHandle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 17 + 7).toByte() }

        val vbc4Page = try {
            AkenVbc4PendingPage.create(
                entryToken = 0x414B_454E_0000_3001L,
                logicalIdentity = vbc4Identity,
                plaintext = vbc4Plaintext,
                resourcePath = "META-INF/.aken/vbc4/unified.bin",
                pageIndex = 0,
                callSiteProof = vbc4Proof,
                random = SecureRandom(),
            )
        } finally {
            Arrays.fill(vbc4Identity, 0)
            Arrays.fill(vbc4Plaintext, 0)
            Arrays.fill(vbc4Proof, 0)
        }
        val stringPage = try {
            AkenPendingClassPage.create(
                logicalIdentity = stringIdentity,
                plaintext = stringPlaintext,
                resourcePath = "META-INF/.aken/class/unified.bin",
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

        var layout: AkenVbc4FinalizationLayout? = null
        try {
            val commitment = AkenVbc4FinalizationLayout.reserve(
                pendingPages = listOf(vbc4Page),
                pendingClassPages = listOf(stringPage),
                fixedEntries = emptyList(),
            )
            val commitmentBytes = commitment.copyBytes()
            val plan = try {
                AkenBuildPlan.create(commitmentBytes, SecureRandom())
            } finally {
                Arrays.fill(commitmentBytes, 0)
            }

            layout = AkenVbc4FinalizationLayout.materializeAndWipe(
                plan = plan,
                commitment = commitment,
                pendingPages = listOf(vbc4Page),
                pendingClassPages = listOf(stringPage),
                fixedEntries = emptyList(),
                vbc4StateBindingLayoutDigest = ByteArray(32) { index -> (index * 19 + 9).toByte() },
            )
            assertTrue(plan.isWiped())
            assertTrue(vbc4Page.isWiped)
            assertTrue(stringPage.isWiped)

            val finalized = checkNotNull(layout)
            assertEquals(
                setOf("META-INF/.aken/vbc4/unified.bin", "META-INF/.aken/class/unified.bin"),
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

            val tamperedClassPage = artifactEntries(finalized) { name, bytes ->
                if (name == "META-INF/.aken/class/unified.bin") {
                    bytes[3] = (bytes[3].toInt() xor 0x5A).toByte()
                }
            }
            assertFalse(finalized.verifyWriterEquivalentArtifactForBuild(tamperedClassPage))
        } finally {
            layout?.wipe()
            vbc4Page.wipe()
            stringPage.wipe()
        }
    }

    private fun artifactEntries(
        layout: AkenVbc4FinalizationLayout,
        mutate: (String, ByteArray) -> Unit = { _, _ -> },
    ): List<AkenArtifactEntry> = layout.entriesForBuild().map { entry ->
        val bytes = entry.copyBytesForBuild()
        try {
            mutate(entry.name, bytes)
            AkenArtifactEntry(entry.name, bytes)
        } finally {
            Arrays.fill(bytes, 0)
        }
    }
}
