package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenNativePageLocatorIncludeTest {
    @Test
    fun no_finalized_pages_expose_no_native_locator_layout() {
        val context = defaultVbc4BuildContext()
        try {
            assertTrue(context.akenVbc4FinalizationLayoutOrNull() == null)
        } finally {
            context.wipe()
        }
    }

    @Test
    fun finalized_pages_expose_only_bounded_current_page_records() {
        val identity = "fixture:aken-native-record:first".encodeToByteArray()
        val plaintext = "current page plaintext must remain outside native records".encodeToByteArray()
        val proof = ByteArray(29) { index -> (index * 7 + 5).toByte() }
        val page = AkenVbc4PendingPage.create(
            entryToken = 0x414B_454E_0000_0101L,
            logicalIdentity = identity,
            plaintext = plaintext,
            resourcePath = "META-INF/.aken/vbc4/native-record.bin",
            pageIndex = 0,
            callSiteProof = proof,
            random = SecureRandom(),
        )
        var context: Vbc4BuildContext? = null
        var layout: AkenVbc4FinalizationLayout? = null
        var records: List<ByteArray> = emptyList()
        try {
            val commitment = AkenVbc4FinalizationLayout.reserve(
                pendingPages = listOf(page),
                fixedEntries = emptyList(),
            )
            context = defaultVbc4BuildContext()
            val planCommitment = commitment.copyBytes()
            val plan = try {
                context.initializeAkenBuildPlan(planCommitment)
            } finally {
                Arrays.fill(planCommitment, 0)
            }
            layout = AkenVbc4FinalizationLayout.materializeAndWipe(
                plan = plan,
                commitment = commitment,
                pendingPages = listOf(page),
                fixedEntries = emptyList(),
                vbc4StateBindingLayoutDigest = AkenVbc4InnerMaterial.copyStateBindingLayoutDigest(context),
            )
            context.publishAkenVbc4FinalizationLayout(layout)
            records = context.withAkenNativeLocatorRecordsForBuild { current ->
                current.map { it.copyOf() }
            }
            assertEquals(1, records.size)
            assertTrue(records.single().isNotEmpty())
            assertFalse(records.single().toString(Charsets.UTF_8).contains(plaintext.decodeToString()))
        } finally {
            records.forEach { Arrays.fill(it, 0) }
            layout?.wipe()
            context?.wipe()
            page.wipe()
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
        }
    }
}
