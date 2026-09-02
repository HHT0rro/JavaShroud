package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.transforms.protection.qp.QpFinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingPage
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpNativePageLocatorIncludeTest {
    @Test
    fun no_finalized_pages_expose_no_native_locator_layout() {
        val context = defaultQpBuildContext()
        try {
            assertTrue(context.qpFinalizationLayoutOrNull() == null)
        } finally {
            context.wipe()
        }
    }

    @Test
    fun finalized_pages_expose_only_bounded_current_page_records() {
        val identity = "fixture:qp-native-record:first".encodeToByteArray()
        val plaintext = "current page plaintext must remain outside native records".encodeToByteArray()
        val proof = ByteArray(29) { index -> (index * 7 + 5).toByte() }
        val page = QpPendingPage.create(
            entryToken = 0x414B_454E_0000_0101L,
            logicalIdentity = identity,
            plaintext = plaintext,
            resourcePath = "META-INF/.qp/qp/native-record.bin",
            pageIndex = 0,
            callSiteProof = proof,
            random = SecureRandom(),
        )
        var context: QpBuildContext? = null
        var layout: QpFinalizationLayout? = null
        var records: List<ByteArray> = emptyList()
        try {
            val commitment = QpFinalizationLayout.reserve(
                pendingPages = listOf(page),
                fixedEntries = emptyList(),
            )
            context = defaultQpBuildContext()
            val planCommitment = commitment.copyBytes()
            val plan = try {
                context.initializeQpBuildPlan(planCommitment)
            } finally {
                Arrays.fill(planCommitment, 0)
            }
            layout = QpFinalizationLayout.materializeAndWipe(
                plan = plan,
                commitment = commitment,
                pendingPages = listOf(page),
                fixedEntries = emptyList(),
                pageStateBindingLayoutDigest = QpInnerMaterial.copyStateBindingLayoutDigest(context),
            )
            context.publishQpFinalizationLayout(layout)
            records = context.withQpLocatorRecordsForBuild { current ->
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
