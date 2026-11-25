package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpResourceKind
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingPage
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class QpBuildPlanTargetPageSizeTest {
    @Test
    fun rejects_invalid_native_target_overrides_without_reserving_the_page_identity() {
        val commitment = ByteArray(32) { index -> (index * 17 + 3).toByte() }
        val identity = "fixture:qp:qp-target-override".encodeToByteArray()
        val plan = try {
            QpBuildPlan.create(commitment, testSecretPackDraft(), FirstChoiceSecureRandom())
        } finally {
            Arrays.fill(commitment, 0)
        }
        try {
            listOf(511, 2049, 128).forEach { unsupportedTarget ->
                assertFailsWith<IllegalArgumentException> {
                    plan.registerPage(
                        kind = QpResourceKind.QpMethod,
                        identity = identity,
                        pageIndex = 0,
                        targetPageSize = unsupportedTarget,
                    )
                }
            }

            val page = plan.registerPage(
                kind = QpResourceKind.QpMethod,
                identity = identity,
                pageIndex = 0,
                targetPageSize = 512,
            )
            assertEquals(512, page.targetSize)
        } finally {
            Arrays.fill(identity, 0)
            plan.wipe()
        }
    }

    @Test
    fun rejects_invalid_pending_native_page_targets_before_page_ownership_is_created() {
        val identity = "fixture:qp:pending-target".encodeToByteArray()
        val plaintext = "pending native VM page".encodeToByteArray()
        val proof = byteArrayOf(7, 11, 19, 23)
        try {
            listOf(511, 2049, 128).forEach { unsupportedTarget ->
                assertFailsWith<IllegalArgumentException> {
                    QpPendingPage.create(
                        entryToken = 0x4A4B_454E_0000_0F10L,
                        logicalIdentity = identity,
                        plaintext = plaintext,
                        resourcePath = "META-INF/.qp/qp/invalid-target.bin",
                        pageIndex = 0,
                        callSiteProof = proof,
                        targetPageSize = unsupportedTarget,
                        random = FirstChoiceSecureRandom(),
                    )
                }
            }

            val page = QpPendingPage.create(
                entryToken = 0x4A4B_454E_0000_0F10L,
                logicalIdentity = identity,
                plaintext = plaintext,
                resourcePath = "META-INF/.qp/qp/valid-target.bin",
                pageIndex = 0,
                callSiteProof = proof,
                targetPageSize = 512,
                random = FirstChoiceSecureRandom(),
            )
            try {
                assertEquals(512, page.targetPageSize)
            } finally {
                page.wipe()
            }
        } finally {
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
        }
    }

    private class FirstChoiceSecureRandom : SecureRandom() {
        private var state: Int = 0x414B_454E

        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { index ->
                state = state * 1_103_515_245 + 12_345
                bytes[index] = (state ushr 16).toByte()
            }
        }

        override fun nextInt(bound: Int): Int {
            require(bound > 0)
            return 0
        }

        override fun nextBoolean(): Boolean = false
    }
}
