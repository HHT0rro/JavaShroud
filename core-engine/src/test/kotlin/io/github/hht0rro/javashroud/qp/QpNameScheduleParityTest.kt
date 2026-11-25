package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class QpNameScheduleParityTest {
    @Test
    fun kotlin_matches_shared_hkdf_vectors() {
        QpNameSchedule.create(SEED, COMMITMENT).use { schedule ->
            assertContentEquals(hex("c444fd0b"), schedule.deriveMagic(QpNameSchedule.ROLE_FRAME))
            assertContentEquals(
                hex("b77c46797eeebbe0fe19d82e58a2b24b"),
                schedule.deriveDomain(QpNameSchedule.ROLE_CRYPTO, 1),
            )
            assertContentEquals(
                hex("26e3cd817882d394bc071f2669c467d3"),
                schedule.deriveDomain(QpNameSchedule.ROLE_DIRECTORY),
            )
            assertContentEquals(
                hex("94c8b4b1d7e6b18090cafc75658c27c7"),
                schedule.deriveDomain(QpNameSchedule.ROLE_TOKEN, 2),
            )
            assertEquals("2BVHBcHeWtGD", schedule.deriveResourceRoot())
            assertEquals("qchmbfhvjdx", schedule.deriveJniName())
            assertEquals("d-rmCtejnK9C", schedule.derivePagePathToken(QpNameSchedule.ROLE_RESOURCE, 7))
            val jni = schedule.deriveJniName()
            assertEquals('q', jni[0])
            assertEquals(true, jni.substring(1).all { it in 'a'..'z' })
            assertEquals(true, jni.length - 1 in 8..12)
        }
    }

    @Test
    fun same_seed_is_stable_across_calls() {
        QpNameSchedule.create(SEED, COMMITMENT).use { schedule ->
            val first = schedule.deriveMagic(QpNameSchedule.ROLE_FRAME)
            val second = schedule.deriveMagic(QpNameSchedule.ROLE_FRAME)
            assertContentEquals(first, second)
            assertEquals(schedule.deriveJniName(), schedule.deriveJniName())
            assertEquals(schedule.deriveResourceRoot(), schedule.deriveResourceRoot())
        }
    }

    @Test
    fun public_pass_ids_are_not_schedule_inputs() {
        val publicIds = listOf(
            "method-virtualization",
            "string-encryption",
            "jni-microkernel-loader",
            "os-anti-debug",
            "os-anti-vm",
            "callsite-rotation-protection",
            "invoke-dynamic-indirection",
            "exception-semantic-virtualization",
        )
        QpNameSchedule.create(SEED, COMMITMENT).use { schedule ->
            val root = schedule.deriveResourceRoot()
            val jni = schedule.deriveJniName()
            val domain = schedule.deriveDomain(QpNameSchedule.ROLE_CRYPTO)
            publicIds.forEach { id ->
                assertFalse(root.contains(id))
                assertFalse(jni.contains(id))
                assertFalse(String(domain, Charsets.US_ASCII).contains(id))
            }
        }
    }

    private companion object {
        val SEED = ByteArray(16) { it.toByte() }
        val COMMITMENT = ByteArray(32) { (it + 32).toByte() }

        fun hex(text: String): ByteArray = ByteArray(text.length / 2) { index ->
            text.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
