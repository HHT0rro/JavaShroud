package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpNameScheduleCrossBuildDivergenceTest {
    @Test
    fun different_build_seeds_change_magic_domain_path_and_jni_names() {
        val commitment = ByteArray(32) { (it + 32).toByte() }
        val leftSeed = ByteArray(16) { it.toByte() }
        val rightSeed = leftSeed.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        QpNameSchedule.create(leftSeed, commitment).use { left ->
            QpNameSchedule.create(rightSeed, commitment).use { right ->
                assertFalse(left.deriveMagic(QpNameSchedule.ROLE_FRAME).contentEquals(right.deriveMagic(QpNameSchedule.ROLE_FRAME)))
                assertFalse(left.deriveDomain(QpNameSchedule.ROLE_CRYPTO).contentEquals(right.deriveDomain(QpNameSchedule.ROLE_CRYPTO)))
                assertFalse(left.deriveResourceRoot() == right.deriveResourceRoot())
                assertFalse(left.deriveJniName() == right.deriveJniName())
                assertFalse(left.derivePagePathToken(QpNameSchedule.ROLE_VM, 0) == right.derivePagePathToken(QpNameSchedule.ROLE_VM, 0))
            }
        }
    }

    @Test
    fun roles_are_separated() {
        val seed = ByteArray(16) { it.toByte() }
        val commitment = ByteArray(32) { (it + 32).toByte() }
        QpNameSchedule.create(seed, commitment).use { schedule ->
            val frame = schedule.deriveDomain(QpNameSchedule.ROLE_FRAME)
            val crypto = schedule.deriveDomain(QpNameSchedule.ROLE_CRYPTO)
            val directory = schedule.deriveDomain(QpNameSchedule.ROLE_DIRECTORY)
            val token = schedule.deriveDomain(QpNameSchedule.ROLE_TOKEN)
            assertFalse(frame.contentEquals(crypto))
            assertFalse(crypto.contentEquals(directory))
            assertFalse(directory.contentEquals(token))
            assertContentEquals(frame, schedule.deriveDomain(QpNameSchedule.ROLE_FRAME))
            assertTrue(schedule.deriveJniName().startsWith("q"))
        }
    }
}
