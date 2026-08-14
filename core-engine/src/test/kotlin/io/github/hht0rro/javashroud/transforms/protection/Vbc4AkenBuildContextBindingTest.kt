package io.github.hht0rro.javashroud.transforms.protection

import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class Vbc4AkenBuildContextBindingTest {
    @Test
    fun aken_build_plan_is_bound_to_exactly_one_artifact_commitment() {
        val masterKey = ByteArray(32) { index -> (index * 7 + 1).toByte() }
        val layoutDigest = ByteArray(32) { index -> (index * 11 + 3).toByte() }
        val commitment = ByteArray(32) { index -> (index * 13 + 5).toByte() }
        val sameCommitment = commitment.copyOf()
        val differentCommitment = commitment.copyOf().also { bytes ->
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x5A).toByte()
        }
        val context = Vbc4BuildContext(
            masterKey = masterKey,
            nativeSeed = 0x5A17C0DEL,
            jarLayoutDigest = layoutDigest,
        )
        try {
            val first = context.initializeAkenBuildPlan(commitment)
            val same = context.initializeAkenBuildPlan(sameCommitment)
            assertSame(first, same)
            assertFailsWith<IllegalArgumentException> {
                context.initializeAkenBuildPlan(differentCommitment)
            }
        } finally {
            context.wipe()
            Arrays.fill(commitment, 0)
            Arrays.fill(sameCommitment, 0)
            Arrays.fill(differentCommitment, 0)
        }
        assertTrue(context.akenBuildPlanOrNull() == null)
    }
}
