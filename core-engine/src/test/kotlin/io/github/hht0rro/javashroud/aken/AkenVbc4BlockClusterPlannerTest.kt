package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4BlockClusterPlanner
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4LogicalMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4MethodCandidate
import java.io.ByteArrayOutputStream
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AkenVbc4BlockClusterPlannerTest {
    @Test
    fun clusters_contiguous_physical_blocks_without_splitting_an_oversized_block() {
        val program = framedVbc4(
            blockIds = listOf(10, 20, 30, 40, 50),
            encodedPayloadLengths = listOf(288, 168, 588, 88, 188),
        )
        val candidate = candidate(program)
        try {
            val plan = AkenVbc4BlockClusterPlanner.plan(candidate) { 512 }

            assertEquals(0x4A4B_454E_0000_0B10L, plan.entryToken)
            assertEquals("META-INF/vbc4/planner-fixture.bin", plan.logicalVmResourcePath)
            assertEquals(program.size, plan.serializedLength)
            assertEquals(3, plan.clusters.size)
            assertEquals(listOf(0, 1, 2), plan.clusters.map { it.pageIndex })
            assertEquals(listOf(0, 2, 3), plan.clusters.map { it.firstStorageBlockOrdinal })
            assertEquals(listOf(1, 2, 4), plan.clusters.map { it.lastStorageBlockOrdinal })
            assertEquals(listOf(480, 600, 300), plan.clusters.map { it.encodedLength })
            assertEquals(plan.blockRegionStart, plan.clusters.first().encodedStart)
            assertEquals(plan.blockRegionEndExclusive, plan.clusters.last().encodedEndExclusive)
            assertTrue(plan.clusters.zipWithNext().all { (left, right) -> left.encodedEndExclusive == right.encodedStart })
            assertTrue(plan.clusters.all { cluster ->
                cluster.encodedLength <= cluster.targetSize ||
                    cluster.firstStorageBlockOrdinal == cluster.lastStorageBlockOrdinal
            })
        } finally {
            candidate.wipe()
            Arrays.fill(program, 0)
        }
    }

    @Test
    fun target_selector_is_page_local_and_rejects_values_outside_the_vbc4_set() {
        val program = framedVbc4(
            blockIds = listOf(7, 8, 9),
            encodedPayloadLengths = listOf(588, 588, 188),
        )
        val candidate = candidate(program)
        try {
            val selectedTargets = listOf(512, 768, 1024)
            var selectorCalls = 0
            val plan = AkenVbc4BlockClusterPlanner.plan(candidate) { pageIndex ->
                assertEquals(pageIndex, selectorCalls)
                selectedTargets[selectorCalls++]
            }
            assertEquals(listOf(512, 768, 1024), plan.clusters.map { it.targetSize })
            assertEquals(3, selectorCalls)

            assertFailsWith<IllegalArgumentException> {
                AkenVbc4BlockClusterPlanner.plan(candidate) { 511 }
            }
        } finally {
            candidate.wipe()
            Arrays.fill(program, 0)
        }
    }

    @Test
    fun malformed_public_frame_geometry_fails_closed_before_a_partial_plan_exists() {
        val valid = framedVbc4(
            blockIds = listOf(1, 2),
            encodedPayloadLengths = listOf(100, 100),
        )
        val badMagic = valid.copyOf().also { it[0] = 'X'.code.toByte() }
        val legacyVbc4Magic = valid.copyOf().also { it[3] = '4'.code.toByte() }
        val emptyConstantPool = framedVbc4(
            blockIds = listOf(10),
            encodedPayloadLengths = listOf(100),
            constantPoolPlainLength = 0L,
        )
        val truncated = valid.copyOf(valid.size - 1)
        val invalidAuthenticationLengthMarker = valid.copyOf().also { it[it.lastIndex] = 31 }
        val trailingByte = valid.copyOf(valid.size + 1).also { it[it.lastIndex] = 1 }
        val duplicateBlockId = framedVbc4(
            blockIds = listOf(3, 3),
            encodedPayloadLengths = listOf(100, 100),
        )
        val overlongConstantPoolPlainLength = framedVbc4(
            blockIds = listOf(4),
            encodedPayloadLengths = listOf(100),
            constantPoolPlainLength = Int.MAX_VALUE.toLong() + 1L,
        )
        val overlongPlainBlockLength = framedVbc4(
            blockIds = listOf(5),
            encodedPayloadLengths = listOf(100),
            plainPayloadLengths = listOf(Int.MAX_VALUE.toLong() + 1L),
        )
        val overlongExceptionPlainLength = framedVbc4(
            blockIds = listOf(6),
            encodedPayloadLengths = listOf(100),
            exceptionPlainLength = Int.MAX_VALUE.toLong() + 1L,
        )
        val overlongExceptionStoredLength = framedVbc4(
            blockIds = listOf(7),
            encodedPayloadLengths = listOf(100),
            exceptionStoredLength = Int.MAX_VALUE.toLong() + 1L,
        )
        val mismatchedBlockCiphertextLength = framedVbc4(
            blockIds = listOf(8),
            encodedPayloadLengths = listOf(100),
            storedPayloadLengths = listOf(99),
        )
        val mismatchedExceptionCiphertextLength = framedVbc4(
            blockIds = listOf(9),
            encodedPayloadLengths = listOf(100),
            exceptionStoredLength = 1,
            exceptionEncryptedLength = 2,
        )
        try {
            listOf(
                badMagic,
                legacyVbc4Magic,
                emptyConstantPool,
                truncated,
                invalidAuthenticationLengthMarker,
                trailingByte,
                duplicateBlockId,
                overlongConstantPoolPlainLength,
                overlongPlainBlockLength,
                overlongExceptionPlainLength,
                overlongExceptionStoredLength,
                mismatchedBlockCiphertextLength,
                mismatchedExceptionCiphertextLength,
            ).forEach { malformed ->
                val candidate = candidate(malformed)
                try {
                    assertFailsWith<IllegalArgumentException> {
                        AkenVbc4BlockClusterPlanner.plan(candidate) { 512 }
                    }
                } finally {
                    candidate.wipe()
                    Arrays.fill(malformed, 0)
                }
            }
        } finally {
            Arrays.fill(valid, 0)
        }
    }

    private fun candidate(program: ByteArray): AkenVbc4MethodCandidate {
        val identity = ByteArray(32) { index -> (index * 11 + 7).toByte() }
        return try {
            AkenVbc4MethodCandidate.create(
                entryToken = 0x4A4B_454E_0000_0B10L,
                logicalMethod = AkenVbc4LogicalMethodIdentity.create(
                    dispatchClassToken = "planner/Fixture",
                    dispatchMethodToken = "run",
                    descriptor = "()V",
                    logicalVmResourcePath = "META-INF/vbc4/planner-fixture.bin",
                ),
                logicalIdentity = identity,
                serializedProgram = program,
            )
        } finally {
            Arrays.fill(identity, 0)
        }
    }

    private fun framedVbc4(
        blockIds: List<Int>,
        encodedPayloadLengths: List<Int>,
        constantPoolPlainLength: Long = 4L,
        plainPayloadLengths: List<Long> = encodedPayloadLengths.map { it.toLong() },
        storedPayloadLengths: List<Int> = encodedPayloadLengths,
        exceptionPlainLength: Long = 0L,
        exceptionStoredLength: Long = 0L,
        exceptionEncryptedLength: Int = 0,
    ): ByteArray {
        require(
            blockIds.isNotEmpty() &&
                blockIds.size == encodedPayloadLengths.size &&
                blockIds.size == plainPayloadLengths.size &&
                blockIds.size == storedPayloadLengths.size,
        )
        require(
            constantPoolPlainLength >= 0 &&
                exceptionPlainLength >= 0 &&
                exceptionStoredLength >= 0 &&
                exceptionEncryptedLength >= 0,
        )
        val out = ByteArrayOutputStream()
        out.write("VBCX".encodeToByteArray())
        out.write(ByteArray(16))
        writeU4(out, 0xAABBCCDDL)
        out.write(ByteArray(16))
        writeU2(out, 0)
        writeU2(out, blockIds.size)
        writeU4(out, constantPoolPlainLength)
        writeU4(out, 4)
        out.write(byteArrayOf(1, 2, 3, 4))
        blockIds.forEachIndexed { ordinal, blockId ->
            writeU2(out, blockId)
            writeU4(out, ordinal.toLong() + 1)
            writeU4(out, ordinal.toLong() + 101)
        }
        encodedPayloadLengths.forEachIndexed { ordinal, encryptedLength ->
            val plainLength = plainPayloadLengths[ordinal]
            val storedLength = storedPayloadLengths[ordinal]
            require(plainLength >= 0)
            require(storedLength > 0 && encryptedLength > 0)
            writeU4(out, plainLength)
            writeU4(out, storedLength.toLong())
            writeU4(out, encryptedLength.toLong())
            out.write(ByteArray(encryptedLength) { index -> (ordinal * 17 + index).toByte() })
        }
        writeU4(out, exceptionPlainLength)
        writeU4(out, exceptionStoredLength)
        writeU4(out, exceptionEncryptedLength.toLong())
        out.write(ByteArray(exceptionEncryptedLength))
        writeU4(out, 0)
        out.write(ByteArray(32))
        out.write(32)
        return out.toByteArray()
    }

    private fun writeU2(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU4(out: ByteArrayOutputStream, value: Long) {
        require(value in 0..0xFFFF_FFFFL)
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }
}
