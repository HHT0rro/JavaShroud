package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.QpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.QpEntryMetadata
import io.github.hht0rro.javashroud.transforms.protection.QpSerializer
import io.github.hht0rro.javashroud.transforms.protection.deriveQpIdentity
import io.github.hht0rro.javashroud.transforms.protection.deriveQpOwnerIdentity
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpSemanticSplitTest {
    @Test
    fun max_hardening_splits_executable_rows_into_non_one_to_one_shares() {
        val hardened = logicalProgram(maxHardening = true)
        val rows = hardened.blocks.flatMap { it.instructions }
        val splitIndexes = rows.indices.filter { (rows[it].flags and 0x0008) != 0 }

        assertTrue(splitIndexes.isNotEmpty(), "max-hardening must emit semantic split heads")
        for (index in splitIndexes) {
            val share = rows.getOrNull(index + 1)
            assertTrue(share != null, "semantic split head must have a following share row")
            assertEquals(0xF7, share.opcode)
            assertEquals(0x4000, share.flags)
            assertFalse(rows[index].opcode == share.dst, "stored head opcode must remain share-masked")
        }
        assertTrue(rows.size > rows.count { (it.flags and 0x0001) != 0 }, "stored row count must diverge from executable instruction count")
    }

    @Test
    fun ordinary_profile_keeps_single_row_lowering() {
        val rows = logicalProgram(maxHardening = false).blocks.flatMap { it.instructions }
        assertTrue(rows.none { (it.flags and (0x0008 or 0x4000)) != 0 })
    }

    private fun logicalProgram(maxHardening: Boolean): QpSerializer.VmLogicalProgram {
        val context = QpBuildContext(
            masterKey = ByteArray(32) { index -> (index * 3 + 1).toByte() },
            nativeSeed = 0x13572468L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 7 + 5).toByte() },
            maxHardening = maxHardening,
        )
        val serializer = QpSerializer(
            buildSeed = 0x24681357,
            stateBinding = "semantic-split-test",
            entryMetadata = QpEntryMetadata(
                entryToken = 0x1122334455667788L,
                returnDescriptor = "I",
                methodLocalProfile = 0,
                methodIdentity = context.deriveQpIdentity("example/Split", "value", "()I"),
                ownerIdentity = context.deriveQpOwnerIdentity("example/Split"),
                argumentTags = "",
                resourcePath = "META-INF/.r/split.bin",
                isStatic = true,
            ),
            buildContext = context,
            structureEntropy = ByteArray(32) { index -> (index * 13 + 9).toByte() },
        )
        serializer.visitInsn(Opcodes.ICONST_1)
        serializer.visitInsn(Opcodes.ICONST_2)
        serializer.visitInsn(Opcodes.IADD)
        serializer.visitInsn(Opcodes.IRETURN)
        return serializer.logicalProgramForTest()
    }
}
