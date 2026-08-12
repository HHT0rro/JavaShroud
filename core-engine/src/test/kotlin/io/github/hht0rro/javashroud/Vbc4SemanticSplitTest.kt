package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.Vbc4EntryMetadata
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import io.github.hht0rro.javashroud.transforms.protection.deriveVbc4Identity
import io.github.hht0rro.javashroud.transforms.protection.deriveVbc4OwnerIdentity
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Vbc4SemanticSplitTest {
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

    private fun logicalProgram(maxHardening: Boolean): VmBytecodeSerializer.VmLogicalProgram {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { index -> (index * 3 + 1).toByte() },
            nativeSeed = 0x13572468L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 7 + 5).toByte() },
            maxHardening = maxHardening,
        )
        val serializer = VmBytecodeSerializer(
            buildSeed = 0x24681357,
            stateBinding = "semantic-split-test",
            entryMetadata = Vbc4EntryMetadata(
                entryToken = 0x1122334455667788L,
                returnDescriptor = "I",
                methodLocalProfile = 0,
                methodIdentity = context.deriveVbc4Identity("example/Split", "value", "()I"),
                ownerIdentity = context.deriveVbc4OwnerIdentity("example/Split"),
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
