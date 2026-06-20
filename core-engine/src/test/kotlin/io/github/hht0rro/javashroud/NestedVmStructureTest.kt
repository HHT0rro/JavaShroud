package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.Vbc4EntryMetadata
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NestedVmStructureTest {
    @Test
    fun nested_micro_stream_is_reproducible_for_same_seed_context_and_profile() {
        val first = nestedBlock(seed = 0x1357_2468, contextSeed = 0x1122_3344, profile = 0x5566_7788)
        val second = nestedBlock(seed = 0x1357_2468, contextSeed = 0x1122_3344, profile = 0x5566_7788)

        assertEquals(first.bytes.toList(), second.bytes.toList(), "Nested VM micro stream must be deterministic for same seed/context/profile")
        assertEquals(first.dialect, second.dialect, "Nested VM dialect must be deterministic for same seed/context/profile")
    }

    @Test
    fun nested_micro_stream_opcode_table_changes_across_vbc4_contexts_and_profiles() {
        val base = nestedBlock(seed = 0x2468_1357, contextSeed = 0x0102_0304, profile = 0x1020_3040)
        val differentContext = nestedBlock(seed = 0x2468_1357, contextSeed = 0x0506_0708, profile = 0x1020_3040)
        val differentProfile = nestedBlock(seed = 0x2468_1357, contextSeed = 0x0102_0304, profile = 0x5060_7080)

        assertFalse(base.bytes.contentEquals(differentContext.bytes), "Nested VM micro stream must bind to Vbc4BuildContext-derived structure seed")
        assertFalse(base.bytes.contentEquals(differentProfile.bytes), "Nested VM micro stream must bind to method-local high-value profile")
        assertTrue(
            base.microOpcodes != differentContext.microOpcodes || base.dialect != differentContext.dialect,
            "Nested VM opcode table or dialect must diverge across contexts",
        )
        assertTrue(
            base.microOpcodes != differentProfile.microOpcodes || base.dialect != differentProfile.dialect,
            "Nested VM opcode table or dialect must diverge across profiles",
        )
    }

    @Test
    fun nested_micro_stream_uses_second_level_envelope_instead_of_plain_register_rows() {
        val nested = nestedBlock(seed = 0x3141_5926, contextSeed = 0x2718_2818, profile = 0x1234_5678)

        assertEquals(4, nested.registerCount, "Fixture register count changed")
        assertEquals(0x4E56, nested.magic, "Nested VM block must carry native-validated nested envelope magic")
        assertEquals(1, nested.version, "Nested VM envelope version changed")
        assertEquals(2, nested.rowCount, "Fixture row count changed")
        assertEquals(nested.rowCount * 7, nested.microCount, "Each register row must lower into six field micro-ops plus commit")
        assertTrue(nested.microOpcodes.take(6).all { it and 0xF000 == 0x7000 }, "Field writes must use nested micro-op opcode space")
        assertTrue(nested.microOpcodes.drop(6).first() and 0xF000 == 0x6000, "Each row must end with nested commit micro-op")
        assertFalse(
            nested.bytes.copyOfRange(2, 4).contentEquals(byteArrayOf(0, nested.rowCount.toByte())),
            "Nested VM block must not use plain register-row header shape",
        )
    }

    private fun nestedBlock(seed: Int, contextSeed: Int, profile: Int): NestedSnapshot {
        val context = fixedContext(contextSeed)
        val serializer = VmBytecodeSerializer(
            buildSeed = seed,
            stateBinding = "nested-vm-structure-test",
            entryMetadata = Vbc4EntryMetadata(
                entryToken = 0x1122_3344_5566_7788L,
                ownerToken = "owner-token",
                methodToken = "method-token",
                returnDescriptor = "I",
                methodLocalProfile = profile,
                originalOwner = "example/NestedVm",
                originalName = "verifyLicense",
                originalDescriptor = "()I",
                resourcePath = "META-INF/.r/nested.bin",
                originalAccess = Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            ),
            buildContext = context,
        )
        val block = VmBytecodeSerializer.VmLogicalBlock(
            blockId = 3,
            entryToken = 0x55AA_33CC,
            instructions = listOf(
                VmBytecodeSerializer.VmRegisterInstruction(0x0210, 0x0001, 1, 2, 3, 0x1234_5678),
                VmBytecodeSerializer.VmRegisterInstruction(0x0340, 0x0002, 3, 1, 0, 0x7F00_0102),
            ),
        )
        val method = VmBytecodeSerializer::class.java.getDeclaredMethod(
            "serializeNestedBlock",
            VmBytecodeSerializer.VmLogicalBlock::class.java,
            Int::class.javaPrimitiveType,
        ).apply { isAccessible = true }
        val bytes = method.invoke(serializer, block, 4) as ByteArray
        return parseNested(bytes)
    }

    private fun parseNested(bytes: ByteArray): NestedSnapshot {
        val microCount = readU2(bytes, 16)
        val microOpcodes = mutableListOf<Int>()
        var offset = 18
        repeat(microCount) {
            microOpcodes += readU2(bytes, offset)
            offset += 8
        }
        assertEquals(bytes.size, offset, "Nested VM micro stream parser must consume full block")
        return NestedSnapshot(
            bytes = bytes,
            registerCount = readU2(bytes, 0),
            magic = readU2(bytes, 2),
            version = readU2(bytes, 4),
            rowCount = readU2(bytes, 6),
            profile = readU4(bytes, 8),
            dialect = readU4(bytes, 12),
            microCount = microCount,
            microOpcodes = microOpcodes,
        )
    }

    private fun fixedContext(seed: Int): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (seed ushr ((index and 3) * 8) xor index * 19).toByte() },
        nativeSeed = seed.toLong() xor 0x1357_2468L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (seed.rotateLeft(index and 31) xor index * 29).toByte() },
    )

    private data class NestedSnapshot(
        val bytes: ByteArray,
        val registerCount: Int,
        val magic: Int,
        val version: Int,
        val rowCount: Int,
        val profile: Int,
        val dialect: Int,
        val microCount: Int,
        val microOpcodes: List<Int>,
    )

    private fun readU2(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun readU4(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)
}
