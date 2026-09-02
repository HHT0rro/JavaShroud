package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.QP_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.QP_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.QpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.NativeVmBuildProfile
import io.github.hht0rro.javashroud.transforms.protection.QpEntryMetadata
import io.github.hht0rro.javashroud.transforms.protection.QpSerializer
import io.github.hht0rro.javashroud.transforms.protection.deriveQpIdentity
import io.github.hht0rro.javashroud.transforms.protection.deriveQpOwnerIdentity
import io.github.hht0rro.javashroud.transforms.protection.nativeArgumentTagVector
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NestedVmStructureTest {
    @Test
    fun nested_micro_stream_is_not_reproducible_for_same_seed_context_and_profile_by_default() {
        val first = nestedBlock(seed = 0x1357_2468, contextSeed = 0x1122_3344, profile = 0x5566_7788)
        val second = nestedBlock(seed = 0x1357_2468, contextSeed = 0x1122_3344, profile = 0x5566_7788)

        assertFalse(first.bytes.contentEquals(second.bytes), "Nested VM micro stream must not be reusable across same-seed production builds")
        assertTrue(
            first.microOpcodes != second.microOpcodes || first.dialect != second.dialect,
            "Nested VM opcode table or dialect must vary across same-seed production builds",
        )
    }

    @Test
    fun nested_micro_stream_is_reproducible_when_structure_entropy_is_fixed() {
        val entropy = fixedStructureEntropy()
        val nativeProfile = NativeVmBuildProfile(1, 2)
        val context = fixedContext(0x1122_3344, nativeProfile)
        val first = nestedBlock(seed = 0x1357_2468, contextSeed = 0x1122_3344, profile = 0x5566_7788, structureEntropy = entropy, nativeVmProfile = nativeProfile, contextOverride = context)
        val second = nestedBlock(seed = 0x1357_2468, contextSeed = 0x1122_3344, profile = 0x5566_7788, structureEntropy = entropy, nativeVmProfile = nativeProfile, contextOverride = context)

        assertEquals(first.bytes.toList(), second.bytes.toList(), "Fixed test entropy must keep nested VM stream reproducible")
        assertEquals(first.dialect, second.dialect, "Fixed test entropy must keep nested VM dialect reproducible")
    }

    @Test
    fun nested_micro_stream_opcode_table_changes_across_native_contexts_and_profiles() {
        val base = nestedBlock(seed = 0x2468_1357, contextSeed = 0x0102_0304, profile = 0x1020_3040)
        val differentContext = nestedBlock(seed = 0x2468_1357, contextSeed = 0x0506_0708, profile = 0x1020_3040)
        val differentProfile = nestedBlock(seed = 0x2468_1357, contextSeed = 0x0102_0304, profile = 0x5060_7080)

        assertFalse(base.bytes.contentEquals(differentContext.bytes), "Nested VM micro stream must bind to QpBuildContext-derived structure seed")
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
        assertEquals(2, nested.rowCount, "Fixture row count changed")
        assertEquals(nested.rowCount * 7, nested.microCount, "Each register row must lower into six field micro-ops plus commit")
        assertTrue(nested.microOpcodes.take(6).all { it and 0xF000 == 0x7000 }, "Field writes must use nested micro-op opcode space")
        assertTrue(nested.microOpcodes.drop(6).first() and 0xF000 == 0x6000, "Each row must end with nested commit micro-op")
        assertFalse(
            nested.bytes.copyOfRange(2, 4).contentEquals(byteArrayOf(0, nested.rowCount.toByte())),
            "Nested VM block must not use plain register-row header shape",
        )
    }

    @Test
    fun nested_micro_stream_is_independent_of_non_nested_parser_family() {
        val entropy = fixedStructureEntropy()
        val snapshots = (0..2).map { parserProfile ->
            nestedBlock(
                seed = 0x3141_5926,
                contextSeed = 0x2718_2818,
                profile = 0x1234_5678,
                structureEntropy = entropy,
                nativeVmProfile = NativeVmBuildProfile(parserProfile, parserProfile),
            )
        }
        assertTrue(snapshots.all { it.magic == 0x4E56 && it.microCount == it.rowCount * 7 }, "Every native parser profile must preserve the nested VM envelope contract")
        assertEquals(3, snapshots.map { it.bytes.toList() }.toSet().size, "Nested VM bytes must still bind the authenticated build-local native profile id")
    }

    private fun nestedBlock(seed: Int, contextSeed: Int, profile: Int, structureEntropy: ByteArray? = null, nativeVmProfile: NativeVmBuildProfile? = null, contextOverride: QpBuildContext? = null): NestedSnapshot {
        val context = contextOverride ?: fixedContext(contextSeed, nativeVmProfile)
        val entryMetadata = QpEntryMetadata(
                entryToken = 0x1122_3344_5566_7788L,
                returnDescriptor = "I",
                methodLocalProfile = profile,
                methodIdentity = context.deriveQpIdentity("example/NestedVm", "verifyLicense", "()I"),
                ownerIdentity = context.deriveQpOwnerIdentity("example/NestedVm"),
                argumentTags = nativeArgumentTagVector("()I"),
                resourcePath = "META-INF/.r/nested.bin",
                isStatic = true,
            )
        val serializer = if (structureEntropy == null) {
            QpSerializer(
                buildSeed = seed,
                stateBinding = "nested-vm-structure-test",
                entryMetadata = entryMetadata,
                buildContext = context,
            )
        } else {
            QpSerializer(
                buildSeed = seed,
                stateBinding = "nested-vm-structure-test",
                entryMetadata = entryMetadata,
                buildContext = context,
                structureEntropy = structureEntropy,
            )
        }
        val block = QpSerializer.VmLogicalBlock(
            blockId = 3,
            entryToken = 0x55AA_33CC,
            instructions = listOf(
                QpSerializer.VmRegisterInstruction(0x0210, 0x0001, 1, 2, 3, 0x1234_5678),
                QpSerializer.VmRegisterInstruction(0x0340, 0x0002, 3, 1, 0, 0x7F00_0102),
            ),
        )
        val method = QpSerializer::class.java.getDeclaredMethod(
            "serializeNestedBlock",
            QpSerializer.VmLogicalBlock::class.java,
            Int::class.javaPrimitiveType,
        ).apply { isAccessible = true }
        val bytes = method.invoke(serializer, block, 4) as ByteArray
        return parseNested(bytes)
    }

    private fun parseNested(bytes: ByteArray): NestedSnapshot {
        val microCount = readU2(bytes, 14)
        val rowCount = readU2(bytes, 4)
        assertEquals(rowCount * 7, microCount, "Nested VM micro-op count changed")

        /*
         * A nested field micro-op is variable-width in the current wire format:
         * opcode (u16) + encoded field (u16) + value (u16 for fields 0..4,
         * u32 for field 5).  The commit micro-op is always 8 bytes.  Field 5
         * is shuffled, so the test parser tries the six possible wide-field
         * positions and keeps the parse that reaches the exact block boundary.
         * This keeps the fixture parser aligned with production without
         * reimplementing the private field-order/masking schedule.
         */
        val microOpcodes = parseNestedMicroOpcodes(bytes, rowCount, 16)
        return NestedSnapshot(
            bytes = bytes,
            registerCount = readU2(bytes, 0),
            magic = readU2(bytes, 2),
            rowCount = readU2(bytes, 4),
            profile = readU4(bytes, 6),
            dialect = readU4(bytes, 10),
            microCount = microCount,
            microOpcodes = microOpcodes,
        )
    }

    private fun parseNestedMicroOpcodes(bytes: ByteArray, rowCount: Int, startOffset: Int): List<Int> {
        fun parseRows(rowIndex: Int, offset: Int, opcodes: List<Int>): List<Int>? {
            if (rowIndex == rowCount) return opcodes.takeIf { offset == bytes.size }
            if (offset < 0 || offset > bytes.size) return null

            for (wideSlot in 0 until 6) {
                var cursor = offset
                val rowOpcodes = ArrayList<Int>(7)
                var valid = true
                for (slot in 0 until 6) {
                    if (cursor > bytes.size - 4) {
                        valid = false
                        break
                    }
                    val opcode = readU2(bytes, cursor)
                    if (opcode and 0xF000 != 0x7000) {
                        valid = false
                        break
                    }
                    rowOpcodes += opcode
                    val width = if (slot == wideSlot) 8 else 6
                    if (cursor > bytes.size - width) {
                        valid = false
                        break
                    }
                    cursor += width
                }
                if (!valid || cursor > bytes.size - 8) continue
                val commitOpcode = readU2(bytes, cursor)
                if (commitOpcode and 0xF000 != 0x6000) continue
                rowOpcodes += commitOpcode
                val parsed = parseRows(rowIndex + 1, cursor + 8, opcodes + rowOpcodes)
                if (parsed != null) return parsed
            }
            return null
        }

        return parseRows(0, startOffset, emptyList())
            ?: error("Nested VM micro stream parser could not consume current variable-width rows")
    }

    private fun fixedContext(seed: Int, nativeVmProfile: NativeVmBuildProfile? = null): QpBuildContext = QpBuildContext(
        masterKey = ByteArray(QP_MASTER_KEY_SIZE) { index -> (seed ushr ((index and 3) * 8) xor index * 19).toByte() },
        nativeSeed = seed.toLong() xor 0x1357_2468L,
        jarLayoutDigest = ByteArray(QP_LAYOUT_DIGEST_SIZE) { index -> (seed.rotateLeft(index and 31) xor index * 29).toByte() },
        nativeVmProfile = nativeVmProfile ?: NativeVmBuildProfile.fromBuildMaterial(
            seed.toLong() xor 0x1357_2468L,
            ByteArray(QP_LAYOUT_DIGEST_SIZE) { index -> (seed.rotateLeft(index and 31) xor index * 29).toByte() },
        ),
    )

    private fun fixedStructureEntropy(): ByteArray = ByteArray(32) { index -> (index * 19 + 7).toByte() }

    private data class NestedSnapshot(
        val bytes: ByteArray,
        val registerCount: Int,
        val magic: Int,
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
