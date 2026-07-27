package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.RuntimeKeyPartitions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.ClassReader

/**
 * Phase 0 / SEC-002 gate: after injection, no key slot of the per-build
 * partition key domains may exist as a single contiguous 32-byte literal array
 * in any method of the helper. Every slot is XOR-split into shares and
 * reassembled only at runtime. This test builds a synthetic holder with the
 * same partitionResourceKey(I)[B shape the real helper exposes, injects a
 * generated multi-partition key domain, then (a) scans every method for a
 * constant byte-array literal equal to any slot and (b) confirms each slot reassembles
 * byte-for-byte.
 */
class RootKeyLiteralTest {

    private fun buildHolder(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, HOLDER, null, "java/lang/Object", null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode(); init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN); init.visitMaxs(1, 1); init.visitEnd()
        val count = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "runtimeResourcePartitionCount", "()I", null, null)
        count.visitCode(); count.visitInsn(Opcodes.ICONST_0); count.visitInsn(Opcodes.IRETURN)
        count.visitMaxs(1, 0); count.visitEnd()
        val anchor = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "anchorResourcePartition", "()I", null, null)
        anchor.visitCode(); anchor.visitInsn(Opcodes.ICONST_0); anchor.visitInsn(Opcodes.IRETURN)
        anchor.visitMaxs(1, 0); anchor.visitEnd()
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "partitionResourceKey", "(I)[B", null, null)
        mv.visitCode(); mv.visitInsn(Opcodes.ACONST_NULL); mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(1, 0); mv.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }


    private class Loader : ClassLoader() {
        fun define(internalName: String, bytes: ByteArray): Class<*> =
            defineClass(internalName.replace('/', '.'), bytes, 0, bytes.size)
    }

    private fun constIntValue(insn: AbstractInsnNode): Int? = when (insn) {
        is IntInsnNode -> if (insn.opcode == Opcodes.BIPUSH || insn.opcode == Opcodes.SIPUSH) insn.operand else null
        is LdcInsnNode -> insn.cst as? Int
        is InsnNode -> when (insn.opcode) {
            Opcodes.ICONST_M1 -> -1
            Opcodes.ICONST_0 -> 0
            Opcodes.ICONST_1 -> 1
            Opcodes.ICONST_2 -> 2
            Opcodes.ICONST_3 -> 3
            Opcodes.ICONST_4 -> 4
            Opcodes.ICONST_5 -> 5
            else -> null
        }
        else -> null
    }
    /**
     * For each method, collect the constant value pushed immediately before each
     * BASTORE (the per-element value written into a byte-array literal), in order.
     * The old continuous-literal injection writes the key bytes this way; the new
     * share split writes only random share bytes, and the reassembly uses I2B
     * (computed), never constant pushes, so the key never appears contiguously.
     */
    private fun bastoreConstSequences(bytes: ByteArray): List<List<Int>> {
        val node = ClassNode()
        ClassReader(bytes).accept(node, 0)
        val sequences = mutableListOf<List<Int>>()
        for (method in node.methods) {
            val values = mutableListOf<Int>()
            var insn = method.instructions.first
            var prevConst: Int? = null
            while (insn != null) {
                if (insn.opcode == Opcodes.BASTORE) {
                    values.add(prevConst?.and(0xFF) ?: Int.MIN_VALUE)
                }
                if (insn.opcode >= 0) prevConst = constIntValue(insn)
                insn = insn.next
            }
            sequences.add(values)
        }
        return sequences
    }

    private fun containsKeySequence(values: List<Int>, key: ByteArray): Boolean {
        val needle = key.map { it.toInt() and 0xFF }
        if (needle.size > values.size) return false
        outer@ for (start in 0..values.size - needle.size) {
            for (i in needle.indices) if (values[start + i] != needle[i]) continue@outer
            return true
        }
        return false
    }

    @Test
    fun slot_keys_are_not_contiguous_literals_after_injection() {
        val partitions = RuntimeKeyPartitions.generate()
        try {
            val keys = (0 until partitions.totalSlots).map(partitions::copyKeyForSlot)
            val injected = EmbeddedHelperDeployment.injectRuntimeResourceKey(buildHolder(), partitions)
            for (sequence in bastoreConstSequences(injected)) {
                keys.forEach { key ->
                    assertFalse(
                        containsKeySequence(sequence, key),
                        "No method may store a slot key as a contiguous byte-array literal",
                    )
                }
            }
        } finally {
            partitions.wipe()
        }
    }

    @Test
    fun reassembled_slot_keys_round_trip_byte_for_byte() {
        val partitions = RuntimeKeyPartitions.generate()
        try {
            val expected = (0 until partitions.totalSlots).map(partitions::copyKeyForSlot)
            val injected = EmbeddedHelperDeployment.injectRuntimeResourceKey(buildHolder(), partitions)
            val cls = Loader().define(HOLDER, injected)
            val countMethod = cls.getDeclaredMethod("runtimeResourcePartitionCount")
            countMethod.isAccessible = true
            assertEquals(partitions.resourcePartitionCount, countMethod.invoke(null) as Int)
            val anchorMethod = cls.getDeclaredMethod("anchorResourcePartition")
            anchorMethod.isAccessible = true
            assertEquals(partitions.anchorSlotId, anchorMethod.invoke(null) as Int)
            val method = cls.getDeclaredMethod("partitionResourceKey", Int::class.javaPrimitiveType)
            method.isAccessible = true
            for (slot in expected.indices) {
                val recomputed = method.invoke(null, slot) as ByteArray
                assertEquals(expected[slot].size, recomputed.size)
                assertTrue(expected[slot].contentEquals(recomputed), "Reassembled key must match the injected key for slot $slot")
            }
            val outOfRange = method.invoke(null, partitions.totalSlots + 5) as ByteArray
            assertTrue(outOfRange.all { it.toInt() == 0 }, "Unknown slots must fail closed to a zero key")
        } finally {
            partitions.wipe()
        }
    }

    companion object { private const val HOLDER = "test/RootKeyHolder" }
}
