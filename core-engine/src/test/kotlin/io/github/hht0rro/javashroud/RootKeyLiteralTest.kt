package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.VBC4_RUNTIME_RESOURCE_KEY_SIZE
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
 * Phase 0 / SEC-002 gate: after injection, the per-build runtime resource root
 * key must NOT exist as a single contiguous 32-byte literal array in any method
 * of the helper. It is XOR-split into shares and reassembled only at runtime.
 * This test builds a synthetic holder with the same runtimeResourceKey()[B
 * shape the real helper exposes, injects a known key, then (a) scans every
 * method for a constant byte-array literal equal to the key and (b) confirms
 * the reassembled key still round-trips byte-for-byte.
 */
class RootKeyLiteralTest {

    private fun buildHolder(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, HOLDER, null, "java/lang/Object", null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode(); init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN); init.visitMaxs(1, 1); init.visitEnd()
        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "runtimeResourceKey", "()[B", null, null)
        mv.visitCode(); mv.visitInsn(Opcodes.ACONST_NULL); mv.visitInsn(Opcodes.ARETURN)
        mv.visitMaxs(1, 0); mv.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }


    private class Loader : ClassLoader() {
        fun define(internalName: String, bytes: ByteArray): Class<*> =
            defineClass(internalName.replace('/', '.'), bytes, 0, bytes.size)
    }

    private fun knownKey(): ByteArray = ByteArray(VBC4_RUNTIME_RESOURCE_KEY_SIZE) { (it * 7 + 11).toByte() }

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

    private fun containsKeySequence(values: List<Int>): Boolean {
        val needle = knownKey().map { it.toInt() and 0xFF }
        if (needle.size > values.size) return false
        outer@ for (start in 0..values.size - needle.size) {
            for (i in needle.indices) if (values[start + i] != needle[i]) continue@outer
            return true
        }
        return false
    }

    @Test
    fun root_key_is_not_a_contiguous_literal_after_injection() {
        val injected = EmbeddedHelperDeployment.injectRuntimeResourceKey(buildHolder(), knownKey())
        for (sequence in bastoreConstSequences(injected)) {
            assertFalse(
                containsKeySequence(sequence),
                "No method may store the root key as a contiguous byte-array literal",
            )
        }
    }
    @Test
    fun reassembled_key_round_trips_byte_for_byte() {
        val key = knownKey()
        val injected = EmbeddedHelperDeployment.injectRuntimeResourceKey(buildHolder(), key)
        val cls = Loader().define(HOLDER, injected)
        val method = cls.getDeclaredMethod("runtimeResourceKey")
        method.isAccessible = true
        val recomputed = method.invoke(null) as ByteArray
        assertEquals(key.size, recomputed.size)
        assertTrue(key.contentEquals(recomputed), "Reassembled key must match the injected root key")
    }

    companion object { private const val HOLDER = "test/RootKeyHolder" }
}