package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.flattenControlFlow
import kotlin.test.Test
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes

class ControlFlowFlatteningSafetyTest {
    @Test
    fun flattening_skips_try_catch_methods_to_preserve_exception_semantics() {
        val bytes = buildTryCatchHost()
        val transformed = flattenControlFlow(bytes)
        assertTrue(bytes.contentEquals(transformed), "Try/catch methods must not be flattened because exception tests depend on exact protected ranges")
    }

    private fun buildTryCatchHost(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/TryCatchHost", null, "java/lang/Object", null)
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
        val start = Label()
        val end = Label()
        val handler = Label()
        method.visitCode()
        method.visitTryCatchBlock(start, end, handler, "java/lang/RuntimeException")
        method.visitLabel(start)
        method.visitTypeInsn(Opcodes.NEW, "java/lang/RuntimeException")
        method.visitInsn(Opcodes.DUP)
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false)
        method.visitInsn(Opcodes.ATHROW)
        method.visitLabel(end)
        method.visitInsn(Opcodes.ICONST_0)
        method.visitInsn(Opcodes.IRETURN)
        method.visitLabel(handler)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(2, 0)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }
}
