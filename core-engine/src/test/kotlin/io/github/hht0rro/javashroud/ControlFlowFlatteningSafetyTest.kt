package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.ControlFlowConfig
import io.github.hht0rro.javashroud.bytecode.flattenControlFlow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.LdcInsnNode

class ControlFlowFlatteningSafetyTest {
    @Test
    fun flattening_skips_try_catch_methods_to_preserve_exception_semantics() {
        val bytes = buildTryCatchHost()
        val transformed = flattenControlFlow(bytes)
        assertTrue(bytes.contentEquals(transformed), "Try/catch methods must not be flattened because exception tests depend on exact protected ranges")
    }

    @Test
    fun flattening_writes_unique_state_along_goto_edges() {
        val bytes = buildGotoHost()
        val transformed = flattenControlFlow(
            bytes,
            ControlFlowConfig(density = 10, handlerComplexity = "field-write", seed = 7L),
        )
        val node = ClassNode()
        ClassReader(transformed).accept(node, 0)
        val method = node.methods.single { it.name == "run" }
        val states = method.instructions.toArray().filterIsInstance<LdcInsnNode>().mapNotNull { it.cst as? Int }
        assertTrue(states.toSet().size >= 2, "flattened edges must write distinct dispatch states, got $states")
        assertTrue(
            method.instructions.toArray().filterIsInstance<FieldInsnNode>().any {
                it.opcode == Opcodes.PUTSTATIC && it.name == "__js_dispatch_state"
            },
            "field-write handler complexity must store dispatch state",
        )
        val originalConsts = iconstOrder(bytes)
        val flattenedConsts = iconstOrder(transformed)
        assertTrue(originalConsts.isNotEmpty() && flattenedConsts.isNotEmpty())
        val type = loadClass(transformed, "sample.GotoHost")
        val run = type.getMethod("run", Int::class.javaPrimitiveType)
        assertEquals(1, run.invoke(null, 20))
        assertEquals(2, run.invoke(null, 5))
        assertEquals(3, run.invoke(null, -1))
    }

    @Test
    fun flattening_preserves_try_catch_semantics_while_rewriting_gotos() {
        val bytes = buildTryCatchGotoHost()
        val transformed = flattenControlFlow(
            bytes,
            ControlFlowConfig(density = 10, handlerComplexity = "field-write", seed = 11L),
        )
        val type = loadClass(transformed, "sample.TryCatchGotoHost")
        assertEquals(1, type.getMethod("run").invoke(null))
        val node = ClassNode()
        ClassReader(transformed).accept(node, 0)
        val method = node.methods.single { it.name == "run" }
        assertTrue(method.tryCatchBlocks.isNotEmpty(), "exception table must remain")
        val states = method.instructions.toArray().filterIsInstance<LdcInsnNode>().mapNotNull { it.cst as? Int }
        assertTrue(states.isNotEmpty(), "try-body GOTOs must still receive edge state")
    }

    @Test
    fun flattening_rewrites_gotos_outside_monitor_regions() {
        val bytes = buildMonitorGotoHost()
        val transformed = flattenControlFlow(
            bytes,
            ControlFlowConfig(density = 10, handlerComplexity = "field-write", seed = 13L),
        )
        val type = loadClass(transformed, "sample.MonitorGotoHost")
        assertEquals(1, type.getMethod("run", Int::class.javaPrimitiveType).invoke(null, 4))
        assertEquals(2, type.getMethod("run", Int::class.javaPrimitiveType).invoke(null, -3))
        val node = ClassNode()
        ClassReader(transformed).accept(node, 0)
        val method = node.methods.single { it.name == "run" }
        assertTrue(method.instructions.toArray().any { it.opcode == Opcodes.MONITORENTER })
        assertTrue(method.instructions.toArray().any { it.opcode == Opcodes.MONITOREXIT })
        val states = method.instructions.toArray().filterIsInstance<LdcInsnNode>().mapNotNull { it.cst as? Int }
        assertTrue(states.isNotEmpty(), "GOTOs after monitorexit must receive edge state")
    }

    @Test
    fun flattening_rewrites_gotos_inside_the_same_monitor_depth() {
        val bytes = buildIntraMonitorGotoHost()
        val transformed = flattenControlFlow(
            bytes,
            ControlFlowConfig(density = 10, handlerComplexity = "field-write", seed = 17L),
        )
        val type = loadClass(transformed, "sample.IntraMonitorGotoHost")
        assertEquals(1, type.getMethod("run", Int::class.javaPrimitiveType).invoke(null, 8))
        assertEquals(2, type.getMethod("run", Int::class.javaPrimitiveType).invoke(null, -2))
        val node = ClassNode()
        ClassReader(transformed).accept(node, 0)
        val method = node.methods.single { it.name == "run" }
        val states = method.instructions.toArray().filterIsInstance<LdcInsnNode>().mapNotNull { it.cst as? Int }
        assertTrue(states.isNotEmpty(), "same-depth monitor GOTOs must receive edge state")
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

    private fun buildGotoHost(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/GotoHost", null, "java/lang/Object", null)
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "(I)I", null, null)
        val elseA = Label()
        val elseB = Label()
        val end = Label()
        method.visitCode()
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitJumpInsn(Opcodes.IFLE, elseA)
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitIntInsn(Opcodes.BIPUSH, 10)
        method.visitJumpInsn(Opcodes.IF_ICMPLE, elseB)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitJumpInsn(Opcodes.GOTO, end)
        method.visitLabel(elseB)
        method.visitInsn(Opcodes.ICONST_2)
        method.visitJumpInsn(Opcodes.GOTO, end)
        method.visitLabel(elseA)
        method.visitInsn(Opcodes.ICONST_3)
        method.visitLabel(end)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(2, 1)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildTryCatchGotoHost(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/TryCatchGotoHost", null, "java/lang/Object", null)
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
        val start = Label()
        val end = Label()
        val handler = Label()
        val exit = Label()
        method.visitCode()
        method.visitTryCatchBlock(start, end, handler, "java/lang/RuntimeException")
        method.visitLabel(start)
        method.visitTypeInsn(Opcodes.NEW, "java/lang/RuntimeException")
        method.visitInsn(Opcodes.DUP)
        method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false)
        method.visitInsn(Opcodes.ATHROW)
        method.visitInsn(Opcodes.ICONST_0)
        method.visitJumpInsn(Opcodes.GOTO, exit)
        method.visitLabel(end)
        method.visitInsn(Opcodes.ICONST_0)
        method.visitInsn(Opcodes.IRETURN)
        method.visitLabel(handler)
        method.visitInsn(Opcodes.POP)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitJumpInsn(Opcodes.GOTO, exit)
        method.visitLabel(exit)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(2, 0)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildMonitorGotoHost(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/MonitorGotoHost", null, "java/lang/Object", null)
        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "LOCK", "Ljava/lang/Object;", null, null).visitEnd()
        val clinit = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        clinit.visitCode()
        clinit.visitTypeInsn(Opcodes.NEW, "java/lang/Object")
        clinit.visitInsn(Opcodes.DUP)
        clinit.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "sample/MonitorGotoHost", "LOCK", "Ljava/lang/Object;")
        clinit.visitInsn(Opcodes.RETURN)
        clinit.visitMaxs(2, 0)
        clinit.visitEnd()
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "(I)I", null, null)
        val elseLbl = Label()
        val end = Label()
        method.visitCode()
        method.visitFieldInsn(Opcodes.GETSTATIC, "sample/MonitorGotoHost", "LOCK", "Ljava/lang/Object;")
        method.visitInsn(Opcodes.DUP)
        method.visitVarInsn(Opcodes.ASTORE, 1)
        method.visitInsn(Opcodes.MONITORENTER)
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitInsn(Opcodes.POP)
        method.visitVarInsn(Opcodes.ALOAD, 1)
        method.visitInsn(Opcodes.MONITOREXIT)
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitJumpInsn(Opcodes.IFLE, elseLbl)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitJumpInsn(Opcodes.GOTO, end)
        method.visitLabel(elseLbl)
        method.visitInsn(Opcodes.ICONST_2)
        method.visitLabel(end)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(2, 2)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildIntraMonitorGotoHost(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/IntraMonitorGotoHost", null, "java/lang/Object", null)
        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "LOCK", "Ljava/lang/Object;", null, null).visitEnd()
        val clinit = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        clinit.visitCode()
        clinit.visitTypeInsn(Opcodes.NEW, "java/lang/Object")
        clinit.visitInsn(Opcodes.DUP)
        clinit.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        clinit.visitFieldInsn(Opcodes.PUTSTATIC, "sample/IntraMonitorGotoHost", "LOCK", "Ljava/lang/Object;")
        clinit.visitInsn(Opcodes.RETURN)
        clinit.visitMaxs(2, 0)
        clinit.visitEnd()
        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "(I)I", null, null)
        val elseLbl = Label()
        val end = Label()
        method.visitCode()
        method.visitFieldInsn(Opcodes.GETSTATIC, "sample/IntraMonitorGotoHost", "LOCK", "Ljava/lang/Object;")
        method.visitInsn(Opcodes.DUP)
        method.visitVarInsn(Opcodes.ASTORE, 1)
        method.visitInsn(Opcodes.MONITORENTER)
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitJumpInsn(Opcodes.IFLE, elseLbl)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitJumpInsn(Opcodes.GOTO, end)
        method.visitLabel(elseLbl)
        method.visitInsn(Opcodes.ICONST_2)
        method.visitLabel(end)
        method.visitVarInsn(Opcodes.ALOAD, 1)
        method.visitInsn(Opcodes.MONITOREXIT)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(2, 2)
        method.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun iconstOrder(bytes: ByteArray): List<Int> {
        val node = ClassNode()
        ClassReader(bytes).accept(node, 0)
        val method = node.methods.single { it.name == "run" }
        return method.instructions.toArray().mapNotNull { insn ->
            when (insn.opcode) {
                Opcodes.ICONST_1 -> 1
                Opcodes.ICONST_2 -> 2
                Opcodes.ICONST_3 -> 3
                else -> null
            }
        }
    }

    private fun loadClass(bytes: ByteArray, name: String): Class<*> {
        return object : ClassLoader() {
            override fun findClass(n: String): Class<*> {
                if (n == name) return defineClass(n, bytes, 0, bytes.size)
                return super.findClass(n)
            }
        }.loadClass(name)
    }
}
