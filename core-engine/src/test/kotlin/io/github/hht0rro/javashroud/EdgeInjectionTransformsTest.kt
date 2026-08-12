package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.ControlFlowConfig
import io.github.hht0rro.javashroud.bytecode.obfuscateControlFlow
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.lang.reflect.InvocationTargetException

class EdgeInjectionTransformsTest {
    @Test
    fun branch_injection_injects_zero_value_public_synthetic_state_and_preserves_behavior() {
        val transformed = obfuscateControlFlow(
            buildLinearGotoHost(),
            ControlFlowConfig(branchInjection = "light", handlerSplit = "none", seed = 7),
        )
        val node = readNode(transformed)
        val state = assertNotNull(node.fields.singleOrNull { it.name.startsWith("__js_flow_state") })
        assertEquals("I", state.desc)
        assertEquals(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, state.access)
        assertEquals(null, state.value, "The JVM, not a ConstantValue or <clinit>, supplies the zero state")
        assertTrue(node.methods.none { it.name == "<clinit>" }, "The transform must not synthesize a class initializer for the state field")

        val fieldUses = node.methods.flatMap { method ->
            method.instructions.toArray().filterIsInstance<FieldInsnNode>().filter { it.owner == node.name && it.name == state.name }
        }
        assertEquals(1, fieldUses.count { it.opcode == Opcodes.GETSTATIC })
        assertEquals(0, fieldUses.count { it.opcode == Opcodes.PUTSTATIC })
        assertEquals(7, define(transformed).getMethod("run").invoke(null))
    }

    @Test
    fun branch_injection_levels_bound_injected_edges_and_none_injects_nothing() {
        val original = buildLinearGotoHost()
        val byLevel = mapOf(
            "none" to 0,
            "light" to 1,
            "normal" to 2,
            "aggressive" to 3,
        )
        for ((level, expectedEdges) in byLevel) {
            val transformed = obfuscateControlFlow(
                original,
                ControlFlowConfig(branchInjection = level, handlerSplit = "none", seed = 19),
            )
            if (level == "none") {
                assertEquals(0, getStaticCount(transformed), "none must not inject any edge for $level")
            } else {
                assertEquals(expectedEdges, getStaticCount(transformed), "Unexpected edge count for $level")
            }
        }
    }

    @Test
    fun branch_injection_level_caps_are_applied_per_method() {
        val original = buildTwoThreeGotoHost()
        val light = obfuscateControlFlow(
            original,
            ControlFlowConfig(branchInjection = "light", handlerSplit = "none", seed = 23),
        )
        val normal = obfuscateControlFlow(
            original,
            ControlFlowConfig(branchInjection = "normal", handlerSplit = "none", seed = 23),
        )

        assertEquals(0, getStaticCount(light), "Three safe edges per method remain below the light 25% cap")
        assertEquals(2, getStaticCount(normal), "Normal coverage must choose one edge from each method, not three class-wide")
    }

    @Test
    fun edge_injection_skips_switch_and_complex_handlers() {
        val switchHost = buildSwitchHost()
        val switchResult = obfuscateControlFlow(
            switchHost,
            ControlFlowConfig(branchInjection = "aggressive", handlerSplit = "none", seed = 1),
        )
        assertEquals(0, getStaticCount(switchResult), "Switch hosts must not receive injected edges")

        val complexHandlerHost = buildHandlingCatchHost()
        val handlerResult = obfuscateControlFlow(
            complexHandlerHost,
            ControlFlowConfig(branchInjection = "none", handlerSplit = "heavy", seed = 1),
        )
        assertEquals(1, tryCatchCount(handlerResult), "Complex handlers must not be split")
    }

    @Test
    fun handler_split_levels_add_same_method_overlapping_typed_rethrow_relays() {
        val original = buildRethrowHost()
        val light = obfuscateControlFlow(
            original,
            ControlFlowConfig(branchInjection = "none", handlerSplit = "light"),
        )
        val heavy = obfuscateControlFlow(
            original,
            ControlFlowConfig(branchInjection = "none", handlerSplit = "heavy"),
        )

        assertEquals(3, tryCatchCount(light), "light should split one of the two simple typed handlers")
        assertEquals(4, tryCatchCount(heavy), "heavy should split each simple typed handler")
        val lightNode = readNode(light)
        val splitMethod = assertNotNull(lightNode.methods.firstOrNull { it.tryCatchBlocks.size == 2 })
        assertTrue(splitMethod.tryCatchBlocks.all { it.type == "java/lang/RuntimeException" })
        val inner = splitMethod.tryCatchBlocks[0]
        val outer = splitMethod.tryCatchBlocks[1]
        assertTrue(inner.start === outer.start, "The split must retain the original protected start")
        assertTrue(inner.end !== outer.end, "The inner handler must end at the selected split R")
        assertTrue(inner.type == outer.type)

        val relay = inner.handler
        val relayInstructions = splitMethod.instructions.toArray()
        val startIndex = relayInstructions.indexOf(inner.start)
        val splitIndex = relayInstructions.indexOf(inner.end)
        val outerEndIndex = relayInstructions.indexOf(outer.end)
        val relayIndex = relayInstructions.indexOf(relay)
        assertTrue(startIndex < splitIndex && splitIndex < outerEndIndex, "Expected [start,R) inside the original outer range")
        assertTrue(relayIndex > outerEndIndex, "The relay must be out of line and outside both protected ranges")
        assertTrue(relayIndex !in startIndex until splitIndex)
        assertTrue(relayIndex !in startIndex until outerEndIndex)
        assertTrue(outer.handler !== relay, "The outer handler must remain the original handler")
        assertTrue(relayInstructions.drop(relayIndex + 1).filter { it.opcode >= 0 }.take(3).let { instructions ->
            instructions.size == 3 &&
                instructions[0] is VarInsnNode && instructions[0].opcode == Opcodes.ASTORE &&
                instructions[1] is VarInsnNode && instructions[1].opcode == Opcodes.ALOAD &&
                instructions[2].opcode == Opcodes.ATHROW
        })

        val target = define(light).getMethod("first")
        val thrown = try {
            target.invoke(null)
            null
        } catch (error: InvocationTargetException) {
            error.cause
        }
        assertTrue(thrown is RuntimeException, "The relay must preserve the original thrown type")
    }

    private fun buildLinearGotoHost(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/EdgeFlowHost", null, "java/lang/Object", null)
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
        val first = Label()
        val second = Label()
        val third = Label()
        val fourth = Label()
        method.visitCode()
        method.visitJumpInsn(Opcodes.GOTO, first)
        method.visitLabel(first)
        method.visitInsn(Opcodes.NOP)
        method.visitJumpInsn(Opcodes.GOTO, second)
        method.visitLabel(second)
        method.visitInsn(Opcodes.NOP)
        method.visitJumpInsn(Opcodes.GOTO, third)
        method.visitLabel(third)
        method.visitInsn(Opcodes.NOP)
        method.visitJumpInsn(Opcodes.GOTO, fourth)
        method.visitLabel(fourth)
        method.visitIntInsn(Opcodes.BIPUSH, 7)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildSwitchHost(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/EdgeSwitchHost", null, "java/lang/Object", null)
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "(I)I", null, null)
        val zero = Label()
        val fallback = Label()
        method.visitCode()
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitTableSwitchInsn(0, 0, fallback, zero)
        method.visitLabel(zero)
        method.visitInsn(Opcodes.ICONST_0)
        method.visitInsn(Opcodes.IRETURN)
        method.visitLabel(fallback)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildTwoThreeGotoHost(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/EdgePerMethodHost", null, "java/lang/Object", null)
        buildThreeGotoMethod(writer, "first")
        buildThreeGotoMethod(writer, "second")
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildThreeGotoMethod(writer: ClassWriter, name: String) {
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, name, "()I", null, null)
        val first = Label()
        val second = Label()
        val third = Label()
        method.visitCode()
        method.visitJumpInsn(Opcodes.GOTO, first)
        method.visitLabel(first)
        method.visitInsn(Opcodes.NOP)
        method.visitJumpInsn(Opcodes.GOTO, second)
        method.visitLabel(second)
        method.visitInsn(Opcodes.NOP)
        method.visitJumpInsn(Opcodes.GOTO, third)
        method.visitLabel(third)
        method.visitInsn(Opcodes.ICONST_3)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
    }

    private fun buildRethrowHost(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/EdgeRethrowHost", null, "java/lang/Object", null)
        buildRethrowMethod(writer, "first")
        buildRethrowMethod(writer, "second")
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildRethrowMethod(writer: ClassWriter, name: String) {
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, name, "()V", null, null)
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
        method.visitLabel(handler)
        method.visitVarInsn(Opcodes.ASTORE, 0)
        method.visitVarInsn(Opcodes.ALOAD, 0)
        method.visitInsn(Opcodes.ATHROW)
        method.visitMaxs(0, 0)
        method.visitEnd()
    }

    private fun buildHandlingCatchHost(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/EdgeHandlingCatchHost", null, "java/lang/Object", null)
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
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
        method.visitLabel(handler)
        method.visitVarInsn(Opcodes.ASTORE, 0)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitInsn(Opcodes.IRETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun readNode(bytes: ByteArray): ClassNode = ClassNode().also { ClassReader(bytes).accept(it, ClassReader.EXPAND_FRAMES) }

    private fun getStaticCount(bytes: ByteArray): Int = readNode(bytes).methods.sumOf { method ->
        method.instructions.toArray().count { instruction -> instruction is FieldInsnNode && instruction.opcode == Opcodes.GETSTATIC }
    }

    private fun tryCatchCount(bytes: ByteArray): Int = readNode(bytes).methods.sumOf { it.tryCatchBlocks.size }

    private fun define(bytes: ByteArray): Class<*> = object : ClassLoader(javaClass.classLoader) {
        fun load(): Class<*> = defineClass(null, bytes, 0, bytes.size)
    }.load()
}
