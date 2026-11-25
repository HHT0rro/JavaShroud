package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.cfg.CfgBuilder
import io.github.hht0rro.javashroud.cfg.EdgeType
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import org.objectweb.asm.tree.TryCatchBlockNode
import org.objectweb.asm.tree.VarInsnNode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CfgAdvancedTest {

    @Test
    fun try_catch_creates_exception_edges() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "tryCatch", "()V", null, null)
        val tryStart = LabelNode(Label())
        val tryEnd = LabelNode(Label())
        val handler = LabelNode(Label())
        val afterHandler = LabelNode(Label())

        // try { ALOAD 0; INVOKEVIRTUAL; } catch (Exception) { POP; }
        method.instructions.add(tryStart)
        method.instructions.add(VarInsnNode(Opcodes.ALOAD, 0))
        method.instructions.add(InsnNode(Opcodes.ATHROW))
        method.instructions.add(tryEnd)
        method.instructions.add(JumpInsnNode(Opcodes.GOTO, afterHandler))
        method.instructions.add(handler)
        method.instructions.add(InsnNode(Opcodes.POP))
        method.instructions.add(afterHandler)
        method.instructions.add(InsnNode(Opcodes.RETURN))

        method.tryCatchBlocks = mutableListOf(
            TryCatchBlockNode(tryStart, tryEnd, handler, "java/lang/Exception")
        )

        val cfg = CfgBuilder.build(method)

        assertTrue(cfg.blockCount >= 2, "Try-catch should produce multiple blocks, got ${cfg.blockCount}")
        val exceptionEdges = cfg.edges.filter { it.type == EdgeType.EXCEPTION }
        assertTrue(exceptionEdges.isNotEmpty(), "Should have at least one EXCEPTION edge")
        assertNotNull(exceptionEdges.first().exceptionType, "Exception edge should have type")
        assertEquals("java/lang/Exception", exceptionEdges.first().exceptionType)
    }

    @Test
    fun tableswitch_creates_multiple_normal_edges() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "tableSwitch", "()V", null, null)
        val case0 = LabelNode(Label())
        val case1 = LabelNode(Label())
        val case2 = LabelNode(Label())
        val dflt = LabelNode(Label())
        val end = LabelNode(Label())

        method.instructions.add(VarInsnNode(Opcodes.ILOAD, 1))
        method.instructions.add(TableSwitchInsnNode(0, 2, dflt, case0, case1, case2))
        method.instructions.add(case0)
        method.instructions.add(InsnNode(Opcodes.ICONST_0))
        method.instructions.add(JumpInsnNode(Opcodes.GOTO, end))
        method.instructions.add(case1)
        method.instructions.add(InsnNode(Opcodes.ICONST_1))
        method.instructions.add(JumpInsnNode(Opcodes.GOTO, end))
        method.instructions.add(case2)
        method.instructions.add(InsnNode(Opcodes.ICONST_2))
        method.instructions.add(JumpInsnNode(Opcodes.GOTO, end))
        method.instructions.add(dflt)
        method.instructions.add(InsnNode(Opcodes.ICONST_M1))
        method.instructions.add(end)
        method.instructions.add(InsnNode(Opcodes.IRETURN))

        val cfg = CfgBuilder.build(method)

        assertTrue(cfg.blockCount >= 4, "TableSwitch should produce at least 4 blocks, got ${cfg.blockCount}")
        val normalEdges = cfg.edges.filter { it.type == EdgeType.NORMAL }
        assertTrue(normalEdges.size >= 4, "Should have at least 4 NORMAL edges for 3 cases + default, got ${normalEdges.size}")
    }

    @Test
    fun lookupswitch_creates_multiple_normal_edges() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "lookupSwitch", "()V", null, null)
        val case10 = LabelNode(Label())
        val case20 = LabelNode(Label())
        val dflt = LabelNode(Label())
        val end = LabelNode(Label())

        method.instructions.add(VarInsnNode(Opcodes.ILOAD, 1))
        method.instructions.add(LookupSwitchInsnNode(dflt, intArrayOf(10, 20), arrayOf(case10, case20)))
        method.instructions.add(case10)
        method.instructions.add(InsnNode(Opcodes.ICONST_0))
        method.instructions.add(JumpInsnNode(Opcodes.GOTO, end))
        method.instructions.add(case20)
        method.instructions.add(InsnNode(Opcodes.ICONST_1))
        method.instructions.add(JumpInsnNode(Opcodes.GOTO, end))
        method.instructions.add(dflt)
        method.instructions.add(InsnNode(Opcodes.ICONST_M1))
        method.instructions.add(end)
        method.instructions.add(InsnNode(Opcodes.IRETURN))

        val cfg = CfgBuilder.build(method)

        assertTrue(cfg.blockCount >= 3, "LookupSwitch should produce at least 3 blocks, got ${cfg.blockCount}")
        val normalEdges = cfg.edges.filter { it.type == EdgeType.NORMAL }
        assertTrue(normalEdges.size >= 3, "Should have at least 3 NORMAL edges for 2 cases + default, got ${normalEdges.size}")
    }

    @Test
    fun nested_if_inside_try_catch() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "nestedIfTryCatch", "()V", null, null)
        val tryStart = LabelNode(Label())
        val ifTarget = LabelNode(Label())
        val tryEnd = LabelNode(Label())
        val handler = LabelNode(Label())

        method.instructions.add(tryStart)
        method.instructions.add(VarInsnNode(Opcodes.ILOAD, 1))
        method.instructions.add(JumpInsnNode(Opcodes.IFEQ, ifTarget))
        method.instructions.add(InsnNode(Opcodes.NOP))
        method.instructions.add(ifTarget)
        method.instructions.add(InsnNode(Opcodes.ICONST_0))
        method.instructions.add(InsnNode(Opcodes.POP))
        method.instructions.add(tryEnd)
        method.instructions.add(InsnNode(Opcodes.RETURN))
        method.instructions.add(handler)
        method.instructions.add(InsnNode(Opcodes.POP))
        method.instructions.add(InsnNode(Opcodes.RETURN))

        method.tryCatchBlocks = mutableListOf(
            TryCatchBlockNode(tryStart, tryEnd, handler, "java/lang/Exception")
        )

        val cfg = CfgBuilder.build(method)

        assertTrue(cfg.blockCount >= 3, "Nested if+try-catch should produce multiple blocks, got ${cfg.blockCount}")
        val exceptionEdges = cfg.edges.filter { it.type == EdgeType.EXCEPTION }
        assertTrue(exceptionEdges.isNotEmpty(), "Should have EXCEPTION edges")
    }

    @Test
    fun multiple_exception_handlers() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "multiCatch", "()V", null, null)
        val tryStart = LabelNode(Label())
        val tryEnd = LabelNode(Label())
        val handler1 = LabelNode(Label())
        val handler2 = LabelNode(Label())

        method.instructions.add(tryStart)
        method.instructions.add(VarInsnNode(Opcodes.ALOAD, 0))
        method.instructions.add(InsnNode(Opcodes.ATHROW))
        method.instructions.add(tryEnd)
        method.instructions.add(handler1)
        method.instructions.add(InsnNode(Opcodes.POP))
        method.instructions.add(InsnNode(Opcodes.RETURN))
        method.instructions.add(handler2)
        method.instructions.add(InsnNode(Opcodes.POP))
        method.instructions.add(InsnNode(Opcodes.RETURN))

        method.tryCatchBlocks = mutableListOf(
            TryCatchBlockNode(tryStart, tryEnd, handler1, "java/lang/NullPointerException"),
            TryCatchBlockNode(tryStart, tryEnd, handler2, "java/lang/IllegalArgumentException")
        )

        val cfg = CfgBuilder.build(method)

        val exceptionEdges = cfg.edges.filter { it.type == EdgeType.EXCEPTION }
        assertTrue(exceptionEdges.size >= 2, "Should have at least 2 EXCEPTION edges for 2 handlers, got ${exceptionEdges.size}")
        val handlerTypes = exceptionEdges.map { it.exceptionType }.distinct()
        assertTrue(handlerTypes.contains("java/lang/NullPointerException"))
        assertTrue(handlerTypes.contains("java/lang/IllegalArgumentException"))
    }

    @Test
    fun cfg_successors_and_predecessors() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "succPred", "()V", null, null)
        val label = LabelNode(Label())
        method.instructions.add(InsnNode(Opcodes.ICONST_0))
        method.instructions.add(JumpInsnNode(Opcodes.IFEQ, label))
        method.instructions.add(InsnNode(Opcodes.NOP))
        method.instructions.add(label)
        method.instructions.add(InsnNode(Opcodes.RETURN))

        val cfg = CfgBuilder.build(method)
        val entry = cfg.entryBlock!!
        val successors = cfg.successors(entry)
        assertTrue(successors.isNotEmpty(), "Entry block should have successors")

        for (succ in successors) {
            val preds = cfg.predecessors(succ)
            assertTrue(preds.contains(entry), "Successor's predecessors should include entry")
        }
    }

    @Test
    fun cfg_exception_handlers_method() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "exHandlers", "()V", null, null)
        val tryStart = LabelNode(Label())
        val tryEnd = LabelNode(Label())
        val handler = LabelNode(Label())

        method.instructions.add(tryStart)
        method.instructions.add(InsnNode(Opcodes.NOP))
        method.instructions.add(tryEnd)
        method.instructions.add(InsnNode(Opcodes.RETURN))
        method.instructions.add(handler)
        method.instructions.add(InsnNode(Opcodes.POP))
        method.instructions.add(InsnNode(Opcodes.RETURN))

        method.tryCatchBlocks = mutableListOf(
            TryCatchBlockNode(tryStart, tryEnd, handler, "java/lang/Exception")
        )

        val cfg = CfgBuilder.build(method)
        val handlers = cfg.exceptionHandlers()
        assertTrue(handlers.isNotEmpty(), "Should identify exception handler blocks")
    }
}
