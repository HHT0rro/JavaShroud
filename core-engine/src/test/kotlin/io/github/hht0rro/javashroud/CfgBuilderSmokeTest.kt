package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.cfg.CfgBuilder
import io.github.hht0rro.javashroud.cfg.EdgeType
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.VarInsnNode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CfgBuilderSmokeTest {

    @Test
    fun build_simple_method_produces_single_block() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "simple", "()V", null, null)
        method.instructions.add(InsnNode(Opcodes.RETURN))

        val cfg = CfgBuilder.build(method)

        assertEquals(1, cfg.blockCount)
        assertNotNull(cfg.entryBlock)
        assertEquals(0, cfg.edgeCount)
    }

    @Test
    fun build_conditional_branch_produces_three_blocks() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "cond", "()V", null, null)
        val label = LabelNode(Label())
        // ICONST_0; IFEQ label; NOP; label: RETURN
        method.instructions.add(InsnNode(Opcodes.ICONST_0))
        method.instructions.add(JumpInsnNode(Opcodes.IFEQ, label))
        method.instructions.add(InsnNode(Opcodes.NOP))
        method.instructions.add(label)
        method.instructions.add(InsnNode(Opcodes.RETURN))

        val cfg = CfgBuilder.build(method)

        assertTrue(cfg.blockCount >= 2, "Should have at least 2 blocks for conditional branch, got ${cfg.blockCount}")
        assertTrue(cfg.edgeCount >= 2, "Should have at least 2 edges for conditional branch, got ${cfg.edgeCount}")
    }

    @Test
    fun build_unconditional_jump_produces_two_blocks() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "jump", "()V", null, null)
        val label = LabelNode(Label())
        // GOTO label; NOP; label: RETURN
        method.instructions.add(JumpInsnNode(Opcodes.GOTO, label))
        method.instructions.add(InsnNode(Opcodes.NOP))
        method.instructions.add(label)
        method.instructions.add(InsnNode(Opcodes.RETURN))

        val cfg = CfgBuilder.build(method)

        assertTrue(cfg.blockCount >= 2, "Should have at least 2 blocks, got ${cfg.blockCount}")
        // Should have a NORMAL edge from entry to the target block
        val normalEdges = cfg.edges.filter { it.type == EdgeType.NORMAL }
        assertTrue(normalEdges.isNotEmpty(), "Should have at least one NORMAL edge")
    }

    @Test
    fun build_returns_correct_entry_block() {
        val method = MethodNode(Opcodes.ACC_PUBLIC, "entry", "()V", null, null)
        val label = LabelNode(Label())
        method.instructions.add(InsnNode(Opcodes.ICONST_0))
        method.instructions.add(JumpInsnNode(Opcodes.IFEQ, label))
        method.instructions.add(InsnNode(Opcodes.RETURN))
        method.instructions.add(label)
        method.instructions.add(InsnNode(Opcodes.RETURN))

        val cfg = CfgBuilder.build(method)

        assertNotNull(cfg.entryBlock)
        assertEquals(cfg.blocks.first(), cfg.entryBlock)
    }
}
