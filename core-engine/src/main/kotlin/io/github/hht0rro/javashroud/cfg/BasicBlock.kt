package io.github.hht0rro.javashroud.cfg

import org.objectweb.asm.tree.AbstractInsnNode

/**
 * A basic block in the control flow graph.
 *
 * A basic block is a straight-line sequence of instructions with:
 * - A single entry point (the first instruction)
 * - A single exit point (the last instruction, which may be a branch)
 * - No branches except at the end
 * - No branch targets except at the beginning
 */
data class BasicBlock(
    val id: Int,
    val instructions: MutableList<AbstractInsnNode> = mutableListOf(),
) {
    val firstInsn: AbstractInsnNode? get() = instructions.firstOrNull()
    val lastInsn: AbstractInsnNode? get() = instructions.lastOrNull()
    val size: Int get() = instructions.size
    val isEmpty: Boolean get() = instructions.isEmpty()
}
