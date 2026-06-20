package io.github.hht0rro.javashroud.cfg

import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import org.objectweb.asm.tree.TryCatchBlockNode

/**
 * Builds a [ControlFlowGraph] from an ASM [MethodNode].
 *
 * Algorithm:
 * 1. Identify block leaders (first instruction, branch targets, instructions after branches)
 * 2. Build blocks by grouping instructions between leaders
 * 3. Add edges based on branch instructions and exception handlers
 */
object CfgBuilder {

    fun build(method: MethodNode): ControlFlowGraph {
        val insns = method.instructions
        if (insns == null || insns.size() == 0) {
            return ControlFlowGraph(emptyList(), emptyList(), null)
        }

        // Step 1: Identify leaders (instruction indices that start a new block)
        val leaders = mutableSetOf<Int>()
        leaders.add(0) // First instruction is always a leader

        // Map label nodes to their instruction indices for exception handler targets
        val labelToIndex = mutableMapOf<LabelNode, Int>()
        var index = 0
        for (insn in insns) {
            if (insn is LabelNode) {
                labelToIndex[insn] = index
            }
            index++
        }

        // Add exception handler targets as leaders
        if (method.tryCatchBlocks != null) {
            for (tcb in method.tryCatchBlocks) {
                val startIdx = labelToIndex[tcb.start]
                if (startIdx != null) leaders.add(startIdx)
                val handlerIdx = labelToIndex[tcb.handler]
                if (handlerIdx != null) leaders.add(handlerIdx)
            }
        }

        // Add branch targets and post-branch instructions as leaders
        index = 0
        val insnArray = insns.toArray()
        // Build O(1) lookup: AbstractInsnNode identity -> index
        val nodeToIndex = HashMap<AbstractInsnNode, Int>(insnArray.size * 2)
        for (i in insnArray.indices) {
            nodeToIndex[insnArray[i]] = i
        }
        for (insn in insnArray) {
            when (insn) {
                is JumpInsnNode -> {
                    val targetIdx = nodeToIndex.getOrDefault(insn.label, -1)
                    if (targetIdx >= 0) leaders.add(targetIdx)
                    val nextIdx = index + 1
                    if (nextIdx < insnArray.size) leaders.add(nextIdx)
                }
                is TableSwitchInsnNode -> {
                    for (label in insn.labels) {
                        val targetIdx = insnArray.indexOf(label)
                        if (targetIdx >= 0) leaders.add(targetIdx)
                    }
                    val dfltIdx = nodeToIndex.getOrDefault(insn.dflt, -1)
                    if (dfltIdx >= 0) leaders.add(dfltIdx)
                    val nextIdx = index + 1
                    if (nextIdx < insnArray.size) leaders.add(nextIdx)
                }
                is LookupSwitchInsnNode -> {
                    for (label in insn.labels) {
                        val targetIdx = insnArray.indexOf(label)
                        if (targetIdx >= 0) leaders.add(targetIdx)
                    }
                    val dfltIdx = nodeToIndex.getOrDefault(insn.dflt, -1)
                    if (dfltIdx >= 0) leaders.add(dfltIdx)
                    val nextIdx = index + 1
                    if (nextIdx < insnArray.size) leaders.add(nextIdx)
                }
            }
            if (insn.opcode in Opcodes.IRETURN..Opcodes.RETURN || insn.opcode == Opcodes.ATHROW) {
                val nextIdx = index + 1
                if (nextIdx < insnArray.size) leaders.add(nextIdx)
            }
            index++
        }

        val sortedLeaders = leaders.sorted()
        if (sortedLeaders.isEmpty()) {
            return ControlFlowGraph(emptyList(), emptyList(), null)
        }

        // Step 2: Build blocks
        val blocks = mutableListOf<BasicBlock>()
        val indexToBlock = mutableMapOf<Int, BasicBlock>()

        for (i in sortedLeaders.indices) {
            val startIdx = sortedLeaders[i]
            val endIdx = if (i + 1 < sortedLeaders.size) sortedLeaders[i + 1] else insnArray.size
            val block = BasicBlock(id = i)
            for (j in startIdx until endIdx) {
                block.instructions.add(insnArray[j])
            }
            if (!block.isEmpty) {
                blocks.add(block)
                indexToBlock[startIdx] = block
            }
        }

        if (blocks.isEmpty()) {
            return ControlFlowGraph(emptyList(), emptyList(), null)
        }

        val entryBlock = blocks.first()

        // Step 3: Build edges
        val edges = mutableListOf<CfgEdge>()

        for (i in blocks.indices) {
            val block = blocks[i]
            val lastInsn = block.lastInsn ?: continue

            when (lastInsn) {
                is JumpInsnNode -> {
                    val targetBlock = findTargetBlock(lastInsn.label, labelToIndex, indexToBlock, insnArray)
                    if (targetBlock != null) {
                        val edgeType = if (lastInsn.opcode == Opcodes.GOTO) {
                            EdgeType.NORMAL
                        } else {
                            EdgeType.CONDITIONAL_TRUE
                        }
                        edges.add(CfgEdge(block, targetBlock, edgeType))
                    }
                    // For conditional branches, add fall-through edge
                    if (lastInsn.opcode != Opcodes.GOTO && i + 1 < blocks.size) {
                        edges.add(CfgEdge(block, blocks[i + 1], EdgeType.CONDITIONAL_FALSE))
                    }
                }
                is TableSwitchInsnNode -> {
                    for (label in lastInsn.labels) {
                        val targetBlock = findTargetBlock(label, labelToIndex, indexToBlock, insnArray)
                        if (targetBlock != null) {
                            edges.add(CfgEdge(block, targetBlock, EdgeType.NORMAL))
                        }
                    }
                    val dfltBlock = findTargetBlock(lastInsn.dflt, labelToIndex, indexToBlock, insnArray)
                    if (dfltBlock != null) {
                        edges.add(CfgEdge(block, dfltBlock, EdgeType.NORMAL))
                    }
                }
                is LookupSwitchInsnNode -> {
                    for (label in lastInsn.labels) {
                        val targetBlock = findTargetBlock(label, labelToIndex, indexToBlock, insnArray)
                        if (targetBlock != null) {
                            edges.add(CfgEdge(block, targetBlock, EdgeType.NORMAL))
                        }
                    }
                    val dfltBlock = findTargetBlock(lastInsn.dflt, labelToIndex, indexToBlock, insnArray)
                    if (dfltBlock != null) {
                        edges.add(CfgEdge(block, dfltBlock, EdgeType.NORMAL))
                    }
                }
                else -> {
                    // If not a terminal instruction and not a throw/return, add fall-through
                    if (lastInsn.opcode !in Opcodes.IRETURN..Opcodes.RETURN &&
                        lastInsn.opcode != Opcodes.ATHROW &&
                        lastInsn.opcode != Opcodes.GOTO &&
                        i + 1 < blocks.size
                    ) {
                        edges.add(CfgEdge(block, blocks[i + 1], EdgeType.NORMAL))
                    }
                }
            }
        }

        // Add exception edges
        if (method.tryCatchBlocks != null) {
            for (tcb in method.tryCatchBlocks) {
                val handlerBlock = findTargetBlock(tcb.handler, labelToIndex, indexToBlock, insnArray)
                if (handlerBlock != null) {
                    // All blocks covered by this try range get an exception edge to the handler
                    val startIdx = labelToIndex[tcb.start] ?: continue
                    val endIdx = labelToIndex[tcb.end] ?: continue
                    for (block in blocks) {
                        val blockStartIdx = nodeToIndex.getOrDefault(block.firstInsn, -1)
                        if (blockStartIdx in startIdx until endIdx) {
                            edges.add(CfgEdge(block, handlerBlock, EdgeType.EXCEPTION, tcb.type))
                        }
                    }
                }
            }
        }

        return ControlFlowGraph(blocks, edges, entryBlock)
    }

    private fun findTargetBlock(
        label: LabelNode,
        labelToIndex: Map<LabelNode, Int>,
        indexToBlock: Map<Int, BasicBlock>,
        insnArray: Array<AbstractInsnNode>,
    ): BasicBlock? {
        val targetIdx = labelToIndex[label] ?: return null
        // Find the block that starts at or contains this index
        val directBlock = indexToBlock[targetIdx]
        if (directBlock != null) return directBlock
        // Fallback: find the nearest block
        for ((idx, block) in indexToBlock.toSortedMap()) {
            if (idx <= targetIdx) return block
        }
        return null
    }
}
