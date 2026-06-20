package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.Random

/**
 * Control flow obfuscation transform with parameterized density, dispatch mode,
 * and algebraic family.
 *
 * Inserts stack-neutral opaque predicates that create spurious control
 * flow edges visible to decompilers and static analysis tools, without
 * altering actual runtime behaviour.
 *
 * Uses the ASM Tree API with [computeFramesWriter] so frames are
 * recomputed from scratch after mutation.  All inserted branches are
 * stack-neutral and local-neutral.
 */
fun obfuscateControlFlow(classBytes: ByteArray, config: ControlFlowConfig = ControlFlowConfig()): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    val rng = if (config.seed != null) Random(config.seed!!) else Random()
    var obfuscatedCount = 0
    // Density controls insertion probability: density=1 means 1 in 10, density=10 means 1 in 1
    val insertionThreshold = 11 - config.density

    for (method in classNode.methods) {
        if (method.name == "<clinit>") continue
        if ((method.access and Opcodes.ACC_ABSTRACT) != 0) continue
        if ((method.access and Opcodes.ACC_NATIVE) != 0) continue
        val insns = method.instructions ?: continue
        if (insns.size() < 2) continue

        // --- Entry opaque predicate based on algebraic family ---
        val firstReal = findFirstRealInstruction(insns) ?: continue
        val entryDeadEnd = LabelNode()
        val entryPredicate = buildAlgebraicPredicate(config.algebraicFamily, entryDeadEnd, rng)
        insns.insertBefore(firstReal, entryPredicate)
        obfuscatedCount++

        // --- Wrap selected GOTOs based on density ---
        val gotosToWrap = mutableListOf<JumpInsnNode>()
        for (insn in insns.toArray()) {
            if (insn is JumpInsnNode && insn.opcode == Opcodes.GOTO) {
                if (rng.nextInt(insertionThreshold) == 0) {
                    gotosToWrap.add(insn)
                }
            }
        }

        for (gotoInsn in gotosToWrap) {
            val target = gotoInsn.label
            val skipLabel = LabelNode()
            val replacement = when (config.dispatchMode) {
                "lookupswitch" -> buildLookupSwitchGuard(target, skipLabel, rng)
                "tableswitch-hybrid" -> buildTableSwitchHybridGuard(target, skipLabel, rng)
                else -> buildIfChainGuard(target, skipLabel) // if-chain (default)
            }
            insns.insertBefore(gotoInsn, replacement)
            insns.remove(gotoInsn)
            obfuscatedCount++
        }
    }

    if (obfuscatedCount == 0) {
        return classBytes
    }

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun buildAlgebraicPredicate(family: String, deadEnd: LabelNode, rng: Random): InsnList {
    return when (family) {
        "quadratic-residue" -> InsnList().apply {
            // x^2 >= 0 is always true for any integer
            add(InsnNode(Opcodes.ICONST_2))
            add(InsnNode(Opcodes.ICONST_2))
            add(InsnNode(Opcodes.IMUL)) // 4
            add(InsnNode(Opcodes.ICONST_2))
            add(InsnNode(Opcodes.IMUL)) // 8
            add(InsnNode(Opcodes.ICONST_0))
            add(JumpInsnNode(Opcodes.IF_ICMPLT, deadEnd)) // 8 < 0 is false, so falls through
            add(InsnNode(Opcodes.NOP))
            add(deadEnd)
        }
        "bitwise-identity" -> InsnList().apply {
            // (x | 0) != 0 is always true for non-zero x
            add(InsnNode(Opcodes.ICONST_1))
            add(InsnNode(Opcodes.ICONST_0))
            add(InsnNode(Opcodes.IOR))
            add(JumpInsnNode(Opcodes.IFEQ, deadEnd))
            add(InsnNode(Opcodes.NOP))
            add(deadEnd)
        }
        "modular-arithmetic" -> InsnList().apply {
            // (x * x + x) % 2 == 0 is always true for any integer
            add(InsnNode(Opcodes.ICONST_3))
            add(InsnNode(Opcodes.DUP))
            add(InsnNode(Opcodes.IMUL)) // 9
            add(InsnNode(Opcodes.ICONST_3))
            add(InsnNode(Opcodes.IADD)) // 12
            add(InsnNode(Opcodes.ICONST_2))
            add(InsnNode(Opcodes.IREM)) // 0
            add(JumpInsnNode(Opcodes.IFNE, deadEnd))
            add(InsnNode(Opcodes.NOP))
            add(deadEnd)
        }
        else -> { // mixed: randomly choose
            val families = listOf("quadratic-residue", "bitwise-identity", "modular-arithmetic")
            buildAlgebraicPredicate(families[rng.nextInt(families.size)], deadEnd, rng)
        }
    }
}

private fun buildIfChainGuard(target: org.objectweb.asm.tree.LabelNode, skipLabel: LabelNode): InsnList {
    return InsnList().apply {
        add(InsnNode(Opcodes.ICONST_0))
        add(InsnNode(Opcodes.ICONST_0))
        add(JumpInsnNode(Opcodes.IF_ICMPEQ, skipLabel))
        add(JumpInsnNode(Opcodes.GOTO, target)) // dead branch
        add(skipLabel)
        add(JumpInsnNode(Opcodes.GOTO, target)) // always taken
    }
}

private fun buildLookupSwitchGuard(target: org.objectweb.asm.tree.LabelNode, skipLabel: LabelNode, rng: Random): InsnList {
    return InsnList().apply {
        add(InsnNode(Opcodes.ICONST_0))
        val cases = intArrayOf(0, 1, 2)
        val labels = Array(3) { LabelNode() }
        add(org.objectweb.asm.tree.LookupSwitchInsnNode(
            labels[0],
            cases,
            labels,
        ))
        add(labels[0])
        add(JumpInsnNode(Opcodes.GOTO, skipLabel))
        add(labels[1])
        add(JumpInsnNode(Opcodes.GOTO, skipLabel))
        add(labels[2])
        add(JumpInsnNode(Opcodes.GOTO, skipLabel))
        add(skipLabel)
        add(JumpInsnNode(Opcodes.GOTO, target))
    }
}

private fun buildTableSwitchHybridGuard(target: org.objectweb.asm.tree.LabelNode, skipLabel: LabelNode, rng: Random): InsnList {
    return InsnList().apply {
        add(InsnNode(Opcodes.ICONST_0))
        val defaultLabel = LabelNode()
        add(org.objectweb.asm.tree.TableSwitchInsnNode(0, 2, defaultLabel, defaultLabel, defaultLabel, defaultLabel))
        add(defaultLabel)
        add(JumpInsnNode(Opcodes.GOTO, skipLabel))
        add(skipLabel)
        add(JumpInsnNode(Opcodes.GOTO, target))
    }
}

private fun findFirstRealInstruction(insns: org.objectweb.asm.tree.InsnList): AbstractInsnNode? {
    for (insn in insns) {
        if (insn is LabelNode) continue
        if (insn.opcode == -1) continue
        return insn
    }
    return null
}
