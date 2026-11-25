package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.TableSwitchInsnNode
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
 * When [ControlFlowConfig.branchInjection] or [ControlFlowConfig.handlerSplit]
 * are enabled, conditional-edge injection and handler splitting run first on the
 * original class, and predicate/dispatch rewriting then applies to the combined
 * result.
 *
 * Uses the ASM Tree API with [computeFramesWriter] so frames are
 * recomputed from scratch after mutation.  All inserted branches are
 * stack-neutral and local-neutral.
 */
fun obfuscateControlFlow(classBytes: ByteArray, config: ControlFlowConfig = ControlFlowConfig()): ByteArray {
    val edgeTransformed = if (config.branchInjection == "none" && config.handlerSplit == "none") {
        classBytes
    } else {
        applyEdgeInjectionObfuscation(classBytes, config)
    }
    return obfuscatePredicateDispatch(edgeTransformed, config)
}

private fun obfuscatePredicateDispatch(classBytes: ByteArray, config: ControlFlowConfig): ByteArray {
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
            val mode = if (config.dispatchMode == "mixed") {
                listOf("if-chain", "lookupswitch", "tableswitch-hybrid")[rng.nextInt(3)]
            } else {
                config.dispatchMode
            }
            val replacement = when (mode) {
                "lookupswitch" -> buildLookupSwitchGuard(target, skipLabel, rng)
                "tableswitch-hybrid" -> buildTableSwitchHybridGuard(target, skipLabel, rng)
                else -> buildIfChainGuard(target, skipLabel)
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
            val x = 2 + rng.nextInt(6)
            add(pushInt(x))
            add(InsnNode(Opcodes.DUP))
            add(InsnNode(Opcodes.IMUL))
            add(pushInt(x))
            add(InsnNode(Opcodes.IADD))
            add(InsnNode(Opcodes.ICONST_2))
            add(InsnNode(Opcodes.IREM))
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
        add(JumpInsnNode(Opcodes.IF_ICMPEQ, target))
        add(skipLabel)
        add(InsnNode(Opcodes.NOP))
        add(JumpInsnNode(Opcodes.GOTO, target))
    }
}

private fun buildLookupSwitchGuard(target: org.objectweb.asm.tree.LabelNode, skipLabel: LabelNode, rng: Random): InsnList {
    val cases = intArrayOf(0, 1, 2)
    val labels = Array(3) { LabelNode() }
    val defaultLabel = LabelNode()
    return InsnList().apply {
        add(InsnNode(Opcodes.ICONST_0))
        add(LookupSwitchInsnNode(defaultLabel, cases, labels))
        add(labels[0])
        add(InsnNode(Opcodes.NOP))
        add(JumpInsnNode(Opcodes.GOTO, target))
        add(labels[1])
        add(pushInt(rng.nextInt(7) + 1))
        add(InsnNode(Opcodes.POP))
        add(JumpInsnNode(Opcodes.GOTO, target))
        add(labels[2])
        add(JumpInsnNode(Opcodes.GOTO, skipLabel))
        add(defaultLabel)
        add(InsnNode(Opcodes.NOP))
        add(JumpInsnNode(Opcodes.GOTO, target))
        add(skipLabel)
        add(JumpInsnNode(Opcodes.GOTO, target))
    }
}

private fun buildTableSwitchHybridGuard(target: org.objectweb.asm.tree.LabelNode, skipLabel: LabelNode, rng: Random): InsnList {
    val case0 = LabelNode()
    val case1 = LabelNode()
    val case2 = LabelNode()
    val defaultLabel = LabelNode()
    return InsnList().apply {
        add(InsnNode(Opcodes.ICONST_0))
        add(TableSwitchInsnNode(0, 2, defaultLabel, case0, case1, case2))
        add(case0)
        add(InsnNode(Opcodes.NOP))
        add(JumpInsnNode(Opcodes.GOTO, target))
        add(case1)
        add(pushInt(rng.nextInt(7) + 1))
        add(InsnNode(Opcodes.POP))
        add(JumpInsnNode(Opcodes.GOTO, target))
        add(case2)
        add(JumpInsnNode(Opcodes.GOTO, skipLabel))
        add(defaultLabel)
        add(InsnNode(Opcodes.NOP))
        add(JumpInsnNode(Opcodes.GOTO, target))
        add(skipLabel)
        add(JumpInsnNode(Opcodes.GOTO, target))
    }
}

private fun pushInt(value: Int): AbstractInsnNode = when (value) {
    -1 -> InsnNode(Opcodes.ICONST_M1)
    in 0..5 -> InsnNode(Opcodes.ICONST_0 + value)
    in Byte.MIN_VALUE..Byte.MAX_VALUE -> IntInsnNode(Opcodes.BIPUSH, value)
    else -> LdcInsnNode(value)
}

private fun findFirstRealInstruction(insns: org.objectweb.asm.tree.InsnList): AbstractInsnNode? {
    for (insn in insns) {
        if (insn is LabelNode) continue
        if (insn.opcode == -1) continue
        return insn
    }
    return null
}
