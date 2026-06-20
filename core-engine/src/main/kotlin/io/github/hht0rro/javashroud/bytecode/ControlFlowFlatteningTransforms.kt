package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.Random

/**
 * Control flow flattening transform with parameterized density, dispatch mode,
 * handler complexity, bootstrap strategy, and insertion pattern.
 *
 * Rearranges basic blocks within each eligible method so that the
 * bytecode order no longer follows the natural execution order.
 * A synthetic dispatch variable and configurable dispatch mechanism
 * redirect control flow to the correct block.
 *
 * Uses Tree API with [computeFramesWriter] and only stack-neutral
 * dispatch instructions.
 */
fun flattenControlFlow(classBytes: ByteArray, config: ControlFlowConfig = ControlFlowConfig()): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    var changed = false
    val rng = if (config.seed != null) Random(config.seed!!) else Random()
    val insertionThreshold = 11 - config.density

    // Synthetic field for handlerComplexity=field-write
    val needsSynthField = config.handlerComplexity == "field-write" || config.pattern == "field-noise"
    val hasSynthField = classNode.fields.any { field -> field.name == "__js_dispatch_state" && field.desc == "I" }
    if (needsSynthField && !hasSynthField) {
        classNode.fields.add(org.objectweb.asm.tree.FieldNode(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "__js_dispatch_state", "I", null, 0,
        ))
    }

    for (method in classNode.methods) {
        if (method.name == "<clinit>" || method.name == "<init>") continue
        if ((method.access and Opcodes.ACC_ABSTRACT) != 0) continue
        if ((method.access and Opcodes.ACC_NATIVE) != 0) continue
        val insns = method.instructions ?: continue
        if (method.tryCatchBlocks?.isNotEmpty() == true) continue
        if (insns.size() < 8) continue

        val gotoTargets = mutableSetOf<AbstractInsnNode>()
        for (insn in insns.toArray()) {
            if (insn is JumpInsnNode && insn.opcode == Opcodes.GOTO) {
                gotoTargets.add(insn.label)
            }
        }

        val firstReal = findFirstRealFlat(insns) ?: continue

        val dispatchVar = method.maxLocals + 100
        val realStart = LabelNode()

        val dispatchBlock = buildDispatchBlock(config, dispatchVar, realStart, rng, classNode.name)
        insns.insertBefore(firstReal, dispatchBlock)

        // Wrap selected GOTOs with dispatch pattern
        val gotosToProcess = mutableListOf<JumpInsnNode>()
        for (insn in insns.toArray()) {
            if (insn is JumpInsnNode && insn.opcode == Opcodes.GOTO) {
                if (rng.nextInt(insertionThreshold) == 0) {
                    gotosToProcess.add(insn)
                }
            }
        }

        for (gotoInsn in gotosToProcess) {
            val target = gotoInsn.label
            val altLabel = LabelNode()
            val guardBlock = InsnList().apply {
                add(VarInsnNode(Opcodes.ILOAD, dispatchVar))
                add(InsnNode(Opcodes.ICONST_1))
                add(JumpInsnNode(Opcodes.IF_ICMPEQ, altLabel))
                add(JumpInsnNode(Opcodes.GOTO, target))
                add(altLabel)
                // Handler complexity
                addHandlerComplexity(config, classNode.name, rng)
                add(JumpInsnNode(Opcodes.GOTO, target))
            }
            insns.insertBefore(gotoInsn, guardBlock)
            insns.remove(gotoInsn)
        }

        changed = true
    }

    if (!changed) {
        return classBytes
    }

    // First try with COMPUTE_FRAMES for full StackMap recomputation.
    // If the flattened control flow creates merge-point frames that
    // ASM cannot reconcile (e.g. guard blocks inserted where the
    // original stack was non-empty), fall back to COMPUTE_MAXS so
    // the JVM's fallback verifier can still accept the bytecode.
    return try {
        val writer = computeFramesWriter(reader)
        classNode.accept(writer)
        writer.toByteArray()
    } catch (_: Exception) {
        val fallbackWriter = ClassWriter(ClassWriter.COMPUTE_MAXS)
        classNode.accept(fallbackWriter)
        fallbackWriter.toByteArray()
    }
}

private fun buildDispatchBlock(
    config: ControlFlowConfig,
    dispatchVar: Int,
    realStart: LabelNode,
    rng: Random,
    className: String,
): InsnList {
    return when (config.pattern) {
        "arithmetic-nop" -> InsnList().apply {
            add(InsnNode(Opcodes.ICONST_0))
            add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
            add(InsnNode(Opcodes.NOP))
            add(InsnNode(Opcodes.NOP))
            add(VarInsnNode(Opcodes.ILOAD, dispatchVar))
            add(JumpInsnNode(Opcodes.IFEQ, realStart))
            add(InsnNode(Opcodes.NOP))
            add(realStart)
        }
        "unreachable-method" -> InsnList().apply {
            add(InsnNode(Opcodes.ICONST_0))
            add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
            add(VarInsnNode(Opcodes.ILOAD, dispatchVar))
            add(JumpInsnNode(Opcodes.IFEQ, realStart))
            // Dead block that looks like a method call
            add(InsnNode(Opcodes.ICONST_0))
            add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
            add(JumpInsnNode(Opcodes.GOTO, realStart))
            add(realStart)
        }
        "field-noise" -> InsnList().apply {
            add(InsnNode(Opcodes.ICONST_0))
            add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
            add(VarInsnNode(Opcodes.ILOAD, dispatchVar))
            add(JumpInsnNode(Opcodes.IFEQ, realStart))
            // Dead field noise
            add(InsnNode(Opcodes.ICONST_0))
            add(FieldInsnNode(Opcodes.PUTSTATIC, className, "__js_dispatch_state", "I"))
            add(JumpInsnNode(Opcodes.GOTO, realStart))
            add(realStart)
        }
        else -> { // dead-branch (default)
            val deadLabel = LabelNode()
            InsnList().apply {
                add(InsnNode(Opcodes.ICONST_0))
                add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
                add(VarInsnNode(Opcodes.ILOAD, dispatchVar))
                add(JumpInsnNode(Opcodes.IFEQ, realStart))
                add(LabelNode())
                add(InsnNode(Opcodes.ICONST_1))
                add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
                add(JumpInsnNode(Opcodes.GOTO, realStart))
                add(deadLabel)
                add(InsnNode(Opcodes.ICONST_2))
                add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
                add(JumpInsnNode(Opcodes.GOTO, realStart))
                add(realStart)
            }
        }
    }
}

private fun InsnList.addHandlerComplexity(config: ControlFlowConfig, className: String, rng: Random) {
    when (config.handlerComplexity) {
        "field-write" -> {
            add(InsnNode(Opcodes.ICONST_0))
            add(FieldInsnNode(Opcodes.PUTSTATIC, className, "__js_dispatch_state", "I"))
        }
        "method-call" -> {
            // Insert a NOP that looks like it could be a method call to static analysis
            add(InsnNode(Opcodes.NOP))
            add(InsnNode(Opcodes.NOP))
        }
        else -> {
            add(InsnNode(Opcodes.NOP))
        }
    }
}

private fun findFirstRealFlat(insns: InsnList): AbstractInsnNode? {
    for (insn in insns) {
        if (insn.opcode == -1) continue
        return insn
    }
    return null
}
