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
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.IdentityHashMap
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
        if (insns.size() < 8) continue
        if (methodHasJsrRet(method)) continue

        val handlerLabels = method.tryCatchBlocks.orEmpty().mapTo(mutableSetOf()) { it.handler }
        val monitorDepth = monitorDepths(insns)
        val hasMonitors = monitorDepth.values.any { it > 0 }
        val gotosToProcess = mutableListOf<JumpInsnNode>()
        for (insn in insns.toArray()) {
            val gotoInsn = insn as? JumpInsnNode ?: continue
            if (gotoInsn.opcode != Opcodes.GOTO) continue
            if (gotoInsn.label in handlerLabels) continue
            val sourceDepth = monitorDepth[gotoInsn] ?: 0
            val targetDepth = monitorDepth[gotoInsn.label] ?: 0
            if (sourceDepth != targetDepth) continue
            if (rng.nextInt(insertionThreshold) == 0) {
                gotosToProcess.add(gotoInsn)
            }
        }
        if (gotosToProcess.isEmpty()) continue

        val dispatchVar = method.maxLocals
        method.maxLocals = dispatchVar + 1
        gotosToProcess.shuffle(rng)
        for (gotoInsn in gotosToProcess) {
            if (gotoInsn.opcode != Opcodes.GOTO) continue
            val target = gotoInsn.label
            val edgeState = rng.nextInt(0x3fffffff) or 1
            val guardBlock = InsnList().apply {
                add(LdcInsnNode(edgeState))
                add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
                addHandlerComplexity(config, classNode.name, rng)
                if (config.handlerComplexity == "field-write") {
                    add(VarInsnNode(Opcodes.ILOAD, dispatchVar))
                    add(FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, "__js_dispatch_state", "I"))
                }
                add(VarInsnNode(Opcodes.ILOAD, dispatchVar))
                add(JumpInsnNode(Opcodes.IFNE, target))
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

    // Recompute StackMapTable frames for every transformed method.  A
    // COMPUTE_MAXS-only class is not verifier-safe for Java 7+ artifacts:
    // once a branch is introduced, the JVM requires a frame at each merge
    // target.  If ASM cannot reconcile a generated control-flow graph, keep
    // the original class rather than emitting an invalid artifact.
    return try {
        val writer = computeFramesWriter(reader)
        classNode.accept(writer)
        val out = writer.toByteArray()
        ClassReader(out).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {}, 0)
        out
    } catch (_: Throwable) {
        classBytes
    }
}

private fun methodHasJsrRet(method: org.objectweb.asm.tree.MethodNode): Boolean {
    for (insn in method.instructions.toArray()) {
        if (insn.opcode == Opcodes.JSR || insn.opcode == Opcodes.RET) return true
    }
    return false
}

private fun monitorDepths(insns: InsnList): Map<AbstractInsnNode, Int> {
    val depths = IdentityHashMap<AbstractInsnNode, Int>()
    var depth = 0
    for (insn in insns.toArray()) {
        depths[insn] = depth
        when (insn.opcode) {
            Opcodes.MONITORENTER -> depth++
            Opcodes.MONITOREXIT -> if (depth > 0) depth--
        }
    }
    return depths
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

private fun shuffleLabeledBlocks(insns: InsnList, rng: Random) {
    val nodes = insns.toArray().toList()
    if (nodes.size < 8) return
    val cuts = mutableListOf(0)
    nodes.forEachIndexed { index, node ->
        if (index > 0 && node is LabelNode) cuts.add(index)
    }
    if (cuts.size < 3) return
    cuts.add(nodes.size)
    val blocks = (0 until cuts.size - 1).map { slot ->
        nodes.subList(cuts[slot], cuts[slot + 1]).toMutableList()
    }.toMutableList()
    for (index in 0 until blocks.size - 1) {
        val last = blocks[index].lastOrNull { it.opcode >= 0 } ?: continue
        if (!isHardTerminator(last)) {
            val nextStart = blocks[index + 1].firstOrNull { it is LabelNode } as? LabelNode ?: continue
            blocks[index].add(JumpInsnNode(Opcodes.GOTO, nextStart))
        }
    }
    val head = blocks.first()
    val tail = blocks.drop(1).toMutableList()
    tail.shuffle(rng)
    val rebuilt = InsnList()
    (listOf(head) + tail).forEach { block ->
        block.forEach(rebuilt::add)
    }
    insns.clear()
    insns.add(rebuilt)
}

private fun isHardTerminator(insn: AbstractInsnNode): Boolean {
    return when (insn.opcode) {
        Opcodes.GOTO, Opcodes.ATHROW,
        Opcodes.IRETURN, Opcodes.LRETURN, Opcodes.FRETURN, Opcodes.DRETURN, Opcodes.ARETURN, Opcodes.RETURN,
        Opcodes.TABLESWITCH, Opcodes.LOOKUPSWITCH,
        -> true
        else -> false
    }
}

private fun installLookupSwitchDispatcher(
    insns: InsnList,
    gotos: List<JumpInsnNode>,
    dispatchVar: Int,
    rng: Random,
    config: ControlFlowConfig,
    className: String,
) {
    val dispatcher = LabelNode()
    val states = LinkedHashMap<LabelNode, Int>()
    fun stateOf(label: LabelNode): Int = states.getOrPut(label) { rng.nextInt(0x3fffffff) or 1 }
    for (gotoInsn in gotos) {
        if (gotoInsn.opcode != Opcodes.GOTO) continue
        val target = gotoInsn.label
        val block = InsnList()
        block.add(LdcInsnNode(stateOf(target)))
        block.add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
        block.addHandlerComplexity(config, className, rng)
        if (config.handlerComplexity == "field-write") {
            block.add(VarInsnNode(Opcodes.ILOAD, dispatchVar))
            block.add(FieldInsnNode(Opcodes.PUTSTATIC, className, "__js_dispatch_state", "I"))
        }
        block.add(JumpInsnNode(Opcodes.GOTO, dispatcher))
        insns.insertBefore(gotoInsn, block)
        insns.remove(gotoInsn)
    }
    val firstReal = findFirstRealFlat(insns) ?: return
    val startLabel = LabelNode()
    insns.insertBefore(firstReal, startLabel)
    val startState = stateOf(startLabel)
    val prelude = InsnList()
    prelude.add(LdcInsnNode(startState))
    prelude.add(VarInsnNode(Opcodes.ISTORE, dispatchVar))
    prelude.add(JumpInsnNode(Opcodes.GOTO, dispatcher))
    insns.insertBefore(startLabel, prelude)
    val ordered = states.entries.sortedBy { it.value }
    val keys = IntArray(ordered.size) { ordered[it].value }
    val labels = Array(ordered.size) { ordered[it].key }
    insns.add(dispatcher)
    insns.add(VarInsnNode(Opcodes.ILOAD, dispatchVar))
    insns.add(LookupSwitchInsnNode(startLabel, keys, labels))
}

private fun findFirstRealFlat(insns: InsnList): AbstractInsnNode? {
    for (insn in insns) {
        if (insn.opcode == -1) continue
        return insn
    }
    return null
}
