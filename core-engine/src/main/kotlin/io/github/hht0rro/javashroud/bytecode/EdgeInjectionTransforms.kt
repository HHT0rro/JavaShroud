package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import org.objectweb.asm.tree.TryCatchBlockNode
import org.objectweb.asm.tree.VarInsnNode
import org.objectweb.asm.tree.analysis.Analyzer
import org.objectweb.asm.tree.analysis.BasicInterpreter
import org.objectweb.asm.tree.analysis.BasicValue
import java.util.Collections
import java.util.Random
import java.util.logging.Logger

private const val EDGE_STATE_FIELD_PREFIX = "__js_flow_state"
private const val MAX_INJECTED_FLOW_EDGES = 8
private const val MAX_HEAVY_HANDLER_SPLITS = 4

private val edgeInjectionLogger = Logger.getLogger("io.github.hht0rro.javashroud.bytecode.EdgeInjection")

/**
 * Conditional-edge injection and same-type handler splitting without reordering basic blocks.
 *
 * The state field deliberately has no ConstantValue, <clinit>, or PUTSTATIC
 * producer. The JVM therefore supplies its zero value, making each injected
 * GETSTATIC/IFEQ edge semantically identical to the replaced GOTO.
 */
internal fun applyEdgeInjectionObfuscation(classBytes: ByteArray, config: ControlFlowConfig): ByteArray {
    require(config.branchInjection in BRANCH_INJECTION_LEVELS) {
        "control-flow-obfuscation branchInjection '${config.branchInjection}' is not supported; supported values: ${BRANCH_INJECTION_LEVELS.joinToString(", ")}"
    }
    require(config.handlerSplit in HANDLER_SPLIT_LEVELS) {
        "control-flow-obfuscation handlerSplit '${config.handlerSplit}' is not supported; supported values: ${HANDLER_SPLIT_LEVELS.joinToString(", ")}"
    }

    val reader = ClassReader(classBytes)
    val classNode = ClassNode()
    reader.accept(classNode, ClassReader.EXPAND_FRAMES)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    val changedMethods = linkedSetOf<MethodKey>()
    var changed = false
    if (config.branchInjection != "none") {
        val flowPlans = selectFlowPlans(classNode, config)
        if (flowPlans.isNotEmpty()) {
            val stateFieldName = nextStateFieldName(classNode)
            classNode.fields.add(
                FieldNode(
                    Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
                    stateFieldName,
                    "I",
                    null,
                    null,
                ),
            )
            for (plan in flowPlans) {
                plan.apply(classNode.name, stateFieldName)
                changedMethods += plan.method.key()
            }
            changed = true
        }
    }

    if (config.handlerSplit != "none") {
        val handlerPlans = selectHandlerSplitPlans(classNode, config.handlerSplit)
        for (plan in handlerPlans) {
            plan.apply()
            changedMethods += plan.method.key()
            changed = true
        }
    }

    if (!changed) {
        return classBytes
    }

    return writeAndVerifyEdgeInjection(reader, classNode, changedMethods)
}

/** A single stack-neutral replacement of an existing empty-stack GOTO edge. */
internal data class FlowEdgeInjection(
    val method: MethodNode,
    private val edge: JumpInsnNode,
) {
    fun apply(className: String, stateFieldName: String) {
        val replacement = InsnList().apply {
            add(FieldInsnNode(Opcodes.GETSTATIC, className, stateFieldName, "I"))
            add(JumpInsnNode(Opcodes.IFEQ, edge.label))
            add(JumpInsnNode(Opcodes.GOTO, edge.label))
        }
        method.instructions.insertBefore(edge, replacement)
        method.instructions.remove(edge)
    }
}

/**
 * Splits a simple typed rethrow handler into overlapping ranges. The inner
 * handler covers [start, split) and targets an appended relay outside either
 * protected range; the original handler remains the outer [start, end) entry.
 */
internal data class HandlerSplitPlan(
    val method: MethodNode,
    private val outerHandler: TryCatchBlockNode,
    private val splitBefore: AbstractInsnNode,
    private val relayLocal: Int,
) {
    fun apply() {
        val split = LabelNode()
        method.instructions.insertBefore(splitBefore, split)

        val relay = LabelNode()
        method.instructions.add(relay)
        method.instructions.add(VarInsnNode(Opcodes.ASTORE, relayLocal))
        method.instructions.add(VarInsnNode(Opcodes.ALOAD, relayLocal))
        method.instructions.add(InsnNode(Opcodes.ATHROW))
        val outerIndex = method.tryCatchBlocks.indexOf(outerHandler)
        check(outerIndex >= 0) { "original outer handler is no longer present" }
        method.tryCatchBlocks.add(
            outerIndex,
            TryCatchBlockNode(
                outerHandler.start,
                split,
                relay,
                outerHandler.type,
            ),
        )
        method.maxLocals = maxOf(method.maxLocals, relayLocal + 1)
    }
}

private val BRANCH_INJECTION_LEVELS = setOf("none", "light", "normal", "aggressive")
private val HANDLER_SPLIT_LEVELS = setOf("none", "light", "heavy")

private data class MethodKey(val name: String, val desc: String)

private fun MethodNode.key(): MethodKey = MethodKey(name, desc)

private fun selectFlowPlans(classNode: ClassNode, config: ControlFlowConfig): List<FlowEdgeInjection> {
    val selected = mutableListOf<FlowEdgeInjection>()
    val skipped = mutableListOf<String>()
    var safeEdgeCount = 0
    val ratio = when (config.branchInjection) {
        "light" -> 0.25
        "normal" -> 0.50
        "aggressive" -> 0.75
        else -> 0.0
    }
    val rng = config.seed?.let(::Random) ?: Random()
    for (method in classNode.methods) {
        val analysis = analyzeSafeFlowEdges(classNode.name, method)
        if (analysis.skipReason != null) {
            skipped += "${method.name}${method.desc}: ${analysis.skipReason}"
        }
        safeEdgeCount += analysis.edges.size
        val methodCount = (analysis.edges.size * ratio).toInt().coerceAtMost(MAX_INJECTED_FLOW_EDGES)
        if (methodCount == 0) continue

        val methodEdges = analysis.edges.toMutableList()
        Collections.shuffle(methodEdges, rng)
        selected += methodEdges.take(methodCount)
    }

    if (safeEdgeCount == 0) {
        logSkipped("branchInjection=${config.branchInjection}; no analyzer-safe GOTO edges", skipped)
        return emptyList()
    }
    if (selected.isEmpty()) {
        logSkipped("branchInjection=${config.branchInjection}; level cap selected zero of $safeEdgeCount safe edges", emptyList())
        return emptyList()
    }
    return selected
}

private data class SafeFlowAnalysis(
    val edges: List<FlowEdgeInjection>,
    val skipReason: String? = null,
)

/**
 * BasicInterpreter frames make the edge selection independent of incidental
 * instruction layout. The additional structural exclusions deliberately keep
 * the transform away from JVM areas whose verifier state is expensive to
 * preserve (monitors, constructors/uninitialized objects, switches, handlers).
 */
private fun analyzeSafeFlowEdges(owner: String, method: MethodNode): SafeFlowAnalysis {
    if (method.name == "<clinit>" || method.name == "<init>") return SafeFlowAnalysis(emptyList(), "initializer")
    if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) return SafeFlowAnalysis(emptyList(), "abstract or native")
    if (method.instructions.size() < 2) return SafeFlowAnalysis(emptyList(), "too small")
    if (method.tryCatchBlocks.isNotEmpty()) return SafeFlowAnalysis(emptyList(), "exception handlers")

    val instructions = method.instructions.toArray()
    val unsafeOpcode = instructions.firstOrNull { instruction ->
        instruction.opcode == Opcodes.MONITORENTER ||
            instruction.opcode == Opcodes.MONITOREXIT ||
            instruction.opcode == Opcodes.NEW ||
            instruction.opcode == Opcodes.JSR ||
            instruction.opcode == Opcodes.RET ||
            instruction is TableSwitchInsnNode ||
            instruction is LookupSwitchInsnNode
    }
    if (unsafeOpcode != null) return SafeFlowAnalysis(emptyList(), "unsupported opcode ${unsafeOpcode.opcode}")

    val frames = try {
        Analyzer(BasicInterpreter()).analyze(owner, method)
    } catch (error: Exception) {
        return SafeFlowAnalysis(emptyList(), "frame analysis failed: ${error.javaClass.simpleName}")
    }
    val indices = instructions.withIndex().associate { (index, instruction) -> instruction to index }
    val safeEdges = instructions.mapNotNull { instruction ->
        val jump = instruction as? JumpInsnNode ?: return@mapNotNull null
        if (jump.opcode != Opcodes.GOTO) return@mapNotNull null
        val sourceIndex = indices[jump] ?: return@mapNotNull null
        val targetIndex = indices[jump.label] ?: return@mapNotNull null
        val sourceFrame = frames[sourceIndex] ?: return@mapNotNull null
        val targetFrame = frames[targetIndex] ?: return@mapNotNull null
        if (sourceFrame.stackSize != 0 || targetFrame.stackSize != 0) return@mapNotNull null
        FlowEdgeInjection(method, jump)
    }
    return if (safeEdges.isEmpty()) {
        SafeFlowAnalysis(emptyList(), "no empty-stack GOTO edges")
    } else {
        SafeFlowAnalysis(safeEdges)
    }
}

private fun selectHandlerSplitPlans(classNode: ClassNode, handlerSplit: String): List<HandlerSplitPlan> {
    val candidates = mutableListOf<HandlerSplitPlan>()
    val skipped = mutableListOf<String>()
    for (method in classNode.methods) {
        val result = analyzeHandlerSplit(classNode.name, method)
        if (result.plan != null) {
            candidates += result.plan
        } else if (result.skipReason != null) {
            skipped += "${method.name}${method.desc}: ${result.skipReason}"
        }
    }
    if (candidates.isEmpty()) {
        logSkipped("handlerSplit=$handlerSplit; no simple typed rethrow handler", skipped)
        return emptyList()
    }
    return when (handlerSplit) {
        "light" -> candidates.take(1)
        "heavy" -> candidates.take(MAX_HEAVY_HANDLER_SPLITS)
        else -> emptyList()
    }
}

private data class HandlerSplitAnalysis(
    val plan: HandlerSplitPlan? = null,
    val skipReason: String? = null,
)

private fun analyzeHandlerSplit(owner: String, method: MethodNode): HandlerSplitAnalysis {
    if (method.name == "<clinit>" || method.name == "<init>") return HandlerSplitAnalysis(skipReason = "initializer")
    if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) return HandlerSplitAnalysis(skipReason = "abstract or native")
    if (method.tryCatchBlocks.size != 1) return HandlerSplitAnalysis(skipReason = "requires one handler")
    if (method.instructions.size() < 4) return HandlerSplitAnalysis(skipReason = "too small")

    val protectedRange = method.tryCatchBlocks.single()
    if (protectedRange.type == null) return HandlerSplitAnalysis(skipReason = "catch-all handler")

    val instructions = method.instructions.toArray()
    if (instructions.any { it.opcode == Opcodes.MONITORENTER || it.opcode == Opcodes.MONITOREXIT || it is TableSwitchInsnNode || it is LookupSwitchInsnNode || it.opcode == Opcodes.JSR || it.opcode == Opcodes.RET }) {
        return HandlerSplitAnalysis(skipReason = "complex control instruction")
    }
    if (instructions.any { it is JumpInsnNode }) return HandlerSplitAnalysis(skipReason = "branching method")

    val handlerIndex = instructions.indexOf(protectedRange.handler)
    val startIndex = instructions.indexOf(protectedRange.start)
    val endIndex = instructions.indexOf(protectedRange.end)
    // ASM may retain consecutive end/handler labels at the same instruction
    // index. That is a valid exception-table boundary; only a handler that
    // starts before the protected range ends is unsafe.
    if (startIndex !in 0..<endIndex || handlerIndex < endIndex) return HandlerSplitAnalysis(skipReason = "invalid protected range")

    val handlerInstructions = instructions.drop(handlerIndex + 1).filter { it.opcode >= 0 && it.opcode != Opcodes.NOP }
    if (handlerInstructions.size != 3) return HandlerSplitAnalysis(skipReason = "handler is not a pure relay")
    val store = handlerInstructions[0] as? VarInsnNode ?: return HandlerSplitAnalysis(skipReason = "handler does not store Throwable")
    val load = handlerInstructions[1] as? VarInsnNode ?: return HandlerSplitAnalysis(skipReason = "handler does not reload Throwable")
    if (store.opcode != Opcodes.ASTORE || load.opcode != Opcodes.ALOAD || store.`var` != load.`var` || handlerInstructions[2].opcode != Opcodes.ATHROW) {
        return HandlerSplitAnalysis(skipReason = "handler is not a pure rethrow")
    }

    val frames = try {
        Analyzer(BasicInterpreter()).analyze(owner, method)
    } catch (error: Exception) {
        return HandlerSplitAnalysis(skipReason = "frame analysis failed: ${error.javaClass.simpleName}")
    }
    val splitBefore = instructions.withIndex().lastOrNull { (index, instruction) ->
        index in (startIndex + 1) until endIndex &&
            instruction.opcode == Opcodes.ATHROW &&
            frames[index]?.let { frame ->
                frame.stackSize == 1 && frame.getStack(0) == BasicValue.REFERENCE_VALUE
            } == true
    }?.value ?: return HandlerSplitAnalysis(skipReason = "no verified throwable split in protected range")

    return HandlerSplitAnalysis(HandlerSplitPlan(method, protectedRange, splitBefore, method.maxLocals))
}

private fun nextStateFieldName(classNode: ClassNode): String {
    var suffix = 0
    while (true) {
        val candidate = if (suffix == 0) EDGE_STATE_FIELD_PREFIX else "${EDGE_STATE_FIELD_PREFIX}_$suffix"
        if (classNode.fields.none { it.name == candidate }) return candidate
        suffix++
    }
}

private fun writeAndVerifyEdgeInjection(
    reader: ClassReader,
    classNode: ClassNode,
    changedMethods: Set<MethodKey>,
): ByteArray = try {
    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    val transformed = writer.toByteArray()
    verifyChangedMethods(classNode.name, transformed, changedMethods)
    transformed
} catch (error: Exception) {
    throw IllegalStateException("Edge-injection frame recomputation or verification failed for ${classNode.name}", error)
}

private fun verifyChangedMethods(owner: String, classBytes: ByteArray, changedMethods: Set<MethodKey>) {
    val classNode = ClassNode()
    ClassReader(classBytes).accept(classNode, ClassReader.EXPAND_FRAMES)
    for (method in classNode.methods) {
        if (method.key() !in changedMethods) continue
        Analyzer<BasicValue>(BasicInterpreter()).analyze(owner, method)
    }
}

private fun logSkipped(summary: String, details: List<String>) {
    val suffix = details.take(3).joinToString("; ")
    if (suffix.isEmpty()) {
        edgeInjectionLogger.warning("Edge injection skipped: $summary")
    } else {
        edgeInjectionLogger.warning("Edge injection skipped: $summary; $suffix")
    }
}
