package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import org.objectweb.asm.tree.analysis.Analyzer
import org.objectweb.asm.tree.analysis.BasicInterpreter
import org.objectweb.asm.tree.analysis.BasicValue

/**
 * Exception Semantic Virtualization transform.
 *
 * Eligible straight-line methods keep a single copy of their body and resume
 * through an exception-driven continuation: the catch handler only reads the
 * next block id. Methods that cannot be split without cloning are skipped.
 */
fun applyExceptionSemanticVirtualization(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "exception-semantic-virtualization")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val virtualizationLevel = (params["virtualizationLevel"] as? String) ?: "selective"
    val supportedVirtualizationLevels = setOf("selective", "aggressive")
    require(virtualizationLevel in supportedVirtualizationLevels) {
        "exception-semantic-virtualization virtualizationLevel '$virtualizationLevel' is not supported; supported values: ${supportedVirtualizationLevels.joinToString(", ", "")}" }

    val flowControlExceptionOriginalOwner = "io/github/hht0rro/javashroud/transforms/protection/FlowControlException"
    val flowControlExceptionOwner = sealedRuntimeHelperInternalName(flowControlExceptionOriginalOwner)
    val flowStateAccessorName = sealedRuntimeHelperMethodName(flowControlExceptionOriginalOwner, "getState", "()I")
    val reflectionObservedClasses = reflectionObservedClassNames(artifact)

    var classCount = 0
    var methodCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact
        if (classArtifact.summary.internalName in reflectionObservedClasses) return@map classArtifact

        val classNode = ClassNode()
        try {
            ClassReader(classArtifact.bytes).accept(classNode, ClassReader.EXPAND_FRAMES)
        } catch (_: Exception) {
            return@map classArtifact
        }

        val originalMethods = classNode.methods.toList()
        var classModified = false
        var methodIndex = 0
        for (method in originalMethods) {
            if (!shouldExceptionVirtualize(classNode, method, virtualizationLevel, methodIndex++)) continue
            if (!rewriteAsExceptionContinuation(classNode.name, method, flowControlExceptionOwner, flowStateAccessorName)) continue
            classModified = true
            methodCount++
        }

        if (!classModified) return@map classArtifact
        val rewrittenBytes = try {
            val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
            classNode.accept(cw)
            cw.toByteArray()
        } catch (_: Exception) {
            return@map classArtifact
        }
        classCount++
        reanalyzedClassArtifact(classArtifact, rewrittenBytes)
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(artifact, updatedClassArtifacts, classCount, methodCount)
}

private fun shouldExceptionVirtualize(classNode: ClassNode, method: MethodNode, level: String, methodIndex: Int): Boolean {
    if (level == "selective" && methodIndex % 3 != 0) return false
    if (method.name == "<init>" || method.name == "<clinit>") return false
    if (method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE or Opcodes.ACC_SYNCHRONIZED or Opcodes.ACC_SYNTHETIC) != 0) return false
    if (method.instructions == null || method.instructions.size() == 0) return false
    if (method.tryCatchBlocks?.isNotEmpty() == true) return false
    for (insn in method.instructions.toArray()) {
        when (insn) {
            is JumpInsnNode, is TableSwitchInsnNode, is LookupSwitchInsnNode, is InvokeDynamicInsnNode -> return false
            is LabelNode -> continue
            is InsnNode -> if (insn.opcode == Opcodes.MONITORENTER || insn.opcode == Opcodes.MONITOREXIT) return false
            is MethodInsnNode -> {
                if (insn.owner.startsWith("io/github/hht0rro/javashroud/transforms/protection/")) return false
                if (isStackTraceIntrospectionCall(insn) || isReflectionExecutionCall(insn)) return false
            }
            is FieldInsnNode -> if (insn.owner == classNode.name && insn.name.startsWith("\$jsv\$")) return false
        }
        if (insn.opcode == Opcodes.JSR || insn.opcode == Opcodes.RET) return false
    }
    return true
}

private fun reflectionObservedClassNames(artifact: BytecodeArtifact): Set<String> {
    val observed = linkedSetOf<String>()
    for (classArtifact in artifact.classArtifacts) {
        val classNode = ClassNode()
        try {
            ClassReader(classArtifact.bytes).accept(classNode, ClassReader.SKIP_FRAMES)
        } catch (_: Exception) {
            continue
        }
        for (method in classNode.methods) {
            val instructions = method.instructions?.toArray().orEmpty()
            val observesMembers = instructions.any { insn ->
                insn is MethodInsnNode &&
                    insn.owner == "java/lang/Class" &&
                    isMemberLookupCall(insn.name)
            }
            if (!observesMembers) continue
            instructions.filterIsInstance<LdcInsnNode>().forEach { insn ->
                val type = insn.cst as? Type ?: return@forEach
                if (type.sort == Type.OBJECT) observed += type.internalName
            }
        }
    }
    return observed
}

private fun isMemberLookupCall(name: String): Boolean =
    name in setOf(
        "getMethods",
        "getDeclaredMethods",
        "getMethod",
        "getDeclaredMethod",
        "getFields",
        "getDeclaredFields",
        "getField",
        "getDeclaredField",
        "getConstructors",
        "getDeclaredConstructors",
        "getConstructor",
        "getDeclaredConstructor",
    )

private fun isStackTraceIntrospectionCall(insn: MethodInsnNode): Boolean =
    (insn.owner == "java/lang/Throwable" && insn.name == "getStackTrace") ||
        insn.owner == "java/lang/StackTraceElement"

private fun isReflectionExecutionCall(insn: MethodInsnNode): Boolean =
    (insn.owner == "java/lang/reflect/Method" && insn.name == "invoke") ||
        (insn.owner == "java/lang/reflect/Constructor" && insn.name == "newInstance")

private fun rewriteAsExceptionContinuation(
    owner: String,
    method: MethodNode,
    flowControlExceptionOwner: String,
    flowStateAccessorName: String,
): Boolean {
    val blocks = splitStraightLineBlocks(owner, method) ?: return false
    val clones = blocks.map { block -> block.map { insn -> insn.clone(emptyMap()) } }
    val argsSize = Type.getArgumentsAndReturnSizes(method.desc) shr 2
    val stateSlot = method.maxLocals.coerceAtLeast(argsSize)
    val exSlot = stateSlot + 1
    method.maxLocals = exSlot + 1
    method.instructions.clear()
    method.tryCatchBlocks.clear()
    method.localVariables?.clear()

    val loop = Label()
    val tryStart = Label()
    val tryEnd = Label()
    val handler = Label()
    val blockLabels = Array(clones.size) { Label() }
    method.visitCode()
    method.visitInsn(Opcodes.ICONST_0)
    method.visitVarInsn(Opcodes.ISTORE, stateSlot)
    method.visitLabel(loop)
    method.visitVarInsn(Opcodes.ILOAD, stateSlot)
    if (clones.size == 1) {
        method.visitInsn(Opcodes.ICONST_1)
        method.visitJumpInsn(Opcodes.IF_ICMPEQ, blockLabels[0])
    } else {
        method.visitTableSwitchInsn(1, clones.size, tryStart, *blockLabels)
    }
    method.visitLabel(tryStart)
    emitThrowFlowControl(method, flowControlExceptionOwner, 1)
    clones.forEachIndexed { index, insns ->
        method.visitLabel(blockLabels[index])
        insns.forEach { method.instructions.add(it) }
        if (index != clones.lastIndex) {
            emitInt(method, index + 2)
            method.visitVarInsn(Opcodes.ISTORE, stateSlot)
            emitThrowFlowControl(method, flowControlExceptionOwner, index + 2)
        }
    }
    method.visitLabel(tryEnd)
    method.visitLabel(handler)
    method.visitVarInsn(Opcodes.ASTORE, exSlot)
    method.visitVarInsn(Opcodes.ALOAD, exSlot)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, flowControlExceptionOwner, flowStateAccessorName, "()I", false)
    method.visitVarInsn(Opcodes.ISTORE, stateSlot)
    method.visitJumpInsn(Opcodes.GOTO, loop)
    method.visitTryCatchBlock(tryStart, tryEnd, handler, flowControlExceptionOwner)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return true
}

private fun splitStraightLineBlocks(owner: String, method: MethodNode): List<List<AbstractInsnNode>>? {
    val real = method.instructions.toArray().filter { it.opcode >= 0 }
    if (real.size < 2) return null
    val frames = try {
        Analyzer<BasicValue>(BasicInterpreter()).analyze(owner, method)
    } catch (_: Exception) {
        return listOf(real)
    }
    val all = method.instructions.toArray()
    val splitAfter = hashSetOf<AbstractInsnNode>()
    for (index in all.indices) {
        val insn = all[index]
        if (insn.opcode < 0 || isReturnOrThrow(insn.opcode)) continue
        val next = frames.getOrNull(index + 1) ?: continue
        if (next.stackSize == 0) splitAfter += insn
    }
    val blocks = mutableListOf<MutableList<AbstractInsnNode>>()
    var current = mutableListOf<AbstractInsnNode>()
    for (insn in real) {
        current.add(insn)
        if (insn in splitAfter) {
            blocks += current
            current = mutableListOf()
        }
    }
    if (current.isNotEmpty()) blocks += current
    return blocks.filter { it.isNotEmpty() }.ifEmpty { null }
}

private fun isReturnOrThrow(opcode: Int): Boolean = opcode in Opcodes.IRETURN..Opcodes.RETURN || opcode == Opcodes.ATHROW

private fun emitThrowFlowControl(method: MethodNode, owner: String, state: Int) {
    method.visitTypeInsn(Opcodes.NEW, owner)
    method.visitInsn(Opcodes.DUP)
    emitInt(method, state)
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, owner, "<init>", "(I)V", false)
    method.visitInsn(Opcodes.ATHROW)
}

private fun emitInt(method: MethodNode, value: Int) {
    when (value) {
        in 0..5 -> method.visitInsn(Opcodes.ICONST_0 + value)
        in Byte.MIN_VALUE..Byte.MAX_VALUE -> method.visitIntInsn(Opcodes.BIPUSH, value)
        else -> method.visitLdcInsn(value)
    }
}
