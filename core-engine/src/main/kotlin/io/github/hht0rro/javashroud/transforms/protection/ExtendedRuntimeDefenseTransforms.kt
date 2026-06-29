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
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import java.security.SecureRandom

/**
 * Exception Semantic Virtualization transform.
 *
 * Eligible methods are rewritten into an exception-driven two-state dispatcher:
 * state 0 throws FlowControlException(1), the catch handler records the next
 * state, and state 1 invokes a synthetic handler containing the original body.
 * Methods with unstable frame/control-flow shapes are skipped fail-safe.
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
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()

    val flowControlExceptionOwner = sealedRuntimeHelperInternalName("io/github/hht0rro/javashroud/transforms/protection/FlowControlException")
    val flowStateFieldName = "state"

    var classCount = 0
    var methodCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact

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
            val handlerName = "\$jsv\$" + method.name.replace('<', '_').replace('>', '_') + "\$" + Integer.toHexString(random.nextInt())
            val handler = cloneAsExceptionVirtualizationHandler(method, handlerName)
            classNode.methods.add(handler)
            rewriteAsExceptionStateDispatcher(classNode.name, method, handlerName, flowControlExceptionOwner, flowStateFieldName)
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
    if (method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE or Opcodes.ACC_SYNCHRONIZED) != 0) return false
    if (method.instructions == null || method.instructions.size() == 0) return false
    if (method.tryCatchBlocks?.isNotEmpty() == true) return false
    for (insn in method.instructions.toArray()) {
        when (insn) {
            is JumpInsnNode, is TableSwitchInsnNode, is LookupSwitchInsnNode, is InvokeDynamicInsnNode -> return false
            is LabelNode -> continue
            is InsnNode -> if (insn.opcode == Opcodes.MONITORENTER || insn.opcode == Opcodes.MONITOREXIT) return false
            is MethodInsnNode -> if (insn.owner.startsWith("io/github/hht0rro/javashroud/transforms/protection/")) return false
            is FieldInsnNode -> if (insn.owner == classNode.name && insn.name.startsWith("\$jsv\$")) return false
        }
        if (insn.opcode == Opcodes.JSR || insn.opcode == Opcodes.RET) return false
    }
    return true
}

private fun cloneAsExceptionVirtualizationHandler(method: MethodNode, handlerName: String): MethodNode {
    val handlerAccess = (method.access or Opcodes.ACC_PRIVATE or Opcodes.ACC_SYNTHETIC) and Opcodes.ACC_PUBLIC.inv() and Opcodes.ACC_PROTECTED.inv()
    val handler = MethodNode(Opcodes.ASM9, handlerAccess, handlerName, method.desc, method.signature, method.exceptions?.toTypedArray())
    method.accept(handler)
    return handler
}

private fun rewriteAsExceptionStateDispatcher(
    owner: String,
    method: MethodNode,
    handlerName: String,
    flowControlExceptionOwner: String,
    flowStateFieldName: String,
) {
    val isStatic = method.access and Opcodes.ACC_STATIC != 0
    val argumentTypes = Type.getArgumentTypes(method.desc)
    val returnType = Type.getReturnType(method.desc)
    method.instructions.clear()
    method.tryCatchBlocks.clear()
    method.localVariables?.clear()

    val mv = method
    mv.visitCode()
    val stateSlot = method.maxLocals.coerceAtLeast(argumentTypes.sumOf { it.size } + if (isStatic) 0 else 1)
    val exSlot = stateSlot + 1
    mv.visitInsn(Opcodes.ICONST_0)
    mv.visitVarInsn(Opcodes.ISTORE, stateSlot)

    val loop = Label()
    val stateOne = Label()
    val tryStart = Label()
    val tryEnd = Label()
    val handler = Label()
    mv.visitLabel(loop)
    mv.visitVarInsn(Opcodes.ILOAD, stateSlot)
    mv.visitInsn(Opcodes.ICONST_1)
    mv.visitJumpInsn(Opcodes.IF_ICMPEQ, stateOne)
    mv.visitLabel(tryStart)
    mv.visitTypeInsn(Opcodes.NEW, flowControlExceptionOwner)
    mv.visitInsn(Opcodes.DUP)
    mv.visitInsn(Opcodes.ICONST_1)
    mv.visitMethodInsn(Opcodes.INVOKESPECIAL, flowControlExceptionOwner, "<init>", "(I)V", false)
    mv.visitInsn(Opcodes.ATHROW)
    mv.visitLabel(tryEnd)
    mv.visitJumpInsn(Opcodes.GOTO, loop)
    mv.visitLabel(handler)
    mv.visitVarInsn(Opcodes.ASTORE, exSlot)
    mv.visitVarInsn(Opcodes.ALOAD, exSlot)
    mv.visitFieldInsn(Opcodes.GETFIELD, flowControlExceptionOwner, flowStateFieldName, "I")
    mv.visitVarInsn(Opcodes.ISTORE, stateSlot)
    mv.visitJumpInsn(Opcodes.GOTO, loop)
    mv.visitTryCatchBlock(tryStart, tryEnd, handler, flowControlExceptionOwner)

    mv.visitLabel(stateOne)
    emitLoadReceiverAndArgs(mv, isStatic, argumentTypes)
    mv.visitMethodInsn(if (isStatic) Opcodes.INVOKESTATIC else Opcodes.INVOKESPECIAL, owner, handlerName, method.desc, false)
    mv.visitInsn(returnOpcode(returnType))
    mv.visitMaxs(0, 0)
    mv.visitEnd()
}

private fun emitLoadReceiverAndArgs(mv: MethodNode, isStatic: Boolean, argumentTypes: Array<Type>) {
    var slot = 0
    if (!isStatic) {
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        slot = 1
    }
    for (type in argumentTypes) {
        mv.visitVarInsn(loadOpcode(type), slot)
        slot += type.size
    }
}

private fun loadOpcode(type: Type): Int = when (type.sort) {
    Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> Opcodes.ILOAD
    Type.LONG -> Opcodes.LLOAD
    Type.FLOAT -> Opcodes.FLOAD
    Type.DOUBLE -> Opcodes.DLOAD
    else -> Opcodes.ALOAD
}

private fun returnOpcode(type: Type): Int = when (type.sort) {
    Type.VOID -> Opcodes.RETURN
    Type.LONG -> Opcodes.LRETURN
    Type.FLOAT -> Opcodes.FRETURN
    Type.DOUBLE -> Opcodes.DRETURN
    Type.ARRAY, Type.OBJECT -> Opcodes.ARETURN
    else -> Opcodes.IRETURN
}
