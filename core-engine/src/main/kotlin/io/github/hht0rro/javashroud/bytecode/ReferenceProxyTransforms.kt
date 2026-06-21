package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode

/**
 * Reference proxy transform using a single production proxy layout.
 */
fun createReferenceProxies(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    data class CallTarget(val owner: String, val name: String, val desc: String, val isInterface: Boolean)
    val targets = mutableSetOf<CallTarget>()
    val callSites = mutableListOf<Pair<MethodNode, MethodInsnNode>>()

    for (method in classNode.methods) {
        val insns = method.instructions ?: continue
        for (insn in insns) {
            if (insn is MethodInsnNode && insn.opcode == Opcodes.INVOKESTATIC) {
                if (insn.name == "<clinit>" || insn.name == "<init>") continue
                if (insn.owner == classNode.name) continue
                if (isPlatformInvocationOwner(insn.owner)) continue
                val target = CallTarget(insn.owner, insn.name, insn.desc, insn.itf)
                targets.add(target)
                callSites.add(Pair(method, insn))
            }
        }
    }

    if (targets.isEmpty()) {
        return classBytes
    }

    val proxyMap = mutableMapOf<CallTarget, String>()
    var proxyIndex = 0

    for (target in targets) {
        val proxyName = "a_px${proxyIndex++}"
        createStaticForwarderProxy(classNode, target.owner, target.name, target.desc, target.isInterface, proxyName)
        proxyMap[target] = proxyName
    }

    for ((method, callInsn) in callSites) {
        val target = CallTarget(callInsn.owner, callInsn.name, callInsn.desc, callInsn.itf)
        val proxyName = proxyMap[target] ?: continue
        val proxyCall = MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, proxyName, callInsn.desc, false)
        method.instructions.insert(callInsn, proxyCall)
        method.instructions.remove(callInsn)
    }

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun isPlatformInvocationOwner(owner: String): Boolean =
    owner.startsWith("java/") ||
        owner.startsWith("javax/") ||
        owner.startsWith("jdk/") ||
        owner.startsWith("sun/") ||
        owner.startsWith("com/sun/")

private fun createStaticForwarderProxy(
    classNode: ClassNode,
    targetOwner: String,
    targetName: String,
    targetDesc: String,
    targetIsInterface: Boolean,
    proxyName: String,
) {
    val proxyMethod = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        proxyName, targetDesc, null, null,
    )
    val insns = InsnList()
    val argTypes = org.objectweb.asm.Type.getArgumentTypes(targetDesc)
    var slot = 0
    for (argType in argTypes) {
        insns.add(createLoadInsnProxy(argType, slot))
        slot += argType.size
    }
    insns.add(MethodInsnNode(Opcodes.INVOKESTATIC, targetOwner, targetName, targetDesc, targetIsInterface))
    val returnType = org.objectweb.asm.Type.getReturnType(targetDesc)
    insns.add(createReturnInsnProxy(returnType))
    proxyMethod.instructions = insns
    classNode.methods.add(proxyMethod)
}

private fun createLoadInsnProxy(type: org.objectweb.asm.Type, slot: Int): AbstractInsnNode {
    return when (type.sort) {
        org.objectweb.asm.Type.BOOLEAN, org.objectweb.asm.Type.BYTE,
        org.objectweb.asm.Type.CHAR, org.objectweb.asm.Type.SHORT,
        org.objectweb.asm.Type.INT -> org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, slot)
        org.objectweb.asm.Type.LONG -> org.objectweb.asm.tree.VarInsnNode(Opcodes.LLOAD, slot)
        org.objectweb.asm.Type.FLOAT -> org.objectweb.asm.tree.VarInsnNode(Opcodes.FLOAD, slot)
        org.objectweb.asm.Type.DOUBLE -> org.objectweb.asm.tree.VarInsnNode(Opcodes.DLOAD, slot)
        else -> org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, slot)
    }
}

private fun createReturnInsnProxy(type: org.objectweb.asm.Type): AbstractInsnNode {
    return when (type.sort) {
        org.objectweb.asm.Type.VOID -> InsnNode(Opcodes.RETURN)
        org.objectweb.asm.Type.BOOLEAN, org.objectweb.asm.Type.BYTE,
        org.objectweb.asm.Type.CHAR, org.objectweb.asm.Type.SHORT,
        org.objectweb.asm.Type.INT -> InsnNode(Opcodes.IRETURN)
        org.objectweb.asm.Type.LONG -> InsnNode(Opcodes.LRETURN)
        org.objectweb.asm.Type.FLOAT -> InsnNode(Opcodes.FRETURN)
        org.objectweb.asm.Type.DOUBLE -> InsnNode(Opcodes.DRETURN)
        else -> InsnNode(Opcodes.ARETURN)
    }
}
