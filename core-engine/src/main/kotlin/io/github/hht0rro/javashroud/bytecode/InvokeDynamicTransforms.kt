package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode

/**
 * InvokeDynamic indirection transform.
 *
 * Replaces selected INVOKESTATIC calls with INVOKEDYNAMIC calls routed
 * through a per-class bootstrap method. The bootstrap method returns a
 * [java.lang.invoke.ConstantCallSite] backed by a target handle that is
 * encoded as a bootstrap argument, so later remapping passes can safely
 * update class and method names.
 *
 * Uses Tree API + [computeFramesWriter] for safe frame recomputation.
 */
fun indirectMethodCalls(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }
    if (isClassLoadingBoundarySensitive(classNode)) {
        return classBytes
    }

    data class CallTarget(val owner: String, val name: String, val desc: String, val isInterface: Boolean)
    val targets = mutableSetOf<CallTarget>()
    val callSites = mutableListOf<Triple<MethodNode, MethodInsnNode, CallTarget>>()

    for (method in classNode.methods) {
        if (method.name == "<clinit>") continue
        val insns = method.instructions ?: continue
        for (insn in insns.toArray()) {
            if (insn is MethodInsnNode && insn.opcode == Opcodes.INVOKESTATIC) {
                if (insn.name == "<clinit>" || insn.name == "<init>") continue
                if (insn.owner == classNode.name) continue
                if (insn.owner == "java/lang/invoke/LambdaMetafactory") continue
                val target = CallTarget(insn.owner, insn.name, insn.desc, insn.itf)
                targets.add(target)
                callSites.add(Triple(method, insn, target))
            }
        }
    }

    if (targets.isEmpty()) {
        return classBytes
    }

    val bootstrapMap = mutableMapOf<CallTarget, String>()
    var bootstrapIndex = 0
    val bsmDesc = "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;"

    for (target in targets) {
        val bsmName = "a_bsm$bootstrapIndex"
        bootstrapIndex++

        val bsmMethod = MethodNode(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            bsmName,
            bsmDesc,
            null,
            null,
        )

        val body = InsnList()
        body.add(VarInsnNode(Opcodes.ALOAD, 3))
        body.add(TypeInsnNode(Opcodes.NEW, "java/lang/invoke/ConstantCallSite"))
        body.add(InsnNode(Opcodes.DUP_X1))
        body.add(InsnNode(Opcodes.SWAP))
        body.add(MethodInsnNode(
            Opcodes.INVOKESPECIAL,
            "java/lang/invoke/ConstantCallSite",
            "<init>",
            "(Ljava/lang/invoke/MethodHandle;)V",
            false,
        ))
        body.add(InsnNode(Opcodes.ARETURN))

        bsmMethod.instructions = body
        classNode.methods.add(bsmMethod)
        bootstrapMap[target] = bsmName
    }

    for ((method, callInsn, target) in callSites) {
        val bsmName = bootstrapMap[target] ?: continue
        val indyInsn = InvokeDynamicInsnNode(
            target.name,
            target.desc,
            Handle(
                Opcodes.H_INVOKESTATIC,
                classNode.name,
                bsmName,
                bsmDesc,
                false,
            ),
            Handle(
                Opcodes.H_INVOKESTATIC,
                target.owner,
                target.name,
                target.desc,
                target.isInterface,
            ),
        )
        method.instructions.insertBefore(callInsn, indyInsn)
        method.instructions.remove(callInsn)
    }

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun isClassLoadingBoundarySensitive(classNode: ClassNode): Boolean {
    if (classNode.superName == "java/lang/ClassLoader" || classNode.superName?.endsWith("ClassLoader") == true) return true
    for (method in classNode.methods) {
        val instructions = method.instructions ?: continue
        for (instruction in instructions) {
            if (instruction is MethodInsnNode && isClassLoadingBoundaryCall(instruction)) return true
        }
    }
    return false
}

private fun isClassLoadingBoundaryCall(call: MethodInsnNode): Boolean {
    if (call.name == "defineClass") return true
    if (call.owner == "java/lang/ClassLoader" && call.name in setOf("loadClass", "findClass", "getResource", "getResourceAsStream")) return true
    if (call.owner == "java/lang/Class" && call.name in setOf("forName", "getClassLoader", "getResource", "getResourceAsStream", "newInstance")) return true
    if (call.owner == "java/lang/reflect/Method" && call.name == "invoke") return true
    if (call.owner == "java/lang/reflect/Constructor" && call.name == "newInstance") return true
    return false
}
