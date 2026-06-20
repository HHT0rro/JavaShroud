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
import java.util.Random

/**
 * MethodHandle combinator chain transform.
 *
 * Replaces selected INVOKESTATIC calls with INVOKEDYNAMIC backed by
 * bootstrap methods that directly receive the target [java.lang.invoke.MethodHandle]
 * as a bootstrap argument. This keeps the target reference remap-safe.
 *
 * Attack model: static analysis / symbolic execution.
 */
fun applyMethodHandleCombinatorChain(classBytes: ByteArray, seed: Long? = null): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) return classBytes

    val rng = if (seed != null) Random(seed) else Random()
    var bsmIdx = 0

    val bsmDesc = "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;"

    data class Replacement(
        val method: MethodNode,
        val callInsn: MethodInsnNode,
        val bsmName: String,
        val targetHandle: Handle,
    )

    val replacements = mutableListOf<Replacement>()
    val newBsmMethods = mutableListOf<MethodNode>()

    for (method in classNode.methods) {
        if (method.name == "<clinit>") continue
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        val insns = method.instructions ?: continue

        val callTargets = insns.toArray()
            .filterIsInstance<MethodInsnNode>()
            .filter { it.opcode == Opcodes.INVOKESTATIC }
            .filter { it.name != "<clinit>" && it.name != "<init>" }
            .filter { it.owner != classNode.name }
            .filter { it.owner != "java/lang/invoke/LambdaMetafactory" }

        val replacementCount = (callTargets.size / 5).coerceAtLeast(1).coerceAtMost(3)
        val toProcess = callTargets.shuffled(rng).take(replacementCount)
        for (callInsn in toProcess) {
            val bsmName = "\$_j_mh_$bsmIdx"
            bsmIdx++

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

            newBsmMethods.add(bsmMethod)
            replacements.add(
                Replacement(
                    method = method,
                    callInsn = callInsn,
                    bsmName = bsmName,
                    targetHandle = Handle(
                        Opcodes.H_INVOKESTATIC,
                        callInsn.owner,
                        callInsn.name,
                        callInsn.desc,
                        callInsn.itf,
                    ),
                ),
            )
        }
    }

    if (replacements.isEmpty()) return classBytes

    for ((method, callInsn, bsmName, targetHandle) in replacements) {
        val indyInsn = InvokeDynamicInsnNode(
            callInsn.name,
            callInsn.desc,
            Handle(Opcodes.H_INVOKESTATIC, classNode.name, bsmName, bsmDesc, false),
            targetHandle,
        )
        method.instructions.insertBefore(callInsn, indyInsn)
        method.instructions.remove(callInsn)
    }

    classNode.methods.addAll(newBsmMethods)

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}
