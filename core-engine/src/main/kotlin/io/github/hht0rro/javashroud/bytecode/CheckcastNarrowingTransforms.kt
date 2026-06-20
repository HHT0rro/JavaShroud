package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.Random

/**
 * Checkcast type-narrowing injection transform.
 *
 * Inserts CHECKCAST to unrelated concrete types on LIVE code paths,
 * guarded by INVOKEDYNAMIC identity calls that decompilers cannot
 * resolve.  The identity BSM returns the same object reference, so
 * the CHECKCAST target type is always Object — safe at runtime.
 * Decompilers that try to resolve the INVOKEDYNAMIC will produce
 * uncompilable output or incorrect type annotations.
 *
 * Attack model: static decompilation type-inference +
 * INVOKEDYNAMIC resolution failure.
 */
fun applyCheckcastNarrowing(classBytes: ByteArray, seed: Long? = null): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) return classBytes

    val rng = if (seed != null) Random(seed) else Random()
    var changed = false
    val className = classNode.name

    // Create identity helper: private static synthetic Object \$_x_id(Object x) { return x; }
    val helperName = HelperNameGenerator.generateReservedHelperMethodName(className, "checkcast_id")
    val helper = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        helperName, "(Ljava/lang/Object;)Ljava/lang/Object;", null, null
    )
    helper.instructions = InsnList().apply {
        add(VarInsnNode(Opcodes.ALOAD, 0))
        add(InsnNode(Opcodes.ARETURN))
    }
    helper.maxLocals = 1
    helper.maxStack = 1
    classNode.methods.add(helper)

    // Create BSM
    val bsmName = HelperNameGenerator.generateReservedHelperMethodName(className, "checkcast_bsm")
    val bsmDesc = "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
    val bsm = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        bsmName, bsmDesc, null, null
    )
    // Use LDC Handle so ClassRemapper can track class/method renames
    val helperHandle = Handle(
        Opcodes.H_INVOKESTATIC, className, helperName, "(Ljava/lang/Object;)Ljava/lang/Object;", false,
    )
    val bsmBody = InsnList()
    bsmBody.add(LdcInsnNode(helperHandle))
    bsmBody.add(TypeInsnNode(Opcodes.NEW, "java/lang/invoke/ConstantCallSite"))
    bsmBody.add(InsnNode(Opcodes.DUP_X1))
    bsmBody.add(InsnNode(Opcodes.SWAP))
    bsmBody.add(MethodInsnNode(
        Opcodes.INVOKESPECIAL, "java/lang/invoke/ConstantCallSite",
        "<init>", "(Ljava/lang/invoke/MethodHandle;)V", false,
    ))
    bsmBody.add(InsnNode(Opcodes.ARETURN))
    bsm.instructions = bsmBody
    bsm.maxLocals = 3
    bsm.maxStack = 3
    classNode.methods.add(bsm)

    val bsmHandle = Handle(
        Opcodes.H_INVOKESTATIC, className, bsmName, bsmDesc, false,
    )

    val narrowingTypes = listOf(
        "java/lang/StringBuilder",
        "java/util/ArrayList",
        "java/lang/Integer",
        "java/io/ByteArrayOutputStream",
        "java/util/HashMap",
        "java/lang/Thread",
    )

    for (method in classNode.methods) {
        if (method === helper || method === bsm) continue
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        if (method.name == "<clinit>") continue
        val insns = method.instructions ?: continue
        if (insns.size() < 4) continue

        // Find ALOAD instructions as insertion points (we have an object reference)
        val aloadInsns = insns.toArray()
            .filter { it.opcode == Opcodes.ALOAD }
            .filterIsInstance<VarInsnNode>()
            .filterNot { method.name == "<init>" && it.`var` == 0 }
            .toMutableList()

        val insertionCount = (aloadInsns.size / 6).coerceAtLeast(1).coerceAtMost(3)
        val toProcess = aloadInsns.shuffled(rng).take(insertionCount)
        for (aload in toProcess) {
            val castType = narrowingTypes[rng.nextInt(narrowingTypes.size)]

            // After ALOAD n, insert: DUP, INVOKEDYNAMIC identity, CHECKCAST, POP
            // This leaves the original reference on the stack unchanged
            val poisonBlock = InsnList()
            poisonBlock.add(InsnNode(Opcodes.DUP))
            poisonBlock.add(InvokeDynamicInsnNode(
                helperName, "(Ljava/lang/Object;)Ljava/lang/Object;", bsmHandle,
            ))
            poisonBlock.add(TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Object"))
            poisonBlock.add(InsnNode(Opcodes.POP))

            insns.insert(aload, poisonBlock)
            changed = true
        }
    }

    if (!changed) return classBytes

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}
