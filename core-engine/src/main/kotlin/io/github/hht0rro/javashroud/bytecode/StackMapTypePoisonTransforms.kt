package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.Random

/**
 * StackMapTable type-merge ambiguity transform.
 *
 * Inserts divergent code paths that load incompatible reference types
 * into the same local variable slot, forcing the JVM verifier to
 * resolve the merged type to `java/lang/Object`. Decompilers that
 * rely on StackMapTable frame types for variable type recovery will
 * see `Object` instead of the actual types.
 *
 * Uses ACONST_NULL on both paths to avoid constructor call failures,
 * then applies CHECKCAST to different types. Both paths are
 * unreachable (guarded by always-false opaque predicates) but the
 * verifier must process the frames at the merge point.
 *
 * Attack model: static decompilation type-inference.
 */
fun applyStackMapTypePoison(classBytes: ByteArray, seed: Long? = null): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) return classBytes

    val rng = if (seed != null) Random(seed) else Random()
    var changed = false

    val poisonPairs = listOf(
        "java/lang/StringBuilder" to "java/lang/String",
        "java/lang/Integer" to "java/lang/String",
        "java/util/ArrayList" to "java/lang/StringBuilder",
    )

    for (method in classNode.methods) {
        if (method.name == "<clinit>") continue
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        val insns = method.instructions ?: continue
        if (insns.size() < 6) continue

        val realInsns = insns.toArray().filter { it.opcode != -1 }
        if (realInsns.size < 4) continue

        val insertCount = (realInsns.size / 10).coerceIn(1, 3)
        for (i in 0 until insertCount) {
            val targetInsn = realInsns[rng.nextInt(realInsns.size)]
            val poisonSlot = method.maxLocals + 20 + i
            val (typeA, typeB) = poisonPairs[rng.nextInt(poisonPairs.size)]

            val poisonBlock = InsnList()
            val branchLabel = LabelNode()
            val mergeLabel = LabelNode()

            // Opaque predicate: 0 != 0 is always false
            poisonBlock.add(InsnNode(Opcodes.ICONST_0))
            poisonBlock.add(JumpInsnNode(Opcodes.IFNE, branchLabel))
            // Path A: null cast to typeA, store to poison slot
            poisonBlock.add(InsnNode(Opcodes.ACONST_NULL))
            poisonBlock.add(org.objectweb.asm.tree.TypeInsnNode(Opcodes.CHECKCAST, typeA))
            poisonBlock.add(VarInsnNode(Opcodes.ASTORE, poisonSlot))
            poisonBlock.add(JumpInsnNode(Opcodes.GOTO, mergeLabel))
            // Path B: null cast to typeB, store to same slot
            poisonBlock.add(branchLabel)
            poisonBlock.add(InsnNode(Opcodes.ACONST_NULL))
            poisonBlock.add(org.objectweb.asm.tree.TypeInsnNode(Opcodes.CHECKCAST, typeB))
            poisonBlock.add(VarInsnNode(Opcodes.ASTORE, poisonSlot))
            poisonBlock.add(mergeLabel)
            // Pop the poison value to stay stack-neutral
            poisonBlock.add(VarInsnNode(Opcodes.ALOAD, poisonSlot))
            poisonBlock.add(InsnNode(Opcodes.POP))

            insns.insertBefore(targetInsn, poisonBlock)
        }

        method.maxLocals = method.maxLocals.coerceAtLeast(method.maxLocals + 20 + insertCount)
        changed = true
    }

    if (!changed) return classBytes

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}
