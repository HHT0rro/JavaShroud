package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.TryCatchBlockNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.Random

/**
 * Finally depth-bomb transform.
 *
 * Wraps method bodies in N layers of try-finally blocks.  Each finally
 * body contains an INVOKEDYNAMIC void no-op call backed by a synthetic
 * BSM that decompilers cannot resolve.  The JVM duplicates the finally
 * body at every exit point (JVMS 3.13), so with N layers the INVOKEDYNAMIC
 * call is duplicated 2^N times, causing exponential decompiler output
 * growth and INVOKEDYNAMIC resolution failures.
 *
 * Attack model: static decompilation (exponential output +
 * INVOKEDYNAMIC resolution failure in CFR/Procyon/FernFlower/JADX).
 */
fun applyFinallyDepthBomb(classBytes: ByteArray, depth: Int = 3, seed: Long? = null): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) return classBytes

    val safeDepth = depth.coerceIn(2, 4)
    val rng = if (seed != null) Random(seed) else Random()
    var changed = false
    val className = classNode.name

    // Create void no-op helper: private static synthetic void \$_f_nop() { return; }
    val helperName = HelperNameGenerator.generateReservedHelperMethodName(className, "finally_nop")
    val helper = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        helperName, "()V", null, null
    )
    helper.instructions = InsnList().apply {
        add(InsnNode(Opcodes.RETURN))
    }
    helper.maxLocals = 0
    helper.maxStack = 0
    classNode.methods.add(helper)

    // Create BSM
    val bsmName = HelperNameGenerator.generateReservedHelperMethodName(className, "finally_bsm")
    val bsmDesc = "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
    val bsm = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        bsmName, bsmDesc, null, null
    )
    // Use LDC Handle so ClassRemapper can track class/method renames
    val helperHandle = Handle(
        Opcodes.H_INVOKESTATIC, className, helperName, "()V", false,
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

    for (method in classNode.methods) {
        if (method === helper || method === bsm) continue
        if (method.name == "<clinit>" || method.name == "<init>") continue
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        val insns = method.instructions ?: continue
        if (insns.size() < 6) continue

        val firstReal = findFirstRealFinally(insns) ?: continue
        val lastReal = findLastRealFinally(insns) ?: continue

        if (method.tryCatchBlocks == null) method.tryCatchBlocks = mutableListOf()

        val layerLabels = mutableListOf<Pair<LabelNode, LabelNode>>() // (tryStart, handlerLabel)
        for (layer in 0 until safeDepth) {
            val tryStart = LabelNode()
            val handlerLabel = LabelNode()
            layerLabels.add(tryStart to handlerLabel)
        }

        // Insert tryStart labels before first real instruction (innermost first)
        for ((tryStart, _) in layerLabels.reversed()) {
            insns.insertBefore(firstReal, InsnList().apply { add(tryStart) })
        }

        // Insert handler bodies at method end
        for ((idx, pair) in layerLabels.withIndex()) {
            val (tryStart, handlerLabel) = pair
            val tryEnd = LabelNode()

            val handlerBody = InsnList()
            handlerBody.add(handlerLabel)
            // Finally body: INVOKEDYNAMIC void no-op (decompiler can't resolve)
            handlerBody.add(InvokeDynamicInsnNode(
                helperName, "()V", bsmHandle,
            ))
            // Re-throw the caught exception (finally pattern)
            handlerBody.add(InsnNode(Opcodes.ATHROW))

            insns.add(handlerBody)

            method.tryCatchBlocks.add(TryCatchBlockNode(
                tryStart, tryEnd, handlerLabel, "java/lang/Throwable",
            ))

            insns.insertBefore(handlerLabel, InsnList().apply { add(tryEnd) })
        }

        changed = true
    }

    if (!changed) return classBytes

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun findFirstRealFinally(insns: InsnList): AbstractInsnNode? {
    for (insn in insns) {
        if (insn.opcode == -1) continue
        return insn
    }
    return null
}

private fun findLastRealFinally(insns: InsnList): AbstractInsnNode? {
    var last: AbstractInsnNode? = null
    for (insn in insns) {
        if (insn.opcode != -1) last = insn
    }
    return last
}
