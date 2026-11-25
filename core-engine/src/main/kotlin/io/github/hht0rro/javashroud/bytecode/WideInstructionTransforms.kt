package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.IincInsnNode
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
 * Wide instruction bloat transform.
 *
 * Inserts IINC no-op pairs AND INVOKEDYNAMIC identity calls after
 * existing ISTORE instructions.  The IINC pairs bloat bytecode and
 * the INVOKEDYNAMIC calls use a BSM that decompilers cannot resolve,
 * producing uncompilable output or semantic distortion.
 *
 * Attack model: static decompilation bytecode-level parsing +
 * INVOKEDYNAMIC resolution failure.
 */
fun applyWideInstructionBloat(classBytes: ByteArray, seed: Long? = null): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) return classBytes

    val rng = if (seed != null) Random(seed) else Random()
    var changed = false
    val className = classNode.name

    // Create identity helper: private static synthetic int \$_w_id(int x) { return x; }
    val helperName = "\$_w_id"
    val helper = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        helperName, "(I)I", null, null
    )
    helper.instructions = InsnList().apply {
        add(VarInsnNode(Opcodes.ILOAD, 0))
        add(InsnNode(Opcodes.IRETURN))
    }
    helper.maxLocals = 1
    helper.maxStack = 1
    classNode.methods.add(helper)

    // Create BSM
    val bsmName = "\$_w_bsm"
    val bsmDesc = "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
    val bsm = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        bsmName, bsmDesc, null, null
    )
    // Use LDC Handle so ClassRemapper can track class/method renames
    val helperHandle = Handle(
        Opcodes.H_INVOKESTATIC, className, helperName, "(I)I", false,
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
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE or Opcodes.ACC_SYNTHETIC or Opcodes.ACC_BRIDGE)) != 0) continue
        val insns = method.instructions ?: continue
        if (insns.size() < 4) continue

        val istores = insns.toArray()
            .filter { it.opcode == Opcodes.ISTORE }
            .filterIsInstance<VarInsnNode>()

        if (istores.isEmpty()) continue

        val toProcess = istores.shuffled(rng).take((istores.size / 3).coerceIn(1, 5))
        for (istore in toProcess) {
            val slot = istore.`var`
            val noopBlock = InsnList()
            // IINC no-op pair for bytecode bloat
            noopBlock.add(IincInsnNode(slot, 1))
            noopBlock.add(IincInsnNode(slot, -1))
            // INVOKEDYNAMIC identity call for decompiler anti-evidence
            noopBlock.add(VarInsnNode(Opcodes.ILOAD, slot))
            noopBlock.add(InvokeDynamicInsnNode(
                helperName, "(I)I", bsmHandle,
            ))
            noopBlock.add(VarInsnNode(Opcodes.ISTORE, slot))
            insns.insert(istore, noopBlock)
        }

        changed = true
    }

    if (!changed) return classBytes

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}
