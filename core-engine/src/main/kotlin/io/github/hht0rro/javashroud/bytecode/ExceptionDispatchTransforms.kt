package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TryCatchBlockNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.Random

/**
 * Exception dispatch logic transform.
 *
 * Inserts dead exception-dispatch blocks guarded by always-false
 * opaque predicates.  Each block contains a call to a SYNTHETIC
 * helper method that holds a try-catch where the try body throws a
 * RuntimeException and the handler performs field-based dispatch
 * logic then re-throws the exception.
 *
 * Isolating the try-catch in a separate synthetic method avoids
 * VerifyError from COMPUTE_FRAMES when the target method already
 * has its own try-catch blocks (nested handler frame merge conflict).
 *
 * Attack model: static CFG reconstruction.
 */
fun applyExceptionDispatch(classBytes: ByteArray, seed: Long? = null): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) return classBytes

    val rng = if (seed != null) Random(seed) else Random()
    var changed = false

    val className = classNode.name
    val fieldName = "\$_j_exd"

    classNode.fields.add(FieldNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        fieldName, "I", null, 0,
    ))

    // Build a SYNTHETIC helper method that contains the try-catch dispatch logic.
    // Keeping the try-catch in its own method prevents frame-merge conflicts
    // with existing try-catch blocks in the target methods.
    val helperName = "\$_exdisp_" + rng.nextInt(100000)
    val helper = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        helperName, "()V", null, null
    )

    val tryStart = LabelNode()
    val tryEnd = LabelNode()
    val handlerEntry = LabelNode()
    val skipLabel = LabelNode()

    val helperInsns = InsnList()
    // --- try body: throw a RuntimeException ---
    helperInsns.add(tryStart)
    helperInsns.add(InsnNode(Opcodes.ICONST_0))
    helperInsns.add(FieldInsnNode(Opcodes.PUTSTATIC, className, fieldName, "I"))
    helperInsns.add(TypeInsnNode(Opcodes.NEW, "java/lang/RuntimeException"))
    helperInsns.add(InsnNode(Opcodes.DUP))
    helperInsns.add(MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false))
    helperInsns.add(InsnNode(Opcodes.ATHROW))
    helperInsns.add(tryEnd)
    // --- handler: field-based dispatch, then re-throw ---
    helperInsns.add(handlerEntry)
    helperInsns.add(VarInsnNode(Opcodes.ASTORE, 0))            // save Throwable to slot 0
    helperInsns.add(FieldInsnNode(Opcodes.GETSTATIC, className, fieldName, "I"))
    helperInsns.add(InsnNode(Opcodes.ICONST_1))
    helperInsns.add(JumpInsnNode(Opcodes.IF_ICMPNE, skipLabel)) // if field != 1, skip
    helperInsns.add(InsnNode(Opcodes.ICONST_0))
    helperInsns.add(FieldInsnNode(Opcodes.PUTSTATIC, className, fieldName, "I"))
    helperInsns.add(skipLabel)
    helperInsns.add(InsnNode(Opcodes.ICONST_1))
    helperInsns.add(FieldInsnNode(Opcodes.PUTSTATIC, className, fieldName, "I"))
    helperInsns.add(VarInsnNode(Opcodes.ALOAD, 0))
    helperInsns.add(InsnNode(Opcodes.ATHROW))                   // re-throw

    helper.instructions = helperInsns
    helper.tryCatchBlocks = mutableListOf(
        TryCatchBlockNode(tryStart, tryEnd, handlerEntry, "java/lang/Throwable")
    )
    helper.maxLocals = 1   // slot 0 = Throwable
    helper.maxStack = 3    // NEW + DUP + INVOKESPECIAL
    classNode.methods.add(helper)

    // Insert dead calls to the helper in each eligible method.
    for (method in classNode.methods) {
        if (method === helper) continue
        if (method.name == "<clinit>" || method.name == "<init>") continue
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE or Opcodes.ACC_SYNTHETIC)) != 0) continue
        val insns = method.instructions ?: continue
        if (insns.size() < 8) continue

        val realInsns = insns.toArray().filter { it.opcode != -1 }
        if (realInsns.size < 6) continue

        val targetInsn = realInsns[rng.nextInt(realInsns.size)]

        val opaqueEnd = LabelNode()
        val block = InsnList()
        // Opaque predicate: ICONST_0; IFEQ always jumps -> dead code follows
        block.add(InsnNode(Opcodes.ICONST_0))
        block.add(JumpInsnNode(Opcodes.IFEQ, opaqueEnd))
        // Dead call to the helper method
        block.add(MethodInsnNode(Opcodes.INVOKESTATIC, className, helperName, "()V", false))
        block.add(opaqueEnd)

        insns.insertBefore(targetInsn, block)
        changed = true
    }

    if (!changed) return classBytes

    val writer = computeFramesWriter(reader)
    return try {
        classNode.accept(writer)
        writer.toByteArray()
    } catch (_: RuntimeException) {
        classBytes
    }
}
