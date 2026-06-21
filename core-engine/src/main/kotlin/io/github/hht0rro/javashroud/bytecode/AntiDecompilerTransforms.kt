package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode

/**
 * Anti-decompiler structure transform.
 *
 * Uses only stack-neutral dead branches to avoid emitting malformed
 * exception edges that can break ASM frame merging on real-world jars.
 */
fun insertAntiDecompilerStructures(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    var changed = false

    for (method in classNode.methods) {
        if (method.name == "<clinit>" || method.name == "<init>") continue
        if ((method.access and Opcodes.ACC_ABSTRACT) != 0) continue
        if ((method.access and Opcodes.ACC_NATIVE) != 0) continue
        if ((method.access and Opcodes.ACC_SYNTHETIC) != 0) continue
        val insns = method.instructions ?: continue
        if (insns.size() < 2) continue

        val firstReal = findFirstRealInstruction(insns) ?: continue
        val deadEnd = LabelNode()
        val deadCode = InsnList().apply {
            add(LdcInsnNode(0))
            add(JumpInsnNode(Opcodes.IFEQ, deadEnd))
            add(InsnNode(Opcodes.NOP))
            add(deadEnd)
        }
        insns.insertBefore(firstReal, deadCode)
        changed = true
    }

    if (!changed) {
        return classBytes
    }

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun findFirstRealInstruction(insns: InsnList): AbstractInsnNode? {
    for (insn in insns) {
        if (insn is LabelNode) continue
        if (insn.opcode == -1) continue
        return insn
    }
    return null
}
