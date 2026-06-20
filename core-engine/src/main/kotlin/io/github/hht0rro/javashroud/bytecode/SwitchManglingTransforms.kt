package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.*

/**
 * Switch mangling transform (fusion from obfuscator-master).
 *
 * Replaces TABLESWITCH and LOOKUPSWITCH instructions with equivalent
 * if-else chains, breaking decompiler switch reconstruction and
 * increasing CFG complexity.
 */
fun mangleSwitches(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    var changed = false

    for (method in classNode.methods) {
        if ((method.access and Opcodes.ACC_ABSTRACT) != 0) continue
        if ((method.access and Opcodes.ACC_NATIVE) != 0) continue
        val insns = method.instructions ?: continue

        val toReplace = mutableListOf<Pair<AbstractInsnNode, InsnList>>()

        for (insn in insns.toArray()) {
            when (insn) {
                is TableSwitchInsnNode -> {
                    val replacement = replaceTableSwitch(insn)
                    toReplace.add(insn to replacement)
                }
                is LookupSwitchInsnNode -> {
                    val replacement = replaceLookupSwitch(insn)
                    toReplace.add(insn to replacement)
                }
            }
        }

        for ((original, replacement) in toReplace) {
            insns.insertBefore(original, replacement)
            insns.remove(original)
            changed = true
        }
    }

    if (!changed) return classBytes

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun replaceTableSwitch(insn: TableSwitchInsnNode): InsnList {
    val result = InsnList()
    val endLabel = LabelNode()

    for (i in insn.min..insn.max) {
        val target = insn.labels[i - insn.min]
        val nextLabel = LabelNode()

        // DUP the switch key for comparison
        result.add(InsnNode(Opcodes.DUP))
        result.add(pushInt(i))
        result.add(JumpInsnNode(Opcodes.IF_ICMPNE, nextLabel))
        result.add(InsnNode(Opcodes.POP)) // consume the key
        result.add(JumpInsnNode(Opcodes.GOTO, target))
        result.add(nextLabel)
    }

    // Default case
    result.add(InsnNode(Opcodes.POP)) // consume the key
    result.add(JumpInsnNode(Opcodes.GOTO, insn.dflt))

    return result
}

private fun replaceLookupSwitch(insn: LookupSwitchInsnNode): InsnList {
    val result = InsnList()

    for (i in insn.keys.indices) {
        val key = insn.keys[i]
        val target = insn.labels[i]
        val nextLabel = LabelNode()

        result.add(InsnNode(Opcodes.DUP))
        result.add(pushInt(key))
        result.add(JumpInsnNode(Opcodes.IF_ICMPNE, nextLabel))
        result.add(InsnNode(Opcodes.POP))
        result.add(JumpInsnNode(Opcodes.GOTO, target))
        result.add(nextLabel)
    }

    // Default case
    result.add(InsnNode(Opcodes.POP))
    result.add(JumpInsnNode(Opcodes.GOTO, insn.dflt))

    return result
}

private fun pushInt(value: Int): AbstractInsnNode {
    return when {
        value in -1..5 -> InsnNode(Opcodes.ICONST_0 + value)
        value in Byte.MIN_VALUE..Byte.MAX_VALUE -> org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, value)
        value in Short.MIN_VALUE..Short.MAX_VALUE -> org.objectweb.asm.tree.IntInsnNode(Opcodes.SIPUSH, value)
        else -> LdcInsnNode(value)
    }
}
