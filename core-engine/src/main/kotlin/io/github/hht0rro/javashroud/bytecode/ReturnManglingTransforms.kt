package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.*

/**
 * Return mangling transform (fusion from obfuscator-master).
 *
 * Wraps return instructions with synthetic method calls that pass through
 * the return value, breaking direct return patterns visible to decompilers.
 * For void returns, inserts NOP sequences to break return-site analysis.
 */
fun mangleReturns(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    var changed = false
    val returnMethods = mutableMapOf<String, MethodNode>()
    var methodIndex = 0

    for (method in classNode.methods) {
        if (method.name == "<clinit>" || method.name == "<init>") continue
        if ((method.access and Opcodes.ACC_ABSTRACT) != 0) continue
        if ((method.access and Opcodes.ACC_NATIVE) != 0) continue
        val insns = method.instructions ?: continue

        val toReplace = mutableListOf<Pair<AbstractInsnNode, InsnList>>()

        for (insn in insns.toArray()) {
            when (insn.opcode) {
                Opcodes.IRETURN -> {
                    val wrapperName = nextReturnWrapperName(classNode.name, "iret", methodIndex++)
                    val wrapper = createIntReturnWrapper(wrapperName)
                    returnMethods[wrapperName] = wrapper
                    val replacement = InsnList().apply {
                        add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, wrapperName, "(I)I", false))
                        add(InsnNode(Opcodes.IRETURN))
                    }
                    toReplace.add(insn to replacement)
                }
                Opcodes.LRETURN -> {
                    val wrapperName = nextReturnWrapperName(classNode.name, "lret", methodIndex++)
                    val wrapper = createLongReturnWrapper(wrapperName)
                    returnMethods[wrapperName] = wrapper
                    val replacement = InsnList().apply {
                        add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, wrapperName, "(J)J", false))
                        add(InsnNode(Opcodes.LRETURN))
                    }
                    toReplace.add(insn to replacement)
                }
                Opcodes.FRETURN -> {
                    val wrapperName = nextReturnWrapperName(classNode.name, "fret", methodIndex++)
                    val wrapper = createFloatReturnWrapper(wrapperName)
                    returnMethods[wrapperName] = wrapper
                    val replacement = InsnList().apply {
                        add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, wrapperName, "(F)F", false))
                        add(InsnNode(Opcodes.FRETURN))
                    }
                    toReplace.add(insn to replacement)
                }
                Opcodes.DRETURN -> {
                    val wrapperName = nextReturnWrapperName(classNode.name, "dret", methodIndex++)
                    val wrapper = createDoubleReturnWrapper(wrapperName)
                    returnMethods[wrapperName] = wrapper
                    val replacement = InsnList().apply {
                        add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, wrapperName, "(D)D", false))
                        add(InsnNode(Opcodes.DRETURN))
                    }
                    toReplace.add(insn to replacement)
                }
                Opcodes.ARETURN -> {
                    // Skip ARETURN wrapping - Object type wrapper causes verification errors
                    // when the actual return type is more specific (e.g., String, List)
                }
                Opcodes.RETURN -> {
                    // Void return: insert NOP noise before return
                    val noise = InsnList().apply {
                        add(InsnNode(Opcodes.NOP))
                        add(InsnNode(Opcodes.NOP))
                        add(InsnNode(Opcodes.NOP))
                    }
                    toReplace.add(insn to noise.apply { add(InsnNode(Opcodes.RETURN)) })
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

    classNode.methods.addAll(returnMethods.values)

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun createIntReturnWrapper(name: String): MethodNode {
    val m = MethodNode(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, name, "(I)I", null, null)
    m.visitCode()
    m.visitVarInsn(Opcodes.ILOAD, 0)
    m.visitInsn(Opcodes.IRETURN)
    m.visitMaxs(1, 1)
    m.visitEnd()
    return m
}

private fun nextReturnWrapperName(className: String, kind: String, index: Int): String {
    return HelperNameGenerator.generateReservedHelperMethodName(className, "return_${kind}_$index")
}

private fun createLongReturnWrapper(name: String): MethodNode {
    val m = MethodNode(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, name, "(J)J", null, null)
    m.visitCode()
    m.visitVarInsn(Opcodes.LLOAD, 0)
    m.visitInsn(Opcodes.LRETURN)
    m.visitMaxs(2, 2)
    m.visitEnd()
    return m
}

private fun createFloatReturnWrapper(name: String): MethodNode {
    val m = MethodNode(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, name, "(F)F", null, null)
    m.visitCode()
    m.visitVarInsn(Opcodes.FLOAD, 0)
    m.visitInsn(Opcodes.FRETURN)
    m.visitMaxs(1, 1)
    m.visitEnd()
    return m
}

private fun createDoubleReturnWrapper(name: String): MethodNode {
    val m = MethodNode(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, name, "(D)D", null, null)
    m.visitCode()
    m.visitVarInsn(Opcodes.DLOAD, 0)
    m.visitInsn(Opcodes.DRETURN)
    m.visitMaxs(2, 2)
    m.visitEnd()
    return m
}

private fun createObjectReturnWrapper(name: String): MethodNode {
    val m = MethodNode(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, name, "(Ljava/lang/Object;)Ljava/lang/Object;", null, null)
    m.visitCode()
    m.visitVarInsn(Opcodes.ALOAD, 0)
    m.visitInsn(Opcodes.ARETURN)
    m.visitMaxs(1, 1)
    m.visitEnd()
    return m
}
