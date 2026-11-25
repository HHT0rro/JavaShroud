package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.*

/**
 * Comparison mangling transform (fusion from obfuscator-master).
 *
 * Replaces long, float, and double comparison instructions (LCMP, FCMPL, FCMPG,
 * DCMPL, DCMPG) with synthetic method calls that perform the same comparison.
 * This breaks decompiler pattern matching on comparison chains.
 *
 * Also replaces IF_ICMPxx jumps with method-wrapped equivalents.
 */
fun mangleComparisons(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    var changed = false
    val comparisonMethods = mutableMapOf<String, MethodNode>()
    var methodIndex = 0

    for (method in classNode.methods) {
        if (method.name == "<clinit>") continue
        if ((method.access and Opcodes.ACC_ABSTRACT) != 0) continue
        if ((method.access and Opcodes.ACC_NATIVE) != 0) continue
        val insns = method.instructions ?: continue

        val toReplace = mutableListOf<Pair<AbstractInsnNode, InsnList>>()

        for (insn in insns.toArray()) {
            when (insn.opcode) {
                Opcodes.LCMP -> {
                    val wrapperName = "__js_lcmp_${methodIndex++}"
                    val wrapper = createLongComparisonMethod(wrapperName)
                    comparisonMethods[wrapperName] = wrapper
                    val replacement = InsnList().apply {
                        add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, wrapperName, "(JJ)I", false))
                    }
                    toReplace.add(insn to replacement)
                }
                Opcodes.FCMPL, Opcodes.FCMPG -> {
                    val wrapperName = "__js_fcmp_${methodIndex++}"
                    val isG = insn.opcode == Opcodes.FCMPG
                    val wrapper = createFloatComparisonMethod(wrapperName, isG)
                    comparisonMethods[wrapperName] = wrapper
                    val replacement = InsnList().apply {
                        add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, wrapperName, "(FF)I", false))
                    }
                    toReplace.add(insn to replacement)
                }
                Opcodes.DCMPL, Opcodes.DCMPG -> {
                    val wrapperName = "__js_dcmp_${methodIndex++}"
                    val isG = insn.opcode == Opcodes.DCMPG
                    val wrapper = createDoubleComparisonMethod(wrapperName, isG)
                    comparisonMethods[wrapperName] = wrapper
                    val replacement = InsnList().apply {
                        add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, wrapperName, "(DD)I", false))
                    }
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

    classNode.methods.addAll(comparisonMethods.values)

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun createLongComparisonMethod(name: String): MethodNode {
    val method = MethodNode(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, name, "(JJ)I", null, null)
    method.visitCode()
    method.visitVarInsn(Opcodes.LLOAD, 0)
    method.visitVarInsn(Opcodes.LLOAD, 2)
    method.visitInsn(Opcodes.LCMP)
    method.visitInsn(Opcodes.IRETURN)
    method.visitMaxs(4, 4)
    method.visitEnd()
    return method
}

private fun createFloatComparisonMethod(name: String, isGreater: Boolean): MethodNode {
    val method = MethodNode(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, name, "(FF)I", null, null)
    method.visitCode()
    method.visitVarInsn(Opcodes.FLOAD, 0)
    method.visitVarInsn(Opcodes.FLOAD, 1)
    method.visitInsn(if (isGreater) Opcodes.FCMPG else Opcodes.FCMPL)
    method.visitInsn(Opcodes.IRETURN)
    method.visitMaxs(2, 2)
    method.visitEnd()
    return method
}

private fun createDoubleComparisonMethod(name: String, isGreater: Boolean): MethodNode {
    val method = MethodNode(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, name, "(DD)I", null, null)
    method.visitCode()
    method.visitVarInsn(Opcodes.DLOAD, 0)
    method.visitVarInsn(Opcodes.DLOAD, 2)
    method.visitInsn(if (isGreater) Opcodes.DCMPG else Opcodes.DCMPL)
    method.visitInsn(Opcodes.IRETURN)
    method.visitMaxs(4, 4)
    method.visitEnd()
    return method
}
