package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

fun renameLocalVariables(classBytes: ByteArray, selectedMethodKeys: Set<String>): ByteArray {
    val classReader = ClassReader(classBytes)
    val classWriter = ClassWriter(classReader, 0)
    val classVisitor = object : ClassVisitor(Opcodes.ASM9, classWriter) {
        override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor {
            val parentMethodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions)
            val methodKey = buildSelectedMethodKey(name, descriptor)
            if (methodKey == null || !selectedMethodKeys.contains(methodKey)) {
                return parentMethodVisitor
            }
            return LocalVariableRenameVisitor(parentMethodVisitor)
        }
    }
    classReader.accept(classVisitor, 0)
    return classWriter.toByteArray()
}

private fun buildSelectedMethodKey(name: String?, descriptor: String?): String? {
    if (name == null || descriptor == null) {
        return null
    }
    return name + ":" + descriptor
}

private class LocalVariableRenameVisitor(methodVisitor: MethodVisitor) : MethodVisitor(Opcodes.ASM9, methodVisitor) {
    private val renamedVariables: MutableMap<Int, String> = mutableMapOf()

    override fun visitLocalVariable(name: String?, descriptor: String?, signature: String?, start: Label?, end: Label?, index: Int) {
        val nextName = when (name) {
            null -> null
            "this" -> name
            "super" -> name
            else -> renamedVariables.getOrPut(index) { buildVariableName(index) }
        }
        super.visitLocalVariable(nextName, descriptor, signature, start, end, index)
    }

    override fun visitParameter(name: String?, access: Int) {
        val nextName = if (name == null) null else buildVariableName(renamedVariables.size)
        super.visitParameter(nextName, access)
    }
}

private fun buildVariableName(index: Int): String {
    return "p" + index.toString().padStart(4, '0')
}
