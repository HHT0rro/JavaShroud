package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

fun stripLineNumbers(classBytes: ByteArray, selectedMethodKeys: Set<String>): ByteArray {
    val classReader = ClassReader(classBytes)
    val classWriter = ClassWriter(0)
    val classVisitor = object : ClassVisitor(Opcodes.ASM9, classWriter) {
        override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor {
            val parentMethodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions)
            val methodKey = if (name != null && descriptor != null) name + ":" + descriptor else null
            if (methodKey == null || !selectedMethodKeys.contains(methodKey)) {
                return parentMethodVisitor
            }
            return object : MethodVisitor(Opcodes.ASM9, parentMethodVisitor) {
                override fun visitLineNumber(line: Int, start: Label?) {
                    // Suppress line number output
                }
            }
        }
    }
    classReader.accept(classVisitor, 0)
    return stripDeadConstantPoolEntries(classWriter.toByteArray())
}
