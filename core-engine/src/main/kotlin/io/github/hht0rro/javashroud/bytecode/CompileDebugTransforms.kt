package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

fun stripCompileDebug(classBytes: ByteArray): ByteArray {
    val classReader = ClassReader(classBytes)
    val classWriter = ClassWriter(0)
    val classVisitor = object : ClassVisitor(Opcodes.ASM9, classWriter) {
        override fun visitSource(source: String?, debug: String?) {
            // Suppress SourceFile and SourceDebugExtension
        }

        override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor {
            val parentMethodVisitor = super.visitMethod(access, name, descriptor, signature, exceptions)
            return object : MethodVisitor(Opcodes.ASM9, parentMethodVisitor) {
                override fun visitLineNumber(line: Int, start: Label?) {
                    // Suppress line numbers
                }

                override fun visitLocalVariable(name: String?, descriptor: String?, signature: String?, start: Label?, end: Label?, index: Int) {
                    // Suppress local variable info
                }

                override fun visitParameter(name: String?, access: Int) {
                    // Suppress parameter names
                }
            }
        }
    }
    classReader.accept(classVisitor, 0)
    return stripDeadConstantPoolEntries(classWriter.toByteArray())
}
