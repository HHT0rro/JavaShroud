package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

fun stripSourceDebug(classBytes: ByteArray): ByteArray {
    val classReader = ClassReader(classBytes)
    val classWriter = ClassWriter(0)
    val classVisitor = object : ClassVisitor(Opcodes.ASM9, classWriter) {
        override fun visitSource(source: String?, debug: String?) {
            // Pass null to suppress SourceFile and SourceDebugExtension output
        }
    }
    classReader.accept(classVisitor, 0)
    return stripDeadConstantPoolEntries(classWriter.toByteArray())
}
