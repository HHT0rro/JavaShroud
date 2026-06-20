package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

fun addSyntheticFlags(classBytes: ByteArray, selectedMemberKeys: Set<String>): ByteArray {
    val classReader = ClassReader(classBytes)
    val classWriter = ClassWriter(classReader, 0)
    var isAnnotationInterface = false
    val classVisitor = object : ClassVisitor(Opcodes.ASM9, classWriter) {
        override fun visit(version: Int, access: Int, name: String?, signature: String?, superName: String?, interfaces: Array<out String>?) {
            isAnnotationInterface = (access and Opcodes.ACC_ANNOTATION) != 0
            super.visit(version, access, name, signature, superName, interfaces)
        }

        override fun visitField(access: Int, name: String?, descriptor: String?, signature: String?, value: Any?): FieldVisitor? {
            val nextAccess = if (matchesSelectedField(name, descriptor, selectedMemberKeys)) {
                access or Opcodes.ACC_SYNTHETIC
            } else {
                access
            }
            return super.visitField(nextAccess, name, descriptor, signature, value)
        }

        override fun visitMethod(access: Int, name: String?, descriptor: String?, signature: String?, exceptions: Array<out String>?): MethodVisitor {
            val nextAccess = if (!isAnnotationInterface && matchesSelectedMethod(name, descriptor, selectedMemberKeys)) {
                access or Opcodes.ACC_SYNTHETIC
            } else {
                access
            }
            return super.visitMethod(nextAccess, name, descriptor, signature, exceptions)
        }
    }
    classReader.accept(classVisitor, 0)
    return classWriter.toByteArray()
}

private fun matchesSelectedField(name: String?, descriptor: String?, selectedMemberKeys: Set<String>): Boolean {
    return matchesSelectedMember("FIELD", name, descriptor, selectedMemberKeys)
}

private fun matchesSelectedMethod(name: String?, descriptor: String?, selectedMemberKeys: Set<String>): Boolean {
    return matchesSelectedMember("METHOD", name, descriptor, selectedMemberKeys)
}

private fun matchesSelectedMember(prefix: String, name: String?, descriptor: String?, selectedMemberKeys: Set<String>): Boolean {
    if (name == null || descriptor == null) {
        return false
    }
    return selectedMemberKeys.contains(prefix + ":" + name + ":" + descriptor)
}