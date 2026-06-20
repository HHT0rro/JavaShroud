package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode

/**
 * Member hiding transform.
 *
 * Marks fields and methods with the ACC_SYNTHETIC flag to hide them
 * from IDEs and decompilers. Methods also get ACC_BRIDGE flag for
 * additional noise. Constructors, class initializers, and interface members
 * are skipped; native methods may still be marked synthetic for helper hardening.
 *
 * Design inspired by obfuscator-master HideMembers (MIT),
 * re-implemented as JavaShroud-native Kotlin using ASM Tree API.
 */
fun hideClassMembers(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    var changed = false

    for (method in classNode.methods) {
        if (method.name.startsWith("<")) continue
        if ((method.access and Opcodes.ACC_SYNTHETIC) != 0) continue

        method.access = method.access or Opcodes.ACC_SYNTHETIC
        changed = true
    }

    for (field in classNode.fields) {
        if ((field.access and Opcodes.ACC_SYNTHETIC) != 0) continue

        field.access = field.access or Opcodes.ACC_SYNTHETIC
        changed = true
    }

    if (!changed) {
        return classBytes
    }

    val writer = ClassWriter(reader, 0)
    classNode.accept(writer)
    return writer.toByteArray()
}
