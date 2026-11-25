package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode

/**
 * Inner class metadata removal transform.
 *
 * Strips outerClass, innerClasses, outerMethod, and outerMethodDesc
 * metadata from classes to break decompiler reconstruction of nested
 * class relationships.
 *
 * Design inspired by obfuscator-master InnerClassRemover (MIT),
 * re-implemented as JavaShroud-native Kotlin using ASM Tree API.
 */
fun stripInnerClassMetadata(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    var changed = false

    if (classNode.outerClass != null) {
        classNode.outerClass = null
        changed = true
    }
    if (classNode.innerClasses.isNotEmpty()) {
        classNode.innerClasses.clear()
        changed = true
    }
    if (classNode.outerMethod != null) {
        classNode.outerMethod = null
        changed = true
    }
    if (classNode.outerMethodDesc != null) {
        classNode.outerMethodDesc = null
        changed = true
    }

    if (!changed) {
        return classBytes
    }

    val writer = ClassWriter(0)
    classNode.accept(writer)
    return stripDeadConstantPoolEntries(writer.toByteArray())
}
