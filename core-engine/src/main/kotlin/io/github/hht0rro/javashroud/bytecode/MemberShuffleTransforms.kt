package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.MethodNode

/**
 * Member shuffle transform.
 *
 * Randomizes the order of fields and methods in a class to break
 * positional assumptions made by decompilers and static analysis tools.
 * Uses ASM Tree API for reliable member reordering.
 *
 * Design inspired by obfuscator-master ShuffleMembersTransformer (MIT),
 * re-implemented as JavaShroud-native Kotlin.
 */
fun shuffleClassMembers(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if (classNode.fields.size <= 1 && classNode.methods.size <= 1) {
        return classBytes
    }

    val shuffledFields: MutableList<FieldNode> = classNode.fields.shuffled().toMutableList()
    val shuffledMethods: MutableList<MethodNode> = classNode.methods.shuffled().toMutableList()

    classNode.fields = shuffledFields
    classNode.methods = shuffledMethods

    val writer = ClassWriter(reader, 0)
    classNode.accept(writer)
    return writer.toByteArray()
}
