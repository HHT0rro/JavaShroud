package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.MethodNode
import java.util.Random

/**
 * JVM-legal / Java-illegal identifier injection transform.
 *
 * Injects synthetic fields and methods whose names are legal in the JVM
 * class-file format (JVMS 4.2.2 permits any valid UTF-8 except for the
 * special method names `<init>` and `<clinit>`) but are Java reserved
 * words (JLS 3.9) or otherwise illegal Java identifiers (JLS 3.8).
 * Decompilers must emit these names verbatim, producing output that
 * does not compile.
 *
 * Injected names: `null`, `true`, `false`, `var`, `yield`, `record`.
 * These are reserved words in Java source but valid UTF-8 strings
 * that the JVM accepts as field/method names.
 *
 * Attack model: static decompilation (all Java-targeting decompilers
 * produce uncompilable source when encountering reserved-word
 * identifiers).
 */
fun injectIllegalIdentifiers(classBytes: ByteArray, seed: Long? = null): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) return classBytes
    if (classNode.name.contains("\$")) return classBytes

    val rng = if (seed != null) Random(seed) else Random()

    val illegalFieldNames = listOf("null", "true", "false", "var", "yield", "record")
    val illegalMethodNames = listOf("null", "true", "false", "var", "yield")

    // Inject synthetic fields with illegal names
    val fieldCount = (1 + rng.nextInt(3)).coerceAtMost(illegalFieldNames.size)
    val usedFieldNames = illegalFieldNames.shuffled(rng).take(fieldCount)
    for (name in usedFieldNames) {
        classNode.fields.add(FieldNode(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            name, "I", null, 0,
        ))
    }

    // Inject synthetic methods with illegal names
    val methodCount = (1 + rng.nextInt(2)).coerceAtMost(illegalMethodNames.size)
    val usedMethodNames = illegalMethodNames.shuffled(rng).take(methodCount)
    for (name in usedMethodNames) {
        val mv = MethodNode(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            name, "()V", null, null,
        )
        mv.instructions.add(InsnNode(Opcodes.RETURN))
        classNode.methods.add(mv)
    }

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}
