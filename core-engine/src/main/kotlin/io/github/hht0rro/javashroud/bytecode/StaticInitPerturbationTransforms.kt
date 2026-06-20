package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode

/**
 * Static initializer perturbation transform.
 *
 * Moves compile-time static field constants (String, Integer) into
 * runtime <clinit> initialization, and injects additional noise
 * assignments to dummy fields. This breaks constant propagation
 * analysis in decompilers and static analysis tools.
 *
 * Design inspired by obfuscator-master StaticInitializionTransformer (MIT),
 * re-implemented as JavaShroud-native Kotlin using ASM Tree API.
 */
fun perturbStaticInitializer(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    // Collect static fields with constant values
    data class ConstantField(val field: FieldNode, val value: Any)

    val constantFields = mutableListOf<ConstantField>()
    for (field in classNode.fields) {
        if (field.value == null) continue
        if ((field.access and Opcodes.ACC_STATIC) == 0) continue
        if (field.value is String || field.value is Int) {
            constantFields.add(ConstantField(field, field.value!!))
        }
    }

    if (constantFields.isEmpty()) {
        return classBytes
    }

    // Remove constant values from field declarations
    for (cf in constantFields) {
        cf.field.value = null
    }

    // Build initialization instructions
    val initInsns = InsnList()
    for (cf in constantFields) {
        when (val v = cf.value) {
            is String -> initInsns.add(LdcInsnNode(v))
            is Int -> {
                when {
                    v >= -1 && v <= 5 -> initInsns.add(InsnNode(Opcodes.ICONST_0 + v))
                    v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE -> initInsns.add(IntInsnNode(Opcodes.BIPUSH, v))
                    v >= Short.MIN_VALUE && v <= Short.MAX_VALUE -> initInsns.add(IntInsnNode(Opcodes.SIPUSH, v))
                    else -> initInsns.add(LdcInsnNode(v))
                }
            }
        }
        initInsns.add(FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, cf.field.name, cf.field.desc))
    }

    // Inject noise: add dummy static field and populate it
    val dummyFieldName = "a_x"
    classNode.fields.add(FieldNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        dummyFieldName,
        "I",
        null,
        null,
    ))
    val random = java.util.Random()
    val noiseValue = random.nextInt(65536)
    when {
        noiseValue >= -1 && noiseValue <= 5 -> initInsns.add(InsnNode(Opcodes.ICONST_0 + noiseValue))
        noiseValue >= Byte.MIN_VALUE && noiseValue <= Byte.MAX_VALUE -> initInsns.add(IntInsnNode(Opcodes.BIPUSH, noiseValue))
        noiseValue >= Short.MIN_VALUE && noiseValue <= Short.MAX_VALUE -> initInsns.add(IntInsnNode(Opcodes.SIPUSH, noiseValue))
        else -> initInsns.add(LdcInsnNode(noiseValue))
    }
    initInsns.add(FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, dummyFieldName, "I"))

    // Inject into <clinit>
    val clinit = findOrCreateClinit(classNode)
    clinit.instructions.insertBefore(clinit.instructions.first, initInsns)

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun findOrCreateClinit(classNode: ClassNode): MethodNode {
    for (method in classNode.methods) {
        if (method.name == "<clinit>") return method
    }
    val clinit = MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
    clinit.instructions = InsnList()
    clinit.instructions.add(InsnNode(Opcodes.RETURN))
    classNode.methods.add(clinit)
    return clinit
}
