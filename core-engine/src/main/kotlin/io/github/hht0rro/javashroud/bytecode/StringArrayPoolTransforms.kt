package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.InsnNode

/**
 * String array pool transform.
 *
 * Collects all string constants from a class, stores them in a
 * private static String[] field initialized in <clinit>, and replaces
 * each LDC string instruction with a field array access.
 *
 * This increases obfuscation by centralizing strings into a single
 * array, making individual string references harder to trace.
 *
 * Design inspired by jar-obfuscator StringArrayVisitor (MIT),
 * re-implemented as JavaShroud-native Kotlin using ASM Tree API.
 */
fun poolClassStrings(classBytes: ByteArray): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    if (containsNativeStringDecodeCallsite(classNode)) {
        return classBytes
    }

    // Collect all unique string constants in order
    val stringPool = mutableListOf<String>()
    val stringIndexMap = mutableMapOf<String, Int>()

    for (method in classNode.methods) {
        val insns = method.instructions ?: continue
        for (insn in insns) {
            if (insn is LdcInsnNode && insn.cst is String) {
                val s = insn.cst as String
                if (s !in stringIndexMap) {
                    stringIndexMap[s] = stringPool.size
                    stringPool.add(s)
                }
            }
        }
    }

    if (stringPool.isEmpty()) {
        return classBytes
    }

    val poolFieldName = "a_sp"
    val poolFieldDesc = "[Ljava/lang/String;"

    // Add the static String[] field
    classNode.fields.add(org.objectweb.asm.tree.FieldNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        poolFieldName,
        poolFieldDesc,
        null,
        null,
    ))

    // Build clinit initialization
    val clinitMethod = findOrCreateClinit(classNode)
    val initInsns = InsnList()

    // Create the array: a_sp = new String[N]
    initInsns.add(IntInsnNode(Opcodes.SIPUSH, stringPool.size))
    initInsns.add(TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"))
    initInsns.add(FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, poolFieldName, poolFieldDesc))

    // Fill the array: a_sp[i] = "string"
    for ((index, s) in stringPool.withIndex()) {
        initInsns.add(FieldInsnNode(Opcodes.GETSTATIC, classNode.name, poolFieldName, poolFieldDesc))
        initInsns.add(IntInsnNode(Opcodes.SIPUSH, index))
        initInsns.add(LdcInsnNode(s))
        initInsns.add(InsnNode(Opcodes.AASTORE))
    }

    clinitMethod.instructions.insertBefore(clinitMethod.instructions.first, initInsns)

    // Replace LDC strings with array access in all methods
    for (method in classNode.methods) {
        if (method.name == "<clinit>") continue
        val insns = method.instructions ?: continue
        val insnList = insns.toArray().toList()
        for (insn in insnList) {
            if (insn is LdcInsnNode && insn.cst is String) {
                val s = insn.cst as String
                val index = stringIndexMap[s]!!
                val replacement = org.objectweb.asm.tree.InsnList()
                replacement.add(FieldInsnNode(Opcodes.GETSTATIC, classNode.name, poolFieldName, poolFieldDesc))
                replacement.add(IntInsnNode(Opcodes.SIPUSH, index))
                replacement.add(InsnNode(Opcodes.AALOAD))
                insns.insert(insn, replacement)
                insns.remove(insn)
            }
        }
    }

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun containsNativeStringDecodeCallsite(classNode: ClassNode): Boolean =
    classNode.methods.any { method ->
        val insns = method.instructions ?: return@any false
        insns.any { insn ->
            insn is MethodInsnNode &&
                insn.opcode == Opcodes.INVOKESTATIC &&
                insn.owner.startsWith("r/") &&
                insn.desc == "([BII)[B"
        }
    }

private fun findOrCreateClinit(classNode: ClassNode): org.objectweb.asm.tree.MethodNode {
    for (method in classNode.methods) {
        if (method.name == "<clinit>") {
            return method
        }
    }
    val clinit = org.objectweb.asm.tree.MethodNode(
        Opcodes.ACC_STATIC,
        "<clinit>",
        "()V",
        null,
        null,
    )
    clinit.instructions.add(InsnNode(Opcodes.RETURN))
    classNode.methods.add(clinit)
    return clinit
}
