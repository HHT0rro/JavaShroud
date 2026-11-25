package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import java.security.SecureRandom
import java.util.Random

/** Configuration for the JVM-only embedded string resolver. */
data class EmbeddedStringResolverConfig(
    val scope: String = "all-strings",
    val lengthThreshold: Int = 3,
    val seed: Long? = null,
    val strength: String = "max",
    val payloadCodec: String? = null,
)

/** Configuration for the JVM-only numeric constant resolver. */
data class NumericResolverConfig(
    val seed: Long? = null,
    val intCoverage: String = "none",
    val longCoverage: String = "none",
    val resolverCodec: String = "xor",
)

internal const val RESOLVER_MEMBER_PREFIX = "\$_jsr_"

internal fun isResolverMemberName(name: String): Boolean = name.startsWith(RESOLVER_MEMBER_PREFIX)

internal fun resolverSupportsInjectedMembers(classNode: ClassNode): Boolean {
    val isInterface = classNode.access and Opcodes.ACC_INTERFACE != 0
    if (!isInterface) return true
    return classNode.access and Opcodes.ACC_ANNOTATION == 0 && classNode.version >= Opcodes.V1_8
}

internal fun resolverMemberAccess(isInterface: Boolean): Int = if (isInterface) {
    Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC
} else {
    Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC
}

internal fun resolverFieldAccess(isInterface: Boolean): Int = if (isInterface) {
    Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL or Opcodes.ACC_SYNTHETIC
} else {
    Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC
}

internal fun resolverRandom(seed: Long?, className: String): Random {
    if (seed != null) return Random(seed xor className.hashCode().toLong())
    val bytes = ByteArray(Long.SIZE_BYTES)
    SecureRandom().nextBytes(bytes)
    var value = 0L
    for (byte in bytes) value = (value shl 8) xor (byte.toLong() and 0xFFL)
    return Random(value xor className.hashCode().toLong())
}

internal fun resolverUniqueMemberName(classNode: ClassNode, role: String, random: Random): String {
    val occupied = buildSet {
        classNode.fields.forEach { add(it.name) }
        classNode.methods.forEach { add(it.name) }
    }
    var suffix = random.nextInt().toUInt().toString(36)
    var candidate = "$RESOLVER_MEMBER_PREFIX$role$suffix"
    while (candidate in occupied) {
        suffix = random.nextInt().toUInt().toString(36)
        candidate = "$RESOLVER_MEMBER_PREFIX$role$suffix"
    }
    return candidate
}

internal fun prependResolverClassInit(classNode: ClassNode, init: InsnList) {
    val existing = classNode.methods.firstOrNull { it.name == "<clinit>" && it.desc == "()V" }
    if (existing != null) {
        val first = existing.instructions.first
        if (first != null) existing.instructions.insertBefore(first, init) else existing.instructions.add(init)
        return
    }
    val clinit = MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
    clinit.instructions.add(init)
    clinit.instructions.add(InsnNode(Opcodes.RETURN))
    classNode.methods.add(clinit)
}

internal fun resolverStringArrayInitialization(owner: String, fieldName: String, values: List<String>): InsnList = InsnList().apply {
    resolverPushInt(values.size)
    add(TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"))
    add(FieldInsnNode(Opcodes.PUTSTATIC, owner, fieldName, "[Ljava/lang/String;"))
    values.forEachIndexed { index, value ->
        add(FieldInsnNode(Opcodes.GETSTATIC, owner, fieldName, "[Ljava/lang/String;"))
        resolverPushInt(index)
        add(LdcInsnNode(value))
        add(InsnNode(Opcodes.AASTORE))
    }
}

internal fun resolverIntArrayInitialization(owner: String, fieldName: String, values: List<Int>): InsnList = InsnList().apply {
    resolverPushInt(values.size)
    add(IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT))
    add(FieldInsnNode(Opcodes.PUTSTATIC, owner, fieldName, "[I"))
    values.forEachIndexed { index, value ->
        add(FieldInsnNode(Opcodes.GETSTATIC, owner, fieldName, "[I"))
        resolverPushInt(index)
        resolverPushInt(value)
        add(InsnNode(Opcodes.IASTORE))
    }
}

internal fun resolverLongArrayInitialization(owner: String, fieldName: String, values: List<Long>): InsnList = InsnList().apply {
    resolverPushInt(values.size)
    add(IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG))
    add(FieldInsnNode(Opcodes.PUTSTATIC, owner, fieldName, "[J"))
    values.forEachIndexed { index, value ->
        add(FieldInsnNode(Opcodes.GETSTATIC, owner, fieldName, "[J"))
        resolverPushInt(index)
        add(LdcInsnNode(value))
        add(InsnNode(Opcodes.LASTORE))
    }
}

internal fun resolverObjectArrayInitialization(owner: String, fieldName: String, size: Int): InsnList = InsnList().apply {
    resolverPushInt(size)
    add(TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"))
    add(FieldInsnNode(Opcodes.PUTSTATIC, owner, fieldName, "[Ljava/lang/Object;"))
}

internal fun InsnList.resolverPushInt(value: Int) {
    when (value) {
        -1 -> add(InsnNode(Opcodes.ICONST_M1))
        0 -> add(InsnNode(Opcodes.ICONST_0))
        1 -> add(InsnNode(Opcodes.ICONST_1))
        2 -> add(InsnNode(Opcodes.ICONST_2))
        3 -> add(InsnNode(Opcodes.ICONST_3))
        4 -> add(InsnNode(Opcodes.ICONST_4))
        5 -> add(InsnNode(Opcodes.ICONST_5))
        in Byte.MIN_VALUE..Byte.MAX_VALUE -> add(IntInsnNode(Opcodes.BIPUSH, value))
        in Short.MIN_VALUE..Short.MAX_VALUE -> add(IntInsnNode(Opcodes.SIPUSH, value))
        else -> add(LdcInsnNode(value))
    }
}

internal fun org.objectweb.asm.MethodVisitor.resolverPushInt(value: Int) {
    when (value) {
        -1 -> visitInsn(Opcodes.ICONST_M1)
        0 -> visitInsn(Opcodes.ICONST_0)
        1 -> visitInsn(Opcodes.ICONST_1)
        2 -> visitInsn(Opcodes.ICONST_2)
        3 -> visitInsn(Opcodes.ICONST_3)
        4 -> visitInsn(Opcodes.ICONST_4)
        5 -> visitInsn(Opcodes.ICONST_5)
        in Byte.MIN_VALUE..Byte.MAX_VALUE -> visitIntInsn(Opcodes.BIPUSH, value)
        in Short.MIN_VALUE..Short.MAX_VALUE -> visitIntInsn(Opcodes.SIPUSH, value)
        else -> visitLdcInsn(value)
    }
}

internal fun resolverXorKey(seed: Int, index: Int): Int = seed xor (index * 0x45D9F3B)

internal fun resolverLongXorKey(seed: Int, index: Int): Long =
    (seed.toLong() shl 32) xor (index.toLong() * 0x5DEECE66DL) xor 0x4CF5AD432745937FL

internal fun resolverXorBytes(value: ByteArray, seed: Int, index: Int): ByteArray {
    val key = resolverXorKey(seed, index)
    return ByteArray(value.size) { offset ->
        val keyByte = (key ushr ((offset and 3) shl 3)) xor (offset * 31)
        (value[offset].toInt() xor keyByte).toByte()
    }
}

internal fun resolverDeadFlow(method: org.objectweb.asm.MethodVisitor, keySlot: Int) {
    val stable = Label()
    method.visitVarInsn(Opcodes.ILOAD, keySlot)
    method.visitVarInsn(Opcodes.ILOAD, keySlot)
    method.visitInsn(Opcodes.IXOR)
    method.visitJumpInsn(Opcodes.IFEQ, stable)
    method.visitTypeInsn(Opcodes.NEW, "java/lang/IllegalStateException")
    method.visitInsn(Opcodes.DUP)
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "()V", false)
    method.visitInsn(Opcodes.ATHROW)
    method.visitLabel(stable)
}
