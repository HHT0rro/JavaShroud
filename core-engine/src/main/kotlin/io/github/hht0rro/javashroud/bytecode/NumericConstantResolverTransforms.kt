package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.Base64
import java.util.Random
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val INT_ARRAY_DESC = "[I"
private const val LONG_ARRAY_DESC = "[J"
private const val OBJECT_ARRAY_DESC = "[Ljava/lang/Object;"
private const val STRING_ARRAY_DESC_NUMERIC = "[Ljava/lang/String;"
private const val BYTES_DESC = "[B"

/**
 * Replaces integer and long constants with resolver calls backed by class-local payload tables.
 * This is the JVM-only resolver rewriting path; [obfuscateIntegerConstants] remains the
 * arithmetic rewriting path.
 */
fun obfuscateNumericConstantsResolver(
    classBytes: ByteArray,
    config: NumericResolverConfig = NumericResolverConfig(),
): ByteArray {
    val reader = ClassReader(classBytes)
    val classNode = ClassNode()
    reader.accept(classNode, 0)
    if (!resolverSupportsInjectedMembers(classNode)) return classBytes
    require(config.intCoverage in INT_COVERAGE_LEVELS) {
        "integer-constant-obfuscation intCoverage '${config.intCoverage}' is not supported; supported values: ${INT_COVERAGE_LEVELS.joinToString(", ")}"
    }
    require(config.longCoverage in LONG_COVERAGE_LEVELS) {
        "integer-constant-obfuscation longCoverage '${config.longCoverage}' is not supported; supported values: ${LONG_COVERAGE_LEVELS.joinToString(", ")}"
    }
    require(config.resolverCodec != "des") {
        "integer-constant-obfuscation resolverCodec 'des' is retired; use xor"
    }
    require(config.resolverCodec in NUMERIC_RESOLVER_CODECS) {
        "integer-constant-obfuscation resolverCodec '${config.resolverCodec}' is not supported; supported values: ${NUMERIC_RESOLVER_CODECS.joinToString(", ")}"
    }
    return obfuscateNumericConstantsWithXor(classBytes, classNode, reader, config)
}

private fun obfuscateNumericConstantsWithXor(
    classBytes: ByteArray,
    classNode: ClassNode,
    reader: ClassReader,
    config: NumericResolverConfig,
): ByteArray {
    val isInterface = classNode.access and Opcodes.ACC_INTERFACE != 0
    val random = resolverRandom(config.seed, classNode.name)
    val seed = random.nextInt() xor classNode.name.hashCode()
    val intField = resolverUniqueMemberName(classNode, "ip", random)
    val longField = resolverUniqueMemberName(classNode, "lp", random)
    val intCacheField = resolverUniqueMemberName(classNode, "ic", random)
    val longCacheField = resolverUniqueMemberName(classNode, "lc", random)
    val intResolver = resolverUniqueMemberName(classNode, "ir", random)
    val longResolver = resolverUniqueMemberName(classNode, "lr", random)
    val intValues = mutableListOf<Int>()
    val longValues = mutableListOf<Long>()

    for (method in classNode.methods) {
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        for (instruction in method.instructions.toArray()) {
            val intValue = resolverIntConstant(instruction)
            if (intValue != null && resolverShouldResolveInt(intValue, config.intCoverage)) {
                val index = intValues.size
                intValues += intValue xor resolverXorKey(seed, index)
                resolverReplaceNumericConstant(method, instruction, classNode.name, intResolver, "(I)I", isInterface, index)
                continue
            }
            val longValue = (instruction as? LdcInsnNode)?.cst as? Long ?: resolverLongInsnConstant(instruction)
            if (longValue != null && resolverShouldResolveLong(longValue, config.longCoverage)) {
                val index = longValues.size
                longValues += longValue xor resolverLongXorKey(seed, index)
                resolverReplaceNumericConstant(method, instruction, classNode.name, longResolver, "(I)J", isInterface, index)
            }
        }
    }

    val fieldInitializers = resolverRewriteNumericConstantValueFields(
        classNode = classNode,
        config = config,
        intResolver = intResolver,
        longResolver = longResolver,
        isInterface = isInterface,
        addInt = { value ->
            val index = intValues.size
            intValues += value xor resolverXorKey(seed, index)
            index
        },
        addLong = { value ->
            val index = longValues.size
            longValues += value xor resolverLongXorKey(seed, index)
            index
        },
    )

    if (intValues.isEmpty() && longValues.isEmpty()) return classBytes

    val fieldAccess = resolverFieldAccess(isInterface)
    val init = InsnList()
    if (intValues.isNotEmpty()) {
        classNode.fields.add(FieldNode(fieldAccess, intField, INT_ARRAY_DESC, null, null))
        classNode.fields.add(FieldNode(fieldAccess, intCacheField, OBJECT_ARRAY_DESC, null, null))
        init.add(resolverIntArrayInitialization(classNode.name, intField, intValues))
        init.add(resolverObjectArrayInitialization(classNode.name, intCacheField, intValues.size))
        classNode.methods.add(createXorIntResolver(classNode.name, isInterface, intResolver, intField, intCacheField, seed))
    }
    if (longValues.isNotEmpty()) {
        classNode.fields.add(FieldNode(fieldAccess, longField, LONG_ARRAY_DESC, null, null))
        classNode.fields.add(FieldNode(fieldAccess, longCacheField, OBJECT_ARRAY_DESC, null, null))
        init.add(resolverLongArrayInitialization(classNode.name, longField, longValues))
        init.add(resolverObjectArrayInitialization(classNode.name, longCacheField, longValues.size))
        classNode.methods.add(createXorLongResolver(classNode.name, isInterface, longResolver, longField, longCacheField, seed))
    }
    init.add(fieldInitializers)
    prependResolverClassInit(classNode, init)
    val writer = computeFramesWriter()
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun obfuscateNumericConstantsWithDes(
    classBytes: ByteArray,
    classNode: ClassNode,
    reader: ClassReader,
    config: NumericResolverConfig,
): ByteArray {
    val isInterface = classNode.access and Opcodes.ACC_INTERFACE != 0
    val random = resolverRandom(config.seed, classNode.name)
    val payloadField = resolverUniqueMemberName(classNode, "np", random)
    val keyField = resolverUniqueMemberName(classNode, "nk", random)
    val cacheField = resolverUniqueMemberName(classNode, "nc", random)
    val decodeName = resolverUniqueMemberName(classNode, "nd", random)
    val intResolver = resolverUniqueMemberName(classNode, "ir", random)
    val longResolver = resolverUniqueMemberName(classNode, "lr", random)
    val payloads = mutableListOf<String>()
    val keys = mutableListOf<String>()
    var hasInt = false
    var hasLong = false

    fun addPayload(bytes: ByteArray): Int {
        val key = ByteArray(8).also(random::nextBytes)
        val cipher = Cipher.getInstance("DES/CBC/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "DES"), IvParameterSpec(ByteArray(8)))
        val index = payloads.size
        payloads += Base64.getEncoder().encodeToString(cipher.doFinal(bytes))
        keys += Base64.getEncoder().encodeToString(key)
        return index
    }

    for (method in classNode.methods) {
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        for (instruction in method.instructions.toArray()) {
            val intValue = resolverIntConstant(instruction)
            if (intValue != null && resolverShouldResolveInt(intValue, config.intCoverage)) {
                val index = addPayload(resolverIntDesBlock(intValue))
                hasInt = true
                resolverReplaceNumericConstant(method, instruction, classNode.name, intResolver, "(I)I", isInterface, index)
                continue
            }
            val longValue = (instruction as? LdcInsnNode)?.cst as? Long ?: resolverLongInsnConstant(instruction)
            if (longValue != null && resolverShouldResolveLong(longValue, config.longCoverage)) {
                val index = addPayload(resolverLongBytes(longValue))
                hasLong = true
                resolverReplaceNumericConstant(method, instruction, classNode.name, longResolver, "(I)J", isInterface, index)
            }
        }
    }

    val fieldInitializers = resolverRewriteNumericConstantValueFields(
        classNode = classNode,
        config = config,
        intResolver = intResolver,
        longResolver = longResolver,
        isInterface = isInterface,
        addInt = { value ->
            hasInt = true
            addPayload(resolverIntDesBlock(value))
        },
        addLong = { value ->
            hasLong = true
            addPayload(resolverLongBytes(value))
        },
    )

    if (payloads.isEmpty()) return classBytes

    val fieldAccess = resolverFieldAccess(isInterface)
    classNode.fields.add(FieldNode(fieldAccess, payloadField, STRING_ARRAY_DESC_NUMERIC, null, null))
    classNode.fields.add(FieldNode(fieldAccess, keyField, STRING_ARRAY_DESC_NUMERIC, null, null))
    classNode.fields.add(FieldNode(fieldAccess, cacheField, OBJECT_ARRAY_DESC, null, null))
    val init = InsnList()
    init.add(resolverStringArrayInitialization(classNode.name, payloadField, payloads))
    init.add(resolverStringArrayInitialization(classNode.name, keyField, keys))
    init.add(resolverObjectArrayInitialization(classNode.name, cacheField, payloads.size))
    init.add(fieldInitializers)
    prependResolverClassInit(classNode, init)
    classNode.methods.add(createDesPayloadDecoder(classNode.name, isInterface, decodeName, payloadField, keyField, cacheField))
    if (hasInt) classNode.methods.add(createDesIntResolver(classNode.name, isInterface, intResolver, decodeName))
    if (hasLong) classNode.methods.add(createDesLongResolver(classNode.name, isInterface, longResolver, decodeName))

    val writer = computeFramesWriter()
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun resolverReplaceNumericConstant(
    method: MethodNode,
    instruction: AbstractInsnNode,
    owner: String,
    resolver: String,
    descriptor: String,
    isInterface: Boolean,
    index: Int,
) {
    val replacement = InsnList().apply {
        resolverPushInt(index)
        add(MethodInsnNode(Opcodes.INVOKESTATIC, owner, resolver, descriptor, isInterface))
    }
    method.instructions.insertBefore(instruction, replacement)
    method.instructions.remove(instruction)
}

private fun resolverRewriteNumericConstantValueFields(
    classNode: ClassNode,
    config: NumericResolverConfig,
    intResolver: String,
    longResolver: String,
    isInterface: Boolean,
    addInt: (Int) -> Int,
    addLong: (Long) -> Int,
): InsnList = InsnList().apply {
    for (field in classNode.fields.toList()) {
        if (field.access and Opcodes.ACC_STATIC == 0) continue
        when (val value = field.value) {
            is Int -> if (field.desc in INT_FIELD_DESCRIPTORS && resolverShouldResolveIntField(value, config.intCoverage)) {
                val index = addInt(value)
                field.value = null
                resolverPushInt(index)
                add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, intResolver, "(I)I", isInterface))
                add(FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, field.name, field.desc))
            }
            is Long -> if (field.desc == "J" && resolverShouldResolveLong(value, config.longCoverage)) {
                val index = addLong(value)
                field.value = null
                resolverPushInt(index)
                add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, longResolver, "(I)J", isInterface))
                add(FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, field.name, field.desc))
            }
        }
    }
}

private fun resolverIntConstant(instruction: AbstractInsnNode): Int? = when (instruction) {
    is IntInsnNode -> when (instruction.opcode) {
        Opcodes.BIPUSH, Opcodes.SIPUSH -> instruction.operand
        else -> null
    }
    is LdcInsnNode -> instruction.cst as? Int
    is InsnNode -> when (instruction.opcode) {
        Opcodes.ICONST_M1 -> -1
        Opcodes.ICONST_0 -> 0
        Opcodes.ICONST_1 -> 1
        Opcodes.ICONST_2 -> 2
        Opcodes.ICONST_3 -> 3
        Opcodes.ICONST_4 -> 4
        Opcodes.ICONST_5 -> 5
        else -> null
    }
    else -> null
}

private fun resolverLongInsnConstant(instruction: AbstractInsnNode): Long? = when ((instruction as? InsnNode)?.opcode) {
    Opcodes.LCONST_0 -> 0L
    Opcodes.LCONST_1 -> 1L
    else -> null
}

private fun resolverShouldResolveInt(value: Int, level: String): Boolean = when (level) {
    "none" -> false
    "normal" -> value < Short.MIN_VALUE || value > Short.MAX_VALUE
    "aggressive" -> value < -1 || value > 5
    else -> false
}

/**
 * The field path uses its own threshold rather than the method-instruction threshold.
 * A configured integer field is moved out of ConstantValue unless it is one of the JVM's
 * tiny sentinel values, even when [level] is `normal`.
 */
private fun resolverShouldResolveIntField(value: Int, level: String): Boolean =
    level != "none" && value !in -1..1

private fun resolverShouldResolveLong(value: Long, level: String): Boolean = when (level) {
    "none" -> false
    "normal" -> value != 0L && value != 1L
    else -> false
}

private fun createXorIntResolver(
    owner: String,
    isInterface: Boolean,
    name: String,
    payloadField: String,
    cacheField: String,
    seed: Int,
): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, "(I)I", null, null)
    val cacheMiss = Label()
    method.visitCode()
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, OBJECT_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitVarInsn(Opcodes.ASTORE, 1)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitJumpInsn(Opcodes.IFNULL, cacheMiss)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Integer")
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false)
    method.visitInsn(Opcodes.IRETURN)

    method.visitLabel(cacheMiss)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, payloadField, INT_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.IALOAD)
    method.visitLdcInsn(seed)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitLdcInsn(0x45D9F3B)
    method.visitInsn(Opcodes.IMUL)
    method.visitInsn(Opcodes.IXOR)
    method.visitInsn(Opcodes.IXOR)
    method.visitVarInsn(Opcodes.ISTORE, 2)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, OBJECT_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitVarInsn(Opcodes.ILOAD, 2)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false)
    method.visitInsn(Opcodes.AASTORE)
    method.visitVarInsn(Opcodes.ILOAD, 2)
    method.visitInsn(Opcodes.IRETURN)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}

private fun createXorLongResolver(
    owner: String,
    isInterface: Boolean,
    name: String,
    payloadField: String,
    cacheField: String,
    seed: Int,
): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, "(I)J", null, null)
    val cacheMiss = Label()
    method.visitCode()
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, OBJECT_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitVarInsn(Opcodes.ASTORE, 1)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitJumpInsn(Opcodes.IFNULL, cacheMiss)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Long")
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Long", "longValue", "()J", false)
    method.visitInsn(Opcodes.LRETURN)

    method.visitLabel(cacheMiss)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, payloadField, LONG_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.LALOAD)
    method.visitLdcInsn(seed.toLong() shl 32)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.I2L)
    method.visitLdcInsn(0x5DEECE66DL)
    method.visitInsn(Opcodes.LMUL)
    method.visitInsn(Opcodes.LXOR)
    method.visitLdcInsn(0x4CF5AD432745937FL)
    method.visitInsn(Opcodes.LXOR)
    method.visitInsn(Opcodes.LXOR)
    method.visitVarInsn(Opcodes.LSTORE, 2)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, OBJECT_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitVarInsn(Opcodes.LLOAD, 2)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false)
    method.visitInsn(Opcodes.AASTORE)
    method.visitVarInsn(Opcodes.LLOAD, 2)
    method.visitInsn(Opcodes.LRETURN)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}

private fun createDesPayloadDecoder(
    owner: String,
    isInterface: Boolean,
    name: String,
    payloadField: String,
    keyField: String,
    cacheField: String,
): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, "(I)[B", null, null)
    val cacheMiss = Label()
    val tryStart = Label()
    val tryEnd = Label()
    val failure = Label()
    method.visitTryCatchBlock(tryStart, tryEnd, failure, "java/lang/Exception")
    method.visitCode()
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, OBJECT_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitVarInsn(Opcodes.ASTORE, 1)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitJumpInsn(Opcodes.IFNULL, cacheMiss)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitTypeInsn(Opcodes.CHECKCAST, BYTES_DESC)
    method.visitInsn(Opcodes.ARETURN)

    method.visitLabel(cacheMiss)
    method.visitLabel(tryStart)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder", "()Ljava/util/Base64\$Decoder;", false)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, payloadField, STRING_ARRAY_DESC_NUMERIC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Base64\$Decoder", "decode", "(Ljava/lang/String;)[B", false)
    method.visitVarInsn(Opcodes.ASTORE, 2)
    method.visitTypeInsn(Opcodes.NEW, "javax/crypto/spec/SecretKeySpec")
    method.visitInsn(Opcodes.DUP)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder", "()Ljava/util/Base64\$Decoder;", false)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, keyField, STRING_ARRAY_DESC_NUMERIC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Base64\$Decoder", "decode", "(Ljava/lang/String;)[B", false)
    method.visitLdcInsn("DES")
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "javax/crypto/spec/SecretKeySpec", "<init>", "([BLjava/lang/String;)V", false)
    method.visitVarInsn(Opcodes.ASTORE, 3)
    method.visitLdcInsn("DES/CBC/NoPadding")
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "javax/crypto/Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", false)
    method.visitVarInsn(Opcodes.ASTORE, 4)
    resolverEmitZeroIvCipherInit(method, cipherSlot = 4, keySlot = 3)
    method.visitVarInsn(Opcodes.ALOAD, 4)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "javax/crypto/Cipher", "doFinal", "([B)[B", false)
    method.visitVarInsn(Opcodes.ASTORE, 5)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, OBJECT_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitInsn(Opcodes.AASTORE)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitLabel(tryEnd)
    method.visitInsn(Opcodes.ARETURN)
    method.visitLabel(failure)
    method.visitVarInsn(Opcodes.ASTORE, 6)
    method.visitTypeInsn(Opcodes.NEW, "java/lang/IllegalStateException")
    method.visitInsn(Opcodes.DUP)
    method.visitLdcInsn("Numeric resolver failed")
    method.visitVarInsn(Opcodes.ALOAD, 6)
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "(Ljava/lang/String;Ljava/lang/Throwable;)V", false)
    method.visitInsn(Opcodes.ATHROW)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}

private fun createDesIntResolver(owner: String, isInterface: Boolean, name: String, decodeName: String): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, "(I)I", null, null)
    method.visitCode()
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, owner, decodeName, "(I)[B", isInterface)
    method.visitVarInsn(Opcodes.ASTORE, 1)
    resolverEmitUnsignedByte(method, 1, 4)
    method.visitIntInsn(Opcodes.BIPUSH, 24)
    method.visitInsn(Opcodes.ISHL)
    resolverEmitUnsignedByte(method, 1, 5)
    method.visitIntInsn(Opcodes.BIPUSH, 16)
    method.visitInsn(Opcodes.ISHL)
    method.visitInsn(Opcodes.IOR)
    resolverEmitUnsignedByte(method, 1, 6)
    method.visitIntInsn(Opcodes.BIPUSH, 8)
    method.visitInsn(Opcodes.ISHL)
    method.visitInsn(Opcodes.IOR)
    resolverEmitUnsignedByte(method, 1, 7)
    method.visitInsn(Opcodes.IOR)
    method.visitInsn(Opcodes.IRETURN)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}

private fun createDesLongResolver(owner: String, isInterface: Boolean, name: String, decodeName: String): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, "(I)J", null, null)
    val loop = Label()
    val done = Label()
    method.visitCode()
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, owner, decodeName, "(I)[B", isInterface)
    method.visitVarInsn(Opcodes.ASTORE, 1)
    method.visitInsn(Opcodes.LCONST_0)
    method.visitVarInsn(Opcodes.LSTORE, 2)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitVarInsn(Opcodes.ISTORE, 4)
    method.visitLabel(loop)
    method.visitVarInsn(Opcodes.ILOAD, 4)
    method.visitIntInsn(Opcodes.BIPUSH, 8)
    method.visitJumpInsn(Opcodes.IF_ICMPGE, done)
    method.visitVarInsn(Opcodes.LLOAD, 2)
    method.visitIntInsn(Opcodes.BIPUSH, 8)
    method.visitInsn(Opcodes.LSHL)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitVarInsn(Opcodes.ILOAD, 4)
    method.visitInsn(Opcodes.BALOAD)
    method.visitIntInsn(Opcodes.SIPUSH, 255)
    method.visitInsn(Opcodes.IAND)
    method.visitInsn(Opcodes.I2L)
    method.visitInsn(Opcodes.LOR)
    method.visitVarInsn(Opcodes.LSTORE, 2)
    method.visitIincInsn(4, 1)
    method.visitJumpInsn(Opcodes.GOTO, loop)
    method.visitLabel(done)
    method.visitVarInsn(Opcodes.LLOAD, 2)
    method.visitInsn(Opcodes.LRETURN)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}

private fun resolverEmitUnsignedByte(method: MethodNode, bytesSlot: Int, offset: Int) {
    method.visitVarInsn(Opcodes.ALOAD, bytesSlot)
    method.resolverPushInt(offset)
    method.visitInsn(Opcodes.BALOAD)
    method.visitIntInsn(Opcodes.SIPUSH, 255)
    method.visitInsn(Opcodes.IAND)
}

private fun resolverEmitZeroIvCipherInit(method: MethodNode, cipherSlot: Int, keySlot: Int) {
    method.visitVarInsn(Opcodes.ALOAD, cipherSlot)
    method.visitInsn(Opcodes.ICONST_2)
    method.visitVarInsn(Opcodes.ALOAD, keySlot)
    method.visitTypeInsn(Opcodes.NEW, "javax/crypto/spec/IvParameterSpec")
    method.visitInsn(Opcodes.DUP)
    method.visitIntInsn(Opcodes.BIPUSH, 8)
    method.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "javax/crypto/spec/IvParameterSpec", "<init>", "([B)V", false)
    method.visitMethodInsn(
        Opcodes.INVOKEVIRTUAL,
        "javax/crypto/Cipher",
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        false,
    )
}

private fun resolverIntBytes(value: Int): ByteArray = byteArrayOf(
    (value ushr 24).toByte(),
    (value ushr 16).toByte(),
    (value ushr 8).toByte(),
    value.toByte(),
)

private fun resolverIntDesBlock(value: Int): ByteArray = ByteArray(8).also { block ->
    resolverIntBytes(value).copyInto(block, destinationOffset = 4)
}

private fun resolverLongBytes(value: Long): ByteArray = ByteArray(8) { index ->
    (value ushr ((7 - index) * 8)).toByte()
}

private val INT_FIELD_DESCRIPTORS = setOf("Z", "B", "C", "S", "I")
private val INT_COVERAGE_LEVELS = setOf("none", "normal", "aggressive")
private val LONG_COVERAGE_LEVELS = setOf("none", "normal")
private val NUMERIC_RESOLVER_CODECS = setOf("xor")
