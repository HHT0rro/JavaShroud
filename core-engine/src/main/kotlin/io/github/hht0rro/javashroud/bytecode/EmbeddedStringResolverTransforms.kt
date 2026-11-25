package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Label
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
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.util.Base64
import java.util.Random
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

private const val SHROUD_ENCRYPT_DESC = "Lio/github/hht0rro/javashroud/bytecode/ShroudEncrypt;"
private const val STRING_ARRAY_DESC = "[Ljava/lang/String;"
private const val STRING_RESOLVER_DESC = "(I)Ljava/lang/String;"
private const val INT_ARRAY_DESC = "[I"
private const val BYTE_ARRAY_DESC = "[B"

/**
 * Replaces string literals with a class-local resolver and cache without pulling in a native runtime.
 */
fun encryptClassStringsEmbeddedResolver(
    classBytes: ByteArray,
    config: EmbeddedStringResolverConfig = EmbeddedStringResolverConfig(),
): ByteArray {
    val reader = ClassReader(classBytes)
    val classNode = ClassNode()
    reader.accept(classNode, 0)
    if (!resolverSupportsInjectedMembers(classNode)) return classBytes

    val strength = config.strength
    require(strength in STRING_RESOLVER_STRENGTHS) {
        "string-encryption strength '$strength' is not supported; supported values: ${STRING_RESOLVER_STRENGTHS.joinToString(", ")}"
    }
    val codec = config.payloadCodec ?: when (strength) {
        "max" -> "aes-gcm"
        else -> "xor"
    }
    require(codec != "des") { "string-encryption payloadCodec 'des' is retired; use aes-gcm" }
    require(codec in STRING_PAYLOAD_CODECS) {
        "string-encryption payloadCodec '$codec' is not supported; supported values: ${STRING_PAYLOAD_CODECS.joinToString(", ")}"
    }
    require(config.scope in STRING_ENCRYPTION_SCOPES) {
        "string-encryption scope '${config.scope}' is not supported; supported values: ${STRING_ENCRYPTION_SCOPES.joinToString(", ")}"
    }
    require(config.lengthThreshold >= 0) { "string-encryption lengthThreshold must be >= 0" }

    val isInterface = classNode.access and Opcodes.ACC_INTERFACE != 0
    val random = resolverRandom(config.seed, classNode.name)
    val classSeed = random.nextInt() xor classNode.name.hashCode()
    val payloadField = resolverUniqueMemberName(classNode, "sp", random)
    val cacheField = resolverUniqueMemberName(classNode, "sc", random)
    val desKeyField = if (codec == "aes-gcm") resolverUniqueMemberName(classNode, "sk", random) else null
    val indexedKeyField = if (codec == "indexed") resolverUniqueMemberName(classNode, "ik", random) else null
    val indexedSlotField = if (codec == "indexed") resolverUniqueMemberName(classNode, "is", random) else null
    val permutationField = if (codec == "indexed") resolverUniqueMemberName(classNode, "ip", random) else null
    val resolverName = resolverUniqueMemberName(classNode, "sr", random)
    val payloads = mutableListOf<String>()
    val desKeys = mutableListOf<String>()
    val indexedKeys = mutableListOf<Int>()
    val permutation = if (codec == "indexed") resolverIndexedPermutation(random) else null
    val fieldInitializers = InsnList()

    for (method in classNode.methods) {
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        expandStringConcatRecipes(method)
        val annotated = resolverHasEncryptAnnotation(method)
        for (instruction in method.instructions.toArray()) {
            val literal = (instruction as? LdcInsnNode)?.cst as? String ?: continue
            if (!resolverShouldEncryptString(literal, config, annotated)) continue
            val index = payloads.size
            val encoded = resolverEncodeString(literal, codec, classSeed, index, random, permutation)
            payloads += encoded.payload
            encoded.desKey?.let(desKeys::add)
            encoded.indexedKey?.let(indexedKeys::add)
            val callsite = InsnList().apply {
                resolverPushInt(index)
                add(MethodInsnNode(Opcodes.INVOKESTATIC, classNode.name, resolverName, STRING_RESOLVER_DESC, isInterface))
            }
            method.instructions.insertBefore(instruction, callsite)
            method.instructions.remove(instruction)
        }
    }

    val encryptInterfaceConstantValues = strength != "standard"
    for (field in classNode.fields.toList()) {
        val value = field.value as? String ?: continue
        if (field.desc != "Ljava/lang/String;" || field.access and Opcodes.ACC_STATIC == 0) continue
        if (isInterface && !encryptInterfaceConstantValues) continue
        if (!resolverShouldEncryptString(value, config, annotated = false)) continue

        val index = payloads.size
        val encoded = resolverEncodeString(value, codec, classSeed, index, random, permutation)
        payloads += encoded.payload
        encoded.desKey?.let(desKeys::add)
        encoded.indexedKey?.let(indexedKeys::add)
        field.value = null
        fieldInitializers.resolverPushInt(index)
        fieldInitializers.add(
            MethodInsnNode(
                Opcodes.INVOKESTATIC,
                classNode.name,
                resolverName,
                STRING_RESOLVER_DESC,
                isInterface,
            ),
        )
        fieldInitializers.add(FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, field.name, field.desc))
    }

    if (payloads.isEmpty()) return classBytes

    val indexedSlots = if (codec == "indexed") resolverIndexedSlots(payloads.size, random) else emptyList()
    val fieldAccess = resolverFieldAccess(isInterface)
    classNode.fields.add(FieldNode(fieldAccess, payloadField, STRING_ARRAY_DESC, null, null))
    classNode.fields.add(FieldNode(fieldAccess, cacheField, STRING_ARRAY_DESC, null, null))
    if (desKeyField != null) classNode.fields.add(FieldNode(fieldAccess, desKeyField, STRING_ARRAY_DESC, null, null))
    if (indexedKeyField != null) classNode.fields.add(FieldNode(fieldAccess, indexedKeyField, INT_ARRAY_DESC, null, null))
    if (indexedSlotField != null) classNode.fields.add(FieldNode(fieldAccess, indexedSlotField, INT_ARRAY_DESC, null, null))
    if (permutationField != null) classNode.fields.add(FieldNode(fieldAccess, permutationField, BYTE_ARRAY_DESC, null, null))

    val init = InsnList()
    init.add(resolverStringArrayInitialization(classNode.name, payloadField, payloads))
    init.add(resolverEmptyStringArrayInitialization(classNode.name, cacheField, payloads.size))
    if (desKeyField != null) init.add(resolverStringArrayInitialization(classNode.name, desKeyField, desKeys))
    if (indexedKeyField != null) init.add(resolverIntArrayInitialization(classNode.name, indexedKeyField, indexedKeys))
    if (indexedSlotField != null) init.add(resolverIntArrayInitialization(classNode.name, indexedSlotField, indexedSlots))
    if (permutationField != null) init.add(resolverByteArrayInitialization(classNode.name, permutationField, checkNotNull(permutation)))
    init.add(fieldInitializers)
    prependResolverClassInit(classNode, init)

    val injectDeadFlow = strength == "flow-guarded"
    classNode.methods.add(
        when (codec) {
            "aes-gcm" -> createDesStringResolver(
                classNode.name,
                isInterface,
                resolverName,
                payloadField,
                cacheField,
                checkNotNull(desKeyField),
                injectDeadFlow,
            )
            "indexed" -> createIndexedStringResolver(
                classNode.name,
                isInterface,
                resolverName,
                payloadField,
                cacheField,
                checkNotNull(indexedKeyField),
                checkNotNull(indexedSlotField),
                checkNotNull(permutationField),
                injectDeadFlow,
            )
            else -> createXorStringResolver(
                classNode.name,
                isInterface,
                resolverName,
                payloadField,
                cacheField,
                classSeed,
                injectDeadFlow,
            )
        },
    )

    val writer = computeFramesWriter()
    classNode.accept(writer)
    return writer.toByteArray()
}

private data class ResolverEncodedString(
    val payload: String,
    val desKey: String? = null,
    val indexedKey: Int? = null,
)

private fun resolverEncodeString(
    value: String,
    codec: String,
    classSeed: Int,
    index: Int,
    random: Random,
    permutation: ByteArray?,
): ResolverEncodedString {
    val plain = value.toByteArray(Charsets.UTF_8)
    return when (codec) {
        "aes-gcm" -> {
            val key = ByteArray(16).also(random::nextBytes)
            val nonce = ByteArray(12).also(random::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), javax.crypto.spec.GCMParameterSpec(128, nonce))
            ResolverEncodedString(
                payload = Base64.getEncoder().encodeToString(nonce + cipher.doFinal(plain)),
                desKey = Base64.getEncoder().encodeToString(key),
            )
        }
        "indexed" -> {
            val encoded = resolverEncodeIndexedString(plain, random.nextInt(), checkNotNull(permutation))
            ResolverEncodedString(
                payload = Base64.getEncoder().encodeToString(encoded.payload),
                indexedKey = encoded.key,
            )
        }
        else -> ResolverEncodedString(
            payload = Base64.getEncoder().encodeToString(resolverXorBytes(plain, classSeed, index)),
        )
    }
}

private fun resolverShouldEncryptString(value: String, config: EmbeddedStringResolverConfig, annotated: Boolean): Boolean = when (config.scope) {
    "annotated" -> annotated
    "length-threshold" -> value.length >= config.lengthThreshold
    else -> true
}

private fun resolverHasEncryptAnnotation(method: MethodNode): Boolean =
    method.visibleAnnotations.orEmpty().any { it.desc == SHROUD_ENCRYPT_DESC } ||
        method.invisibleAnnotations.orEmpty().any { it.desc == SHROUD_ENCRYPT_DESC }

private fun resolverEmptyStringArrayInitialization(owner: String, fieldName: String, size: Int): InsnList = InsnList().apply {
    resolverPushInt(size)
    add(TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"))
    add(FieldInsnNode(Opcodes.PUTSTATIC, owner, fieldName, STRING_ARRAY_DESC))
}

private fun resolverByteArrayInitialization(owner: String, fieldName: String, values: ByteArray): InsnList = InsnList().apply {
    resolverPushInt(values.size)
    add(IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE))
    add(FieldInsnNode(Opcodes.PUTSTATIC, owner, fieldName, BYTE_ARRAY_DESC))
    values.forEachIndexed { index, value ->
        add(FieldInsnNode(Opcodes.GETSTATIC, owner, fieldName, BYTE_ARRAY_DESC))
        resolverPushInt(index)
        resolverPushInt(value.toInt() and 0xFF)
        add(InsnNode(Opcodes.I2B))
        add(InsnNode(Opcodes.BASTORE))
    }
}

private fun resolverIndexedPermutation(random: Random): ByteArray {
    val values = IntArray(256) { it }
    for (index in values.lastIndex downTo 1) {
        val swap = random.nextInt(index + 1)
        val value = values[index]
        values[index] = values[swap]
        values[swap] = value
    }
    return ByteArray(values.size) { values[it].toByte() }
}

private fun resolverIndexedSlots(size: Int, random: Random): List<Int> {
    val slots = MutableList(size) { it }
    for (index in slots.lastIndex downTo 1) {
        val swap = random.nextInt(index + 1)
        val value = slots[index]
        slots[index] = slots[swap]
        slots[swap] = value
    }
    return slots
}

private data class ResolverIndexedCiphertext(val payload: ByteArray, val key: Int)

private fun resolverEncodeIndexedString(plain: ByteArray, randomKey: Int, permutation: ByteArray): ResolverIndexedCiphertext {
    if (plain.isEmpty()) return ResolverIndexedCiphertext(ByteArray(0), randomKey)

    // Pick the first cipher byte, then derive the low key byte that satisfies P[cipher[0]].
    val firstCipher = (randomKey ushr 16) and 0xFF
    val salt = permutation[firstCipher].toInt() and 0xFF
    val firstPlain = plain[0].toInt() and 0xFF
    val lowKeyByte = ((firstCipher xor firstPlain) + salt) and 0xFF
    val key = (randomKey and -0x10000) or (randomKey and 0xFF00) or lowKeyByte
    val cipher = ByteArray(plain.size)
    var even = ((key and 0xFF) - salt) and 0xFF
    var odd = (((key and 0xFFFF) ushr 8) - salt) and 0xFF
    for (index in plain.indices) {
        val value = plain[index].toInt() and 0xFF
        val state = if (index and 1 == 0) even else odd
        cipher[index] = (value xor state).toByte()
        val updated = resolverRotateRight8(state, 3) xor value
        if (index and 1 == 0) even = updated else odd = updated
    }
    return ResolverIndexedCiphertext(cipher, key)
}

private fun resolverRotateRight8(value: Int, count: Int): Int =
    ((value ushr count) or (value shl (8 - count))) and 0xFF

private fun createXorStringResolver(
    owner: String,
    isInterface: Boolean,
    name: String,
    payloadField: String,
    cacheField: String,
    classSeed: Int,
    injectDeadFlow: Boolean,
): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, STRING_RESOLVER_DESC, null, null)
    val cacheMiss = Label()
    val loop = Label()
    val loopDone = Label()
    method.visitCode()
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitVarInsn(Opcodes.ASTORE, 1)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitJumpInsn(Opcodes.IFNULL, cacheMiss)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitInsn(Opcodes.ARETURN)

    method.visitLabel(cacheMiss)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder", "()Ljava/util/Base64\$Decoder;", false)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, payloadField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Base64\$Decoder", "decode", "(Ljava/lang/String;)[B", false)
    method.visitVarInsn(Opcodes.ASTORE, 2)
    method.visitLdcInsn(classSeed)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitLdcInsn(0x45D9F3B)
    method.visitInsn(Opcodes.IMUL)
    method.visitInsn(Opcodes.IXOR)
    method.visitVarInsn(Opcodes.ISTORE, 3)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitVarInsn(Opcodes.ISTORE, 4)
    method.visitLabel(loop)
    method.visitVarInsn(Opcodes.ILOAD, 4)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitInsn(Opcodes.ARRAYLENGTH)
    method.visitJumpInsn(Opcodes.IF_ICMPGE, loopDone)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitVarInsn(Opcodes.ILOAD, 4)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitVarInsn(Opcodes.ILOAD, 4)
    method.visitInsn(Opcodes.BALOAD)
    method.visitVarInsn(Opcodes.ILOAD, 3)
    method.visitVarInsn(Opcodes.ILOAD, 4)
    method.visitInsn(Opcodes.ICONST_3)
    method.visitInsn(Opcodes.IAND)
    method.visitInsn(Opcodes.ICONST_3)
    method.visitInsn(Opcodes.ISHL)
    method.visitInsn(Opcodes.IUSHR)
    method.visitVarInsn(Opcodes.ILOAD, 4)
    method.resolverPushInt(31)
    method.visitInsn(Opcodes.IMUL)
    method.visitInsn(Opcodes.IXOR)
    method.visitInsn(Opcodes.IXOR)
    method.visitInsn(Opcodes.I2B)
    method.visitInsn(Opcodes.BASTORE)
    method.visitIincInsn(4, 1)
    method.visitJumpInsn(Opcodes.GOTO, loop)
    method.visitLabel(loopDone)
    method.visitTypeInsn(Opcodes.NEW, "java/lang/String")
    method.visitInsn(Opcodes.DUP)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitFieldInsn(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;")
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([BLjava/nio/charset/Charset;)V", false)
    method.visitVarInsn(Opcodes.ASTORE, 5)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitInsn(Opcodes.AASTORE)
    if (injectDeadFlow) resolverDeadFlow(method, 3)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitInsn(Opcodes.ARETURN)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}

/**
 * Resolver for the indexed codec.  The token remains an int so existing
 * indy indirection can wrap it, while key and cache slots stay class-local.
 */
private fun createIndexedStringResolver(
    owner: String,
    isInterface: Boolean,
    name: String,
    payloadField: String,
    cacheField: String,
    keyField: String,
    slotField: String,
    permutationField: String,
    injectDeadFlow: Boolean,
): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, STRING_RESOLVER_DESC, null, null)
    val cacheMiss = Label()
    val nonEmpty = Label()
    val loop = Label()
    val loopDone = Label()
    val oddLane = Label()
    val stateReady = Label()
    val updateOdd = Label()
    val loopNext = Label()
    val decoded = Label()

    method.visitCode()
    // token -> shuffled cache slot
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, slotField, INT_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.IALOAD)
    method.visitVarInsn(Opcodes.ISTORE, 1)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 1)
    method.visitInsn(Opcodes.AALOAD)
    method.visitVarInsn(Opcodes.ASTORE, 2)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitJumpInsn(Opcodes.IFNULL, cacheMiss)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitInsn(Opcodes.ARETURN)

    method.visitLabel(cacheMiss)
    method.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "java/util/Base64",
        "getDecoder",
        "()Ljava/util/Base64\$Decoder;",
        false,
    )
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, payloadField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitMethodInsn(
        Opcodes.INVOKEVIRTUAL,
        "java/util/Base64\$Decoder",
        "decode",
        "(Ljava/lang/String;)[B",
        false,
    )
    method.visitVarInsn(Opcodes.ASTORE, 3)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, keyField, INT_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.IALOAD)
    method.visitVarInsn(Opcodes.ISTORE, 4)
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitInsn(Opcodes.ARRAYLENGTH)
    method.visitJumpInsn(Opcodes.IFNE, nonEmpty)
    method.visitJumpInsn(Opcodes.GOTO, decoded)

    method.visitLabel(nonEmpty)
    // salt = P[cipher[0] & 0xff]
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, permutationField, BYTE_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitInsn(Opcodes.BALOAD)
    method.visitIntInsn(Opcodes.SIPUSH, 0xFF)
    method.visitInsn(Opcodes.IAND)
    method.visitInsn(Opcodes.BALOAD)
    method.visitIntInsn(Opcodes.SIPUSH, 0xFF)
    method.visitInsn(Opcodes.IAND)
    method.visitVarInsn(Opcodes.ISTORE, 5)
    // even = ((key & 0xff) - salt) & 0xff
    method.visitVarInsn(Opcodes.ILOAD, 4)
    method.visitIntInsn(Opcodes.SIPUSH, 0xFF)
    method.visitInsn(Opcodes.IAND)
    method.visitVarInsn(Opcodes.ILOAD, 5)
    method.visitInsn(Opcodes.ISUB)
    method.visitIntInsn(Opcodes.SIPUSH, 0xFF)
    method.visitInsn(Opcodes.IAND)
    method.visitVarInsn(Opcodes.ISTORE, 6)
    // odd = (((key & 0xffff) >>> 8) - salt) & 0xff
    method.visitVarInsn(Opcodes.ILOAD, 4)
    method.visitLdcInsn(0xFFFF)
    method.visitInsn(Opcodes.IAND)
    method.visitIntInsn(Opcodes.BIPUSH, 8)
    method.visitInsn(Opcodes.IUSHR)
    method.visitVarInsn(Opcodes.ILOAD, 5)
    method.visitInsn(Opcodes.ISUB)
    method.visitIntInsn(Opcodes.SIPUSH, 0xFF)
    method.visitInsn(Opcodes.IAND)
    method.visitVarInsn(Opcodes.ISTORE, 7)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitVarInsn(Opcodes.ISTORE, 8)

    method.visitLabel(loop)
    method.visitVarInsn(Opcodes.ILOAD, 8)
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitInsn(Opcodes.ARRAYLENGTH)
    method.visitJumpInsn(Opcodes.IF_ICMPGE, loopDone)
    method.visitVarInsn(Opcodes.ILOAD, 8)
    method.visitInsn(Opcodes.ICONST_1)
    method.visitInsn(Opcodes.IAND)
    method.visitJumpInsn(Opcodes.IFNE, oddLane)
    method.visitVarInsn(Opcodes.ILOAD, 6)
    method.visitVarInsn(Opcodes.ISTORE, 9)
    method.visitJumpInsn(Opcodes.GOTO, stateReady)
    method.visitLabel(oddLane)
    method.visitVarInsn(Opcodes.ILOAD, 7)
    method.visitVarInsn(Opcodes.ISTORE, 9)
    method.visitLabel(stateReady)

    // plain = cipher[i] ^ state; write it back in place.
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitVarInsn(Opcodes.ILOAD, 8)
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitVarInsn(Opcodes.ILOAD, 8)
    method.visitInsn(Opcodes.BALOAD)
    method.visitIntInsn(Opcodes.SIPUSH, 0xFF)
    method.visitInsn(Opcodes.IAND)
    method.visitVarInsn(Opcodes.ILOAD, 9)
    method.visitInsn(Opcodes.IXOR)
    method.visitVarInsn(Opcodes.ISTORE, 10)
    method.visitVarInsn(Opcodes.ILOAD, 10)
    method.visitInsn(Opcodes.I2B)
    method.visitInsn(Opcodes.BASTORE)

    // state = ROR8(state, 3) ^ plain; update the matching parity lane.
    method.visitVarInsn(Opcodes.ILOAD, 9)
    method.visitIntInsn(Opcodes.BIPUSH, 3)
    method.visitInsn(Opcodes.IUSHR)
    method.visitVarInsn(Opcodes.ILOAD, 9)
    method.visitIntInsn(Opcodes.BIPUSH, 5)
    method.visitInsn(Opcodes.ISHL)
    method.visitInsn(Opcodes.IOR)
    method.visitIntInsn(Opcodes.SIPUSH, 0xFF)
    method.visitInsn(Opcodes.IAND)
    method.visitVarInsn(Opcodes.ILOAD, 10)
    method.visitInsn(Opcodes.IXOR)
    method.visitVarInsn(Opcodes.ISTORE, 11)
    method.visitVarInsn(Opcodes.ILOAD, 8)
    method.visitInsn(Opcodes.ICONST_1)
    method.visitInsn(Opcodes.IAND)
    method.visitJumpInsn(Opcodes.IFNE, updateOdd)
    method.visitVarInsn(Opcodes.ILOAD, 11)
    method.visitVarInsn(Opcodes.ISTORE, 6)
    method.visitJumpInsn(Opcodes.GOTO, loopNext)
    method.visitLabel(updateOdd)
    method.visitVarInsn(Opcodes.ILOAD, 11)
    method.visitVarInsn(Opcodes.ISTORE, 7)
    method.visitLabel(loopNext)
    method.visitIincInsn(8, 1)
    method.visitJumpInsn(Opcodes.GOTO, loop)
    method.visitLabel(loopDone)

    method.visitLabel(decoded)
    method.visitTypeInsn(Opcodes.NEW, "java/lang/String")
    method.visitInsn(Opcodes.DUP)
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitFieldInsn(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;")
    method.visitMethodInsn(
        Opcodes.INVOKESPECIAL,
        "java/lang/String",
        "<init>",
        "([BLjava/nio/charset/Charset;)V",
        false,
    )
    method.visitVarInsn(Opcodes.ASTORE, 12)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 1)
    method.visitVarInsn(Opcodes.ALOAD, 12)
    method.visitInsn(Opcodes.AASTORE)
    if (injectDeadFlow) resolverDeadFlow(method, 4)
    method.visitVarInsn(Opcodes.ALOAD, 12)
    method.visitInsn(Opcodes.ARETURN)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}

private fun createDesStringResolver(
    owner: String,
    isInterface: Boolean,
    name: String,
    payloadField: String,
    cacheField: String,
    keyField: String,
    injectDeadFlow: Boolean,
): MethodNode {
    val method = MethodNode(resolverMemberAccess(isInterface), name, STRING_RESOLVER_DESC, null, null)
    val cacheMiss = Label()
    val tryStart = Label()
    val tryEnd = Label()
    val failure = Label()
    method.visitTryCatchBlock(tryStart, tryEnd, failure, "java/lang/Exception")
    method.visitCode()
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitVarInsn(Opcodes.ASTORE, 1)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitJumpInsn(Opcodes.IFNULL, cacheMiss)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitInsn(Opcodes.ARETURN)

    method.visitLabel(cacheMiss)
    method.visitLabel(tryStart)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder", "()Ljava/util/Base64\$Decoder;", false)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, payloadField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Base64\$Decoder", "decode", "(Ljava/lang/String;)[B", false)
    method.visitVarInsn(Opcodes.ASTORE, 2)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitIntInsn(Opcodes.BIPUSH, 12)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Arrays", "copyOfRange", "([BII)[B", false)
    method.visitVarInsn(Opcodes.ASTORE, 7)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitIntInsn(Opcodes.BIPUSH, 12)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitInsn(Opcodes.ARRAYLENGTH)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Arrays", "copyOfRange", "([BII)[B", false)
    method.visitVarInsn(Opcodes.ASTORE, 8)
    method.visitTypeInsn(Opcodes.NEW, "javax/crypto/spec/SecretKeySpec")
    method.visitInsn(Opcodes.DUP)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder", "()Ljava/util/Base64\$Decoder;", false)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, keyField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitInsn(Opcodes.AALOAD)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Base64\$Decoder", "decode", "(Ljava/lang/String;)[B", false)
    method.visitLdcInsn("AES")
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "javax/crypto/spec/SecretKeySpec", "<init>", "([BLjava/lang/String;)V", false)
    method.visitVarInsn(Opcodes.ASTORE, 3)
    method.visitLdcInsn("AES/GCM/NoPadding")
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "javax/crypto/Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", false)
    method.visitVarInsn(Opcodes.ASTORE, 4)
    method.visitVarInsn(Opcodes.ALOAD, 4)
    method.visitInsn(Opcodes.ICONST_2)
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitTypeInsn(Opcodes.NEW, "javax/crypto/spec/GCMParameterSpec")
    method.visitInsn(Opcodes.DUP)
    method.visitIntInsn(Opcodes.SIPUSH, 128)
    method.visitVarInsn(Opcodes.ALOAD, 7)
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "javax/crypto/spec/GCMParameterSpec", "<init>", "(I[B)V", false)
    method.visitMethodInsn(
        Opcodes.INVOKEVIRTUAL,
        "javax/crypto/Cipher",
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        false,
    )
    method.visitTypeInsn(Opcodes.NEW, "java/lang/String")
    method.visitInsn(Opcodes.DUP)
    method.visitVarInsn(Opcodes.ALOAD, 4)
    method.visitVarInsn(Opcodes.ALOAD, 8)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "javax/crypto/Cipher", "doFinal", "([B)[B", false)
    method.visitFieldInsn(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;")
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([BLjava/nio/charset/Charset;)V", false)
    method.visitVarInsn(Opcodes.ASTORE, 5)
    method.visitFieldInsn(Opcodes.GETSTATIC, owner, cacheField, STRING_ARRAY_DESC)
    method.visitVarInsn(Opcodes.ILOAD, 0)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitInsn(Opcodes.AASTORE)
    if (injectDeadFlow) resolverDeadFlow(method, 0)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitLabel(tryEnd)
    method.visitInsn(Opcodes.ARETURN)
    method.visitLabel(failure)
    method.visitVarInsn(Opcodes.ASTORE, 6)
    method.visitTypeInsn(Opcodes.NEW, "java/lang/IllegalStateException")
    method.visitInsn(Opcodes.DUP)
    method.visitLdcInsn("Embedded string resolver failed")
    method.visitVarInsn(Opcodes.ALOAD, 6)
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "(Ljava/lang/String;Ljava/lang/Throwable;)V", false)
    method.visitInsn(Opcodes.ATHROW)
    method.visitMaxs(0, 0)
    method.visitEnd()
    return method
}

private val STRING_RESOLVER_STRENGTHS = setOf("standard", "strong", "flow-guarded", "max")
private val STRING_PAYLOAD_CODECS = setOf("xor", "indexed", "aes-gcm")
private val STRING_ENCRYPTION_SCOPES = setOf("all-strings", "annotated", "length-threshold")
