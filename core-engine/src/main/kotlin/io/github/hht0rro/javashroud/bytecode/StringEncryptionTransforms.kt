package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Random
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import io.github.hht0rro.javashroud.transforms.protection.VBC4_CLEAN_ENTRY_INTEGRITY_HEX
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext

/**
 * Configuration for native-backed string encryption.
 */
data class StringEncryptionConfig(
    val scope: String = "all-strings",
    val lengthThreshold: Int = 3,
    val seed: Long? = null,
)

private const val STRING_HELPER_OWNER = "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper"
private const val STRING_HELPER_DECODE_DESC = "([BII)Ljava/lang/String;"
private const val SHROUD_ENCRYPT_DESC = "Lio/github/hht0rro/javashroud/bytecode/ShroudEncrypt;"

/**
 * Replaces string LDC constants with native-backed cached decode callsites.
 */
fun encryptClassStrings(
    classBytes: ByteArray,
    config: StringEncryptionConfig = StringEncryptionConfig(),
): ByteArray {
    val reader = ClassReader(classBytes)
    val classNode = org.objectweb.asm.tree.ClassNode()
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) return classBytes

    val random = deterministicRandom(config.seed, classNode.name)
    val classSalt = mix32(classNode.name.hashCode() + random.nextInt())
    var encryptedCount = 0

    for (method in classNode.methods) {
        if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
        expandStringConcatRecipes(method)
        val annotated = hasShroudEncryptAnnotation(method)
        val instructions = method.instructions ?: continue
        val methodSalt = mix32(classSalt + method.name.hashCode() * 31 + method.desc.hashCode())
        for (insn in instructions.toArray()) {
            val value = (insn as? LdcInsnNode)?.cst as? String ?: continue
            if (!shouldEncryptString(value, config, annotated)) continue
            val literalSeed = mix32(methodSalt + encryptedCount + random.nextInt())
            val flags = mix32(classSalt.rotateLeft(5) + methodSalt.rotateRight(3) + encryptedCount)
            val payload = encodeStringPayload(value, literalSeed, flags)
            instructions.insert(insn, buildDecodeCallsite(literalSeed, flags, payload))
            instructions.remove(insn)
            encryptedCount++
        }
    }

    if (encryptedCount == 0) return classBytes

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}


private fun expandStringConcatRecipes(method: MethodNode) {
    val instructions = method.instructions ?: return
    for (insn in instructions.toArray()) {
        val indy = insn as? InvokeDynamicInsnNode ?: continue
        if (indy.bsm.owner != "java/lang/invoke/StringConcatFactory" || indy.bsm.name != "makeConcatWithConstants") continue
        val recipe = indy.bsmArgs.firstOrNull() as? String ?: continue
        val argTypes = Type.getArgumentTypes(indy.desc)
        val localSlots = IntArray(argTypes.size)
        var nextSlot = method.maxLocals.coerceAtLeast(0)
        for (index in argTypes.indices) {
            localSlots[index] = nextSlot
            nextSlot += argTypes[index].size
        }
        method.maxLocals = method.maxLocals.coerceAtLeast(nextSlot)

        val replacement = InsnList()
        for (index in argTypes.indices.reversed()) {
            replacement.addStore(argTypes[index], localSlots[index])
        }
        replacement.add(TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"))
        replacement.add(InsnNode(Opcodes.DUP))
        replacement.add(MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false))

        var argIndex = 0
        var constantArgIndex = 1
        val constantBuffer = StringBuilder()
        fun flushConstantBuffer() {
            if (constantBuffer.isEmpty()) return
            replacement.add(LdcInsnNode(constantBuffer.toString()))
            replacement.add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false))
            constantBuffer.clear()
        }

        for (char in recipe) {
            when (char) {
                '\u0001' -> {
                    flushConstantBuffer()
                    if (argIndex < argTypes.size) {
                        replacement.addLoad(argTypes[argIndex], localSlots[argIndex])
                        replacement.addStringBuilderAppend(argTypes[argIndex])
                        argIndex++
                    }
                }
                '\u0002' -> {
                    flushConstantBuffer()
                    val constant = indy.bsmArgs.getOrNull(constantArgIndex++)?.toString() ?: ""
                    replacement.add(LdcInsnNode(constant))
                    replacement.add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false))
                }
                else -> constantBuffer.append(char)
            }
        }
        flushConstantBuffer()
        replacement.add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false))
        instructions.insert(indy, replacement)
        instructions.remove(indy)
    }
}

private fun InsnList.addStore(type: Type, slot: Int) {
    add(VarInsnNode(type.getOpcode(Opcodes.ISTORE), slot))
}

private fun InsnList.addLoad(type: Type, slot: Int) {
    add(VarInsnNode(type.getOpcode(Opcodes.ILOAD), slot))
}

private fun InsnList.addStringBuilderAppend(type: Type) {
    val desc = when (type.sort) {
        Type.BOOLEAN -> "(Z)Ljava/lang/StringBuilder;"
        Type.CHAR -> "(C)Ljava/lang/StringBuilder;"
        Type.BYTE, Type.SHORT, Type.INT -> "(I)Ljava/lang/StringBuilder;"
        Type.FLOAT -> "(F)Ljava/lang/StringBuilder;"
        Type.LONG -> "(J)Ljava/lang/StringBuilder;"
        Type.DOUBLE -> "(D)Ljava/lang/StringBuilder;"
        else -> "(Ljava/lang/Object;)Ljava/lang/StringBuilder;"
    }
    add(MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", desc, false))
}
private fun deterministicRandom(seed: Long?, className: String): Random = if (seed != null) {
    Random(seed + className.hashCode().toLong())
} else {
    val bytes = ByteArray(Long.SIZE_BYTES)
    SecureRandom().nextBytes(bytes)
    var value = 0L
    for (byte in bytes) value = value * 257L + (byte.toLong() and 0xFFL)
    Random(value + className.hashCode().toLong())
}

private fun hiddenMemberName(prefix: String, className: String, salt: Int, random: Random): String {
    val value = mix32(className.hashCode() + salt + random.nextInt())
    return "_${prefix}_${value.toUInt().toString(36)}"
}

private fun hasShroudEncryptAnnotation(method: MethodNode): Boolean =
    method.visibleAnnotations.orEmpty().any { it.desc == SHROUD_ENCRYPT_DESC } ||
        method.invisibleAnnotations.orEmpty().any { it.desc == SHROUD_ENCRYPT_DESC }

private fun shouldEncryptString(value: String, config: StringEncryptionConfig, annotated: Boolean): Boolean = when (config.scope) {
    "length-threshold" -> value.length >= config.lengthThreshold
    "annotated" -> annotated
    else -> true
}

private fun buildDecodeCallsite(
    seed: Int,
    flags: Int,
    payload: ByteArray,
): InsnList = InsnList().apply {
    addByteArray(payload)
    addInt(seed)
    addInt(flags)
    add(MethodInsnNode(Opcodes.INVOKESTATIC, STRING_HELPER_OWNER, "cachedDecodeString", STRING_HELPER_DECODE_DESC, false))
}

private fun InsnList.addByteArray(bytes: ByteArray) {
    addInt(bytes.size)
    add(IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE))
    for (index in bytes.indices) {
        add(InsnNode(Opcodes.DUP))
        addInt(index)
        addInt(bytes[index].toInt())
        add(InsnNode(Opcodes.BASTORE))
    }
}

private fun InsnList.addInt(value: Int) {
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

internal fun encodeStringPayload(input: String, seed: Int, flags: Int): ByteArray {
    val plain = input.toByteArray(Charsets.UTF_8)
    return stringPayloadAesCtr(plain, seed, flags)
}

internal fun decodeStringPayload(payload: ByteArray, seed: Int, flags: Int): ByteArray = stringPayloadAesCtr(payload, seed, flags)

private fun stringPayloadAesCtr(data: ByteArray, seed: Int, flags: Int): ByteArray {
    // TASK-203 audit: string-encryption derivation root is Vbc4BuildContext
    // (master key + layout digest via session-integrity material), using
    // HMAC-SHA256 keyed PRF. This is cryptographically sound (not enumerable,
    // not non-cryptographic). Unification to the shared HKDF-SHA256 skeleton
    // (TASK-101) is deferred: it changes byte output and requires synchronized
    // native jsn_r21 changes + target-platform smoke testing.
    val buildContext = requireVbc4BuildContext()
    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    cipher.init(
        Cipher.ENCRYPT_MODE,
        SecretKeySpec(stringPayloadAesKey(buildContext, seed, flags, data.size), "AES"),
        IvParameterSpec(stringPayloadAesIv(buildContext, seed, flags, data.size)),
    )
    return cipher.doFinal(data)
}

private fun stringPayloadAesKey(buildContext: Vbc4BuildContext, seed: Int, flags: Int, length: Int): ByteArray =
    stringPayloadHmac(buildContext, "js-string-aes-key", seed, flags, length).copyOfRange(0, 16)

private fun stringPayloadAesIv(buildContext: Vbc4BuildContext, seed: Int, flags: Int, length: Int): ByteArray =
    stringPayloadHmac(buildContext, "js-string-aes-iv", seed, flags, length).copyOfRange(0, 16)

private fun stringPayloadHmac(buildContext: Vbc4BuildContext, label: String, seed: Int, flags: Int, length: Int): ByteArray {
    val parts = listOf(
        label.toByteArray(Charsets.US_ASCII),
        intBytes(seed),
        intBytes(flags),
        intBytes(length),
    )
    val sessionMaterial = MessageDigest.getInstance("SHA-256").apply {
        update("vbc4-session-integrity".toByteArray(Charsets.US_ASCII))
        update(buildContext.copyMasterKey())
        update(buildContext.jarLayoutDigest)
        update(cleanEntryIntegrityBytes())
    }.digest()
    val scopedKey = hmacSha256(sessionMaterial, parts)
    return hmacSha256(scopedKey, parts)
}

private fun hmacSha256(key: ByteArray, parts: List<ByteArray>): ByteArray {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(key, "HmacSHA256"))
    for (part in parts) mac.update(part)
    return mac.doFinal()
}

private fun cleanEntryIntegrityBytes(): ByteArray = VBC4_CLEAN_ENTRY_INTEGRITY_HEX.chunked(2)
    .map { it.toInt(16).toByte() }
    .toByteArray()

private fun intBytes(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xFF).toByte(),
    ((value ushr 16) and 0xFF).toByte(),
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte(),
)
private fun mix32(value: Int): Int {
    var x = value
    x += x.rotateRight(16)
    x *= 0x7FEB352D
    x += x.rotateRight(15)
    x *= 0x846CA68B.toInt()
    x += x.rotateRight(16)
    return x
}
