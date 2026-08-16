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
import java.util.Arrays
import java.util.Base64
import java.util.Random
import io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenStringPageCandidate

/**
 * Configuration for native-backed string encryption.
 */
data class StringEncryptionConfig(
    val scope: String = "all-strings",
    val lengthThreshold: Int = 3,
    val seed: Long? = null,
)

private const val STRING_HELPER_OWNER = "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper"
private const val STRING_HELPER_AKEN_DECODE_DESC = "([BI[B)Ljava/lang/String;"
private const val SHROUD_ENCRYPT_DESC = "Lio/github/hht0rro/javashroud/bytecode/ShroudEncrypt;"
private const val AKEN_STRING_PAGE_INDEX = 0
private const val AKEN_STRING_PAGE_NONCE_SIZE = 16

private val AKEN_STRING_PAGE_IDENTITY_DOMAIN =
    "AKEN-v4-string-page-logical-identity-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_HANDLE_DOMAIN =
    "AKEN-v4-string-page-handle-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_PROOF_DOMAIN =
    "AKEN-v4-string-page-call-site-proof-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_PATH_DOMAIN =
    "AKEN-v4-string-page-logical-path-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_PATH_ROOTS = arrayOf(
    "META-INF/.a4/s",
    "META-INF/.r4/p",
    "assets/.a4/s",
    "META-INF/.j4/r",
)
private val AKEN_STRING_PAGE_PATH_SUFFIXES = arrayOf(".bin", ".dat", ".p", ".r")

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
    val candidateRandom = SecureRandom()
    val candidates = ArrayList<AkenStringPageCandidate>()
    var encryptedCount = 0

    try {
        for (method in classNode.methods) {
            if ((method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) continue
            expandStringConcatRecipes(method)
            val annotated = hasShroudEncryptAnnotation(method)
            val instructions = method.instructions ?: continue
            var methodLiteralOrdinal = 0
            for (insn in instructions.toArray()) {
                val value = (insn as? LdcInsnNode)?.cst as? String ?: continue
                if (value.isEmpty() || !shouldEncryptString(value, config, annotated)) continue

                val buildNonce = ByteArray(AKEN_STRING_PAGE_NONCE_SIZE).also(random::nextBytes)
                var logicalIdentity: ByteArray? = null
                var plaintext: ByteArray? = null
                var encodedHandle: ByteArray? = null
                var callSiteProof: ByteArray? = null
                var candidate: AkenStringPageCandidate? = null
                try {
                    logicalIdentity = deriveAkenStringPageIdentity(
                        classInternalName = classNode.name,
                        methodName = method.name,
                        methodDescriptor = method.desc,
                        classLiteralOrdinal = encryptedCount,
                        methodLiteralOrdinal = methodLiteralOrdinal,
                        buildNonce = buildNonce,
                    )
                    encodedHandle = deriveAkenStringPageHandle(logicalIdentity, buildNonce)
                    val logicalBindingPath = akenStringPageLogicalBindingPath(logicalIdentity, encodedHandle)
                    callSiteProof = deriveAkenStringPageCallSiteProof(
                        logicalIdentity = logicalIdentity,
                        encodedHandle = encodedHandle,
                        pageIndex = AKEN_STRING_PAGE_INDEX,
                        logicalBindingPath = logicalBindingPath,
                    )
                    plaintext = value.toByteArray(Charsets.UTF_8)
                    candidate = AkenStringPageCandidate.create(
                        logicalIdentity = logicalIdentity,
                        plaintext = plaintext,
                        pageIndex = AKEN_STRING_PAGE_INDEX,
                        callSiteProof = callSiteProof,
                        encodedHandle = encodedHandle,
                        logicalBindingPath = logicalBindingPath,
                        random = candidateRandom,
                    )
                    val decodeCallsite = buildAkenStringPageDecodeCallsite(
                        encodedHandle = encodedHandle,
                        pageIndex = AKEN_STRING_PAGE_INDEX,
                        callSiteProof = callSiteProof,
                    )
                    instructions.insert(insn, decodeCallsite)
                    instructions.remove(insn)
                    candidates += candidate
                    candidate = null
                    encryptedCount++
                    methodLiteralOrdinal++
                } finally {
                    candidate?.wipe()
                    Arrays.fill(buildNonce, 0)
                    logicalIdentity?.let { Arrays.fill(it, 0) }
                    plaintext?.let { Arrays.fill(it, 0) }
                    encodedHandle?.let { Arrays.fill(it, 0) }
                    callSiteProof?.let { Arrays.fill(it, 0) }
                }
            }
        }

        if (encryptedCount == 0) return classBytes

        val writer = computeFramesWriter(reader)
        classNode.accept(writer)
        val transformed = writer.toByteArray()
        requireVbc4BuildContext().registerAkenStringPageCandidates(candidates)
        return transformed
    } finally {
        candidates.forEach { it.wipe() }
    }
}


internal fun expandStringConcatRecipes(method: MethodNode) {
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

private fun hasShroudEncryptAnnotation(method: MethodNode): Boolean =
    method.visibleAnnotations.orEmpty().any { it.desc == SHROUD_ENCRYPT_DESC } ||
        method.invisibleAnnotations.orEmpty().any { it.desc == SHROUD_ENCRYPT_DESC }

private fun shouldEncryptString(value: String, config: StringEncryptionConfig, annotated: Boolean): Boolean = when (config.scope) {
    "length-threshold" -> value.length >= config.lengthThreshold
    "annotated" -> annotated
    else -> true
}

private fun buildAkenStringPageDecodeCallsite(
    encodedHandle: ByteArray,
    pageIndex: Int,
    callSiteProof: ByteArray,
): InsnList = InsnList().apply {
    addByteArray(encodedHandle)
    addInt(pageIndex)
    addByteArray(callSiteProof)
    add(
        MethodInsnNode(
            Opcodes.INVOKESTATIC,
            STRING_HELPER_OWNER,
            "cachedDecodeAkenStringPage",
            STRING_HELPER_AKEN_DECODE_DESC,
            false,
        ),
    )
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

private fun deriveAkenStringPageIdentity(
    classInternalName: String,
    methodName: String,
    methodDescriptor: String,
    classLiteralOrdinal: Int,
    methodLiteralOrdinal: Int,
    buildNonce: ByteArray,
): ByteArray = MessageDigest.getInstance("SHA-256").apply {
    update(AKEN_STRING_PAGE_IDENTITY_DOMAIN)
    updateAkenString(classInternalName)
    updateAkenString(methodName)
    updateAkenString(methodDescriptor)
    updateAkenInt(classLiteralOrdinal)
    updateAkenInt(methodLiteralOrdinal)
    updateAkenBytes(buildNonce)
}.digest()

private fun deriveAkenStringPageHandle(
    logicalIdentity: ByteArray,
    buildNonce: ByteArray,
): ByteArray {
    val digest = digestAkenBinding(AKEN_STRING_PAGE_HANDLE_DOMAIN, logicalIdentity, buildNonce)
    return try {
        digest.copyOf(AkenHandle.ENCODED_HANDLE_SIZE)
    } finally {
        Arrays.fill(digest, 0)
    }
}

private fun deriveAkenStringPageCallSiteProof(
    logicalIdentity: ByteArray,
    encodedHandle: ByteArray,
    pageIndex: Int,
    logicalBindingPath: String,
): ByteArray {
    val pageBytes = intBytes(pageIndex)
    val pathBytes = logicalBindingPath.toByteArray(Charsets.UTF_8)
    return try {
        digestAkenBinding(
            AKEN_STRING_PAGE_PROOF_DOMAIN,
            logicalIdentity,
            encodedHandle,
            pageBytes,
            pathBytes,
        )
    } finally {
        Arrays.fill(pageBytes, 0)
        Arrays.fill(pathBytes, 0)
    }
}

private fun akenStringPageLogicalBindingPath(
    logicalIdentity: ByteArray,
    encodedHandle: ByteArray,
): String {
    val digest = digestAkenBinding(AKEN_STRING_PAGE_PATH_DOMAIN, logicalIdentity, encodedHandle)
    return try {
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        val root = AKEN_STRING_PAGE_PATH_ROOTS[(digest[0].toInt() and 0xFF) % AKEN_STRING_PAGE_PATH_ROOTS.size]
        val prefixLength = 2 + ((digest[1].toInt() and 0xFF) % 3)
        val suffix = AKEN_STRING_PAGE_PATH_SUFFIXES[(digest[2].toInt() and 0xFF) % AKEN_STRING_PAGE_PATH_SUFFIXES.size]
        "$root/${token.substring(0, prefixLength)}/${token.substring(prefixLength)}$suffix"
    } finally {
        Arrays.fill(digest, 0)
    }
}

private fun digestAkenBinding(domain: ByteArray, vararg values: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").apply {
        update(domain)
        values.forEach(::updateAkenBytes)
    }.digest()

private fun MessageDigest.updateAkenString(value: String) {
    val encoded = value.toByteArray(Charsets.UTF_8)
    try {
        updateAkenBytes(encoded)
    } finally {
        Arrays.fill(encoded, 0)
    }
}

private fun MessageDigest.updateAkenBytes(value: ByteArray) {
    updateAkenInt(value.size)
    update(value)
}

private fun MessageDigest.updateAkenInt(value: Int) {
    update((value ushr 24).toByte())
    update((value ushr 16).toByte())
    update((value ushr 8).toByte())
    update(value.toByte())
}

private fun intBytes(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xFF).toByte(),
    ((value ushr 16) and 0xFF).toByte(),
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte(),
)
