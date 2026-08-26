package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import org.objectweb.asm.tree.TypeInsnNode
import org.objectweb.asm.tree.VarInsnNode
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64
import java.util.Random
import java.util.Collections
import java.util.IdentityHashMap
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
private const val STRING_HELPER_AKEN_DECODE_DESC = "([B)Ljava/lang/String;"
private const val STRING_HELPER_AKEN_BSM_DESC =
    "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
        "Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;"
private val STRING_HELPER_AKEN_BSM_NAMES = arrayOf("q0", "m7", "x3", "v8")
private const val STRING_HELPER_TOKEN_DESC = "(Ljava/lang/String;)[B"
private const val STRING_HELPER_TOKEN_BSM_DESC =
    "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
        "Ljava/lang/String;)Ljava/lang/invoke/CallSite;"
private val STRING_HELPER_TOKEN_BSM_NAMES = arrayOf("u0", "u1", "u2", "u3")
private const val SHROUD_ENCRYPT_DESC = "Lio/github/hht0rro/javashroud/bytecode/ShroudEncrypt;"
private const val AKEN_STRING_PAGE_NONCE_SIZE = 16

private enum class AkenIntPushShape {
    Canonical,
    Bipush,
    Sipush,
    Ldc,
}

private enum class AkenTokenEmission {
    PackedArray,
    LdcPayload,
    IndyConstant,
}

private data class AkenStringCallsiteShape(
    val handleLengthPush: AkenIntPushShape,
    val proofLengthPush: AkenIntPushShape,
    val pageIndexPush: AkenIntPushShape,
    val reverseStores: Boolean,
    val useInvokeDynamic: Boolean,
    val bootstrapSlot: Int,
    val tokenEmission: AkenTokenEmission,
)

private val AKEN_STRING_PAGE_IDENTITY_DOMAIN =
    "AKEN-v4-string-page-logical-identity-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_HANDLE_DOMAIN =
    "AKEN-v4-string-page-handle-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_PROOF_DOMAIN =
    "AKEN-v4-string-page-call-site-proof-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_PATH_DOMAIN =
    "AKEN-v4-string-page-logical-path-v1".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_INDEX_DOMAIN =
    "AKEN-v4-string-page-index-v2".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_TEMPLATE_DOMAIN =
    "AKEN-v4-string-page-callsite-template-v2".toByteArray(Charsets.US_ASCII)
private val AKEN_STRING_PAGE_PATH_ROOTS = arrayOf(
    "META-INF/.a4/s",
    "META-INF/.r4/p",
    "assets/.a4/s",
    "META-INF/.j4/r",
)
private val AKEN_STRING_PAGE_PATH_SUFFIXES = arrayOf(".bin", ".dat", ".p", ".r")

/**
 * Replaces string LDC constants with native-backed authenticated decode callsites.
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
            val reflectionMemberNameNodes = reflectionMemberNameConstants(method)
            val loopMembers = backwardLoopMembers(method)
            val loopLocalInitializers = InsnList()
            var methodLiteralOrdinal = 0
            for (insn in instructions.toArray()) {
                val ldc = insn as? LdcInsnNode ?: continue
                if (reflectionMemberNameNodes.contains(ldc)) continue
                val value = ldc.cst as? String ?: continue
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
                    val pageIndex = deriveAkenStringPageIndex(logicalIdentity, buildNonce)
                    val logicalBindingPath = akenStringPageLogicalBindingPath(logicalIdentity, encodedHandle)
                    callSiteProof = deriveAkenStringPageCallSiteProof(
                        logicalIdentity = logicalIdentity,
                        encodedHandle = encodedHandle,
                        pageIndex = pageIndex,
                        logicalBindingPath = logicalBindingPath,
                    )
                    plaintext = value.toByteArray(Charsets.UTF_8)
                    candidate = AkenStringPageCandidate.create(
                        logicalIdentity = logicalIdentity,
                        plaintext = plaintext,
                        pageIndex = pageIndex,
                        callSiteProof = callSiteProof,
                        encodedHandle = encodedHandle,
                        logicalBindingPath = logicalBindingPath,
                        random = candidateRandom,
                    )
                    val callsiteShape = selectAkenStringCallsiteShape(
                        logicalIdentity = logicalIdentity,
                        classLiteralOrdinal = encryptedCount,
                        methodLiteralOrdinal = methodLiteralOrdinal,
                    )
                    val decodeCallsite = buildAkenStringPageDecodeCallsite(
                        encodedHandle = encodedHandle,
                        pageIndex = pageIndex,
                        callSiteProof = callSiteProof,
                        shape = callsiteShape,
                    )
                    val replacement = if (loopMembers.contains(insn)) {
                        val local = method.maxLocals
                        method.maxLocals += 1
                        loopLocalInitializers.add(InsnNode(Opcodes.ACONST_NULL))
                        loopLocalInitializers.add(VarInsnNode(Opcodes.ASTORE, local))
                        lazyLoopStringLoad(local, decodeCallsite)
                    } else {
                        decodeCallsite
                    }
                    instructions.insert(insn, replacement)
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
            if (loopLocalInitializers.size() > 0) {
                instructions.insertBefore(instructions.first, loopLocalInitializers)
            }
        }

        if (encryptedCount == 0) return classBytes

        // Do not seed the writer from the source reader: ASM's reader-backed
        // constant-pool copy can retain now-unreferenced plaintext LDC entries.
        // Building a fresh pool ensures protected literals are absent from the
        // emitted class bytes, not merely absent from the instruction stream.
        val writer = computeFramesWriter()
        classNode.accept(writer)
        val transformed = writer.toByteArray()
        requireVbc4BuildContext().registerAkenStringPageCandidates(candidates)
        return transformed
    } finally {
        candidates.forEach { it.wipe() }
    }
}

/**
 * Finds instructions enclosed by a backward jump/switch edge. String pages in
 * such a region are authenticated lazily once per method invocation and then
 * kept only in a local variable until that invocation returns. This preserves
 * all-strings protection without turning a loop-invariant literal into a JNI
 * page open on every iteration or introducing a Java/static plaintext cache.
 */
private fun backwardLoopMembers(method: MethodNode): Set<AbstractInsnNode> {
    val instructions = method.instructions?.toArray() ?: return emptySet()
    if (instructions.isEmpty()) return emptySet()
    val positions = IdentityHashMap<AbstractInsnNode, Int>(instructions.size)
    instructions.forEachIndexed { index, instruction -> positions[instruction] = index }
    val members = Collections.newSetFromMap(IdentityHashMap<AbstractInsnNode, Boolean>())

    fun addBackwardRange(branchIndex: Int, target: LabelNode) {
        val targetIndex = positions[target] ?: return
        if (targetIndex >= branchIndex) return
        for (index in targetIndex..branchIndex) members.add(instructions[index])
    }

    instructions.forEachIndexed { index, instruction ->
        when (instruction) {
            is JumpInsnNode -> addBackwardRange(index, instruction.label)
            is TableSwitchInsnNode -> {
                addBackwardRange(index, instruction.dflt)
                instruction.labels.forEach { label -> addBackwardRange(index, label) }
            }
            is LookupSwitchInsnNode -> {
                addBackwardRange(index, instruction.dflt)
                instruction.labels.forEach { label -> addBackwardRange(index, label) }
            }
        }
    }
    return members
}

private fun lazyLoopStringLoad(local: Int, decodeCallsite: InsnList): InsnList = InsnList().apply {
    val ready = LabelNode()
    add(VarInsnNode(Opcodes.ALOAD, local))
    add(InsnNode(Opcodes.DUP))
    add(JumpInsnNode(Opcodes.IFNONNULL, ready))
    add(InsnNode(Opcodes.POP))
    add(decodeCallsite)
    add(InsnNode(Opcodes.DUP))
    add(VarInsnNode(Opcodes.ASTORE, local))
    add(ready)
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

private val REFLECTION_MEMBER_LOOKUP_METHODS = setOf(
    "getDeclaredMethod",
    "getMethod",
    "getDeclaredField",
    "getField",
)

/**
 * Returns string LDC nodes used as member names by java.lang.Class reflection
 * lookups. These names must remain ordinary constants until the member rename
 * stage can rewrite them together with the corresponding declaration.
 */
private fun reflectionMemberNameConstants(method: MethodNode): Set<LdcInsnNode> {
    val marked = Collections.newSetFromMap(IdentityHashMap<LdcInsnNode, Boolean>())
    val instructions = method.instructions ?: return marked
    for (instruction in instructions.toArray()) {
        val call = instruction as? MethodInsnNode ?: continue
        if (call.owner != "java/lang/Class" || call.name !in REFLECTION_MEMBER_LOOKUP_METHODS) continue
        reflectionMemberNameConstantBefore(call)?.let(marked::add)
    }
    return marked
}

private fun reflectionMemberNameConstantBefore(call: MethodInsnNode): LdcInsnNode? {
    var current = call.previous
    var scanned = 0
    while (current != null && scanned < 48) {
        if (current.opcode >= 0) {
            scanned++
            val ldc = current as? LdcInsnNode
            if (ldc?.cst is String) return ldc
            // Do not cross another invocation: any earlier string belongs to a
            // different call's arguments rather than this reflection lookup.
            if (current is MethodInsnNode || current is InvokeDynamicInsnNode) break
        }
        current = current.previous
    }
    return null
}

private fun buildAkenStringPageDecodeCallsite(
    encodedHandle: ByteArray,
    pageIndex: Int,
    callSiteProof: ByteArray,
    shape: AkenStringCallsiteShape,
): InsnList = InsnList().apply {
    addAkenStringToken(encodedHandle, pageIndex, callSiteProof, shape)
    if (shape.useInvokeDynamic) {
        add(
            InvokeDynamicInsnNode(
                "a${shape.bootstrapSlot}",
                STRING_HELPER_AKEN_DECODE_DESC,
                Handle(
                    Opcodes.H_INVOKESTATIC,
                    STRING_HELPER_OWNER,
                    STRING_HELPER_AKEN_BSM_NAMES[shape.bootstrapSlot],
                    STRING_HELPER_AKEN_BSM_DESC,
                    false,
                ),
                Handle(
                    Opcodes.H_INVOKESTATIC,
                    STRING_HELPER_OWNER,
                    "invokeAkenStringTerminal",
                    STRING_HELPER_AKEN_DECODE_DESC,
                    false,
                ),
            ),
        )
    } else {
        add(
            MethodInsnNode(
                Opcodes.INVOKESTATIC,
                STRING_HELPER_OWNER,
                "invokeAkenStringTerminal",
                STRING_HELPER_AKEN_DECODE_DESC,
                false,
            ),
        )
    }
}

private fun InsnList.addAkenStringToken(
    encodedHandle: ByteArray,
    pageIndex: Int,
    callSiteProof: ByteArray,
    shape: AkenStringCallsiteShape,
) {
    val packed = packAkenStringToken(encodedHandle, pageIndex, callSiteProof)
    try {
        when (shape.tokenEmission) {
            AkenTokenEmission.PackedArray -> addByteArray(packed, shape.handleLengthPush, shape.reverseStores)
            AkenTokenEmission.LdcPayload -> {
                add(LdcInsnNode(Base64.getUrlEncoder().withoutPadding().encodeToString(packed)))
                add(
                    MethodInsnNode(
                        Opcodes.INVOKESTATIC,
                        STRING_HELPER_OWNER,
                        "materializeAkenStringToken",
                        STRING_HELPER_TOKEN_DESC,
                        false,
                    ),
                )
            }
            AkenTokenEmission.IndyConstant -> add(
                InvokeDynamicInsnNode(
                    "t${shape.bootstrapSlot}",
                    "()[B",
                    Handle(
                        Opcodes.H_INVOKESTATIC,
                        STRING_HELPER_OWNER,
                        STRING_HELPER_TOKEN_BSM_NAMES[shape.bootstrapSlot],
                        STRING_HELPER_TOKEN_BSM_DESC,
                        false,
                    ),
                    Base64.getUrlEncoder().withoutPadding().encodeToString(packed),
                ),
            )
        }
    } finally {
        Arrays.fill(packed, 0)
    }
}

private fun InsnList.addByteArray(
    bytes: ByteArray,
    lengthPush: AkenIntPushShape = AkenIntPushShape.Canonical,
    reverseStores: Boolean = false,
) {
    addInt(bytes.size, lengthPush)
    add(IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE))
    val indices = if (reverseStores) bytes.indices.reversed() else bytes.indices
    for (index in indices) {
        add(InsnNode(Opcodes.DUP))
        addInt(index)
        addInt(bytes[index].toInt())
        add(InsnNode(Opcodes.BASTORE))
    }
}

private fun InsnList.addInt(value: Int, shape: AkenIntPushShape = AkenIntPushShape.Canonical) {
    when (shape) {
        AkenIntPushShape.Canonical -> when (value) {
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
        AkenIntPushShape.Bipush -> {
            require(value in Byte.MIN_VALUE..Byte.MAX_VALUE) { "AKEN callsite BIPUSH value is out of range" }
            add(IntInsnNode(Opcodes.BIPUSH, value))
        }
        AkenIntPushShape.Sipush -> {
            require(value in Short.MIN_VALUE..Short.MAX_VALUE) { "AKEN callsite SIPUSH value is out of range" }
            add(IntInsnNode(Opcodes.SIPUSH, value))
        }
        AkenIntPushShape.Ldc -> add(LdcInsnNode(value))
    }
}

private fun packAkenStringToken(encodedHandle: ByteArray, pageIndex: Int, callSiteProof: ByteArray): ByteArray {
    require(encodedHandle.size == 24) { "AKEN string handle must be 24 bytes" }
    require(callSiteProof.isNotEmpty() && callSiteProof.size <= 4096) { "AKEN string proof size is invalid" }
    val packed = ByteArray(24 + 4 + callSiteProof.size)
    encodedHandle.copyInto(packed)
    packed[24] = (pageIndex ushr 24).toByte()
    packed[25] = (pageIndex ushr 16).toByte()
    packed[26] = (pageIndex ushr 8).toByte()
    packed[27] = pageIndex.toByte()
    callSiteProof.copyInto(packed, 28)
    return packed
}

private fun deriveAkenStringPageIndex(
    logicalIdentity: ByteArray,
    buildNonce: ByteArray,
): Int {
    val digest = digestAkenBinding(AKEN_STRING_PAGE_INDEX_DOMAIN, logicalIdentity, buildNonce)
    return try {
        // Typed StringPages are not dispatcher page-zero bindings. Keep the
        // index bounded and non-zero while still binding it into the proof,
        // descriptor, evaluator graph, and native request.
        val mixed = ((digest[0].toInt() and 0xFF) shl 8) or (digest[1].toInt() and 0xFF)
        1 + (mixed and 0x1F)
    } finally {
        Arrays.fill(digest, 0)
    }
}

private fun selectAkenStringCallsiteShape(
    logicalIdentity: ByteArray,
    classLiteralOrdinal: Int,
    methodLiteralOrdinal: Int,
): AkenStringCallsiteShape {
    val digest = digestAkenBinding(
        AKEN_STRING_PAGE_TEMPLATE_DOMAIN,
        logicalIdentity,
        intBytes(classLiteralOrdinal),
        intBytes(methodLiteralOrdinal),
    )
    return try {
        val first = digest[0].toInt() and 0xFF
        val second = digest[1].toInt() and 0xFF
        fun pushShape(bits: Int): AkenIntPushShape = when (bits and 0x03) {
            0 -> AkenIntPushShape.Canonical
            1 -> AkenIntPushShape.Bipush
            2 -> AkenIntPushShape.Sipush
            else -> AkenIntPushShape.Ldc
        }
        AkenStringCallsiteShape(
            handleLengthPush = pushShape(first),
            proofLengthPush = pushShape(first ushr 2),
            pageIndexPush = pushShape(first ushr 4),
            reverseStores = (second and 0x01) != 0,
            // Alternate direct and indy terminals while the shape digest
            // randomizes the surrounding encodings and bootstrap alias.
            useInvokeDynamic = (classLiteralOrdinal and 1) != 0,
            bootstrapSlot = (second ushr 1) and (STRING_HELPER_AKEN_BSM_NAMES.lastIndex),
            tokenEmission = AkenTokenEmission.entries[
                (classLiteralOrdinal + (digest[2].toInt() and 0xFF)) % AkenTokenEmission.entries.size
            ],
        )
    } finally {
        Arrays.fill(digest, 0)
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
