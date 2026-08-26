package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.computeFramesWriter
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkHandlerDescriptor
import org.objectweb.asm.*
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.MethodInsnNode
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

// --- Phase 4: High-cost Protection Kernels ---

private fun isJniLoaderTimingSensitiveClass(classBytes: ByteArray): Boolean {
    val classNode = ClassNode()
    return try {
        ClassReader(classBytes).accept(classNode, ClassReader.SKIP_DEBUG)
        classNode.methods.any { method ->
            method.instructions?.any { instruction ->
                instruction is MethodInsnNode && isJniLoaderTimingSensitiveCall(instruction)
            } == true
        }
    } catch (_: Exception) {
        true
    }
}

private fun isJniLoaderTimingSensitiveCall(call: MethodInsnNode): Boolean {
    if (call.owner == "java/lang/Thread" && call.name == "sleep") return true
    if (call.owner.startsWith("java/util/concurrent/")) return true
    return false
}

internal fun isPriorJavaShroudGeneratedRuntimeClass(classNode: ClassNode): Boolean {
    if (classNode.name.startsWith("io/github/hht0rro/javashroud/transforms/protection/")) return true
    if (hasPriorSealedRuntimeNameShape(classNode.name)) return true
    return false
}

private fun hasPriorSealedRuntimeNameShape(internalName: String): Boolean {
    val current = internalName.startsWith("jsh/")
    val retired = internalName.startsWith("r/")
    if (!current && !retired) return false
    val parts = internalName.split('/')
    if (parts.size != 3 || parts[1].length != 2) return false
    val simpleName = parts[2]
    if (current && !simpleName.startsWith('H')) return false
    if (retired && !simpleName.startsWith('C')) return false
    val outerName = simpleName.substringBefore('$')
    if (outerName.length < 10) return false
    return '$' !in simpleName || simpleName.substringAfter('$').startsWith('I')
}

internal fun usesJavaShroudVmDispatch(classNode: ClassNode): Boolean = classNode.methods.any { method ->
    method.instructions?.toArray().orEmpty().any { instruction ->
        instruction is MethodInsnNode && isJavaShroudVmDispatchCall(instruction)
    }
}

internal fun hasPriorSealedRuntimeDependency(classNode: ClassNode): Boolean = classNode.methods.any { method ->
    method.instructions?.toArray().orEmpty().any { instruction ->
        instruction is MethodInsnNode && isPriorSealedRuntimeDependencyCall(instruction)
    }
}

private fun isPriorSealedRuntimeDependencyCall(call: MethodInsnNode): Boolean {
    if (!call.owner.startsWith("r/") && !call.owner.startsWith("jsh/")) return false
    if (!hasPriorSealedRuntimeNameShape(call.owner)) return false
    // Sealed helper methods are renamed to m_*. That is not proof the JNI
    // loader already wired loadKernel — callsite rotation / string helpers
    // also land as m_* and must still receive a bootstrap native load.
    return call.name in setOf(
        "isNativeLoaded",
        "loadKernel",
        "executeVmResource",
        "executeVmResourceVoid",
        "executeVmResourceInt",
        "executeVmResourceIntInt",
        "executeVmResourceIntVoid",
        "nativeExecuteVmResource",
        "nativeExecuteVmResourceByToken",
        "nativeExecuteVmResourceVoid",
        "nativeExecuteVmResourceInt",
        "nativeExecuteVmResourceIntInt",
        "nativeExecuteVmResourceIntVoid",
    )
}

private fun isJavaShroudVmDispatchCall(call: MethodInsnNode): Boolean {
    if (call.opcode != Opcodes.INVOKESTATIC) return false
    if (call.desc !in setOf(
            "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
            "(J[Ljava/lang/Object;)Ljava/lang/Object;",
            "(J)V",
            "(J)I",
            "(JI)I",
            "(JI)V",
        )
    ) return false
    if (call.name in setOf(
            "nativeExecuteVmResource",
            "nativeExecuteVmResourceByToken",
            "executeVmResource",
            "nativeExecuteVmResourceVoid",
            "nativeExecuteVmResourceInt",
            "nativeExecuteVmResourceIntInt",
            "nativeExecuteVmResourceIntVoid",
            "executeVmResourceVoid",
            "executeVmResourceInt",
            "executeVmResourceIntInt",
            "executeVmResourceIntVoid",
        )
    ) return true
    return false
}

fun applyJniMicrokernelLoader(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "jni-microkernel-loader")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val kernelComponents = (params["kernelComponents"] as? String) ?: "loader"
    val supportedKernelComponents = setOf("loader", "decrypt", "vm", "guards", "all")
    require(kernelComponents in supportedKernelComponents) { "jni-microkernel-loader kernelComponents '$kernelComponents' is not supported; supported values: ${supportedKernelComponents.joinToString("", "")}" }
    val targetPlatform = (params["targetPlatform"] as? String) ?: "auto"
    val targetPlatforms = EmbeddedHelperDeployment.resolveNativeCompileTargetPlatforms(targetPlatform)
    val runtimeTargetPlatform = when {
        targetPlatform.trim() == "auto" -> "auto"
        targetPlatform.trim() == "all" -> "all"
        else -> targetPlatforms.joinToString(",")
    }
    val diversifiedVirtualization = (params["diversifiedVirtualization"] as? Boolean) ?: true
    val vmMode = if (diversifiedVirtualization) "vm-diverse" else "vm-off"

    val nativeKeyRandom = SecureRandom()
    val akenBuildContext = currentVbc4BuildContextOrNull()
    val nativeChunkOwner = akenBuildContext?.let {
        selectAkenNativeLoaderHandlerOwner(
            artifact = artifact,
            matchedClassNames = matchedClassNames,
        )
    }
    var nativeChunkBinding: AkenNativeLoaderHandlerBinding? = nativeChunkOwner?.let { ownerInternalName ->
        createAkenNativeLoaderHandlerBinding(
            ownerInternalName = ownerInternalName,
            kernelComponents = kernelComponents,
            runtimeTargetPlatform = runtimeTargetPlatform,
            targetPlatforms = targetPlatforms,
            vmMode = vmMode,
            random = nativeKeyRandom,
        )
    }
    var nativeChunkInjected = false

    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact
        if (isJniLoaderTimingSensitiveClass(classArtifact.bytes)) return@map classArtifact

        val classNode = ClassNode()
        try {
            ClassReader(classArtifact.bytes).accept(classNode, ClassReader.SKIP_FRAMES)
        } catch (_: Exception) { return@map classArtifact }
        if (isPriorJavaShroudGeneratedRuntimeClass(classNode)) return@map classArtifact
        if (hasPriorSealedRuntimeDependency(classNode)) return@map classArtifact
        if (usesJavaShroudVmDispatch(classNode)) return@map classArtifact

        val attachesNativeChunk = classNode.name == nativeChunkBinding?.ownerInternalName

        val cr = ClassReader(classArtifact.bytes)
        val cw = computeFramesWriter(cr)
        var classModified = false
        var clinitSeen = false
        var isInterfaceClass = false
        var classNativeChunkInjected = false

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visit(
                version: Int, access: Int, name: String, signature: String?, superName: String?, interfaces: Array<String>?,
            ) {
                // Synthesizing a <clinit> for an interface is only legal on class
                // file v52+ (Java 8). To stay safe, skip clinit synthesis for
                // interfaces and rely on an existing one if present.
                isInterfaceClass = (access and Opcodes.ACC_INTERFACE) != 0
                super.visit(version, access, name, signature, superName, interfaces)
            }

            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)
                if (name != "<clinit>" && name != "<init>" && diversifiedVirtualization) {
                    return object : MethodVisitor(Opcodes.ASM9, superMv) {
                        private val vmSeed = methodKeySeed(nativeKeyRandom)
                        private fun tryObfuscateInt(value: Int): Boolean {
                            val delta = diversifiedConstant(value, vmSeed).let { if (it == 0) vmSeed or 1 else it }
                            val encoded = value - delta
                            super.visitLdcInsn(encoded)
                            super.visitLdcInsn(delta)
                            super.visitInsn(Opcodes.IADD)
                            classModified = true
                            return true
                        }
                        override fun visitIntInsn(opcode: Int, operand: Int) {
                            if ((opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) && operand != 0 && operand != 1 && tryObfuscateInt(operand)) {
                                return
                            }
                            super.visitIntInsn(opcode, operand)
                        }
                        override fun visitLdcInsn(value: Any?) {
                            if (value is Int && value != 0 && value != 1 && tryObfuscateInt(value)) {
                                return
                            }
                            super.visitLdcInsn(value)
                        }
                    }
                }
                if (name != "<clinit>") return superMv
                clinitSeen = true

                return object : MethodVisitor(Opcodes.ASM9, superMv) {
                    override fun visitCode() {
                        super.visitCode()
                        emitJniMicrokernelLoad(this, kernelComponents, runtimeTargetPlatform, vmMode)
                        if (attachesNativeChunk) {
                            checkNotNull(nativeChunkBinding).emitConsume(this)
                            classNativeChunkInjected = true
                        }
                        classModified = true
                    }
                }
            }

            override fun visitEnd() {
                // If the matched class has no static initializer, synthesize one so
                // the kernel loader is actually wired in. Without this, classes that
                // lack a <clinit> would silently get no loadKernel call.
                if (!clinitSeen && !isInterfaceClass) {
                    val mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
                    mv.visitCode()
                    emitJniMicrokernelLoad(mv, kernelComponents, runtimeTargetPlatform, vmMode)
                    if (attachesNativeChunk) {
                        checkNotNull(nativeChunkBinding).emitConsume(mv)
                        classNativeChunkInjected = true
                    }
                    mv.visitInsn(Opcodes.RETURN)
                    mv.visitMaxs(0, 0)
                    mv.visitEnd()
                    classModified = true
                }
                super.visitEnd()
            }
        }

        try {
            cr.accept(cv, ClassReader.SKIP_FRAMES)
        } catch (_: Exception) { return@map classArtifact }
        if (!classModified) return@map classArtifact
        if (classNativeChunkInjected) nativeChunkInjected = true
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) {
        nativeChunkBinding?.wipe()
        return unchangedTransformResult(artifact)
    }
    return try {
        nativeChunkBinding?.let { binding ->
            require(nativeChunkInjected) {
                "AKEN native loader handler candidate was not attached to its bootstrap class"
            }
            checkNotNull(akenBuildContext).registerAkenNativeChunkCandidates(
                listOf(binding.candidateForRegistration()),
            )
        }
        updatedArtifactTransformResult(
            artifact = artifact,
            updatedClassArtifacts = updatedClassArtifacts,
            transformedClassCount = classCount,
            transformedMemberCount = classCount,
        )
    } finally {
        nativeChunkBinding?.wipe()
        nativeChunkBinding = null
    }
}

private fun diversifiedConstant(value: Int, seed: Int): Int {
    var mixed = value xor seed.rotateLeft(7) xor 0x6A09E667
    mixed = mixed xor mixed.rotateRight(13)
    mixed *= 0x45D9F3B
    mixed = mixed xor mixed.rotateRight(16)
    return mixed xor seed.rotateLeft(3)
}

private fun emitJniMicrokernelLoad(mv: MethodVisitor, kernelComponents: String, targetPlatform: String, vmMode: String) {
    mv.visitLdcInsn(kernelComponents)
    mv.visitLdcInsn(targetPlatform)
    mv.visitLdcInsn(vmMode)
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper",
        "loadKernel",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        false,
    )
}

private const val AKEN_NATIVE_LOADER_HANDLER_PAGE_INDEX = 0
private const val AKEN_NATIVE_LOADER_HANDLER_NONCE_SIZE = 32
private const val AKEN_NATIVE_LOADER_HANDLER_HELPER_OWNER =
    "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
private const val AKEN_NATIVE_LOADER_HANDLER_CONSUME_DESC = "([BI[B)V"
private const val AKEN_NATIVE_LOADER_HANDLER_HEX = "0123456789abcdef"

private class AkenNativeLoaderHandlerBinding(
    val ownerInternalName: String,
    private var candidate: AkenNativeChunkCandidate?,
    private var encodedHandle: ByteArray,
    private var callSiteProof: ByteArray,
) {
    private var wiped: Boolean = false

    fun emitConsume(mv: MethodVisitor) {
        requireLive()
        emitAkenNativeLoaderHandlerByteArray(mv, encodedHandle)
        emitAkenNativeLoaderHandlerInt(mv, AKEN_NATIVE_LOADER_HANDLER_PAGE_INDEX)
        emitAkenNativeLoaderHandlerByteArray(mv, callSiteProof)
        mv.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            AKEN_NATIVE_LOADER_HANDLER_HELPER_OWNER,
            "consumeAkenNativeChunk",
            AKEN_NATIVE_LOADER_HANDLER_CONSUME_DESC,
            false,
        )
    }

    fun candidateForRegistration(): AkenNativeChunkCandidate {
        requireLive()
        return checkNotNull(candidate) { "AKEN native loader handler candidate is unavailable" }
    }

    fun wipe() {
        if (wiped) return
        candidate?.wipe()
        candidate = null
        Arrays.fill(encodedHandle, 0)
        Arrays.fill(callSiteProof, 0)
        encodedHandle = ByteArray(0)
        callSiteProof = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN native loader handler binding has been wiped" }
    }
}

private fun selectAkenNativeLoaderHandlerOwner(
    artifact: BytecodeArtifact,
    matchedClassNames: Collection<String>,
): String? = artifact.classArtifacts
    .asSequence()
    .filter { classArtifact -> classArtifact.summary.internalName in matchedClassNames }
    .mapNotNull { classArtifact ->
        if (isJniLoaderTimingSensitiveClass(classArtifact.bytes)) return@mapNotNull null
        val classNode = ClassNode()
        try {
            ClassReader(classArtifact.bytes).accept(classNode, ClassReader.SKIP_FRAMES)
        } catch (_: Exception) {
            return@mapNotNull null
        }
        if (isPriorJavaShroudGeneratedRuntimeClass(classNode) ||
            hasPriorSealedRuntimeDependency(classNode) ||
            usesJavaShroudVmDispatch(classNode)
        ) {
            return@mapNotNull null
        }
        val isInterface = (classNode.access and Opcodes.ACC_INTERFACE) != 0
        val canEmitBootstrap = !isInterface || classNode.methods.any { method -> method.name == "<clinit>" }
        classNode.name.takeIf { canEmitBootstrap }
    }
    .sorted()
    .firstOrNull()

private fun createAkenNativeLoaderHandlerBinding(
    ownerInternalName: String,
    kernelComponents: String,
    runtimeTargetPlatform: String,
    targetPlatforms: Collection<String>,
    vmMode: String,
    random: SecureRandom,
): AkenNativeLoaderHandlerBinding {
    val nonce = ByteArray(AKEN_NATIVE_LOADER_HANDLER_NONCE_SIZE).also(random::nextBytes)
    val ownerBytes = ownerInternalName.toByteArray(Charsets.UTF_8)
    val componentsBytes = kernelComponents.toByteArray(Charsets.UTF_8)
    val runtimeTargetBytes = runtimeTargetPlatform.toByteArray(Charsets.UTF_8)
    val targetSetBytes = targetPlatforms.sorted().joinToString(",").toByteArray(Charsets.UTF_8)
    val vmModeBytes = vmMode.toByteArray(Charsets.UTF_8)
    var identity: ByteArray? = null
    var encodedHandle: ByteArray? = null
    var logicalBindingPath: String? = null
    var callSiteProof: ByteArray? = null
    var descriptor: ByteArray? = null
    var candidate: AkenNativeChunkCandidate? = null
    try {
        identity = deriveAkenNativeLoaderHandlerDigest(
            domain = "AKEN-v4-native-loader-handler-identity-v1",
            ownerBytes,
            componentsBytes,
            runtimeTargetBytes,
            targetSetBytes,
            vmModeBytes,
            nonce,
        )
        encodedHandle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE).also(random::nextBytes)
        logicalBindingPath = akenNativeLoaderHandlerLogicalBindingPath(checkNotNull(identity))
        callSiteProof = deriveAkenNativeLoaderHandlerDigest(
            domain = "AKEN-v4-native-loader-handler-proof-v1",
            checkNotNull(identity),
            checkNotNull(encodedHandle),
            akenNativeLoaderHandlerIntBytes(AKEN_NATIVE_LOADER_HANDLER_PAGE_INDEX),
            logicalBindingPath.toByteArray(Charsets.UTF_8),
        )
        descriptor = expandAkenNativeLoaderHandlerDescriptor(
            identity = checkNotNull(identity),
            encodedHandle = checkNotNull(encodedHandle),
            callSiteProof = checkNotNull(callSiteProof),
            nonce = nonce,
        )
        candidate = AkenNativeChunkCandidate.create(
            logicalIdentity = checkNotNull(identity),
            plaintext = checkNotNull(descriptor),
            pageIndex = AKEN_NATIVE_LOADER_HANDLER_PAGE_INDEX,
            callSiteProof = checkNotNull(callSiteProof),
            encodedHandle = checkNotNull(encodedHandle),
            logicalBindingPath = checkNotNull(logicalBindingPath),
            random = random,
        )
        return AkenNativeLoaderHandlerBinding(
            ownerInternalName = ownerInternalName,
            candidate = checkNotNull(candidate),
            encodedHandle = checkNotNull(encodedHandle).copyOf(),
            callSiteProof = checkNotNull(callSiteProof).copyOf(),
        ).also {
            candidate = null
        }
    } finally {
        candidate?.wipe()
        Arrays.fill(nonce, 0)
        Arrays.fill(ownerBytes, 0)
        Arrays.fill(componentsBytes, 0)
        Arrays.fill(runtimeTargetBytes, 0)
        Arrays.fill(targetSetBytes, 0)
        Arrays.fill(vmModeBytes, 0)
        identity?.let { Arrays.fill(it, 0) }
        encodedHandle?.let { Arrays.fill(it, 0) }
        callSiteProof?.let { Arrays.fill(it, 0) }
        descriptor?.let { Arrays.fill(it, 0) }
    }
}

private fun expandAkenNativeLoaderHandlerDescriptor(
    identity: ByteArray,
    encodedHandle: ByteArray,
    callSiteProof: ByteArray,
    nonce: ByteArray,
): ByteArray =
    AkenNativeChunkHandlerDescriptor.createLoaderAttestation(
        logicalIdentity = identity,
        encodedHandle = encodedHandle,
        callSiteProof = callSiteProof,
        nonce = nonce,
    )

private fun deriveAkenNativeLoaderHandlerDigest(
    domain: String,
    vararg parts: ByteArray,
): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    val domainBytes = domain.toByteArray(Charsets.US_ASCII)
    try {
        updateAkenNativeLoaderHandlerDigest(digest, domainBytes)
        parts.forEach { part -> updateAkenNativeLoaderHandlerDigest(digest, part) }
        return digest.digest()
    } finally {
        Arrays.fill(domainBytes, 0)
    }
}

private fun updateAkenNativeLoaderHandlerDigest(
    digest: MessageDigest,
    bytes: ByteArray,
) {
    val lengthBytes = akenNativeLoaderHandlerIntBytes(bytes.size)
    try {
        digest.update(lengthBytes)
        digest.update(bytes)
    } finally {
        Arrays.fill(lengthBytes, 0)
    }
}

private fun akenNativeLoaderHandlerLogicalBindingPath(identity: ByteArray): String {
    require(identity.size >= 12) { "AKEN native loader handler identity is too short" }
    val segment = buildString(24) {
        for (index in 0 until 12) {
            val value = identity[index].toInt() and 0xFF
            append(AKEN_NATIVE_LOADER_HANDLER_HEX[value ushr 4])
            append(AKEN_NATIVE_LOADER_HANDLER_HEX[value and 0x0F])
        }
    }
    return "META-INF/.logical/native/loader/$segment.bin"
}

private fun emitAkenNativeLoaderHandlerByteArray(
    mv: MethodVisitor,
    bytes: ByteArray,
) {
    emitAkenNativeLoaderHandlerInt(mv, bytes.size)
    mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
    bytes.forEachIndexed { index, value ->
        mv.visitInsn(Opcodes.DUP)
        emitAkenNativeLoaderHandlerInt(mv, index)
        mv.visitIntInsn(Opcodes.BIPUSH, value.toInt())
        mv.visitInsn(Opcodes.BASTORE)
    }
}

private fun emitAkenNativeLoaderHandlerInt(
    mv: MethodVisitor,
    value: Int,
) {
    when (value) {
        -1 -> mv.visitInsn(Opcodes.ICONST_M1)
        0 -> mv.visitInsn(Opcodes.ICONST_0)
        1 -> mv.visitInsn(Opcodes.ICONST_1)
        2 -> mv.visitInsn(Opcodes.ICONST_2)
        3 -> mv.visitInsn(Opcodes.ICONST_3)
        4 -> mv.visitInsn(Opcodes.ICONST_4)
        5 -> mv.visitInsn(Opcodes.ICONST_5)
        in Byte.MIN_VALUE..Byte.MAX_VALUE -> mv.visitIntInsn(Opcodes.BIPUSH, value)
        in Short.MIN_VALUE..Short.MAX_VALUE -> mv.visitIntInsn(Opcodes.SIPUSH, value)
        else -> mv.visitLdcInsn(value)
    }
}

private fun akenNativeLoaderHandlerIntBytes(value: Int): ByteArray = byteArrayOf(
    (value ushr 24).toByte(),
    (value ushr 16).toByte(),
    (value ushr 8).toByte(),
    value.toByte(),
)

/**
 * Apply diversified arithmetic virtualization obfuscation to classes matching the target prefix.
 * Used to obfuscate helper classes injected by EmbeddedHelperDeployment.
 */
fun applyDiversifiedVmToClasses(
    artifact: io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact,
    seed: Int,
    targetPrefix: String,
): io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact {
    val buildContext = requireVbc4BuildContext()
    val random = java.security.SecureRandom(seed.toString().toByteArray())
    val nativeKeyRandom = java.security.SecureRandom()
    val opcodeMapping = generateOpcodeMapping(random)
    val handlerOrder = generateHandlerOrder(opcodeMapping.size, random)
    val newResources = mutableListOf<io.github.hht0rro.javashroud.model.artifact.JarEntryData>()
    var modified = false

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!classArtifact.summary.internalName.startsWith(targetPrefix)) return@map classArtifact

        val cr = org.objectweb.asm.ClassReader(classArtifact.bytes)
        val cw = org.objectweb.asm.ClassWriter(cr, org.objectweb.asm.ClassWriter.COMPUTE_FRAMES)
        val className = classArtifact.summary.internalName
        var classModified = false

        val cv = object : org.objectweb.asm.ClassVisitor(org.objectweb.asm.Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): org.objectweb.asm.MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)

                // Skip constructors, static initializers, abstract and native methods
                if (name == "<init>" || name == "<clinit>") return superMv
                if (access and (org.objectweb.asm.Opcodes.ACC_ABSTRACT or org.objectweb.asm.Opcodes.ACC_NATIVE) != 0) return superMv

                val bodyCapture = MethodBodyCapture()
                return object : org.objectweb.asm.MethodVisitor(org.objectweb.asm.Opcodes.ASM9, bodyCapture) {
                    override fun visitEnd() {
                        super.visitEnd()
                        if (bodyCapture.instructionCount == 0 || bodyCapture.hasInvokeDynamic) {
                            bodyCapture.replayTo(superMv)
                            return
                        }

                        // Serialize method body into VM bytecode
                        val methodSeed = methodKeySeed(nativeKeyRandom)
                        val resourcePath = opaqueVmResourcePath(random, className, name, descriptor, methodSeed)
                        val dispatchClassToken = ObfuscatedIdentifierUtil.classToken(className)
                        val dispatchMethodToken = ObfuscatedIdentifierUtil.methodToken(name, descriptor)
                        val entryToken = vmEntryToken(dispatchClassToken, dispatchMethodToken, descriptor, resourcePath, methodSeed)
                        val serializer = VmBytecodeSerializer(
                            buildSeed = methodSeed,
                            stateBinding = vmStateBinding(entryToken, resourcePath),
                            entryMetadata = Vbc4EntryMetadata(
                                entryToken = entryToken,
                                returnDescriptor = vbc4ReturnTag(descriptor),
                                methodIdentity = buildContext.deriveVbc4Identity(className, name, descriptor),
                                ownerIdentity = buildContext.deriveVbc4OwnerIdentity(className),
                                argumentTags = vbc4ArgumentTagVector(descriptor),
                                resourcePath = resourcePath,
                                isStatic = access and org.objectweb.asm.Opcodes.ACC_STATIC != 0,
                            ),
                            buildContext = buildContext,
                        )
                        bodyCapture.replayTo(serializer)
                        val vmBytes = serializer.serialize()
                        newResources.add(io.github.hht0rro.javashroud.model.artifact.JarEntryData(name = resourcePath, bytes = encodeNativeDiversifiedVmResource(vmBytes, methodSeed)))

                        // Replace method body with VM dispatcher.
                        generateVmDispatcher(
                            superMv, className, name, descriptor, access,
                            opcodeMapping, handlerOrder, "vbc4", random, resourcePath,
                            entryToken = entryToken,
                        )
                        classModified = true
                    }
                }
            }
        }

        try {
            cr.accept(cv, org.objectweb.asm.ClassReader.SKIP_FRAMES)
        } catch (_: Exception) { return@map classArtifact }
        if (!classModified) return@map classArtifact
        modified = true
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (!modified) return artifact
    val updatedArtifact = if (newResources.isNotEmpty()) {
        artifact.copy(
            classArtifacts = updatedClassArtifacts,
            jarEntries = artifact.jarEntries + newResources,
        )
    } else {
        artifact.copy(classArtifacts = updatedClassArtifacts)
    }
    return updatedArtifact
}
