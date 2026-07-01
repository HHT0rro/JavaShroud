package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import org.objectweb.asm.*
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.MethodInsnNode
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import java.security.SecureRandom

// --- Phase 4: High-cost Protection Kernels ---

/**
 * Anti-Instrumentation transform.
 *
 * Injects checks for -javaagent, ByteBuddy, JVMTI agents, suspicious
 * class retransformation, and debug/attach traces into matched classes.
 *
 * The detection is injected into static initializers and performs
 * environment checks at class load time.
 */
fun applyAntiInstrumentation(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "anti-instrumentation")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val detectionLevel = (params["detectionLevel"] as? String) ?: "standard"
    val supportedDetectionLevels = setOf("standard", "aggressive")
    require(detectionLevel in supportedDetectionLevels) { "anti-instrumentation detectionLevel '$detectionLevel' is not supported; supported values: ${supportedDetectionLevels.joinToString("", "")}" }
    val response = (params["response"] as? String) ?: "log"
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()

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

        val candidateMethods = classNode.methods
            .asSequence()
            .filter { it.name != "<clinit>" && it.name != "<init>" }
            .filter { it.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) == 0 }
            .filterNot { isRuntimeGuardProbeHotPath(classNode.name, it) }
            .map { it.name + it.desc }
            .toMutableList()

        val cr = ClassReader(classArtifact.bytes)
        val cw = ClassWriter(cr, ClassWriter.COMPUTE_FRAMES)
        var classModified = false
        var hasClinit = false

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)
                if (name != "<clinit>") return superMv
                hasClinit = true

                return object : MethodVisitor(Opcodes.ASM9, superMv) {
                    override fun visitInsn(opcode: Int) {
                        if (opcode == Opcodes.RETURN) {
                            emitAntiInstrumentationCheck(this, detectionLevel, response)
                            classModified = true
                        }
                        super.visitInsn(opcode)
                    }
                }
            }

            override fun visitEnd() {
                if (!hasClinit) {
                    val mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
                    mv.visitCode()
                    emitAntiInstrumentationCheck(mv, detectionLevel, response)
                    mv.visitInsn(Opcodes.RETURN)
                    mv.visitMaxs(2, 0)
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

        // Phase 2: inject distributed integrity probes into selected non-clinit methods.
        // Use first-pass output bytes so clinit injection is preserved.
        val firstPassBytes = cw.toByteArray()
        val selectedForProbe = candidateMethods.shuffled(random).take(maxOf(1, minOf(3, candidateMethods.size)))
        if (selectedForProbe.isNotEmpty()) {
            val cr2 = ClassReader(firstPassBytes)
            val cw2 = ClassWriter(cr2, ClassWriter.COMPUTE_FRAMES)
            var probeInjected = false
            val cv2 = object : ClassVisitor(Opcodes.ASM9, cw2) {
                override fun visitMethod(
                    access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
                ): MethodVisitor {
                    val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)
                    val key = name + descriptor
                    if (key !in selectedForProbe) return superMv
                    if (access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) != 0) return superMv

                    return object : MethodVisitor(Opcodes.ASM9, superMv) {
                        override fun visitCode() {
                            super.visitCode()
                            try {
                                emitDistributedIntegrityProbe(this, detectionLevel, response)
                                probeInjected = true
                            } catch (_: Throwable) { /* method may have maxs issues, skip */ }
                        }
                    }
                }
            }
            try {
                cr2.accept(cv2, ClassReader.SKIP_FRAMES)
                if (probeInjected) {
                    classCount++
                    reanalyzedClassArtifact(classArtifact, cw2.toByteArray())
                    return@map reanalyzedClassArtifact(classArtifact, cw2.toByteArray())
                }
            } catch (_: Exception) { /* second pass failed, keep first-pass result */ }
        }

        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = classCount,
    )
}

private fun isJniLoaderTimingSensitiveClass(classBytes: ByteArray): Boolean {
    val classNode = ClassNode()
    return try {
        ClassReader(classBytes).accept(classNode, ClassReader.SKIP_DEBUG)
        classNode.methods.any { method ->
            method.instructions?.any { instruction ->
                instruction is InvokeDynamicInsnNode ||
                    (instruction is MethodInsnNode && isJniLoaderTimingSensitiveCall(instruction))
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

private fun isJavaShroudRuntimeStateClass(classNode: ClassNode): Boolean {
    if (classNode.name.startsWith("io/github/hht0rro/javashroud/transforms/protection/")) return true
    var hasRuntimeResourceState = false
    var hasNativeKernelBindingState = false
    for (method in classNode.methods) {
        val instructions = method.instructions?.toArray().orEmpty()
        for (instruction in instructions) {
            when (instruction) {
                is org.objectweb.asm.tree.LdcInsnNode -> {
                    val value = instruction.cst as? String ?: continue
                    if (value == "META-INF/.r/vm.idx" || value == "META-INF/.r/vm-current.idx" || value.startsWith("META-INF/2b/") || value == "JSRP" || value == "JSBI") {
                        hasRuntimeResourceState = true
                    }
                    if (value == "j.b" || value == "j.m" || value == "j.l") {
                        hasNativeKernelBindingState = true
                    }
                }
                is MethodInsnNode -> {
                    if (instruction.name in setOf(
                        "nativeExecuteVmResource",
                        "nativeExecuteVmResourceByToken",
                        "executeVmResource",
                        "decodeRuntimeResource",
                        "decodeBootstrapNativeIndex",
                        "sealedNativeIndexText",
                        "publishSealedNativeBindings",
                    )) {
                        hasRuntimeResourceState = true
                    }
                    if (instruction.owner.endsWith("/JniMicrokernelHelper") || instruction.owner.endsWith("/AntiDumpRuntimeHelper")) {
                        hasNativeKernelBindingState = true
                    }
                }
            }
        }
    }
    return hasRuntimeResourceState && hasNativeKernelBindingState
}

internal fun isPriorJavaShroudGeneratedRuntimeClass(classNode: ClassNode): Boolean {
    if (classNode.name.startsWith("io/github/hht0rro/javashroud/transforms/protection/")) return true
    if (hasPriorSealedRuntimeNameShape(classNode.name)) return true
    return false
}

private fun hasPriorSealedRuntimeNameShape(internalName: String): Boolean {
    if (!internalName.startsWith("r/")) return false
    val parts = internalName.split('/')
    if (parts.size != 3 || parts[1].length != 2) return false
    val simpleName = parts[2]
    if (!simpleName.startsWith('C')) return false
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
    if (!call.owner.startsWith("r/")) return false
    if (!hasPriorSealedRuntimeNameShape(call.owner)) return false
    if (call.name.startsWith("m_")) return true
    return call.name in setOf(
        "isNativeLoaded",
        "loadKernel",
        "executeVmResource",
        "executeVmResourceVoid",
        "executeVmResourceIntVoid",
        "nativeExecuteVmResource",
        "nativeExecuteVmResourceByToken",
        "nativeExecuteVmResourceVoid",
        "nativeExecuteVmResourceIntVoid",
    )
}

private fun isJavaShroudVmDispatchCall(call: MethodInsnNode): Boolean {
    if (call.opcode != Opcodes.INVOKESTATIC) return false
    if (call.desc !in setOf(
            "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
            "(J[Ljava/lang/Object;)Ljava/lang/Object;",
            "(J)V",
            "(JI)V",
        )
    ) return false
    if (call.name in setOf(
            "nativeExecuteVmResource",
            "nativeExecuteVmResourceByToken",
            "executeVmResource",
            "nativeExecuteVmResourceVoid",
            "nativeExecuteVmResourceIntVoid",
            "executeVmResourceVoid",
            "executeVmResourceIntVoid",
        )
    ) return true
    return call.owner.startsWith("r/") && call.name.startsWith("m_")
}

private fun isRuntimeGuardProbeHotPath(owner: String, method: org.objectweb.asm.tree.MethodNode): Boolean {
    val instructions = method.instructions?.toArray().orEmpty()
    var hasBackwardJump = false
    var hasSelfCall = false
    var hasElapsedTimeProbe = false
    var hasThreadOrConcurrentBoundary = false
    var hasStringBuilderLoop = false
    val labelIndex = instructions.mapIndexedNotNull { index, instruction ->
        (instruction as? org.objectweb.asm.tree.LabelNode)?.let { it to index }
    }.toMap()
    for ((index, instruction) in instructions.withIndex()) {
        when (instruction) {
            is org.objectweb.asm.tree.JumpInsnNode -> {
                val targetIndex = labelIndex[instruction.label]
                if (targetIndex != null && targetIndex <= index) hasBackwardJump = true
            }
            is MethodInsnNode -> {
                if (instruction.owner == owner && instruction.name == method.name && instruction.desc == method.desc) hasSelfCall = true
                if (instruction.owner == "java/lang/System" && instruction.name == "currentTimeMillis" && instruction.desc == "()J") hasElapsedTimeProbe = true
                if (isJniLoaderTimingSensitiveCall(instruction)) hasThreadOrConcurrentBoundary = true
                if (instruction.owner == "java/lang/StringBuilder" || instruction.owner == "java/lang/String") hasStringBuilderLoop = true
            }
        }
    }
    return hasThreadOrConcurrentBoundary || hasElapsedTimeProbe || hasSelfCall || (hasBackwardJump && hasStringBuilderLoop)
}

/**
 * Anti-JVMTI Agent transform.
 *
 * Injects JVMTI agent detection into class initializers.
 * Detects agent attach, retransform, and redefine operations.
 */
fun applyAntiJvmTiAgent(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "anti-jvmti-agent")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val detectionMode = (params["detectionMode"] as? String) ?: "passive"
    val supportedDetectionModes = setOf("passive", "active")
    require(detectionMode in supportedDetectionModes) { "anti-jvmti-agent detectionMode '$detectionMode' is not supported; supported values: ${supportedDetectionModes.joinToString("", "")}" }
    val response = (params["response"] as? String) ?: "log"

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

        val cr = ClassReader(classArtifact.bytes)
        val cw = ClassWriter(cr, ClassWriter.COMPUTE_FRAMES)
        var classModified = false
        var hasClinit = false

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)
                if (name != "<clinit>") return superMv
                hasClinit = true

                return object : MethodVisitor(Opcodes.ASM9, superMv) {
                    override fun visitInsn(opcode: Int) {
                        if (opcode == Opcodes.RETURN) {
                            emitAntiJvmTiCheck(this, detectionMode, response)
                            classModified = true
                        }
                        super.visitInsn(opcode)
                    }
                }
            }

            override fun visitEnd() {
                if (!hasClinit) {
                    val mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
                    mv.visitCode()
                    emitAntiJvmTiCheck(mv, detectionMode, response)
                    mv.visitInsn(Opcodes.RETURN)
                    mv.visitMaxs(2, 0)
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
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = classCount,
    )
}

/**
 * Anti-Dump Protection transform.
 *
 * Injects memory dump detection and sensitive field scrambling.
 * Uses JNI-layer key holding to prevent key material from appearing in heap dumps.
 */
fun applyAntiDumpProtection(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "anti-dump-protection")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val protectionLevel = (params["protectionLevel"] as? String) ?: "field-scramble"
    val supportedProtectionLevels = setOf("field-scramble", "jni-key-hold", "full")
    require(protectionLevel in supportedProtectionLevels) { "anti-dump-protection protectionLevel '$protectionLevel' is not supported; supported values: ${supportedProtectionLevels.joinToString("", "")}" }

    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact
        if (isJniLoaderTimingSensitiveClass(classArtifact.bytes)) return@map classArtifact

        val cr = ClassReader(classArtifact.bytes)
        val classNode = ClassNode()
        try {
            cr.accept(classNode, ClassReader.EXPAND_FRAMES)
        } catch (_: Exception) { return@map classArtifact }
        if (isPriorJavaShroudGeneratedRuntimeClass(classNode)) return@map classArtifact
        if (hasPriorSealedRuntimeDependency(classNode)) return@map classArtifact
        if (usesJavaShroudVmDispatch(classNode)) return@map classArtifact

        val scrambledFields = if ((protectionLevel == "field-scramble" || protectionLevel == "full") && !isJavaShroudRuntimeStateClass(classNode)) {
            eligibleAntiDumpScrambleFields(classNode)
        } else {
            emptyMap()
        }
        val fieldRewriteCount = rewriteAntiDumpFieldAccesses(classNode, scrambledFields)

        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        var classModified = false
        var hasClinit = false

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)
                if (name != "<clinit>") return superMv
                hasClinit = true

                return object : MethodVisitor(Opcodes.ASM9, superMv) {
                    override fun visitInsn(opcode: Int) {
                        if (opcode == Opcodes.RETURN) {
                            emitAntiDumpProtectionInit(this, protectionLevel, classArtifact.summary.internalName)
                            classModified = true
                        }
                        super.visitInsn(opcode)
                    }
                }
            }

            override fun visitEnd() {
                if (!hasClinit) {
                    val mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
                    mv.visitCode()
                    emitAntiDumpProtectionInit(mv, protectionLevel, classArtifact.summary.internalName)
                    mv.visitInsn(Opcodes.RETURN)
                    mv.visitMaxs(1, 0)
                    mv.visitEnd()
                    classModified = true
                }
                super.visitEnd()
            }
        }

        try {
            classNode.accept(cv)
        } catch (_: Exception) { return@map classArtifact }
        if (!classModified && fieldRewriteCount == 0) return@map classArtifact
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = classCount,
    )
}

/**
 * Anti-ByteBuddy Transform detection.
 *
 * Detects ByteBuddy agent injection and method interception.
 */
fun applyAntiByteBuddyTransform(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "anti-bytebuddy-transform")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val response = (params["response"] as? String) ?: "log"
    val supportedResponses = setOf("log", "degrade", "refuse")
    require(response in supportedResponses) {
        "anti-bytebuddy-transform response '$response' is not supported; supported values: ${supportedResponses.joinToString("", "")}"
    }


    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact
        if (isJniLoaderTimingSensitiveClass(classArtifact.bytes)) return@map classArtifact

        val cr = ClassReader(classArtifact.bytes)
        val classNode = ClassNode()
        try {
            cr.accept(classNode, ClassReader.SKIP_FRAMES)
        } catch (_: Exception) { return@map classArtifact }
        if (isPriorJavaShroudGeneratedRuntimeClass(classNode)) return@map classArtifact
        if (hasPriorSealedRuntimeDependency(classNode)) return@map classArtifact
        if (usesJavaShroudVmDispatch(classNode)) return@map classArtifact

        val cw = ClassWriter(cr, ClassWriter.COMPUTE_FRAMES)
        var classModified = false
        var hasClinit = false

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)
                if (name != "<clinit>") return superMv
                hasClinit = true

                return object : MethodVisitor(Opcodes.ASM9, superMv) {
                    override fun visitInsn(opcode: Int) {
                        if (opcode == Opcodes.RETURN) {
                            emitAntiByteBuddyCheck(this, response)
                            classModified = true
                        }
                        super.visitInsn(opcode)
                    }
                }
            }

            override fun visitEnd() {
                if (!hasClinit) {
                    val mv = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
                    mv.visitCode()
                    emitAntiByteBuddyCheck(mv, response)
                    mv.visitInsn(Opcodes.RETURN)
                    mv.visitMaxs(1, 0)
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
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = classCount,
    )
}


private fun emitAntiInstrumentationCheck(mv: MethodVisitor, detectionLevel: String, response: String) {
    mv.visitLdcInsn(detectionLevel)
    mv.visitLdcInsn(response)
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "io/github/hht0rro/javashroud/transforms/protection/AntiInstrumentationHelper",
        "checkInstrumentation",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        false,
    )
}

/**
 * Emit an extended distributed integrity check into a method entry point.
 * Uses checkInstrumentationEx which combines native anti-instrumentation
 * with kernel boot token verification, so patching checkInstrumentation alone
 * does not bypass this probe. Only injected when the random selection picks
 * this method for this build.
 */
private fun emitDistributedIntegrityProbe(mv: MethodVisitor, detectionLevel: String, response: String) {
    mv.visitLdcInsn(detectionLevel)
    mv.visitLdcInsn(response)
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "io/github/hht0rro/javashroud/transforms/protection/AntiInstrumentationHelper",
        "checkInstrumentationExSafe",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        false,
    )
}

private fun emitAntiJvmTiCheck(mv: MethodVisitor, detectionMode: String, response: String) {
    mv.visitLdcInsn(detectionMode)
    mv.visitLdcInsn(response)
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "io/github/hht0rro/javashroud/transforms/protection/AntiJvmTiHelper",
        "checkJvmTiAgents",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        false,
    )
}

private fun emitAntiDumpProtectionInit(mv: MethodVisitor, protectionLevel: String, ownerInternalName: String) {
    mv.visitLdcInsn(protectionLevel)
    mv.visitLdcInsn(Type.getObjectType(ownerInternalName))
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "io/github/hht0rro/javashroud/transforms/protection/AntiDumpRuntimeHelper",
        "initializeProtection",
        "(Ljava/lang/String;Ljava/lang/Class;)V",
        false,
    )
}

private fun eligibleAntiDumpScrambleFields(classNode: ClassNode): Map<String, String> = classNode.fields
    .filter { field ->
        field.access and (Opcodes.ACC_FINAL or Opcodes.ACC_VOLATILE) == 0 &&
            field.value == null &&
            field.desc == "Ljava/lang/String;"
    }
    .associate { field -> field.name + field.desc to field.desc }

private fun rewriteAntiDumpFieldAccesses(classNode: ClassNode, fields: Map<String, String>): Int {
    if (fields.isEmpty()) return 0
    var rewrites = 0
    for (method in classNode.methods) {
        val instructions = method.instructions ?: continue
        for (insn in instructions.toArray()) {
            val fieldInsn = insn as? FieldInsnNode ?: continue
            if (fieldInsn.owner != classNode.name) continue
            val descriptor = fields[fieldInsn.name + fieldInsn.desc] ?: continue
            val helper = antiDumpFieldHelper(descriptor, fieldInsn.opcode) ?: continue
            val wrap = InsnList()
            wrap.add(org.objectweb.asm.tree.LdcInsnNode(classNode.name))
            wrap.add(org.objectweb.asm.tree.LdcInsnNode(fieldInsn.name))
            wrap.add(MethodInsnNode(Opcodes.INVOKESTATIC, ANTI_DUMP_RUNTIME_HELPER, helper, antiDumpFieldHelperDescriptor(descriptor), false))
            when (fieldInsn.opcode) {
                Opcodes.GETFIELD, Opcodes.GETSTATIC -> instructions.insert(fieldInsn, wrap)
                Opcodes.PUTFIELD, Opcodes.PUTSTATIC -> instructions.insertBefore(fieldInsn, wrap)
            }
            rewrites++
        }
    }
    return rewrites
}

private const val ANTI_DUMP_RUNTIME_HELPER = "io/github/hht0rro/javashroud/transforms/protection/AntiDumpRuntimeHelper"

private fun antiDumpFieldHelper(descriptor: String, opcode: Int): String? {
    val prefix = when (opcode) {
        Opcodes.GETFIELD, Opcodes.GETSTATIC -> "unscramble"
        Opcodes.PUTFIELD, Opcodes.PUTSTATIC -> "scramble"
        else -> return null
    }
    return when (descriptor) {
        "Ljava/lang/String;" -> prefix + "String"
        "[B" -> prefix + "Bytes"
        "[C" -> prefix + "Chars"
        else -> null
    }
}

private fun antiDumpFieldHelperDescriptor(descriptor: String): String = when (descriptor) {
    "Ljava/lang/String;" -> "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"
    "[B" -> "([BLjava/lang/String;Ljava/lang/String;)[B"
    "[C" -> "([CLjava/lang/String;Ljava/lang/String;)[C"
    else -> error("unsupported anti-dump field descriptor: $descriptor")
}

private fun emitAntiByteBuddyCheck(mv: MethodVisitor, response: String) {
    mv.visitLdcInsn(response)
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "io/github/hht0rro/javashroud/transforms/protection/AntiByteBuddyHelper",
        "checkByteBuddy",
        "(Ljava/lang/String;)V",
        false,
    )
}

/**
 * JNI Microkernel Loader transform.
 *
 * Injects native library loading and JNI-based kernel dispatch.
 * The native kernel handles high-value protection operations like
 * decryption, class loading, and VM interpretation.
 *
 * Only sinks protection kernels into native - does not native-ize the program.
 */
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
    val supportedTargetPlatforms = setOf("auto", "windows-x64", "linux-x64", "macos-x64", "macos-arm64")
    require(targetPlatform in supportedTargetPlatforms) { "jni-microkernel-loader targetPlatform '$targetPlatform' is not supported; supported values: ${supportedTargetPlatforms.joinToString("", "")}" }
    val diversifiedVirtualization = (params["diversifiedVirtualization"] as? Boolean) ?: true
    val vmMode = if (diversifiedVirtualization) "vm-diverse" else "vm-off"

    val nativeKeyRandom = java.security.SecureRandom()

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

        val cr = ClassReader(classArtifact.bytes)
        val cw = ClassWriter(cr, ClassWriter.COMPUTE_FRAMES)
        var classModified = false
        var clinitSeen = false
        var isInterfaceClass = false

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
                        emitJniMicrokernelLoad(this, kernelComponents, targetPlatform, vmMode)
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
                    emitJniMicrokernelLoad(mv, kernelComponents, targetPlatform, vmMode)
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
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = classCount,
    )
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
                                ownerToken = dispatchClassToken,
                                methodToken = dispatchMethodToken,
                                returnDescriptor = org.objectweb.asm.Type.getReturnType(descriptor).descriptor,
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

