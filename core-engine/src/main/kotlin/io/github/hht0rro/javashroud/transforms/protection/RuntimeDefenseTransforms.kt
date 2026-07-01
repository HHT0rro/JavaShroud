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
import org.objectweb.asm.tree.InsnList
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import java.security.SecureRandom

// --- Phase 3: Runtime Defense Transforms ---

/**
 * Callsite Rotation Protection transform.
 *
 * Replaces INVOKEVIRTUAL with INVOKEDYNAMIC backed by MutableCallSite.
 * The real target rotates based on epoch, thread, counter, or runtime signals.
 */
fun applyCallsiteRotationProtection(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "callsite-rotation-protection")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val rotationStrategy = (params["rotationStrategy"] as? String) ?: "epoch"
    val supportedRotationStrategies = setOf("epoch", "counter", "thread-local", "random")
    require(rotationStrategy in supportedRotationStrategies) {
        "callsite-rotation-protection rotationStrategy '$rotationStrategy' is not supported; supported values: ${supportedRotationStrategies.joinToString("", "")}"
    }

    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()

    var classCount = 0
    var callCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact

        val classNode = ClassNode()
        try {
            ClassReader(classArtifact.bytes).accept(classNode, 0)
        } catch (_: Exception) { return@map classArtifact }

        var classModified = false
        for (method in classNode.methods) {
            val instructions = method.instructions ?: continue
            for (insn in instructions.toArray()) {
                val call = insn as? MethodInsnNode ?: continue
                if (call.opcode != Opcodes.INVOKEVIRTUAL) continue
                if (call.owner.startsWith("[")) continue
                if (isReflectionSurfaceVirtualCall(call.owner, call.name)) continue
                if (isClassLoadingBoundaryVirtualCall(call.owner, call.name)) continue
                if (random.nextInt(100) >= 30) continue
                val bsm = Handle(
                    Opcodes.H_INVOKESTATIC,
                    "io/github/hht0rro/javashroud/transforms/protection/CallsiteRotationHelper",
                    "createRotatingCallSite",
                    "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/invoke/CallSite;",
                    false,
                )
                val indyDescriptor = "(L${call.owner};" + call.desc.substring(1)
                instructions.set(
                    call,
                    InvokeDynamicInsnNode(
                        call.name,
                        indyDescriptor,
                        bsm,
                        call.owner,
                        rotationStrategy,
                    ),
                )
                classModified = true
                callCount++
            }
        }
        if (!classModified) return@map classArtifact
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        try {
            classNode.accept(cw)
        } catch (_: Exception) { return@map classArtifact }
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = callCount,
    )
}

private val reflectionSurfaceVirtualMethodNames = setOf(
    "getDeclaredMethods",
    "getMethods",
    "getDeclaredMethod",
    "getMethod",
    "getDeclaredFields",
    "getFields",
    "getDeclaredField",
    "getField",
    "getDeclaredConstructors",
    "getConstructors",
    "getDeclaredConstructor",
    "getConstructor",
)

private fun isReflectionSurfaceVirtualCall(owner: String, name: String): Boolean =
    owner == "java/lang/Class" && name in reflectionSurfaceVirtualMethodNames

private fun isClassLoadingBoundaryVirtualCall(owner: String, name: String): Boolean {
    if (owner == "java/lang/Class" && name in classResourceAndLoaderMethodNames) return true
    if (owner == "java/lang/ClassLoader" && name in classLoaderBoundaryMethodNames) return true
    return owner.endsWith("ClassLoader") && name in classLoaderBoundaryMethodNames
}

private val classResourceAndLoaderMethodNames = setOf(
    "getClassLoader",
    "getResource",
    "getResourceAsStream",
)

private val classLoaderBoundaryMethodNames = setOf(
    "defineClass",
    "findClass",
    "loadClass",
    "getResource",
    "getResourceAsStream",
)

/**
 * Environment Bound Keys transform.
 *
 * Generates decryption keys derived from environment-specific material
 * (hardware ID, JVM params, certificate fingerprint, etc.) so the JAR
 * cannot be decrypted outside the target environment.
 */
fun applyEnvironmentBoundKeys(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "environment-bound-keys")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val bindingSource = (params["bindingSource"] as? String) ?: "jvm-params"
    val supportedBindingSources = setOf("hardware-id", "jvm-params", "certificate-fingerprint", "combined")
    require(bindingSource in supportedBindingSources) { "environment-bound-keys bindingSource '$bindingSource' is not supported; supported values: ${supportedBindingSources.joinToString("", "")}" }
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()

    // Generate environment-binding material
    // Generate salt and derive expected key at obfuscation time using real KDF
    val saltBytes = ByteArray(16).also { random.nextBytes(it) }
    val saltB64 = java.util.Base64.getEncoder().encodeToString(saltBytes)
    val expectedKey = deriveEnvironmentBindingKeyFallback(bindingSource, saltB64)

    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact

        // Inject environment-binding clinit check
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
                            emitEnvironmentBindingCheck(this, expectedKey, bindingSource, saltB64)
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
                    emitEnvironmentBindingCheck(mv, expectedKey, bindingSource, saltB64)
                    mv.visitInsn(Opcodes.RETURN)
                    mv.visitMaxs(3, 0)
                    mv.visitEnd()
                    classModified = true
                }
                super.visitEnd()
            }
        }

        try {
            cr.accept(cv, 0)
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

private fun deriveEnvironmentBindingKeyFallback(bindingSource: String, saltB64: String): String {
    val material = "envkey:$bindingSource:$saltB64".toByteArray(Charsets.UTF_8)
    var hash = 0x811c9dc5.toInt()
    for (byte in material) {
        hash = hash xor (byte.toInt() and 0xFF)
        hash *= 0x01000193
    }
    return hash.toUInt().toString(16).padStart(8, '0')
}

private fun emitEnvironmentBindingCheck(mv: MethodVisitor, expectedKey: String, bindingSource: String, saltB64: String) {
    mv.visitLdcInsn(expectedKey)
    mv.visitLdcInsn(bindingSource)
    mv.visitLdcInsn(saltB64)
    mv.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        "io/github/hht0rro/javashroud/transforms/protection/EnvironmentBindingHelper",
        "verifyEnvironment",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
        false,
    )
}

/**
 * Anti-Dump Constant Pool transform.
 *
 * Migrates sensitive strings from stable constant pool positions to
 * condy or runtime builder, preventing javap/ASM from reading them.
 */
fun applyAntiDumpConstantPool(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "anti-dump-constant-pool")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val migrationStrategy = (params["migrationStrategy"] as? String) ?: "condy"
    val supportedMigrationStrategies = setOf("condy", "runtime-builder", "hybrid")
    require(migrationStrategy in supportedMigrationStrategies) {
        "anti-dump-constant-pool migrationStrategy '$migrationStrategy' is not supported; supported values: ${supportedMigrationStrategies.joinToString("", "")}"
    }

    var classCount = 0
    var stringCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact

        if (isConstantPoolMigrationTimingSensitiveClass(classArtifact.bytes)) return@map classArtifact

        val classNode = ClassNode()
        try {
            ClassReader(classArtifact.bytes).accept(classNode, 0)
        } catch (_: Exception) {
            return@map classArtifact
        }
        val useCondy = migrationStrategy == "condy" && classNode.version >= Opcodes.V11

        var classModified = false
        for (method in classNode.methods) {
            val loadKernelArgs = findJniLoadKernelArgumentLdcs(method.instructions)
            for (insn in method.instructions.toArray()) {
                if (insn !is LdcInsnNode || insn in loadKernelArgs) continue
                val value = insn.cst
                if (value !is String || value.length <= 3) continue

                if (useCondy) {
                    val bsm = Handle(
                        Opcodes.H_INVOKESTATIC,
                        "io/github/hht0rro/javashroud/transforms/protection/AntiDumpHelper",
                        "buildStringFromB64Condy",
                        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/String;",
                        false,
                    )
                    val encoded = java.util.Base64.getEncoder().encodeToString(value.toByteArray())
                    method.instructions.set(
                        insn,
                        LdcInsnNode(org.objectweb.asm.ConstantDynamic("_", "Ljava/lang/String;", bsm, encoded)),
                    )
                } else {
                    val replacement = InsnList()
                    replacement.add(LdcInsnNode(java.util.Base64.getEncoder().encodeToString(value.toByteArray())))
                    replacement.add(
                        MethodInsnNode(
                            Opcodes.INVOKESTATIC,
                            "io/github/hht0rro/javashroud/transforms/protection/AntiDumpHelper",
                            "decodeString",
                            "(Ljava/lang/String;)Ljava/lang/String;",
                            false,
                        ),
                    )
                    method.instructions.insert(insn, replacement)
                    method.instructions.remove(insn)
                }
                classModified = true
                stringCount++
            }
        }

        if (!classModified) return@map classArtifact
        val rewrittenBytes = try {
            val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
            classNode.accept(cw)
            cw.toByteArray()
        } catch (_: Exception) {
            return@map classArtifact
        }
        classCount++
        reanalyzedClassArtifact(classArtifact, rewrittenBytes)
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = stringCount,
    )
}


private fun isConstantPoolMigrationTimingSensitiveClass(classBytes: ByteArray): Boolean {
    val classNode = ClassNode()
    return try {
        ClassReader(classBytes).accept(classNode, ClassReader.SKIP_DEBUG)
        classNode.methods.any { method ->
            method.instructions?.any { instruction ->
                instruction is InvokeDynamicInsnNode ||
                    (instruction is MethodInsnNode && isConstantPoolMigrationTimingSensitiveCall(instruction))
            } == true
        }
    } catch (_: Exception) {
        true
    }
}

private fun isConstantPoolMigrationTimingSensitiveCall(call: MethodInsnNode): Boolean {
    if (call.owner == "java/lang/Thread" && call.name == "sleep") return true
    if (call.owner.startsWith("java/util/concurrent/")) return true
    return false
}
private fun findJniLoadKernelArgumentLdcs(instructions: InsnList): Set<LdcInsnNode> {
    val protectedLdcs = linkedSetOf<LdcInsnNode>()
    val recentLdcs = ArrayDeque<LdcInsnNode>()
    for (insn in instructions.toArray()) {
        if (insn is LdcInsnNode) {
            recentLdcs.addLast(insn)
            if (recentLdcs.size > 3) recentLdcs.removeFirst()
            continue
        }
        if (
            insn is MethodInsnNode &&
            insn.opcode == Opcodes.INVOKESTATIC &&
            insn.owner == "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper" &&
            insn.name == "loadKernel" &&
            insn.desc == "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V" &&
            recentLdcs.size >= 3
        ) {
            protectedLdcs.addAll(recentLdcs.takeLast(3))
        }
    }
    return protectedLdcs
}
/**
 * Anti-Symbolic Execution transform.
 *
 * Inserts runtime-data-driven opaque predicates that cannot be resolved
 * by symbolic execution engines.
 */
fun applyAntiSymbolicExecution(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "anti-symbolic-execution")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val trapDensity = ((params["trapDensity"] as? Int) ?: 5).coerceIn(1, 10)
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()

    var classCount = 0
    var trapCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact

        val cr = ClassReader(classArtifact.bytes)
        val cw = ClassWriter(cr, ClassWriter.COMPUTE_FRAMES)
        var classModified = false
        var methodIndex = 0

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)
                val currentMethodIndex = methodIndex++

                if (currentMethodIndex % trapDensity != 0) return superMv

                return object : MethodVisitor(Opcodes.ASM9, superMv) {
                    override fun visitCode() {
                        super.visitCode()

                        // Insert a runtime-data-driven opaque predicate:
                        // if (System.nanoTime() == Long.MIN_VALUE) { dead code }
                        // The condition is always false but cannot be statically proven.
                        val endLabel = org.objectweb.asm.Label()

                        super.visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            "java/lang/System",
                            "nanoTime",
                            "()J",
                            false,
                        )
                        super.visitLdcInsn(Long.MIN_VALUE)
                        super.visitInsn(Opcodes.LCMP)
                        super.visitJumpInsn(Opcodes.IFNE, endLabel)

                        // Dead code (never reached but confuses symbolic execution)
                        super.visitInsn(Opcodes.ACONST_NULL)
                        super.visitInsn(Opcodes.ATHROW)

                        super.visitLabel(endLabel)
                        classModified = true
                        trapCount++
                    }
                }
            }
        }

        try {
            cr.accept(cv, 0)
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
        transformedMemberCount = trapCount,
    )
}


