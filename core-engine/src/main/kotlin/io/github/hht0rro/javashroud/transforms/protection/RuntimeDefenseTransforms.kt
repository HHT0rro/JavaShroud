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
import io.github.hht0rro.javashroud.transforms.protection.hardening.IndyTargetTokenEnvelope
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

    val rotationStrategy = (params["rotationStrategy"] as? String) ?: "mixed"
    val canonicalByAlias = mapOf(
        "mixed" to "mixed",
        "mutable" to "mutable",
        "guarded" to "guarded",
        "table" to "table",
        "thread-slot" to "thread-slot",
        "oneshot" to "oneshot",
        "epoch" to "mutable",
        "counter" to "table",
        "thread-local" to "thread-slot",
        "random" to "guarded",
    )
    require(rotationStrategy in canonicalByAlias) {
        "callsite-rotation-protection rotationStrategy '$rotationStrategy' is not supported; supported values: ${canonicalByAlias.keys.joinToString(", ")}"
    }
    val resolvedStrategy = canonicalByAlias.getValue(rotationStrategy)
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()
    val mixedPool = mutableListOf("mutable", "guarded", "table", "thread-slot", "oneshot")
    mixedPool.shuffle(java.util.Random(seed ?: random.nextLong()))

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
                if (isConcurrencyBoundaryVirtualCall(call.owner, call.name)) continue
                if (random.nextInt(100) >= 30) continue
                val bsm = Handle(
                    Opcodes.H_INVOKESTATIC,
                    "io/github/hht0rro/javashroud/transforms/protection/CallsiteRotationHelper",
                    "createRotatingCallSite",
                    "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/invoke/CallSite;",
                    false,
                )
                val indyName = "r" + Integer.toHexString(callCount xor 0x5f3759df)
                val indyDescriptor = "(L${call.owner};" + call.desc.substring(1)
                val token = callsiteTargetToken(
                    callerOwner = classNode.name,
                    indyName = indyName,
                    indyMethodType = indyDescriptor,
                    targetOwner = call.owner,
                    targetName = call.name,
                    targetDescriptor = call.desc,
                    siteIndex = callCount,
                    random = random,
                )
                val siteStrategy = if (resolvedStrategy == "mixed") {
                    mixedPool[callCount % mixedPool.size]
                } else {
                    resolvedStrategy
                }
                instructions.set(
                    call,
                    InvokeDynamicInsnNode(
                        indyName,
                        indyDescriptor,
                        bsm,
                        token,
                        siteStrategy,
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

private fun callsiteTargetToken(
    callerOwner: String,
    indyName: String,
    indyMethodType: String,
    targetOwner: String,
    targetName: String,
    targetDescriptor: String,
    siteIndex: Int,
    random: SecureRandom,
): String {
    val zeros = ByteArray(32)
    val binding = IndyTargetTokenEnvelope.Binding(
        artifactDigest = currentVbc4BuildContextOrNull()?.jarLayoutDigest?.copyOf() ?: zeros,
        callerOwner = callerOwner,
        indyName = indyName,
        indyMethodType = indyMethodType,
        siteIndex = siteIndex,
        protocolVersion = 3,
    )
    return IndyTargetTokenEnvelope.seal(
        target = IndyTargetTokenEnvelope.Target(
            owner = targetOwner,
            name = targetName,
            descriptor = targetDescriptor,
            tag = Opcodes.H_INVOKEVIRTUAL,
            isInterface = false,
        ),
        binding = binding,
        random = random,
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
    (owner == "java/lang/Class" && name in reflectionSurfaceVirtualMethodNames) ||
        (owner == "java/lang/reflect/Method" && name == "invoke") ||
        (owner == "java/lang/reflect/Constructor" && name == "newInstance") ||
        // Class identity is a JVM linkage boundary used by lambda construction;
        // rotating it adds startup latency without changing the protected target.
        (owner == "java/lang/Object" && name == "getClass")

private fun isClassLoadingBoundaryVirtualCall(owner: String, name: String): Boolean {
    if (owner == "java/lang/Class" && name in classResourceAndLoaderMethodNames) return true
    if (owner == "java/lang/ClassLoader" && name in classLoaderBoundaryMethodNames) return true
    return owner.endsWith("ClassLoader") && name in classLoaderBoundaryMethodNames
}

private fun isConcurrencyBoundaryVirtualCall(owner: String, name: String): Boolean =
    owner.startsWith("java/util/concurrent/") ||
        (owner == "java/lang/Thread" && name in setOf("start", "join", "interrupt"))

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

