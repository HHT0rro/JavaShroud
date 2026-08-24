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
import io.github.hht0rro.javashroud.transforms.protection.hardening.ProtectionFormat
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

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
                val token = callsiteTargetToken(
                    owner = call.owner,
                    name = call.name,
                    descriptor = call.desc,
                    siteIndex = callCount,
                    random = random,
                )
                instructions.set(
                    call,
                    InvokeDynamicInsnNode(
                        "r" + Integer.toHexString(callCount xor 0x5f3759df),
                        indyDescriptor,
                        bsm,
                        token,
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

private fun callsiteTargetToken(
    owner: String,
    name: String,
    descriptor: String,
    siteIndex: Int,
    random: SecureRandom,
): String {
    val key = ByteArray(IndyTargetTokenEnvelope.KEY_SIZE)
    val material = currentVbc4BuildContextOrNull()?.copyMasterKey()
    if (material != null) {
        try {
            MessageDigest.getInstance("SHA-256").digest(material + "indy-token-key-r1".toByteArray()).copyInto(key, endIndex = key.size)
        } finally {
            material.fill(0)
        }
    } else {
        random.nextBytes(key)
    }
    val zeros = ByteArray(32)
    val binding = IndyTargetTokenEnvelope.Binding(
        artifactDigest = currentVbc4BuildContextOrNull()?.jarLayoutDigest?.copyOf() ?: zeros,
        classIdentityDigest = MessageDigest.getInstance("SHA-256").digest(owner.toByteArray()),
        descriptorDigest = MessageDigest.getInstance("SHA-256").digest(descriptor.toByteArray()),
        callSiteIdentity = MessageDigest.getInstance("SHA-256").digest((owner + "#" + name + "#" + siteIndex).toByteArray()),
        routeId = MessageDigest.getInstance("SHA-256").digest(("callsite-" + siteIndex).toByteArray()),
    )
    return IndyTargetTokenEnvelope.seal(
        target = IndyTargetTokenEnvelope.Target(
            owner = owner,
            name = name,
            descriptor = descriptor,
            tag = Opcodes.H_INVOKEVIRTUAL,
            isInterface = false,
        ),
        binding = binding,
        key = key,
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

