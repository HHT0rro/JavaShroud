package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.artifact.classArtifactIndex
import io.github.hht0rro.javashroud.bytecode.computeFramesWriter
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import java.security.MessageDigest
import java.security.SecureRandom
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode

internal object IndyTargetRewriter {
    const val BOOTSTRAP_OWNER = "io/github/hht0rro/javashroud/transforms/protection/IndyTargetBootstrap"
    const val BOOTSTRAP_NAME = "bootstrap"
    const val BOOTSTRAP_DESC =
        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"

    fun wrapBusinessHandles(
        artifact: BytecodeArtifact,
        key: ByteArray,
        artifactDigest: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): BytecodeArtifact {
        var changed = false
        val updatedClasses = artifact.classArtifacts.map { classArtifact ->
            val rewritten = wrapClass(classArtifact.bytes, classArtifact.summary.internalName, key, artifactDigest, random)
            if (rewritten.contentEquals(classArtifact.bytes)) classArtifact else {
                changed = true
                reanalyzedClassArtifact(classArtifact, rewritten)
            }
        }
        if (!changed) return artifact
        val byEntry = updatedClasses.associateBy { it.entryName }
        val jarEntries = artifact.jarEntries.map { entry ->
            val updated = byEntry[entry.name] ?: return@map entry
            entry.copy(bytes = updated.bytes)
        }
        return artifact.copy(
            jarEntries = jarEntries,
            classArtifacts = updatedClasses,
            classArtifactIndex = classArtifactIndex(updatedClasses),
        )
    }

    private fun wrapClass(
        classBytes: ByteArray,
        internalName: String,
        key: ByteArray,
        artifactDigest: ByteArray,
        random: SecureRandom,
    ): ByteArray {
        val node = ClassNode()
        val reader = ClassReader(classBytes)
        reader.accept(node, 0)
        var modified = false
        var siteIndex = 0
        val wrapper = Handle(Opcodes.H_INVOKESTATIC, BOOTSTRAP_OWNER, BOOTSTRAP_NAME, BOOTSTRAP_DESC, false)
        node.methods.orEmpty().forEach { method ->
            val instructions = method.instructions ?: return@forEach
            instructions.toArray().forEach { insn ->
                val indy = insn as? InvokeDynamicInsnNode ?: return@forEach
                if (indy.bsm.owner == BOOTSTRAP_OWNER) return@forEach
                val args = indy.bsmArgs ?: emptyArray()
                if (args.none { it is Handle && IndyTargetTokenEnvelope.isBusinessTargetHandle(it) }) return@forEach
                val classIdentity = sha256(internalName + "#" + method.name + method.desc)
                val rewrittenArgs = ArrayList<Any>(args.size + 1)
                val bsmIdentity = sha256(internalName + "#" + method.name + "#bsm#" + siteIndex + "#" + indy.bsm.owner + indy.bsm.name)
                val bsmBinding = IndyTargetTokenEnvelope.Binding(
                    artifactDigest = artifactDigest,
                    classIdentityDigest = classIdentity,
                    descriptorDigest = sha256(indy.bsm.desc),
                    callSiteIdentity = bsmIdentity,
                    routeId = sha256("indy-bsm-" + siteIndex),
                )
                rewrittenArgs += IndyTargetTokenEnvelope.seal(
                    IndyTargetTokenEnvelope.fromHandle(indy.bsm),
                    bsmBinding,
                    key,
                    random,
                )
                args.forEach { arg ->
                    val handle = arg as? Handle
                    if (handle != null && IndyTargetTokenEnvelope.isBusinessTargetHandle(handle)) {
                        val callSiteIdentity = sha256(internalName + "#" + method.name + "#" + siteIndex + "#" + handle.owner + handle.name)
                        val binding = IndyTargetTokenEnvelope.Binding(
                            artifactDigest = artifactDigest,
                            classIdentityDigest = classIdentity,
                            descriptorDigest = sha256(handle.desc),
                            callSiteIdentity = callSiteIdentity,
                            routeId = sha256("indy-" + siteIndex),
                        )
                        rewrittenArgs += IndyTargetTokenEnvelope.seal(IndyTargetTokenEnvelope.fromHandle(handle), binding, key, random)
                        siteIndex++
                    } else {
                        rewrittenArgs += arg
                    }
                }
                // LambdaMetafactory receives the invokedynamic call-site name as
                // the SAM method name (for example, "run" for Runnable).  The
                // VM uses that name when it links the generated lambda class;
                // replacing it with an obfuscation token makes the lambda fail
                // later with AbstractMethodError even though its implementation
                // handle is valid.  Preserve the JVM-required name for the two
                // standard LambdaMetafactory bootstraps while retaining the
                // dummy name for every other business invokedynamic site.
                val rewrittenName =
                    if (
                        indy.bsm.owner == "java/lang/invoke/LambdaMetafactory" &&
                            indy.bsm.name in setOf("metafactory", "altMetafactory")
                    ) {
                        indy.name
                    } else {
                        "r" + Integer.toHexString(siteIndex * -1640531527)
                    }
                instructions.set(indy, InvokeDynamicInsnNode(rewrittenName, indy.desc, wrapper, *rewrittenArgs.toTypedArray()))
                modified = true
            }
        }
        if (!modified) return classBytes
        // This is the final class-level rewrite in the hardened pipeline.  Do
        // not seed the writer with the input reader: ASM may copy a stale
        // StackMapTable for methods that were not visited as modified, even
        // though earlier transforms changed the offsets of their branch
        // targets.  The unseeded writer forces a complete CFG/frame rebuild
        // for every method in the class.
        val writer = computeFramesWriter()
        node.accept(writer)
        return writer.toByteArray()
    }

    private fun sha256(value: String): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.UTF_8))
}
