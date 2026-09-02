package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.artifact.classArtifactIndex
import io.github.hht0rro.javashroud.bytecode.computeFramesWriter
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import java.security.SecureRandom
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode

internal object QpTargetRewriter {
    const val BOOTSTRAP_OWNER = "io/github/hht0rro/javashroud/transforms/protection/qp/QpBootstrap"
    const val BOOTSTRAP_NAME = "bootstrap"
    const val BOOTSTRAP_DESC =
        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"

    internal data class BootstrapTarget(val owner: String, val name: String)

    private const val RESOLVE_HANDLE_NAME = "resolveHandle"
    private const val RESOLVE_HANDLE_DESC =
        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;)Ljava/lang/invoke/MethodHandle;"

    /**
     * Return the class that owns the current target-token bootstrap. Runtime
     * sealing may relocate QpBootstrap before this final pass, so looking only
     * for the source owner would make the rewriter append a second canonical
     * bootstrap whose QpBridge reference no longer exists.
     */
    internal fun bootstrapTargetOrNull(artifact: BytecodeArtifact): BootstrapTarget? {
        for (classArtifact in artifact.classArtifacts) {
            var hasBootstrap = false
            var hasResolveHandle = false
            try {
                ClassReader(classArtifact.bytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
                    override fun visitMethod(
                        access: Int,
                        name: String,
                        descriptor: String,
                        signature: String?,
                        exceptions: Array<out String>?,
                    ): org.objectweb.asm.MethodVisitor? {
                        if (
                            access and Opcodes.ACC_STATIC != 0 &&
                                name == BOOTSTRAP_NAME &&
                                descriptor == BOOTSTRAP_DESC
                        ) {
                            hasBootstrap = true
                        }
                        if (
                            access and Opcodes.ACC_STATIC != 0 &&
                                name == RESOLVE_HANDLE_NAME &&
                                descriptor == RESOLVE_HANDLE_DESC
                        ) {
                            hasResolveHandle = true
                        }
                        return null
                    }
                }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
            } catch (_: RuntimeException) {
                hasBootstrap = false
                hasResolveHandle = false
            }
            if (hasBootstrap && hasResolveHandle) {
                return BootstrapTarget(classArtifact.summary.internalName, BOOTSTRAP_NAME)
            }
        }
        return null
    }

    fun wrapBusinessHandles(
        artifact: BytecodeArtifact,
        artifactDigest: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): BytecodeArtifact {
        val bootstrapTarget = bootstrapTargetOrNull(artifact) ?: BootstrapTarget(BOOTSTRAP_OWNER, BOOTSTRAP_NAME)
        var changed = false
        val updatedClasses = artifact.classArtifacts.map { classArtifact ->
            val rewritten = wrapClass(
                classBytes = classArtifact.bytes,
                internalName = classArtifact.summary.internalName,
                bootstrapTarget = bootstrapTarget,
                artifactDigest = artifactDigest,
                random = random,
            )
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
        bootstrapTarget: BootstrapTarget,
        artifactDigest: ByteArray,
        random: SecureRandom,
    ): ByteArray {
        val node = ClassNode()
        val reader = ClassReader(classBytes)
        reader.accept(node, 0)
        var modified = false
        var siteIndex = 0
        val wrapper = Handle(
            Opcodes.H_INVOKESTATIC,
            bootstrapTarget.owner,
            bootstrapTarget.name,
            BOOTSTRAP_DESC,
            false,
        )
        node.methods.orEmpty().forEach { method ->
            val instructions = method.instructions ?: return@forEach
            instructions.toArray().forEach { insn ->
                val indy = insn as? InvokeDynamicInsnNode ?: return@forEach
                if (indy.bsm.owner == BOOTSTRAP_OWNER || indy.bsm.owner == bootstrapTarget.owner) return@forEach
                if (indy.desc == "([B)Ljava/lang/String;") return@forEach
                if (isStandardLambdaMetafactory(indy)) return@forEach
                val originalArgs = indy.bsmArgs ?: emptyArray()
                val reboundArgs = originalArgs.map { arg ->
                    val token = arg as? String
                    if (token == null || !QpTargetTokenEnvelope.isToken(token)) {
                        arg
                    } else {
                        QpTargetTokenEnvelope.rebindArtifact(
                            token = token,
                            artifactDigest = artifactDigest,
                            callerOwner = internalName,
                            indyName = indy.name,
                            indyMethodType = indy.desc,
                            random = random,
                        )
                    }
                }.toTypedArray()
                val argsRebound = reboundArgs.withIndex().any { (index, arg) -> arg !== originalArgs[index] }
                val args = if (argsRebound) reboundArgs else originalArgs
                if (args.none { it is Handle && QpTargetTokenEnvelope.isBusinessTargetHandle(it) }) {
                    if (argsRebound) {
                        instructions.set(
                            indy,
                            InvokeDynamicInsnNode(indy.name, indy.desc, indy.bsm, *args),
                        )
                        modified = true
                    }
                    return@forEach
                }
                val rewrittenName = "r" + Integer.toHexString(siteIndex * -1640531527)
                val binding = QpTargetTokenEnvelope.Binding(
                    artifactDigest = artifactDigest,
                    callerOwner = internalName,
                    indyName = rewrittenName,
                    indyMethodType = indy.desc,
                    siteIndex = siteIndex,
                    protocolVersion = ProtectionFormat.CURRENT,
                )
                val rewrittenArgs = ArrayList<Any>(args.size + 1)
                rewrittenArgs += QpTargetTokenEnvelope.seal(
                    QpTargetTokenEnvelope.fromHandle(indy.bsm),
                    binding,
                    random,
                )
                args.forEach { arg ->
                    val handle = arg as? Handle
                    if (handle != null && QpTargetTokenEnvelope.isBusinessTargetHandle(handle)) {
                        rewrittenArgs += QpTargetTokenEnvelope.seal(QpTargetTokenEnvelope.fromHandle(handle), binding, random)
                    } else {
                        rewrittenArgs += arg
                    }
                }
                instructions.set(indy, InvokeDynamicInsnNode(rewrittenName, indy.desc, wrapper, *rewrittenArgs.toTypedArray()))
                modified = true
                siteIndex++
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

    private fun isStandardLambdaMetafactory(indy: InvokeDynamicInsnNode): Boolean =
        indy.bsm.owner == "java/lang/invoke/LambdaMetafactory" &&
            indy.bsm.name in setOf("metafactory", "altMetafactory")

}
