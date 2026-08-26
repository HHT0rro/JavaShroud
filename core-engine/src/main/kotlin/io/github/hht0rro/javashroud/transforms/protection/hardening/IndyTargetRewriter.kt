package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.artifact.classArtifactIndex
import io.github.hht0rro.javashroud.bytecode.computeFramesWriter
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import java.security.SecureRandom
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode

internal object IndyTargetRewriter {
    const val BOOTSTRAP_OWNER = "io/github/hht0rro/javashroud/transforms/protection/IndyTargetBootstrap"
    const val BOOTSTRAP_NAME = "bootstrap"
    const val BOOTSTRAP_DESC =
        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"

    fun wrapBusinessHandles(
        artifact: BytecodeArtifact,
        artifactDigest: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): BytecodeArtifact {
        var changed = false
        val updatedClasses = artifact.classArtifacts.map { classArtifact ->
            val rewritten = wrapClass(classArtifact.bytes, classArtifact.summary.internalName, artifactDigest, random)
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
        artifactDigest: ByteArray,
        random: SecureRandom,
    ): ByteArray {
        val node = ClassNode()
        val reader = ClassReader(classBytes)
        reader.accept(node, 0)
        var modified = false
        var siteIndex = 0
        var bridgeIndex = 0
        val wrapper = Handle(Opcodes.H_INVOKESTATIC, BOOTSTRAP_OWNER, BOOTSTRAP_NAME, BOOTSTRAP_DESC, false)
        val existingMethodKeys = node.methods.orEmpty().mapTo(mutableSetOf()) { it.name + it.desc }
        val lambdaBridges = mutableMapOf<String, Handle>()
        val generatedLambdaBridges = mutableListOf<MethodNode>()
        node.methods.orEmpty().forEach { method ->
            val instructions = method.instructions ?: return@forEach
            val preserveLambdaLinkage = isJvmTimingSensitive(method)
            instructions.toArray().forEach { insn ->
                val indy = insn as? InvokeDynamicInsnNode ?: return@forEach
                if (indy.bsm.owner == BOOTSTRAP_OWNER) return@forEach
                if (indy.desc == "([B)Ljava/lang/String;") return@forEach
                val args = indy.bsmArgs ?: emptyArray()
                if (args.none { it is Handle && IndyTargetTokenEnvelope.isBusinessTargetHandle(it) }) return@forEach
                val isLambdaMetafactory = isStandardLambdaMetafactory(indy)
                if (isLambdaMetafactory && preserveLambdaLinkage) {
                    val bridgedArgs = args.map { arg ->
                        val handle = arg as? Handle
                        if (handle == null || !IndyTargetTokenEnvelope.isBusinessTargetHandle(handle)) {
                            arg
                        } else {
                            val key = handleKey(handle)
                            val bridgeHandle = lambdaBridges[key] ?: run {
                                val bridgeName = nextBridgeName(existingMethodKeys, bridgeIndex)
                                bridgeIndex++
                                val bridge = createLambdaBridge(internalName, bridgeName, handle)
                                if (bridge == null) {
                                    null
                                } else {
                                    existingMethodKeys += bridgeName + bridge.method.desc
                                    generatedLambdaBridges += bridge.method
                                    lambdaBridges[key] = bridge.handle
                                    bridge.handle
                                }
                            }
                            bridgeHandle ?: arg
                        }
                    }
                    if (bridgedArgs.withIndex().any { (index, arg) -> arg !== args[index] }) {
                        instructions.set(indy, InvokeDynamicInsnNode(indy.name, indy.desc, indy.bsm, *bridgedArgs.toTypedArray()))
                        modified = true
                    }
                    return@forEach
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
                    if (isLambdaMetafactory) indy.name else "r" + Integer.toHexString(siteIndex * -1640531527)
                val binding = IndyTargetTokenEnvelope.Binding(
                    artifactDigest = artifactDigest,
                    callerOwner = internalName,
                    indyName = rewrittenName,
                    indyMethodType = indy.desc,
                    siteIndex = siteIndex,
                    protocolVersion = 3,
                )
                val rewrittenArgs = ArrayList<Any>(args.size + 1)
                rewrittenArgs += IndyTargetTokenEnvelope.seal(
                    IndyTargetTokenEnvelope.fromHandle(indy.bsm),
                    binding,
                    random,
                )
                args.forEach { arg ->
                    val handle = arg as? Handle
                    if (handle != null && IndyTargetTokenEnvelope.isBusinessTargetHandle(handle)) {
                        rewrittenArgs += IndyTargetTokenEnvelope.seal(IndyTargetTokenEnvelope.fromHandle(handle), binding, random)
                    } else {
                        rewrittenArgs += arg
                    }
                }
                instructions.set(indy, InvokeDynamicInsnNode(rewrittenName, indy.desc, wrapper, *rewrittenArgs.toTypedArray()))
                modified = true
                siteIndex++
            }
        }
        if (generatedLambdaBridges.isNotEmpty()) {
            node.methods.addAll(generatedLambdaBridges)
            modified = true
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

    private data class LambdaBridge(val handle: Handle, val method: MethodNode)

    private fun isStandardLambdaMetafactory(indy: InvokeDynamicInsnNode): Boolean =
        indy.bsm.owner == "java/lang/invoke/LambdaMetafactory" &&
            indy.bsm.name in setOf("metafactory", "altMetafactory")

    private fun isJvmTimingSensitive(method: MethodNode): Boolean =
        method.instructions?.any { instruction ->
            val call = instruction as? MethodInsnNode ?: return@any false
            if (call.owner == "java/lang/Thread") {
                call.name in setOf("sleep", "start", "join", "interrupt")
            } else {
                call.owner.startsWith("java/util/concurrent/")
            }
        } == true

    private fun handleKey(handle: Handle): String =
        "${handle.tag}|${handle.owner}|${handle.name}|${handle.desc}|${handle.isInterface}"

    private fun nextBridgeName(existingMethodKeys: Set<String>, index: Int): String {
        var candidateIndex = index
        var name: String
        do {
            name = "\$_j_lambda_$candidateIndex"
            candidateIndex++
        } while (existingMethodKeys.any { it.startsWith(name) })
        return name
    }

    private fun createLambdaBridge(internalName: String, bridgeName: String, target: Handle): LambdaBridge? {
        if (target.tag == Opcodes.H_NEWINVOKESPECIAL) return null
        val targetType = Type.getMethodType(target.desc)
        val bridgeArguments = if (target.tag == Opcodes.H_INVOKESTATIC) {
            targetType.argumentTypes
        } else {
            arrayOf(Type.getObjectType(target.owner), *targetType.argumentTypes)
        }
        val bridgeDescriptor = Type.getMethodDescriptor(targetType.returnType, *bridgeArguments)
        val method = MethodNode(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            bridgeName,
            bridgeDescriptor,
            null,
            null,
        )
        method.visitCode()
        var localIndex = 0
        bridgeArguments.forEach { argument ->
            method.visitVarInsn(argument.getOpcode(Opcodes.ILOAD), localIndex)
            localIndex += argument.size
        }
        val opcode = if (target.tag == Opcodes.H_INVOKESTATIC) Opcodes.INVOKESTATIC else when (target.tag) {
            Opcodes.H_INVOKEVIRTUAL -> Opcodes.INVOKEVIRTUAL
            Opcodes.H_INVOKEINTERFACE -> Opcodes.INVOKEINTERFACE
            Opcodes.H_INVOKESPECIAL -> Opcodes.INVOKESPECIAL
            else -> return null
        }
        method.visitMethodInsn(opcode, target.owner, target.name, target.desc, target.isInterface)
        method.visitInsn(targetType.returnType.getOpcode(Opcodes.IRETURN))
        method.visitMaxs(0, 0)
        method.visitEnd()
        return LambdaBridge(
            handle = Handle(Opcodes.H_INVOKESTATIC, internalName, bridgeName, bridgeDescriptor, false),
            method = method,
        )
    }
}
