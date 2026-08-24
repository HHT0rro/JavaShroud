package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.computeFramesWriter
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode

private const val DEFENSE_KERNEL_HELPER_OWNER =
    "io/github/hht0rro/javashroud/transforms/protection/DefenseKernelRuntimeHelper"

/**
 * Current-format native-defense injection.  Both public passes use exactly the
 * same native state machine; they differ only by the authenticated defense
 * surface sent to the Rust kernel.
 */
fun applyOsAntiDebug(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult = applyUnifiedDefense(artifact, ruleMatches, params, "os-anti-debug")

fun applyOsAntiVm(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult = applyUnifiedDefense(artifact, ruleMatches, params, "os-anti-vm")

private fun applyUnifiedDefense(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
    surface: String,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, surface)
    require(matchedClassNames.isNotEmpty()) {
        "$surface requires at least one eligible application class; refusing a no-op hardened defense build"
    }

    val profile = (params["profile"] as? String ?: "hardened").trim().lowercase()
    require(profile in setOf("balanced", "hardened")) {
        "$surface profile '$profile' is not supported; supported values: balanced, hardened"
    }
    val distributedProbeCount = ((params["distributedProbeCount"] as? Number)?.toInt() ?: 2).coerceIn(1, 4)

    var transformedClassCount = 0
    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (classArtifact.summary.internalName !in matchedClassNames) return@map classArtifact

        val classNode = try {
            ClassNode().also { ClassReader(classArtifact.bytes).accept(it, ClassReader.SKIP_DEBUG) }
        } catch (error: Throwable) {
            throw IllegalStateException("$surface could not parse ${classArtifact.summary.internalName}", error)
        }
        if (
            isPriorJavaShroudGeneratedRuntimeClass(classNode) ||
            hasPriorSealedRuntimeDependency(classNode) ||
            usesJavaShroudVmDispatch(classNode)
        ) {
            return@map classArtifact
        }

        val probeMethods = classNode.methods.orEmpty()
            .asSequence()
            .filter { method -> method.name != "<clinit>" && method.name != "<init>" }
            .filter { method -> method.access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) == 0 }
            .map { method -> method.name + method.desc }
            .sortedBy { methodKey -> stableProbeOrder(classNode.name, methodKey, surface) }
            .take(distributedProbeCount)
            .toSet()

        val reader = ClassReader(classArtifact.bytes)
        val writer = computeFramesWriter(reader)
        var hasClinit = false
        var isInterface = false
        var modified = false
        val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
            override fun visit(
                version: Int,
                access: Int,
                name: String?,
                signature: String?,
                superName: String?,
                interfaces: Array<out String>?,
            ) {
                isInterface = access and Opcodes.ACC_INTERFACE != 0
                super.visit(version, access, name, signature, superName, interfaces)
            }

            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<out String>?,
            ): MethodVisitor {
                val delegate = super.visitMethod(access, name, descriptor, signature, exceptions)
                if (name == "<clinit>") {
                    hasClinit = true
                    return object : MethodVisitor(Opcodes.ASM9, delegate) {
                        override fun visitCode() {
                            super.visitCode()
                            emitDefenseInitialize(this, surface, profile)
                            modified = true
                        }
                    }
                }
                if (name + descriptor !in probeMethods) return delegate
                return object : MethodVisitor(Opcodes.ASM9, delegate) {
                    override fun visitCode() {
                        super.visitCode()
                        emitDefenseProbe(this, surface, probePoint(name, descriptor))
                        modified = true
                    }
                }
            }

            override fun visitEnd() {
                if (!hasClinit && !isInterface) {
                    val initializer = super.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
                    initializer.visitCode()
                    emitDefenseInitialize(initializer, surface, profile)
                    initializer.visitInsn(Opcodes.RETURN)
                    initializer.visitMaxs(0, 0)
                    initializer.visitEnd()
                    modified = true
                }
                super.visitEnd()
            }
        }
        try {
            reader.accept(visitor, ClassReader.SKIP_FRAMES)
        } catch (error: Throwable) {
            throw IllegalStateException("$surface could not instrument ${classArtifact.summary.internalName}", error)
        }
        if (!modified) return@map classArtifact
        transformedClassCount++
        reanalyzedClassArtifact(classArtifact, writer.toByteArray())
    }

    require(transformedClassCount > 0) {
        "$surface did not inject an authenticated startup/probe path; refusing a no-op hardened defense build"
    }
    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = transformedClassCount,
        transformedMemberCount = transformedClassCount,
    )
}

private fun emitDefenseInitialize(methodVisitor: MethodVisitor, surface: String, profile: String) {
    methodVisitor.visitLdcInsn(surface)
    methodVisitor.visitLdcInsn(profile)
    methodVisitor.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        DEFENSE_KERNEL_HELPER_OWNER,
        "initialize",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        false,
    )
}

private fun emitDefenseProbe(methodVisitor: MethodVisitor, surface: String, point: String) {
    methodVisitor.visitLdcInsn(surface)
    methodVisitor.visitLdcInsn(point)
    methodVisitor.visitMethodInsn(
        Opcodes.INVOKESTATIC,
        DEFENSE_KERNEL_HELPER_OWNER,
        "probe",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        false,
    )
}

private fun stableProbeOrder(owner: String, method: String, surface: String): ULong {
    var value = 0xcbf29ce484222325UL
    for (character in "$surface\u0000$owner\u0000$method") {
        value = (value xor character.code.toULong()) * 0x100000001b3UL
    }
    return value
}

private fun probePoint(name: String, descriptor: String): String =
    "m" + stableProbeOrder("", name + descriptor, "probe").toString(16).take(14)
