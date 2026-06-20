package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult
import org.objectweb.asm.*
import java.security.SecureRandom

/**
 * Exception Semantic Virtualization transform.
 *
 * Converts normal control flow into exception-driven control flow
 * using custom exception types as message passing and state switching mechanisms.
 * This confuses decompilers and static analysis tools.
 */
fun applyExceptionSemanticVirtualization(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "exception-semantic-virtualization")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val virtualizationLevel = (params["virtualizationLevel"] as? String) ?: "selective"
    val supportedVirtualizationLevels = setOf("selective", "aggressive")
    require(virtualizationLevel in supportedVirtualizationLevels) {
        "exception-semantic-virtualization virtualizationLevel '$virtualizationLevel' is not supported; supported values: ${supportedVirtualizationLevels.joinToString(", ", "")}" }
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val random = seed?.let { SecureRandom(it.toString().toByteArray()) } ?: SecureRandom()

    val exceptionHelperOwner = sealedRuntimeHelperInternalName("io/github/hht0rro/javashroud/transforms/protection/ExceptionVirtualizationHelper")
    val exceptionHelperShouldVirtualize = sealedRuntimeHelperMethodName(
        "io/github/hht0rro/javashroud/transforms/protection/ExceptionVirtualizationHelper",
        "shouldVirtualize",
        "()Z",
    )
    val flowControlExceptionOwner = sealedRuntimeHelperInternalName("io/github/hht0rro/javashroud/transforms/protection/FlowControlException")

    var classCount = 0
    var methodCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (!matchedClassNames.contains(classArtifact.summary.internalName)) return@map classArtifact

        val cr = ClassReader(classArtifact.bytes)
        val cw = ClassWriter(cr, ClassWriter.COMPUTE_FRAMES)
        var classModified = false
        var methodIdx = 0

        val cv = object : ClassVisitor(Opcodes.ASM9, cw) {
            override fun visitMethod(
                access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?,
            ): MethodVisitor {
                val superMv = super.visitMethod(access, name, descriptor, signature, exceptions)
                if (name == "<init>" || name == "<clinit>") return superMv
                if (access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE) != 0) return superMv

                val currentIdx = methodIdx++
                if (virtualizationLevel == "selective" && currentIdx % 3 != 0) return superMv

                return object : MethodVisitor(Opcodes.ASM9, superMv) {
                    override fun visitCode() {
                        super.visitCode()

                        // Insert exception-based dispatch guard at method entry.
                        val tryStart = Label()
                        val tryEnd = Label()
                        val catchHandler = Label()

                        super.visitLabel(tryStart)
                        super.visitMethodInsn(
                            Opcodes.INVOKESTATIC,
                            exceptionHelperOwner,
                            exceptionHelperShouldVirtualize,
                            "()Z",
                            false,
                        )
                        super.visitJumpInsn(Opcodes.IFEQ, tryEnd)

                        super.visitTypeInsn(Opcodes.NEW, flowControlExceptionOwner)
                        super.visitInsn(Opcodes.DUP)
                        super.visitMethodInsn(
                            Opcodes.INVOKESPECIAL,
                            flowControlExceptionOwner,
                            "<init>",
                            "()V",
                            false,
                        )
                        super.visitInsn(Opcodes.ATHROW)

                        super.visitLabel(tryEnd)
                        val normalEnd = Label()
                        super.visitJumpInsn(Opcodes.GOTO, normalEnd)

                        super.visitLabel(catchHandler)
                        super.visitInsn(Opcodes.POP)
                        super.visitLabel(normalEnd)

                        super.visitTryCatchBlock(
                            tryStart,
                            tryEnd,
                            catchHandler,
                            flowControlExceptionOwner,
                        )

                        classModified = true
                        methodCount++
                    }
                }
            }
        }

        try {
            cr.accept(cv, ClassReader.SKIP_FRAMES)
        } catch (_: Exception) {
            return@map classArtifact
        }
        if (!classModified) return@map classArtifact
        classCount++
        reanalyzedClassArtifact(classArtifact, cw.toByteArray())
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(artifact, updatedClassArtifacts, classCount, methodCount)
}


