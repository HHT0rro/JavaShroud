package io.github.hht0rro.javashroud.transforms

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.artifact.updateArtifactClassSet
import io.github.hht0rro.javashroud.artifact.updateRenamedArtifactClasses
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter

internal fun unchangedTransformResult(artifact: BytecodeArtifact): TransformResult =
    TransformResult(artifact = artifact, transformedClassCount = 0, transformedMemberCount = 0)

internal fun updatedArtifactTransformResult(
    artifact: BytecodeArtifact,
    updatedClassArtifacts: List<ClassArtifact>,
    transformedClassCount: Int,
    transformedMemberCount: Int,
): TransformResult = TransformResult(
    artifact = updateArtifactClassSet(artifact, updatedClassArtifacts),
    transformedClassCount = transformedClassCount,
    transformedMemberCount = transformedMemberCount,
)

internal fun renamedArtifactTransformResult(
    artifact: BytecodeArtifact,
    updatedClassArtifacts: List<ClassArtifact>,
    classRenameMap: Map<String, String>,
): TransformResult = TransformResult(
    artifact = updateRenamedArtifactClasses(artifact, updatedClassArtifacts, classRenameMap),
    transformedClassCount = classRenameMap.size,
    transformedMemberCount = 0,
)

internal fun reanalyzedClassArtifact(
    classArtifact: ClassArtifact,
    updatedBytes: ByteArray,
): ClassArtifact = classArtifact.copy(
    summary = analyzeClassBytes(updatedBytes),
    bytes = updatedBytes,
)

internal fun renamedClassArtifact(classArtifact: ClassArtifact, updatedBytes: ByteArray): ClassArtifact {
    val updatedSummary = analyzeClassBytes(updatedBytes)
    return classArtifact.copy(
        entryName = updatedSummary.internalName + ".class",
        summary = updatedSummary,
        bytes = updatedBytes,
    )
}

/**
 * Safely apply a visitor-based class transform with COMPUTE_FRAMES.
 * Returns transformed bytes, or null if the transform produced no changes or failed.
 * This centralizes the try-catch around ClassReader.accept so individual
 * transforms don't need to duplicate resilience logic.
 */
internal fun safeVisitorTransform(
    classBytes: ByteArray,
    flags: Int = ClassReader.SKIP_FRAMES,
    visitorFactory: (ClassWriter) -> ClassVisitor,
): ByteArray? {
    return try {
        val cr = ClassReader(classBytes)
        val cw = object : ClassWriter(cr, ClassWriter.COMPUTE_FRAMES) {
            override fun getCommonSuperClass(type1: String, type2: String): String = "java/lang/Object"
        }
        val cv = visitorFactory(cw)
        cr.accept(cv, flags)
        val result = cw.toByteArray()
        if (result.contentEquals(classBytes)) null else result
    } catch (_: Exception) {
        null
    }
}
