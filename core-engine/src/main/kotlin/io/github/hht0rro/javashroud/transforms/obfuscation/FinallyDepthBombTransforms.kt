package io.github.hht0rro.javashroud.transforms.obfuscation

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.applyFinallyDepthBomb
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.excludeReflectionSurfaceSensitiveClasses
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun applyFinallyDepthBombInjection(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedClassNames = excludeReflectionSurfaceSensitiveClasses(artifact, eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "finally-depth-bomb"))
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val depth = ((params["depth"] as? Number)?.toInt() ?: 3).coerceIn(2, 4)
    val seed = (params["seed"] as? Number)?.toLong()
    var classCount = 0
    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val obfuscatedBytes = applyFinallyDepthBomb(classArtifact.bytes, depth, seed)
            if (!obfuscatedBytes.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, obfuscatedBytes)
            } else classArtifact
        } else classArtifact
    }
    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(artifact, updatedClassArtifacts, classCount, 0)
}

