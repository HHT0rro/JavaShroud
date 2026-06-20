package io.github.hht0rro.javashroud.transforms.encryption

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.poolClassStrings
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.excludeReflectionSurfaceSensitiveClasses
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun poolStrings(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedClassNames = excludeReflectionSurfaceSensitiveClasses(artifact, eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "string-array-pool"))
    if (matchedClassNames.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val pooledBytes = poolClassStrings(classArtifact.bytes)
            if (!pooledBytes.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, pooledBytes)
            } else {
                classArtifact
            }
        } else {
            classArtifact
        }
    }

    if (classCount == 0) {
        return unchangedTransformResult(artifact)
    }

    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = 0,
    )
}

