package io.github.hht0rro.javashroud.transforms.obfuscation

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.indirectMethodCalls
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.excludeReflectionSurfaceSensitiveClasses
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun invokeDynamicIndirect(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedClassNames = excludeReflectionSurfaceSensitiveClasses(artifact, eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "invoke-dynamic-indirection"))
    if (matchedClassNames.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val indirectBytes = indirectMethodCalls(classArtifact.bytes)
            if (!indirectBytes.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, indirectBytes)
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

