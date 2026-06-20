package io.github.hht0rro.javashroud.transforms.obfuscation

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.analysis.fallbackEligibleClassNames
import io.github.hht0rro.javashroud.bytecode.injectJunkCode
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun injectJunkCode(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedClassNames = if (ruleMatches.isEmpty()) {
        fallbackEligibleClassNames(artifact.classArtifacts, emptySet())
    } else {
        val controlFlowClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "control-flow-obfuscation")
        eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "junk-code-injection") - controlFlowClassNames
    }
    if (matchedClassNames.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val junkCount = ((params["count"] as? Int) ?: 3).coerceIn(1, 10)
            val junkBytes = injectJunkCode(classArtifact.bytes, junkCount)
            if (!junkBytes.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, junkBytes)
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
