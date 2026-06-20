package io.github.hht0rro.javashroud.transforms.obfuscation

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.mangleSwitches
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun applySwitchMangling(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "switch-mangling")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    var classCount = 0
    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val result = mangleSwitches(classArtifact.bytes)
            if (!result.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, result)
            } else classArtifact
        } else classArtifact
    }

    if (classCount == 0) return unchangedTransformResult(artifact)
    return updatedArtifactTransformResult(artifact, updatedClassArtifacts, classCount, 0)
}
