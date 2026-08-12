package io.github.hht0rro.javashroud.transforms.obfuscation

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.buildControlFlowConfig
import io.github.hht0rro.javashroud.bytecode.obfuscateControlFlow
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun applyControlFlowObfuscation(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    validateControlFlowObfuscationParams(params)

    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "control-flow-obfuscation")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val config = buildControlFlowConfig(params)
    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val obfuscatedBytes = obfuscateControlFlow(classArtifact.bytes, config)
            if (!obfuscatedBytes.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, obfuscatedBytes)
            } else classArtifact
        } else classArtifact
    }

    if (classCount == 0) return unchangedTransformResult(artifact)

    return updatedArtifactTransformResult(
        artifact = artifact,
        updatedClassArtifacts = updatedClassArtifacts,
        transformedClassCount = classCount,
        transformedMemberCount = 0,
    )
}

private fun validateControlFlowObfuscationParams(params: Map<String, Any>) {
    val branchInjection = params["branchInjection"] as? String
    val supportedBranchInjectionLevels = setOf("none", "light", "normal", "aggressive")
    require(branchInjection == null || branchInjection in supportedBranchInjectionLevels) {
        "control-flow-obfuscation branchInjection '$branchInjection' is not supported; supported values: ${supportedBranchInjectionLevels.joinToString(", ")}"
    }

    val handlerSplit = params["handlerSplit"] as? String
    val supportedHandlerSplitLevels = setOf("none", "light", "heavy")
    require(handlerSplit == null || handlerSplit in supportedHandlerSplitLevels) {
        "control-flow-obfuscation handlerSplit '$handlerSplit' is not supported; supported values: ${supportedHandlerSplitLevels.joinToString(", ")}"
    }
}
