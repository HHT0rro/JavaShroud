package io.github.hht0rro.javashroud.transforms.obfuscation

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.buildControlFlowConfig
import io.github.hht0rro.javashroud.bytecode.insertBogusExceptionFlow
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.excludeReflectionSurfaceSensitiveClasses
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun applyBogusExceptionFlow(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    validateBogusExceptionFlowParams(params)

    val matchedClassNames = excludeReflectionSurfaceSensitiveClasses(artifact, eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "bogus-exception-flow"))
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val config = buildControlFlowConfig(params)
    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val obfuscatedBytes = insertBogusExceptionFlow(classArtifact.bytes, config)
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

private fun validateBogusExceptionFlowParams(params: Map<String, Any>) {
    val supportedHandlerComplexities = setOf("nop", "field-write", "method-call")
    val handlerComplexity = params["handlerComplexity"] as? String
    require(handlerComplexity == null || handlerComplexity in supportedHandlerComplexities) {
        "bogus-exception-flow handlerComplexity '$handlerComplexity' is not supported; supported values: ${supportedHandlerComplexities.joinToString(", ")}"
    }
}
