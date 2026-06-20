package io.github.hht0rro.javashroud.transforms.obfuscation

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.buildControlFlowConfig
import io.github.hht0rro.javashroud.bytecode.flattenControlFlow
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.excludeReflectionSurfaceSensitiveClasses
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun applyControlFlowFlattening(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    validateControlFlowFlatteningParams(params)

    val matchedClassNames = excludeReflectionSurfaceSensitiveClasses(artifact, eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "control-flow-flattening"))
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val config = buildControlFlowConfig(params)
    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val flattenedBytes = flattenControlFlow(classArtifact.bytes, config)
            if (!flattenedBytes.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, flattenedBytes)
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

private fun validateControlFlowFlatteningParams(params: Map<String, Any>) {
    val supportedHandlerComplexities = setOf("nop", "field-write", "method-call")
    val handlerComplexity = params["handlerComplexity"] as? String
    require(handlerComplexity == null || handlerComplexity in supportedHandlerComplexities) {
        "control-flow-flattening handlerComplexity '$handlerComplexity' is not supported; supported values: ${supportedHandlerComplexities.joinToString(", ")}"
    }

    val supportedPatterns = setOf("arithmetic-nop", "dead-branch", "unreachable-method", "field-noise")
    val pattern = params["pattern"] as? String
    require(pattern == null || pattern in supportedPatterns) {
        "control-flow-flattening pattern '$pattern' is not supported; supported values: ${supportedPatterns.joinToString(", ")}"
    }
}

