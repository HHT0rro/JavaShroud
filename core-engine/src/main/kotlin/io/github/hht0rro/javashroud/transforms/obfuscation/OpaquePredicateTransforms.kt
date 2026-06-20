package io.github.hht0rro.javashroud.transforms.obfuscation

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.buildControlFlowConfig
import io.github.hht0rro.javashroud.bytecode.insertOpaquePredicates
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun applyOpaquePredicates(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    validateOpaquePredicateParams(params)

    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "opaque-predicate")
    if (matchedClassNames.isEmpty()) return unchangedTransformResult(artifact)

    val frequency = ((params["frequency"] as? Int) ?: 8).coerceIn(1, 20)
    val config = buildControlFlowConfig(params).copy(frequency = frequency)
    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val obfuscatedBytes = insertOpaquePredicates(classArtifact.bytes, frequency, config)
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

private fun validateOpaquePredicateParams(params: Map<String, Any>) {
    val supportedFamilies = setOf("quadratic-residue", "bitwise-identity", "modular-arithmetic", "mixed")
    val algebraicFamily = params["algebraicFamily"] as? String
    require(algebraicFamily == null || algebraicFamily in supportedFamilies) {
        "opaque-predicate algebraicFamily '$algebraicFamily' is not supported; supported values: ${supportedFamilies.joinToString(", ")}"
    }

    val supportedModes = setOf("arithmetic-split", "arithmetic-chain", "lookup-table", "mixed")
    val mode = params["mode"] as? String
    require(mode == null || mode in supportedModes) {
        "opaque-predicate mode '$mode' is not supported; supported values: ${supportedModes.joinToString(", ")}"
    }
}
