package io.github.hht0rro.javashroud.transforms.obfuscation

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.obfuscateIntegerConstants
import io.github.hht0rro.javashroud.bytecode.NumericResolverConfig
import io.github.hht0rro.javashroud.bytecode.obfuscateNumericConstantsResolver
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun obfuscateIntConstants(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "integer-constant-obfuscation")
    if (matchedClassNames.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    val obfuscateClass: (ByteArray) -> ByteArray = when (val rewriteMode = params["rewriteMode"]) {
        null -> ::obfuscateIntegerConstants
        "arithmetic" -> ::obfuscateIntegerConstants
        "resolver" -> {
            val config = buildNumericResolverConfig(params)
            ({ classBytes: ByteArray -> obfuscateNumericConstantsResolver(classBytes, config) })
        }
        is String -> throw IllegalArgumentException("integer-constant-obfuscation rewriteMode '$rewriteMode' is not supported; supported values: arithmetic, resolver")
        else -> throw IllegalArgumentException("integer-constant-obfuscation rewriteMode must be a string")
    }
    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val obfuscatedBytes = obfuscateClass(classArtifact.bytes)
            if (!obfuscatedBytes.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, obfuscatedBytes)
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

private fun buildNumericResolverConfig(params: Map<String, Any>): NumericResolverConfig = NumericResolverConfig(
    seed = when (val raw = params["seed"]) {
        is Int -> raw.toLong()
        is Long -> raw
        null -> null
        else -> throw IllegalArgumentException("integer-constant-obfuscation seed must be a number")
    },
    intCoverage = numericStringParam(params, "intCoverage", "none"),
    longCoverage = numericStringParam(params, "longCoverage", "none"),
    resolverCodec = numericStringParam(params, "resolverCodec", "xor"),
)

private fun numericStringParam(params: Map<String, Any>, key: String, default: String): String = when (val raw = params[key]) {
    null -> default
    is String -> raw
    else -> throw IllegalArgumentException("integer-constant-obfuscation $key must be a string")
}
