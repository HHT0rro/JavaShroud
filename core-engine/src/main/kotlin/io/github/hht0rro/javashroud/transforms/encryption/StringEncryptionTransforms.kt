package io.github.hht0rro.javashroud.transforms.encryption

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.StringEncryptionConfig
import io.github.hht0rro.javashroud.bytecode.encryptClassStrings
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_PRELOAD_INDEX_RESOURCE
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun encryptStrings(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    if (artifact.jarEntries.any { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE } &&
        artifact.jarEntries.none { it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE }
    ) {
        return unchangedTransformResult(artifact)
    }
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "string-encryption")
    if (matchedClassNames.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    val config = buildStringEncryptionConfig(params)
    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val encryptedBytes = encryptClassStrings(
                classArtifact.bytes,
                config = config,
            )
            if (!encryptedBytes.contentEquals(classArtifact.bytes)) {
                classCount++
                reanalyzedClassArtifact(classArtifact, encryptedBytes)
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
        transformedMemberCount = classCount,
    )
}

private fun buildStringEncryptionConfig(params: Map<String, Any>): StringEncryptionConfig {
    rejectLegacyStringEncryptionParams(params)
    val scope = (params["scope"] as? String) ?: "all-strings"
    val lengthThreshold = when (val raw = params["lengthThreshold"]) {
        is Int -> raw
        is Long -> raw.toInt()
        is Number -> raw.toInt()
        null -> 3
        else -> throw IllegalArgumentException("string-encryption lengthThreshold must be a number")
    }
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)

    validateStringEncryptionConfig(scope, lengthThreshold)

    return StringEncryptionConfig(
        scope = scope,
        lengthThreshold = lengthThreshold,
        seed = seed,
    )
}

private fun rejectLegacyStringEncryptionParams(params: Map<String, Any>) {
    val legacyKeys = listOf("strategy", "algorithm", "layerMode", "keyMode").filter(params::containsKey)
    require(legacyKeys.isEmpty()) {
        "string-encryption legacy params were removed: ${legacyKeys.joinToString(", ")}; " +
            "native-backed string encryption accepts only scope, lengthThreshold, and seed"
    }
}

private fun validateStringEncryptionConfig(scope: String, lengthThreshold: Int) {
    val supportedScopes = setOf("all-strings", "annotated", "length-threshold")
    require(scope in supportedScopes) {
        "string-encryption scope '$scope' is not supported; supported values: ${supportedScopes.joinToString(", ")}"
    }
    require(lengthThreshold >= 0) {
        "string-encryption lengthThreshold must be >= 0"
    }
}
