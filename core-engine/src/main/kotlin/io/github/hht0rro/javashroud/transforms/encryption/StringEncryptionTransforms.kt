package io.github.hht0rro.javashroud.transforms.encryption

import io.github.hht0rro.javashroud.analysis.eligibleClassNamesForAction
import io.github.hht0rro.javashroud.bytecode.StringEncryptionConfig
import io.github.hht0rro.javashroud.bytecode.EmbeddedStringResolverConfig
import io.github.hht0rro.javashroud.bytecode.encryptClassStrings
import io.github.hht0rro.javashroud.bytecode.encryptClassStringsEmbeddedResolver
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.reanalyzedClassArtifact
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.transforms.updatedArtifactTransformResult

fun encryptStrings(artifact: BytecodeArtifact, ruleMatches: List<RuleMatch>, params: Map<String, Any>): TransformResult {
    val matchedClassNames = eligibleClassNamesForAction(artifact.classArtifacts, ruleMatches, "string-encryption")
    if (matchedClassNames.isEmpty()) {
        return unchangedTransformResult(artifact)
    }

    val encryptClass: (ByteArray) -> ByteArray = when (val backend = params["decoderBackend"]) {
        null, "native-kernel" -> {
            val config = buildStringEncryptionConfig(params - "decoderBackend")
            ({ classBytes: ByteArray -> encryptClassStrings(classBytes, config) })
        }
        "jvm-resolver" -> {
            val config = buildEmbeddedStringResolverConfig(params)
            ({ classBytes: ByteArray -> encryptClassStringsEmbeddedResolver(classBytes, config) })
        }
        is String -> throw IllegalArgumentException("string-encryption decoderBackend '$backend' is not supported; supported values: native-kernel, jvm-resolver")
        else -> throw IllegalArgumentException("string-encryption decoderBackend must be a string")
    }
    var classCount = 0

    val updatedClassArtifacts = artifact.classArtifacts.map { classArtifact ->
        if (matchedClassNames.contains(classArtifact.summary.internalName)) {
            val encryptedBytes = encryptClass(classArtifact.bytes)
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

private fun buildEmbeddedStringResolverConfig(params: Map<String, Any>): EmbeddedStringResolverConfig {
    val scope = (params["scope"] as? String) ?: "all-strings"
    val lengthThreshold = when (val raw = params["lengthThreshold"]) {
        is Int -> raw
        is Long -> raw.toInt()
        is Number -> raw.toInt()
        null -> 3
        else -> throw IllegalArgumentException("string-encryption lengthThreshold must be a number")
    }
    val seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long)
    val strength = optionalStringParam(params, "strength") ?: "max"
    val payloadCodec = optionalStringParam(params, "payloadCodec")?.takeUnless { it == "auto" }

    validateStringEncryptionConfig(scope, lengthThreshold)
    return EmbeddedStringResolverConfig(
        scope = scope,
        lengthThreshold = lengthThreshold,
        seed = seed,
        strength = strength,
        payloadCodec = payloadCodec,
    )
}

private fun optionalStringParam(params: Map<String, Any>, key: String): String? = when (val raw = params[key]) {
    null -> null
    is String -> raw
    else -> throw IllegalArgumentException("string-encryption $key must be a string")
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
    val legacyKeys = listOf("strategy", "algorithm", "layerMode", "keyMode", "mode", "codecFamily").filter(params::containsKey)
    require(legacyKeys.isEmpty()) {
        "string-encryption params were removed: ${legacyKeys.joinToString(", ")}; " +
            "supported params are decoderBackend, strength, payloadCodec, scope, lengthThreshold, and seed"
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
