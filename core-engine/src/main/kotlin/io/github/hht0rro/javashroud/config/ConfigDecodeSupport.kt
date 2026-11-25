package io.github.hht0rro.javashroud.config

import com.fasterxml.jackson.databind.JsonNode
import io.github.hht0rro.javashroud.model.config.ARTIFACT_FORMAT_AUTO
import io.github.hht0rro.javashroud.model.config.ApkConfig
import io.github.hht0rro.javashroud.model.config.ApkSigningConfig
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.RuleSet
import java.nio.file.Path

fun decodeConfig(rootNode: JsonNode, configPath: Path): ObfuscationConfig {
    val scalarRoot = configScalarRoot(rootNode)
    val scalarRootPath = if (scalarRoot === rootNode) "root" else "root.meta"
    val inputRoot = configInputRoot(rootNode, scalarRoot)
    val inputRootPath = if (inputRoot === scalarRoot) scalarRootPath else "root.input"
    val inputJarPath = requiredNestedText(inputRoot, "inputJarPath", configPath, inputRootPath)
    val outputJarPath = requiredNestedText(inputRoot, "outputJarPath", configPath, inputRootPath)
    val passes = decodePasses(rootNode.path("passes"), configPath)
    val ruleSet = when {
        rootNode.has("ruleSet") -> decodeRuleSet(rootNode.path("ruleSet"), configPath)
        rootNode.has("rules") -> decodeTopLevelRules(rootNode.path("rules"), configPath)
        else -> RuleSet(emptyList())
    }
    val passSelections = decodePassSelections(rootNode.path("passSelections"), configPath)

    val allowIncomplete = optionalNestedBoolean(scalarRoot, "allowIncomplete", configPath, scalarRootPath)
    val allowOptInPasses = optionalNestedBooleanOrDefault(
        scalarRoot,
        "allowOptInPasses",
        configPath,
        scalarRootPath,
        default = isWorkbenchConfig(scalarRoot),
    )
    val allowRedundantPasses = optionalNestedBoolean(scalarRoot, "allowRedundantPasses", configPath, scalarRootPath)
    val allowAnnotationPasses = optionalNestedBoolean(scalarRoot, "allowAnnotationPasses", configPath, scalarRootPath)
    val protectionProfile = HardenedProtectionProfile.fromWireValue(
        optionalNestedTextOrDefault(
            scalarRoot,
            "protectionProfile",
            configPath,
            scalarRootPath,
            default = HardenedProtectionProfile.RELEASE_HARDENED.wireValue,
        ),
    )
    val protectionProfileExplicit = scalarRoot.has("protectionProfile")
    val artifactFormat = optionalNestedTextOrDefault(
        scalarRoot,
        "artifactFormat",
        configPath,
        scalarRootPath,
        default = ARTIFACT_FORMAT_AUTO,
    )
    val logFilePath = optionalNestedTextOrDefault(
        scalarRoot,
        "logFilePath",
        configPath,
        scalarRootPath,
        default = "",
    )
    val apk = decodeApkConfig(rootNode.path("apk"), configPath)

    return ObfuscationConfig(
        inputJarPath = inputJarPath,
        outputJarPath = outputJarPath,
        passes = passes,
        ruleSet = ruleSet,
        passSelections = passSelections,
        allowIncomplete = allowIncomplete,
        allowOptInPasses = allowOptInPasses,
        allowRedundantPasses = allowRedundantPasses,
        allowAnnotationPasses = allowAnnotationPasses,
        protectionProfile = protectionProfile,
        protectionProfileExplicit = protectionProfileExplicit,
        artifactFormat = artifactFormat,
        logFilePath = logFilePath,
        apk = apk,
    )
}

private fun decodeApkConfig(node: JsonNode, configPath: Path): ApkConfig {
    if (node.isMissingNode || node.isNull) return ApkConfig()
    if (!node.isObject) {
        throw IllegalArgumentException("Config validation failed: root.apk must be a table, path=${configPath}")
    }
    val minApi = optionalNestedIntOrDefault(node, "minApi", configPath, "root.apk", default = ApkConfig().minApi)
    val androidJarPath = optionalNestedTextOrDefault(node, "androidJarPath", configPath, "root.apk", default = "")
    val d8JarPath = optionalNestedTextOrDefault(node, "d8JarPath", configPath, "root.apk", default = "")
    val dex2jarDirPath = optionalNestedTextOrDefault(node, "dex2jarDirPath", configPath, "root.apk", default = "")
    val extraKeepPrefixes = decodeApkExtraKeepPrefixes(node.get("extraKeepPrefixes"), configPath)
    val soPageSizeRaw = optionalNestedIntOrDefault(node, "soPageSize", configPath, "root.apk", default = ApkConfig().soPageSize)
    if (soPageSizeRaw != 4096 && soPageSizeRaw != 16384) {
        throw IllegalArgumentException(
            "Config validation failed: root.apk.soPageSize must be 4096 or 16384, got=$soPageSizeRaw, path=$configPath",
        )
    }
    val signing = decodeApkSigningConfig(node.path("signing"), configPath)
    return ApkConfig(
        minApi = minApi,
        minApiExplicit = node.has("minApi"),
        androidJarPath = androidJarPath,
        d8JarPath = d8JarPath,
        dex2jarDirPath = dex2jarDirPath,
        extraKeepPrefixes = extraKeepPrefixes,
        soPageSize = soPageSizeRaw,
        signing = signing,
    )
}

private fun decodeApkSigningConfig(node: JsonNode, configPath: Path): ApkSigningConfig {
    if (node.isMissingNode || node.isNull) return ApkSigningConfig()
    if (!node.isObject) {
        throw IllegalArgumentException("Config validation failed: root.apk.signing must be a table, path=$configPath")
    }
    return ApkSigningConfig(
        keystorePath = optionalNestedTextOrDefault(node, "keystorePath", configPath, "root.apk.signing", default = ""),
        storePassword = optionalNestedTextOrDefault(node, "storePassword", configPath, "root.apk.signing", default = ""),
        keyAlias = optionalNestedTextOrDefault(node, "keyAlias", configPath, "root.apk.signing", default = ""),
        keyPassword = optionalNestedTextOrDefault(node, "keyPassword", configPath, "root.apk.signing", default = ""),
        v1Enabled = optionalNestedBooleanOrDefault(node, "v1Enabled", configPath, "root.apk.signing", default = true),
        v2Enabled = optionalNestedBooleanOrDefault(node, "v2Enabled", configPath, "root.apk.signing", default = true),
    )
}

private fun decodeApkExtraKeepPrefixes(node: JsonNode?, configPath: Path): List<String> {
    if (node == null || node.isMissingNode || node.isNull) return emptyList()
    if (!node.isArray) {
        throw IllegalArgumentException(
            "Config validation failed: root.apk.extraKeepPrefixes must be an array of strings, path=$configPath",
        )
    }
    return node.mapIndexed { index, element ->
        if (!element.isTextual) {
            throw IllegalArgumentException(
                "Config validation failed: root.apk.extraKeepPrefixes[$index] must be a string, path=$configPath",
            )
        }
        element.textValue().trim()
    }.filter { it.isNotEmpty() }
}

private fun optionalNestedIntOrDefault(
    node: JsonNode,
    fieldName: String,
    configPath: Path,
    parentPath: String,
    default: Int,
): Int {
    val valueNode = node.get(fieldName) ?: return default
    if (!valueNode.isInt && !valueNode.isLong) {
        throw IllegalArgumentException(
            "Config validation failed: $parentPath.$fieldName must be an integer, path=${configPath}",
        )
    }
    return valueNode.intValue()
}

private fun configScalarRoot(rootNode: JsonNode): JsonNode =
    if (rootNode.has("inputJarPath") || !rootNode.path("meta").isObject) rootNode else rootNode.path("meta")

private fun configInputRoot(rootNode: JsonNode, scalarRoot: JsonNode): JsonNode =
    if (rootNode.path("input").isObject) rootNode.path("input") else scalarRoot

private fun isWorkbenchConfig(scalarRoot: JsonNode): Boolean =
    scalarRoot.path("format").asText() == "javashroud-workbench"
