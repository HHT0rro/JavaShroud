package io.github.hht0rro.javashroud.config

import com.fasterxml.jackson.databind.JsonNode
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

    val allowIncomplete = optionalNestedBoolean(scalarRoot, "allowIncomplete", configPath, scalarRootPath)
    val allowOptInPasses = optionalNestedBooleanOrDefault(
        scalarRoot,
        "allowOptInPasses",
        configPath,
        scalarRootPath,
        default = isWorkbenchConfig(scalarRoot),
    )
    val allowRedundantPasses = optionalNestedBoolean(scalarRoot, "allowRedundantPasses", configPath, scalarRootPath)

    return ObfuscationConfig(
        inputJarPath = inputJarPath,
        outputJarPath = outputJarPath,
        passes = passes,
        ruleSet = ruleSet,
        allowIncomplete = allowIncomplete,
        allowOptInPasses = allowOptInPasses,
        allowRedundantPasses = allowRedundantPasses,
    )
}

private fun configScalarRoot(rootNode: JsonNode): JsonNode =
    if (rootNode.has("inputJarPath") || !rootNode.path("meta").isObject) rootNode else rootNode.path("meta")

private fun configInputRoot(rootNode: JsonNode, scalarRoot: JsonNode): JsonNode =
    if (rootNode.path("input").isObject) rootNode.path("input") else scalarRoot

private fun isWorkbenchConfig(scalarRoot: JsonNode): Boolean =
    scalarRoot.path("format").asText() == "javashroud-workbench"
