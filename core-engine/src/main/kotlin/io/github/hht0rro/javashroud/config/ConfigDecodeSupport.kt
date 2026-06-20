package io.github.hht0rro.javashroud.config

import com.fasterxml.jackson.databind.JsonNode
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import java.nio.file.Path

fun decodeConfig(rootNode: JsonNode, configPath: Path): ObfuscationConfig {
    val inputJarPath = requiredRootText(rootNode, "inputJarPath", configPath)
    val outputJarPath = requiredRootText(rootNode, "outputJarPath", configPath)
    val passes = decodePasses(rootNode.path("passes"), configPath)
    val ruleSet = decodeRuleSet(rootNode.path("ruleSet"), configPath)

    val allowIncomplete = optionalRootBoolean(rootNode, "allowIncomplete", configPath)
    val allowOptInPasses = optionalRootBoolean(rootNode, "allowOptInPasses", configPath)
    val allowRedundantPasses = optionalRootBoolean(rootNode, "allowRedundantPasses", configPath)

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
