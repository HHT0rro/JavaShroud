package io.github.hht0rro.javashroud.model.config

import com.fasterxml.jackson.databind.JsonNode

data class PassSpec(
    val id: String,
    val enabled: Boolean,
    val params: Map<String, JsonNode>,
)

data class RuleSpec(
    val target: String,
    val action: String,
)

data class RuleSet(
    val rules: List<RuleSpec>,
)

data class ObfuscationConfig(
    val inputJarPath: String,
    val outputJarPath: String,
    val passes: List<PassSpec>,
    val ruleSet: RuleSet,
    val allowIncomplete: Boolean = false,
    val allowOptInPasses: Boolean = false,
    val allowRedundantPasses: Boolean = false,
)
