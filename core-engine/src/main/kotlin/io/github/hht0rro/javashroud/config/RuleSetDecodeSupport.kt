package io.github.hht0rro.javashroud.config

import com.fasterxml.jackson.databind.JsonNode
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import java.nio.file.Path
import kotlin.io.path.absolutePathString

internal fun decodeRuleSet(ruleSetNode: JsonNode, configPath: Path): RuleSet {
    if (!ruleSetNode.isObject) {
        throw IllegalArgumentException("Config validation failed: ruleSet must be an object, path=${configPath.absolutePathString()}")
    }

    val rulesNode = ruleSetNode.path("rules")
    if (!rulesNode.isArray) {
        throw IllegalArgumentException("Config validation failed: ruleSet.rules must be an array, path=${configPath.absolutePathString()}")
    }

    val rules = mutableListOf<RuleSpec>()
    var index = 0
    for (ruleNode in rulesNode) {
        val target = requiredNestedText(ruleNode, "target", configPath, "ruleSet.rules[$index]")
        val action = requiredNestedText(ruleNode, "action", configPath, "ruleSet.rules[$index]")
        rules.add(RuleSpec(target = target, action = action))
        index += 1
    }

    return RuleSet(rules = rules)
}
