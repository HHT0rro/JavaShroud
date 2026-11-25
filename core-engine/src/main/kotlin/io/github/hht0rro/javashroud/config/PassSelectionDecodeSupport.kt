package io.github.hht0rro.javashroud.config

import com.fasterxml.jackson.databind.JsonNode
import io.github.hht0rro.javashroud.model.config.PassSelectionMode
import io.github.hht0rro.javashroud.model.config.PassSelectionSpec
import io.github.hht0rro.javashroud.model.config.RuleSpec
import java.nio.file.Path
import kotlin.io.path.absolutePathString

internal fun decodePassSelections(passSelectionsNode: JsonNode, configPath: Path): List<PassSelectionSpec> {
    if (passSelectionsNode.isMissingNode || passSelectionsNode.isNull) return emptyList()
    if (!passSelectionsNode.isArray) {
        throw IllegalArgumentException(
            "Config validation failed: passSelections must be an array, path=${configPath.absolutePathString()}",
        )
    }

    return passSelectionsNode.mapIndexed { index, selectionNode ->
        if (!selectionNode.isObject) {
            throw IllegalArgumentException(
                "Config validation failed: passSelections[$index] must be an object, path=${configPath.absolutePathString()}",
            )
        }
        val passId = requiredNestedText(selectionNode, "passId", configPath, "passSelections[$index]")
        val mode = PassSelectionMode.fromWireValue(
            requiredNestedText(selectionNode, "mode", configPath, "passSelections[$index]"),
        )
        val rulesNode = selectionNode.path("rules")
        val rules = when {
            rulesNode.isMissingNode || rulesNode.isNull -> emptyList()
            rulesNode.isArray -> decodeSelectionRules(rulesNode, configPath, index)
            else -> throw IllegalArgumentException(
                "Config validation failed: passSelections[$index].rules must be an array, path=${configPath.absolutePathString()}",
            )
        }
        PassSelectionSpec(passId = passId, mode = mode, rules = rules)
    }
}

private fun decodeSelectionRules(rulesNode: JsonNode, configPath: Path, selectionIndex: Int): List<RuleSpec> =
    rulesNode.mapIndexed { ruleIndex, ruleNode ->
        RuleSpec(
            target = requiredNestedText(ruleNode, "target", configPath, "passSelections[$selectionIndex].rules[$ruleIndex]"),
            action = requiredNestedText(ruleNode, "action", configPath, "passSelections[$selectionIndex].rules[$ruleIndex]"),
        )
    }
