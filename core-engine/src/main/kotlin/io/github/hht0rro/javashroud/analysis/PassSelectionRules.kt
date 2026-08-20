package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.config.PassSelectionMode
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSetScope
import io.github.hht0rro.javashroud.model.config.RuleSpec

/**
 * Produces the rule view consumed by one pass execution.
 *
 * Legacy/inherit-global passes receive the shared global rule set unchanged.
 * A selected-only pass is an independent range: it starts with that pass
 * enabled for every target, then its local class/method rules narrow the
 * range with ["exclude"] or recover a more-specific child with ["obfuscate"].
 * This deliberately reuses the established RuleMatch/action machinery rather
 * than creating a second targeting pipeline inside individual transforms.
 */
internal fun effectiveRuleSetForPass(
    config: io.github.hht0rro.javashroud.model.config.ObfuscationConfig,
    passId: String,
): RuleSet {
    val selection = config.passSelections.singleOrNull { it.passId == passId }
        ?: return config.ruleSet
    if (selection.mode == PassSelectionMode.INHERIT_GLOBAL) return config.ruleSet

    return RuleSet(
        rules = listOf(RuleSpec(target = "*", action = passId)) + selection.rules,
        scope = RuleSetScope.SELECTED_ONLY,
    )
}

