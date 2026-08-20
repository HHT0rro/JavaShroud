package io.github.hht0rro.javashroud.model.config

import com.fasterxml.jackson.annotation.JsonIgnore
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

/**
 * Runtime provenance for a rule view.
 *
 * Global configuration and all legacy callers use [GLOBAL]. [SELECTED_ONLY] is
 * attached only to the ephemeral effective RuleSet compiled for one enabled
 * pass, so it is never serialized as user configuration.
 */
enum class RuleSetScope {
    GLOBAL,
    SELECTED_ONLY,
}

data class RuleSet(
    val rules: List<RuleSpec>,
    @get:JsonIgnore
    val scope: RuleSetScope = RuleSetScope.GLOBAL,
)

/**
 * Controls how a pass obtains its target rules.
 *
 * [INHERIT_GLOBAL] preserves the legacy ruleSet behavior. [SELECTED_ONLY]
 * is an independent range with an implicit all-targets-enabled baseline; local
 * class or method rules exclude targets or recover more-specific children.
 */
enum class PassSelectionMode(val wireValue: String) {
    INHERIT_GLOBAL("inherit-global"),
    SELECTED_ONLY("selected-only"),
    ;

    companion object {
        fun fromWireValue(value: String): PassSelectionMode = values().firstOrNull { it.wireValue == value }
            ?: throw IllegalArgumentException(
                "Config validation failed: pass selection mode '$value' is not supported; " +
                    "supported values: ${values().joinToString(", ") { it.wireValue }}",
            )
    }
}

/**
 * Per-pass target selection. Rules use the same selector syntax as the global
 * ruleSet, but selected-only selections are limited to class and JVM-method
 * selectors by configuration validation.
 */
data class PassSelectionSpec(
    val passId: String,
    val mode: PassSelectionMode = PassSelectionMode.INHERIT_GLOBAL,
    val rules: List<RuleSpec> = emptyList(),
)

data class ObfuscationConfig(
    val inputJarPath: String,
    val outputJarPath: String,
    val passes: List<PassSpec>,
    val ruleSet: RuleSet,
    val passSelections: List<PassSelectionSpec> = emptyList(),
    val allowIncomplete: Boolean = false,
    val allowOptInPasses: Boolean = false,
    val allowRedundantPasses: Boolean = false,
    val allowAnnotationPasses: Boolean = false,
)
