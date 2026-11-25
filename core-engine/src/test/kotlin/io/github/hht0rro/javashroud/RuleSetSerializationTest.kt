package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.toml.TomlMapper
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSetScope
import io.github.hht0rro.javashroud.model.config.RuleSpec
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RuleSetSerializationTest {
    @Test
    fun runtime_scope_is_omitted_from_json_and_toml_rule_set_payloads() {
        val ruleSet = RuleSet(
            rules = listOf(RuleSpec(target = "example/Target", action = "obfuscate")),
            scope = RuleSetScope.SELECTED_ONLY,
        )

        val json = ObjectMapper().writeValueAsString(ruleSet)
        val toml = TomlMapper().writeValueAsString(ruleSet)

        assertTrue(json.contains("\"rules\""), "JSON must retain persisted rules")
        assertTrue(toml.contains("rules"), "TOML must retain persisted rules")
        assertFalse(json.contains("scope"), "runtime RuleSet.scope must not leak into JSON")
        assertFalse(toml.contains("scope"), "runtime RuleSet.scope must not leak into TOML")
        assertFalse(json.contains("SELECTED_ONLY"), "runtime RuleSetScope must not leak into JSON")
        assertFalse(toml.contains("SELECTED_ONLY"), "runtime RuleSetScope must not leak into TOML")
    }
}
