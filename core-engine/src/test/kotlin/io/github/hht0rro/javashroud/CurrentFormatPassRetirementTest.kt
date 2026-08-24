package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.config.RETIRED_CURRENT_FORMAT_PASS_IDS
import io.github.hht0rro.javashroud.config.rejectRetiredCurrentFormatPassIds
import io.github.hht0rro.javashroud.model.config.PassSelectionSpec
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.passes.requireExecutablePass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CurrentFormatPassRetirementTest {
    @Test
    fun unified_defense_passes_replace_every_retired_public_id() {
        val modules = buildEngineSchemaPayload().modules.associateBy { it.id }

        assertEquals(
            listOf("jni-microkernel-loader"),
            modules.getValue(OS_ANTI_DEBUG).requiredPassIds,
        )
        assertEquals(
            listOf("jni-microkernel-loader"),
            modules.getValue(OS_ANTI_VM).requiredPassIds,
        )
        assertTrue(requireExecutablePass(OS_ANTI_DEBUG).descriptor.id == OS_ANTI_DEBUG)
        assertTrue(requireExecutablePass(OS_ANTI_VM).descriptor.id == OS_ANTI_VM)

        RETIRED_PASS_IDS.forEach { passId ->
            assertFalse(passId in modules, "retired pass remains in the current schema: $passId")
            val error = assertFailsWith<IllegalArgumentException> {
                requireExecutablePass(passId)
            }
            assertTrue(
                error.message.orEmpty().contains(passId),
                "retired pass rejection should identify the unsupported id: $passId",
            )
        }
    }

    @Test
    fun config_rejects_each_retired_id_in_pass_specs_and_pass_selections() {
        assertEquals(EXPECTED_RETIRED_PASS_IDS, RETIRED_CURRENT_FORMAT_PASS_IDS)
        RETIRED_CURRENT_FORMAT_PASS_IDS.forEach { passId ->
            val passError = assertFailsWith<IllegalArgumentException> {
                rejectRetiredCurrentFormatPassIds(
                    passes = listOf(PassSpec(id = passId, enabled = true, params = emptyMap())),
                    passSelections = emptyList(),
                )
            }
            assertTrue(passError.message.orEmpty().contains(passId))

            val selectionError = assertFailsWith<IllegalArgumentException> {
                rejectRetiredCurrentFormatPassIds(
                    passes = emptyList(),
                    passSelections = listOf(PassSelectionSpec(passId = passId)),
                )
            }
            assertTrue(selectionError.message.orEmpty().contains(passId))

            val ruleError = assertFailsWith<IllegalArgumentException> {
                rejectRetiredCurrentFormatPassIds(
                    passes = emptyList(),
                    globalRules = listOf(RuleSpec(target = "fixture/Target", action = passId)),
                    passSelections = emptyList(),
                )
            }
            assertTrue(ruleError.message.orEmpty().contains(passId))
        }
    }

    private companion object {
        const val OS_ANTI_DEBUG = "os-anti-debug"
        const val OS_ANTI_VM = "os-anti-vm"

        val RETIRED_PASS_IDS: Set<String>
            get() = RETIRED_CURRENT_FORMAT_PASS_IDS

        val EXPECTED_RETIRED_PASS_IDS = setOf(
            "environment-bound-keys",
            "method-body-delayed-decryption",
            "class-encryption-loader",
            "anti-instrumentation",
            "anti-jvmti-agent",
            "anti-bytebuddy-transform",
            "anti-dump-protection",
            "anti-symbolic-execution",
        )
    }
}
