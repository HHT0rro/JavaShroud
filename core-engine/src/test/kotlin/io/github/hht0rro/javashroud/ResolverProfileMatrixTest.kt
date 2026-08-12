package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.compatibility.buildOrderingConstraints
import io.github.hht0rro.javashroud.compatibility.hardConflictPairs
import io.github.hht0rro.javashroud.compatibility.softConflictPairs
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.requiredPassIdsFor
import io.github.hht0rro.javashroud.model.schema.requiresAnyPassIdsFor
import io.github.hht0rro.javashroud.transforms.protection.planPassOrdering
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ResolverProfileMatrixTest {

    @Test
    fun resolver_profile_matrix_declares_all_17_profiles() {
        assertEquals(
            listOf(
                "baseline",
                "branch-light",
                "branch-normal",
                "branch-aggressive",
                "handler-light",
                "handler-heavy",
                "strings-standard",
                "strings-strong",
                "strings-flow-guarded",
                "strings-max",
                "integers-normal",
                "integers-aggressive",
                "longs-normal",
                "parameters-fixed",
                "parameters-random",
                "parameters-object-array",
                "maximum-compatible",
            ),
            resolverProfiles.map(ResolverProfile::id),
        )
    }

    @Test
    fun schema_declares_fused_defaults_for_all_resolver_profile_passes() {
        val modules = buildEngineSchemaPayload().modules.associateBy(ModuleDefinition::id)

        assertEnumDefault(modules, "control-flow-obfuscation", "branchInjection", "none")
        assertEnumDefault(modules, "control-flow-obfuscation", "handlerSplit", "none")
        assertEnumDefault(modules, "string-encryption", "decoderBackend", "native-kernel")
        assertEnumDefault(modules, "string-encryption", "strength", "max")
        assertEnumDefault(modules, "string-encryption", "payloadCodec", "auto")
        assertEnumDefault(modules, "integer-constant-obfuscation", "rewriteMode", "arithmetic")
        assertEnumDefault(modules, "integer-constant-obfuscation", "intCoverage", "none")
        assertEnumDefault(modules, "integer-constant-obfuscation", "longCoverage", "none")
        assertEnumDefault(modules, "integer-constant-obfuscation", "resolverCodec", "xor")
        assertEnumDefault(modules, "invoke-dynamic-indirection", "callSiteForm", "bootstrap-table")
        assertEnumDefault(modules, "rename-methods", "descriptorPadding", "off")
        assertEnumDefault(modules, "rename-methods", "parameterPacking", "off")
        assertEquals(
            false,
            modules.getValue("rename-methods").params.single { it.key == "returnSensitiveNaming" }.defaultValue?.asBoolean(),
        )
    }

    @Test
    fun every_profile_maps_only_to_supported_javashroud_parameters() {
        val modules = buildEngineSchemaPayload().modules.associateBy(ModuleDefinition::id)

        for (profile in resolverProfiles) {
            assertTrue(profile.branchInjection in branchInjectionLevels, "${profile.id}: unsupported branch injection level ${profile.branchInjection}")
            assertTrue(profile.handlerSplit in handlerSplitLevels, "${profile.id}: unsupported handler split level ${profile.handlerSplit}")
            assertTrue(profile.stringStrength in stringStrengths, "${profile.id}: unsupported string strength ${profile.stringStrength}")
            assertTrue(profile.intCoverage in intCoverageLevels, "${profile.id}: unsupported integer coverage ${profile.intCoverage}")
            assertTrue(profile.longCoverage in longCoverageLevels, "${profile.id}: unsupported long coverage ${profile.longCoverage}")
            assertTrue(
                profile.descriptorPadding in descriptorPaddingModes,
                "${profile.id}: unsupported descriptor padding mode ${profile.descriptorPadding}",
            )
            assertTrue(
                profile.parameterPacking in parameterPackingModes,
                "${profile.id}: unsupported parameter packing mode ${profile.parameterPacking}",
            )

            for ((passId, params) in profile.passParams()) {
                val module = modules[passId]
                assertTrue(module != null, "${profile.id}: profile references missing pass $passId")
                for ((key, value) in params) {
                    val param = module!!.params.singleOrNull { it.key == key }
                    assertTrue(param != null, "${profile.id}: $passId exposes no '$key' parameter")
                    when (param!!.type) {
                        "enum" -> assertTrue(
                            value is String && value in param.options.orEmpty(),
                            "${profile.id}: $passId.$key=$value is not one of ${param.options}",
                        )
                        "boolean" -> assertTrue(value is Boolean, "${profile.id}: $passId.$key must be boolean")
                        else -> error("${profile.id}: matrix only declares enum or boolean options, found ${param.type}")
                    }
                }
            }
        }
    }

    @Test
    fun jvm_resolver_string_profiles_avoid_jni_loader_dependency() {
        val stringModule = buildEngineSchemaPayload().modules.single { it.id == "string-encryption" }
        val jvmResolverParams = mapOf("decoderBackend" to JsonNodeFactory.instance.textNode("jvm-resolver"))
        val nativeKernelParams = mapOf("decoderBackend" to JsonNodeFactory.instance.textNode("native-kernel"))

        assertFalse(
            "jni-microkernel-loader" in stringModule.requiredPassIdsFor(jvmResolverParams),
            "decoderBackend=jvm-resolver must not inject the JNI loader",
        )
        assertFalse(
            "jni-microkernel-loader" in stringModule.requiresAnyPassIdsFor(jvmResolverParams),
            "decoderBackend=jvm-resolver must not require a JNI companion",
        )
        assertEquals(
            listOf("jni-microkernel-loader"),
            stringModule.requiredPassIdsFor(nativeKernelParams),
            "decoderBackend=native-kernel must preserve its existing JNI dependency",
        )

        for (profile in resolverProfiles.filter { it.stringStrength != "none" }) {
            val params = profile.passParams().getValue("string-encryption")
            assertEquals("jvm-resolver", params["decoderBackend"], "${profile.id}: string profile must select the JVM resolver")
            assertFalse(
                "jni-microkernel-loader" in stringModule.requiredPassIdsFor(jvmResolverParams),
                "${profile.id}: JVM resolver must remain JNI-free",
            )
        }
    }

    @Test
    fun profiles_have_accepted_parameter_aware_orders() {
        val schema = buildEngineSchemaPayload()
        val availablePassIds = schema.modules.mapTo(linkedSetOf(), ModuleDefinition::id)

        for (profile in resolverProfiles) {
            val passParams = profile.passParams()
            val requestedPassIds = if (passParams.isEmpty()) {
                listOf("strip-compile-debug-info")
            } else {
                passParams.keys.reversed()
            }
            val result = planPassOrdering(
                passIds = requestedPassIds,
                orderingConstraints = buildOrderingConstraints(),
                hardConflicts = hardConflictPairs,
                softConflicts = softConflictPairs,
                availablePassIds = availablePassIds,
                passParams = passParams,
            )

            assertTrue(result.accepted, "${profile.id}: profile order rejected: ${result.diagnostics}")
            assertEquals(profile.id != "baseline", result.resolverProfileActive, "${profile.id}: resolver profile detection mismatch")
            for (expected in profile.expectedOrder) {
                assertBefore(profile.id, result.orderedPasses, expected.before, expected.after)
            }
        }
    }

    @Test
    fun strict_resolver_profile_rejects_hard_conflict_without_fallback_acceptance() {
        val profile = resolverProfiles.single { it.id == "maximum-compatible" }
        val schema = buildEngineSchemaPayload()
        val result = planPassOrdering(
            passIds = profile.passParams().keys.toList() + listOf("class-encryption-loader", "method-virtualization"),
            orderingConstraints = buildOrderingConstraints(),
            hardConflicts = hardConflictPairs,
            softConflicts = softConflictPairs,
            availablePassIds = schema.modules.mapTo(linkedSetOf(), ModuleDefinition::id),
            passParams = profile.passParams(),
        )

        assertTrue(result.resolverProfileActive)
        assertFalse(result.accepted, "strict resolver profile must reject incompatible selected passes")
        assertTrue(result.diagnostics.any { it.causeId == "hard-conflict" }, "expected a hard-conflict diagnostic: ${result.diagnostics}")
    }

    private fun assertEnumDefault(
        modules: Map<String, ModuleDefinition>,
        passId: String,
        paramKey: String,
        expected: String,
    ) {
        val actual = modules.getValue(passId).params.single { it.key == paramKey }.defaultValue?.asText()
        assertEquals(expected, actual, "$passId.$paramKey default mismatch")
    }

    private fun assertBefore(profileId: String, orderedPasses: List<String>, before: String, after: String) {
        val beforeIndex = orderedPasses.indexOf(before)
        val afterIndex = orderedPasses.indexOf(after)
        assertTrue(beforeIndex >= 0, "$profileId: missing pass '$before' in $orderedPasses")
        assertTrue(afterIndex >= 0, "$profileId: missing pass '$after' in $orderedPasses")
        assertTrue(beforeIndex < afterIndex, "$profileId: expected $before before $after, actual $orderedPasses")
    }

    private data class ExpectedOrder(val before: String, val after: String)

    private data class ResolverProfile(
        val id: String,
        val branchInjection: String,
        val handlerSplit: String,
        val stringStrength: String,
        val intCoverage: String,
        val longCoverage: String,
        val descriptorPadding: String,
        val parameterPacking: String,
        val returnSensitiveNaming: Boolean = false,
        val expectedOrder: List<ExpectedOrder> = emptyList(),
    ) {
        fun passParams(): Map<String, Map<String, Any?>> = buildMap {
            if (branchInjection != "none" || handlerSplit != "none") {
                put(
                    "control-flow-obfuscation",
                    mapOf(
                        "branchInjection" to branchInjection,
                        "handlerSplit" to handlerSplit,
                    ),
                )
            }
            if (stringStrength != "none") {
                put(
                    "string-encryption",
                    mapOf(
                        "decoderBackend" to "jvm-resolver",
                        "strength" to stringStrength,
                    ),
                )
                if (stringStrength == "max") {
                    put("invoke-dynamic-indirection", mapOf("callSiteForm" to "constant-resolver"))
                }
            }
            if (intCoverage != "none" || longCoverage != "none") {
                put(
                    "integer-constant-obfuscation",
                    mapOf(
                        "rewriteMode" to "resolver",
                        "intCoverage" to intCoverage,
                        "longCoverage" to longCoverage,
                    ),
                )
            }
            if (descriptorPadding != "off" || parameterPacking != "off" || returnSensitiveNaming) {
                put(
                    "rename-methods",
                    mapOf(
                        "descriptorPadding" to descriptorPadding,
                        "parameterPacking" to parameterPacking,
                        "returnSensitiveNaming" to returnSensitiveNaming,
                    ),
                )
            }
        }
    }

    private companion object {
        val branchInjectionLevels = setOf("none", "light", "normal", "aggressive")
        val handlerSplitLevels = setOf("none", "light", "heavy")
        val stringStrengths = setOf("none", "standard", "strong", "flow-guarded", "max")
        val intCoverageLevels = setOf("none", "normal", "aggressive")
        val longCoverageLevels = setOf("none", "normal")
        val descriptorPaddingModes = setOf("off", "fixed", "random")
        val parameterPackingModes = setOf("off", "object-array")

        val stringParameterOrder = listOf(
            ExpectedOrder("string-encryption", "rename-methods"),
            ExpectedOrder("rename-methods", "invoke-dynamic-indirection"),
        )
        val maximumCompatibleOrder =
            listOf(ExpectedOrder("integer-constant-obfuscation", "rename-methods")) +
                stringParameterOrder +
                listOf(
                    ExpectedOrder("invoke-dynamic-indirection", "control-flow-obfuscation"),
                    ExpectedOrder("rename-methods", "control-flow-obfuscation"),
                )

        val resolverProfiles = listOf(
            ResolverProfile("baseline", "none", "none", "none", "none", "none", "off", "off"),
            ResolverProfile("branch-light", "light", "none", "none", "none", "none", "off", "off"),
            ResolverProfile("branch-normal", "normal", "none", "none", "none", "none", "off", "off"),
            ResolverProfile("branch-aggressive", "aggressive", "none", "none", "none", "none", "off", "off"),
            ResolverProfile("handler-light", "none", "light", "none", "none", "none", "off", "off"),
            ResolverProfile("handler-heavy", "none", "heavy", "none", "none", "none", "off", "off"),
            ResolverProfile("strings-standard", "none", "none", "standard", "none", "none", "off", "off"),
            ResolverProfile("strings-strong", "none", "none", "strong", "none", "none", "off", "off"),
            ResolverProfile("strings-flow-guarded", "none", "none", "flow-guarded", "none", "none", "off", "off"),
            ResolverProfile("strings-max", "none", "none", "max", "none", "none", "fixed", "off", expectedOrder = stringParameterOrder),
            ResolverProfile("integers-normal", "none", "none", "none", "normal", "none", "off", "off"),
            ResolverProfile("integers-aggressive", "none", "none", "none", "aggressive", "none", "off", "off"),
            ResolverProfile("longs-normal", "none", "none", "none", "none", "normal", "off", "off"),
            ResolverProfile("parameters-fixed", "none", "none", "max", "none", "none", "fixed", "off", expectedOrder = stringParameterOrder),
            ResolverProfile("parameters-random", "none", "none", "max", "none", "none", "random", "off", expectedOrder = stringParameterOrder),
            ResolverProfile("parameters-object-array", "none", "none", "none", "none", "none", "off", "object-array"),
            ResolverProfile(
                "maximum-compatible",
                "normal",
                "heavy",
                "max",
                "aggressive",
                "normal",
                "random",
                "object-array",
                returnSensitiveNaming = true,
                expectedOrder = maximumCompatibleOrder,
            ),
        )
    }
}
