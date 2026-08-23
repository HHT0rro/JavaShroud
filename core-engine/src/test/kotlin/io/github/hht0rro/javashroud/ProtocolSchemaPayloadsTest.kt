package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.adapters.protocol.buildEngineSchemaProtocolPayload
import io.github.hht0rro.javashroud.adapters.protocol.serializeProtocolPayload
import io.github.hht0rro.javashroud.model.schema.EngineSchemaPayload
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ModuleTargetingCapability
import io.github.hht0rro.javashroud.model.schema.ModuleTagDefinition
import io.github.hht0rro.javashroud.model.schema.ParamSchema
import io.github.hht0rro.javashroud.model.schema.VariantRequirement
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ProtocolSchemaPayloadsTest {
    @Test
    fun buildEngineSchemaProtocolPayload_serializes_tags_modules_and_params() {
        val payload = buildEngineSchemaProtocolPayload(
            EngineSchemaPayload(
                schemaVersion = "schema-v2",
                engineVersion = "1.0.0",
                tags = listOf(
                    ModuleTagDefinition(
                        id = "metadata",
                        name = "Metadata",
                        description = "metadata transforms",
                        order = 1,
                    ),
                ),
                modules = listOf(
                    ModuleDefinition(
                        id = "strip-compile-debug-info",
                        name = "Strip Compile Debug Info",
                        description = "removes compile debug",
                        tagIds = listOf("metadata"),
                        params = listOf(
                            ParamSchema(
                                key = "mode",
                                type = "enum",
                                defaultValue = JsonNodeFactory.instance.textNode("safe"),
                                options = listOf("safe", "aggressive"),
                                description = "execution mode",
                                hidden = true,
                            ),
                        ),
                        stability = "beta",
                        targeting = ModuleTargetingCapability(
                            supported = true,
                            targetKinds = listOf("class"),
                        ),
                        requiredPassIds = listOf("jni-microkernel-loader"),
                        requiresAnyPassIds = listOf("class-encryption-loader", "method-virtualization"),
                        variantRequirements = listOf(
                            VariantRequirement(
                                whenParam = "mode",
                                equals = "aggressive",
                                requiredPassIds = listOf("jni-microkernel-loader"),
                            ),
                        ),
                    ),
                ),
                compatibility = listOf(
                    io.github.hht0rro.javashroud.model.schema.PassCompatibilityRule(
                        passIds = listOf("class-encryption-loader", "method-virtualization"),
                        severity = "hard",
                        description = "cannot run together",
                    ),
                ),
            ),
        )

        assertEquals("schema-v2", payload["schemaVersion"])
        assertEquals("1.0.0", payload["engineVersion"])

        val tags = payload["tags"] as List<*>
        assertEquals(1, tags.size)
        val tagPayload = tags.single() as Map<*, *>
        assertEquals("metadata", tagPayload["id"])

        val modules = payload["modules"] as List<*>
        assertEquals(1, modules.size)
        val modulePayload = modules.single() as Map<*, *>
        assertEquals("strip-compile-debug-info", modulePayload["id"])
        assertEquals("beta", modulePayload["stability"])
        val targeting = modulePayload["targeting"] as Map<*, *>
        assertEquals(true, targeting["supported"])
        assertEquals(listOf("class"), targeting["targetKinds"])
        assertEquals(listOf("jni-microkernel-loader"), modulePayload["requiredPassIds"])
        assertEquals(listOf("class-encryption-loader", "method-virtualization"), modulePayload["requiresAnyPassIds"])
        val variantRequirements = modulePayload["variantRequirements"] as List<*>
        assertEquals(1, variantRequirements.size)
        val variantRequirement = variantRequirements.single() as Map<*, *>
        assertEquals("mode", variantRequirement["whenParam"])
        assertEquals("aggressive", variantRequirement["equals"])
        assertEquals(listOf("jni-microkernel-loader"), variantRequirement["requiredPassIds"])

        val params = modulePayload["params"] as List<*>
        assertEquals(1, params.size)
        val paramPayload = params.single() as Map<*, *>
        assertEquals("mode", paramPayload["key"])
        assertEquals(listOf("safe", "aggressive"), paramPayload["options"])
        assertTrue(paramPayload.containsKey("defaultValue"))
        assertEquals(true, paramPayload["hidden"])

        val compatibility = payload["compatibility"] as List<*>
        assertEquals(1, compatibility.size)
        val compatibilityPayload = compatibility.single() as Map<*, *>
        assertEquals(listOf("class-encryption-loader", "method-virtualization"), compatibilityPayload["passIds"])
        assertEquals("hard", compatibilityPayload["severity"])
    }

    @Test
    fun serialized_toml_omits_null_options_and_default_value() {
        val payload = buildEngineSchemaProtocolPayload(
            EngineSchemaPayload(
                schemaVersion = "schema-v2",
                engineVersion = "1.0.0",
                tags = listOf(
                    ModuleTagDefinition(
                        id = "runtime-defense",
                        name = "Runtime Defense",
                        description = "runtime defense transforms",
                        order = 1,
                    ),
                ),
                modules = listOf(
                    ModuleDefinition(
                        id = "anti-symbolic-execution",
                        name = "Anti Symbolic Execution",
                        description = "adds traps",
                        tagIds = listOf("runtime-defense"),
                        params = listOf(
                            ParamSchema(
                                key = "seed",
                                type = "number",
                                defaultValue = JsonNodeFactory.instance.nullNode(),
                                options = null,
                                description = "deterministic seed",
                            ),
                        ),
                        stability = "experimental",
                        targeting = ModuleTargetingCapability(
                            supported = true,
                            targetKinds = listOf("class"),
                        ),
                    ),
                ),
            ),
        )

        val toml = serializeProtocolPayload(payload)

        // TOML 无 null；为 null 的 options/defaultValue 必须被省略，而不是写成空字符串 ''。
        assertFalse(toml.contains("options = ''"), "options 不应序列化为空字符串，toml=$toml")
        assertFalse(toml.contains("options = \"\""), "options 不应序列化为空字符串，toml=$toml")
        assertFalse(toml.contains("defaultValue = ''"), "defaultValue 不应序列化为空字符串，toml=$toml")
        assertFalse(toml.contains("defaultValue = \"\""), "defaultValue 不应序列化为空字符串，toml=$toml")
    }
}
