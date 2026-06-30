package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.config.decodeConfig
import io.github.hht0rro.javashroud.config.decodePasses
import io.github.hht0rro.javashroud.config.decodeRuleSet
import io.github.hht0rro.javashroud.config.ensureReadableFile
import io.github.hht0rro.javashroud.config.parseConfig
import io.github.hht0rro.javashroud.config.requiredRootText
import io.github.hht0rro.javashroud.config.validateConfig
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ConfigCodecTest {

    private val mapper = ObjectMapper()
    private val dummyPath = Path.of("C:/tmp/config.toml")

    @Test
    fun decodeConfig_parses_valid_json() {
        val json = mapper.readTree("""
            {
                "inputJarPath": "C:/tmp/input.jar",
                "outputJarPath": "C:/tmp/output.jar",
                "passes": [{"id": "strip-compile-debug-info", "enabled": true}],
                "ruleSet": {"rules": [{"target": "class **", "action": "rename"}]}
            }
        """)
        val config = decodeConfig(json, dummyPath)
        assertEquals("C:/tmp/input.jar", config.inputJarPath)
        assertEquals("C:/tmp/output.jar", config.outputJarPath)
        assertEquals(1, config.passes.size)
        assertEquals("strip-compile-debug-info", config.passes[0].id)
        assertTrue(config.passes[0].enabled)
        assertEquals(1, config.ruleSet.rules.size)
        assertEquals("class **", config.ruleSet.rules[0].target)
        assertEquals("rename", config.ruleSet.rules[0].action)
    }

    @Test
    fun parseConfig_parses_valid_toml() {
        val tempDir = Files.createTempDirectory("javashroud-config-codec")
        val inputJar = tempDir.resolve("input.jar")
        val outputJar = tempDir.resolve("output.jar")
        val configPath = tempDir.resolve("config.toml")
        Files.writeString(inputJar, "fixture")
        Files.writeString(configPath, """
            inputJarPath = "${inputJar.toAbsolutePath().normalize().toString().replace('\\', '/')}"
            outputJarPath = "${outputJar.toAbsolutePath().normalize().toString().replace('\\', '/')}"
            allowOptInPasses = true
            allowRedundantPasses = true

            [[passes]]
            id = "method-virtualization"
            enabled = true

            [passes.params]
            maxInstructions = 4096
            strictVirtualization = true
            methodSelection = "annotated"

            [ruleSet]
            [[ruleSet.rules]]
            target = "com/example/App"
            action = "exclude"
        """.trimIndent())

        try {
            val config = parseConfig(configPath)

            assertEquals(formatTomlPath(inputJar), config.inputJarPath.replace('\\', '/'))
            assertEquals(formatTomlPath(outputJar), config.outputJarPath.replace('\\', '/'))
            assertEquals("method-virtualization", config.passes.single().id)
            assertEquals(4096, config.passes.single().params["maxInstructions"]?.intValue())
            assertTrue(config.passes.single().params["strictVirtualization"]?.booleanValue() == true)
            assertEquals("annotated", config.passes.single().params["methodSelection"]?.textValue())
            assertEquals("com/example/App", config.ruleSet.rules.single().target)
            assertTrue(config.allowOptInPasses)
            assertTrue(config.allowRedundantPasses)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun parseConfig_parses_workbench_meta_toml() {
        val tempDir = Files.createTempDirectory("javashroud-workbench-config-codec")
        val inputJar = tempDir.resolve("input.jar")
        val outputJar = tempDir.resolve("output.jar")
        val configPath = tempDir.resolve("workbench.toml")
        Files.writeString(inputJar, "fixture")
        Files.writeString(configPath, """
            [meta]
            format = "javashroud-workbench"
            version = 1
            inputJarPath = "${formatTomlPath(inputJar)}"
            outputJarPath = "${formatTomlPath(outputJar)}"
            [[passes]]
            id = "method-virtualization"
            enabled = true

            [passes.params]
            methodSelection = "all-compatible"
            strictVirtualization = true
            maxInstructions = 99999999
        """.trimIndent())

        try {
            val config = parseConfig(configPath)

            assertEquals(formatTomlPath(inputJar), config.inputJarPath.replace('\\', '/'))
            assertEquals(formatTomlPath(outputJar), config.outputJarPath.replace('\\', '/'))
            assertTrue(config.allowOptInPasses)
            assertEquals("method-virtualization", config.passes.single().id)
            assertEquals("all-compatible", config.passes.single().params["methodSelection"]?.textValue())
            assertTrue(config.passes.single().params["strictVirtualization"]?.booleanValue() == true)
            assertEquals(99999999, config.passes.single().params["maxInstructions"]?.intValue())
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun parseConfig_parses_frontend_workbench_toml() {
        val tempDir = Files.createTempDirectory("javashroud-frontend-workbench-config-codec")
        val inputJar = tempDir.resolve("input.jar")
        val outputJar = tempDir.resolve("output.jar")
        val configPath = tempDir.resolve("workbench.toml")
        Files.writeString(inputJar, "fixture")
        Files.writeString(configPath, """
            [meta]
            format = "javashroud-workbench"
            version = 1

            [input]
            inputJarPath = "${formatTomlPath(inputJar)}"
            outputJarPath = "${formatTomlPath(outputJar)}"

            [[passes]]
            id = "method-virtualization"
            enabled = true

            [passes.params]
            methodSelection = "all-compatible"
            strictVirtualization = true
            maxInstructions = 0
            maxBroadVirtualizedMethods = 0

            [[rules]]
            target = "com/example/*"
            action = "obfuscate"

            [[rules]]
            target = "com/example/internal/*"
            action = "exclude"
        """.trimIndent())

        try {
            val config = parseConfig(configPath)

            assertEquals(formatTomlPath(inputJar), config.inputJarPath.replace('\\', '/'))
            assertEquals(formatTomlPath(outputJar), config.outputJarPath.replace('\\', '/'))
            assertTrue(config.allowOptInPasses)
            assertEquals("method-virtualization", config.passes.single().id)
            assertEquals("all-compatible", config.passes.single().params["methodSelection"]?.textValue())
            assertEquals(2, config.ruleSet.rules.size)
            assertEquals("com/example/*", config.ruleSet.rules[0].target)
            assertEquals("obfuscate", config.ruleSet.rules[0].action)
            assertEquals("com/example/internal/*", config.ruleSet.rules[1].target)
            assertEquals("exclude", config.ruleSet.rules[1].action)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    private fun formatTomlPath(path: Path): String = path.toAbsolutePath().normalize().toString().replace('\\', '/')

    @Test
    fun decodeConfig_rejects_missing_inputJarPath() {
        val json = mapper.readTree("""
            {
                "outputJarPath": "C:/tmp/output.jar",
                "passes": [{"id": "strip-compile-debug-info", "enabled": true}],
                "ruleSet": {"rules": []}
            }
        """)
        assertFailsWith<IllegalArgumentException> {
            decodeConfig(json, dummyPath)
        }
    }

    @Test
    fun decodeConfig_rejects_missing_outputJarPath() {
        val json = mapper.readTree("""
            {
                "inputJarPath": "C:/tmp/input.jar",
                "passes": [{"id": "strip-compile-debug-info", "enabled": true}],
                "ruleSet": {"rules": []}
            }
        """)
        assertFailsWith<IllegalArgumentException> {
            decodeConfig(json, dummyPath)
        }
    }

    @Test
    fun decodeConfig_rejects_non_boolean_root_flags() {
        val flagNames = listOf("allowIncomplete", "allowOptInPasses", "allowRedundantPasses")
        for (flagName in flagNames) {
            val json = mapper.readTree("""
                {
                    "inputJarPath": "C:/tmp/input.jar",
                    "outputJarPath": "C:/tmp/output.jar",
                    "passes": [{"id": "strip-compile-debug-info", "enabled": true}],
                    "ruleSet": {"rules": []},
                    "$flagName": "true"
                }
            """)
            assertFailsWith<IllegalArgumentException>("Expected $flagName to reject non-boolean value") {
                decodeConfig(json, dummyPath)
            }
        }
    }

    @Test
    fun decodePasses_parses_array_with_params() {
        val json = mapper.readTree("""[{"id": "rename-classes", "enabled": true, "params": {"depth": 3}}]""")
        val passes = decodePasses(json, dummyPath)
        assertEquals(1, passes.size)
        assertEquals("rename-classes", passes[0].id)
        assertTrue(passes[0].enabled)
        assertEquals(3, passes[0].params["depth"]?.intValue())
    }

    @Test
    fun decodePasses_rejects_non_array() {
        val json = mapper.readTree("""{"id": "foo"}""")
        assertFailsWith<IllegalArgumentException> {
            decodePasses(json, dummyPath)
        }
    }

    @Test
    fun decodePasses_rejects_missing_enabled() {
        val json = mapper.readTree("""[{"id": "foo"}]""")
        assertFailsWith<IllegalArgumentException> {
            decodePasses(json, dummyPath)
        }
    }

    @Test
    fun decodePasses_rejects_non_boolean_enabled() {
        val json = mapper.readTree("""[{"id": "foo", "enabled": "yes"}]""")
        assertFailsWith<IllegalArgumentException> {
            decodePasses(json, dummyPath)
        }
    }

    @Test
    fun decodePasses_returns_empty_for_empty_array() {
        val json = mapper.readTree("[]")
        val passes = decodePasses(json, dummyPath)
        assertTrue(passes.isEmpty())
    }

    @Test
    fun decodeRuleSet_parses_rules() {
        val json = mapper.readTree("""{"rules": [{"target": "class com/**", "action": "rename"}]}""")
        val ruleSet = decodeRuleSet(json, dummyPath)
        assertEquals(1, ruleSet.rules.size)
        assertEquals("class com/**", ruleSet.rules[0].target)
        assertEquals("rename", ruleSet.rules[0].action)
    }

    @Test
    fun decodeRuleSet_returns_empty_rules_for_empty_array() {
        val json = mapper.readTree("""{"rules": []}""")
        val ruleSet = decodeRuleSet(json, dummyPath)
        assertTrue(ruleSet.rules.isEmpty())
    }

    @Test
    fun decodeRuleSet_rejects_non_object() {
        val json = mapper.readTree("""["not", "object"]""")
        assertFailsWith<IllegalArgumentException> {
            decodeRuleSet(json, dummyPath)
        }
    }

    @Test
    fun decodeRuleSet_rejects_missing_rules_array() {
        val json = mapper.readTree("""{"rules": "not-array"}""")
        assertFailsWith<IllegalArgumentException> {
            decodeRuleSet(json, dummyPath)
        }
    }

    @Test
    fun requiredRootText_returns_text_value() {
        val json = mapper.readTree("""{"key": "value"}""")
        assertEquals("value", requiredRootText(json, "key", dummyPath))
    }

    @Test
    fun requiredRootText_rejects_missing_field() {
        val json = mapper.readTree("""{"other": "value"}""")
        assertFailsWith<IllegalArgumentException> {
            requiredRootText(json, "key", dummyPath)
        }
    }

    @Test
    fun requiredRootText_rejects_non_text_field() {
        val json = mapper.readTree("""{"key": 42}""")
        assertFailsWith<IllegalArgumentException> {
            requiredRootText(json, "key", dummyPath)
        }
    }

    @Test
    fun requiredRootText_rejects_blank_text_field() {
        val json = mapper.readTree("""{"key": "   "}""")
        assertFailsWith<IllegalArgumentException> {
            requiredRootText(json, "key", dummyPath)
        }
    }

    @Test
    fun validateConfig_rejects_blank_inputJarPath() {
        val config = testConfig(inputJarPath = "", outputJarPath = "C:/tmp/out.jar", passes = listOf(testPassSpec()))
        assertFailsWith<IllegalArgumentException> {
            validateConfig(config, dummyPath)
        }
    }

    @Test
    fun validateConfig_rejects_blank_outputJarPath() {
        val config = testConfig(inputJarPath = "C:/tmp/in.jar", outputJarPath = "", passes = listOf(testPassSpec()))
        assertFailsWith<IllegalArgumentException> {
            validateConfig(config, dummyPath)
        }
    }

    @Test
    fun validateConfig_rejects_empty_passes() {
        val config = testConfig(inputJarPath = "C:/tmp/in.jar", outputJarPath = "C:/tmp/out.jar", passes = emptyList())
        assertFailsWith<IllegalArgumentException> {
            validateConfig(config, dummyPath)
        }
    }

    @Test
    fun validateConfig_filters_legacy_internal_planner_pass() {
        val inputJar = Files.createTempFile("javashroud-config", ".jar")
        try {
            val config = testConfig(
                inputJarPath = inputJar.toString(),
                outputJarPath = inputJar.resolveSibling("out.jar").toString(),
                passes = listOf(
                    testPassSpec(id = "pass-ordering-planner"),
                    testPassSpec(id = "strip-compile-debug-info"),
                ),
                allowOptInPasses = true,
            )

            val validated = validateConfig(config, dummyPath)

            assertEquals(listOf("strip-compile-debug-info"), validated.passes.map { it.id })
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }


    @Test
    fun ensureReadableFile_rejects_nonexistent_path() {
        assertFailsWith<IllegalArgumentException> {
            ensureReadableFile(Path.of("C:/nonexistent/file.jar"))
        }
    }
}
