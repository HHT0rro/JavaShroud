package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.config.validateConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.file.Files
import java.util.jar.JarOutputStream

class PassCompatibilityRegressionTest {

    @Test
    fun formerly_hard_conflicted_bytecode_surface_pairs_are_allowed_for_planner_ordering() {
        val pairs = listOf(
            listOf("control-flow-obfuscation", "field-string-encryption"),
            listOf("field-string-encryption", "member-hide"),
            listOf("member-hide", "reference-proxy"),
            listOf("anti-decompiler-structure", "reference-proxy"),
            listOf("reference-proxy", "string-encryption"),
            listOf("anti-decompiler-structure", "static-init-perturbation"),
            listOf("field-string-encryption", "reference-proxy"),
            listOf("anti-decompiler-structure", "field-string-encryption"),
            listOf("anti-decompiler-structure", "member-hide"),
            listOf("control-flow-obfuscation", "reference-proxy"),
            listOf("field-string-encryption", "static-init-perturbation"),
            listOf("member-hide", "string-encryption"),
            listOf("reference-proxy", "static-init-perturbation"),
            listOf("anti-decompiler-structure", "control-flow-obfuscation"),
            listOf("member-hide", "static-init-perturbation"),
            listOf("field-string-encryption", "string-encryption"),
        )

        for (passes in pairs) {
            assertCompatibleCombination(passes, allowOptInPasses = true)
        }
    }

    @Test
    fun string_encryption_and_field_string_encryption_are_planner_ordered_not_hard_conflicted() {
        assertCompatibleCombination(listOf("string-encryption", "field-string-encryption"), allowOptInPasses = true)
    }

    @Test
    fun method_virtualization_and_control_flow_flattening_allowed_with_ordering() {
        assertCompatibleCombination(listOf("method-virtualization", "control-flow-flattening"), allowOptInPasses = true)
    }

    @Test
    fun string_encryption_auto_includes_jni_microkernel_loader() {
        assertAutoIncludedJniLoaderDependency("string-encryption")
    }

    @Test
    fun jvm_resolver_string_encryption_does_not_include_jni_microkernel_loader() {
        val configPath = Files.createTempFile("javashroud-jvm-resolver-string", ".json")
        val inputJar = Files.createTempFile("javashroud-jvm-resolver-string-input", ".jar")
        val outputJar = Files.createTempFile("javashroud-jvm-resolver-string-output", ".jar")
        JarOutputStream(Files.newOutputStream(inputJar)).use { }
        try {
            val validated = validateConfig(
                config = testConfig(
                    inputJarPath = inputJar.toAbsolutePath().normalize().toString(),
                    outputJarPath = outputJar.toAbsolutePath().normalize().toString(),
                    passes = listOf(
                        PassSpec(
                            id = "string-encryption",
                            enabled = true,
                            params = mapOf("decoderBackend" to JsonNodeFactory.instance.textNode("jvm-resolver")),
                        ),
                    ),
                    allowOptInPasses = true,
                ),
                configPath = configPath,
            )

            assertTrue(
                validated.passes.none { it.id == "jni-microkernel-loader" && it.enabled },
                "JVM-resolver string encryption must not auto-include JNI, actual passes: ${validated.passes.map { it.id }}",
            )
        } finally {
            Files.deleteIfExists(configPath)
            Files.deleteIfExists(inputJar)
            Files.deleteIfExists(outputJar)
        }
    }

    @Test
    fun jni_microkernel_loader_cannot_be_enabled_without_helper_runtime_pass() {
        assertIncompatibleCombination(listOf("jni-microkernel-loader"), "missing companion passes")
    }

    @Test
    fun jni_microkernel_loader_and_method_virtualization_are_allowed_with_opt_in() {
        assertCompatibleCombination(listOf("method-virtualization", "jni-microkernel-loader"), allowOptInPasses = true)
    }

    @Test
    fun high_risk_current_format_vm_pass_requires_explicit_opt_in() {
        assertOptInRejected(listOf("method-virtualization"))
        assertCompatibleCombination(listOf("method-virtualization"), allowOptInPasses = true)
    }

    @Test
    fun os_anti_debug_auto_includes_jni_microkernel_loader() {
        assertAutoIncludedJniLoaderDependency("os-anti-debug")
    }

    @Test
    fun os_anti_vm_auto_includes_jni_microkernel_loader() {
        assertAutoIncludedJniLoaderDependency("os-anti-vm")
    }

    private fun assertAutoIncludedJniLoaderDependency(passId: String) {
        val passSpecs = listOf(PassSpec(id = passId, enabled = true, params = emptyMap()))
        val configPath = Files.createTempFile("javashroud-pass-dependency", ".json")
        val inputJar = Files.createTempFile("javashroud-pass-dependency-input", ".jar")
        val outputJar = Files.createTempFile("javashroud-pass-dependency-output", ".jar")
        JarOutputStream(Files.newOutputStream(inputJar)).use { }
        try {
            val validated = validateConfig(
                config = testConfig(
                    inputJarPath = inputJar.toAbsolutePath().normalize().toString(),
                    outputJarPath = outputJar.toAbsolutePath().normalize().toString(),
                    passes = passSpecs,
                    allowOptInPasses = true,
                ),
                configPath = configPath,
            )
            assertTrue(
                validated.passes.any { it.id == "jni-microkernel-loader" && it.enabled },
                "Expected jni-microkernel-loader to be auto-included for pass $passId, actual passes: ${validated.passes.map { it.id }}",
            )
        } finally {
            Files.deleteIfExists(configPath)
            Files.deleteIfExists(inputJar)
            Files.deleteIfExists(outputJar)
        }
    }

    private fun assertCompatibleCombination(passes: List<String>, allowRedundantPasses: Boolean = false, allowOptInPasses: Boolean = false) {
        val passSpecs = passes.map { passId -> PassSpec(id = passId, enabled = true, params = emptyMap()) }
        val configPath = Files.createTempFile("javashroud-pass-compat-ok", ".json")
        val inputJar = Files.createTempFile("javashroud-pass-compat-ok-input", ".jar")
        val outputJar = Files.createTempFile("javashroud-pass-compat-ok-output", ".jar")
        JarOutputStream(Files.newOutputStream(inputJar)).use { }
        try {
            validateConfig(
                config = testConfig(
                    inputJarPath = inputJar.toAbsolutePath().normalize().toString(),
                    outputJarPath = outputJar.toAbsolutePath().normalize().toString(),
                    passes = passSpecs,
                    allowOptInPasses = allowOptInPasses,
                    allowRedundantPasses = allowRedundantPasses,
                ),
                configPath = configPath,
            )
        } finally {
            Files.deleteIfExists(configPath)
            Files.deleteIfExists(inputJar)
            Files.deleteIfExists(outputJar)
        }
    }

    private fun assertSoftConflictCombination(passes: List<String>) {
        val passSpecs = passes.map { passId -> PassSpec(id = passId, enabled = true, params = emptyMap()) }
        val configPath = Files.createTempFile("javashroud-soft-conflict", ".json")
        val inputJar = Files.createTempFile("javashroud-soft-conflict-input", ".jar")
        val outputJar = Files.createTempFile("javashroud-soft-conflict-output", ".jar")
        JarOutputStream(Files.newOutputStream(inputJar)).use { }
        try {
            assertThrows<IllegalArgumentException> {
                validateConfig(
                    config = testConfig(
                        inputJarPath = inputJar.toAbsolutePath().normalize().toString(),
                        outputJarPath = outputJar.toAbsolutePath().normalize().toString(),
                        passes = passSpecs,
                    ),
                    configPath = configPath,
                )
            }

            validateConfig(
                config = testConfig(
                    inputJarPath = inputJar.toAbsolutePath().normalize().toString(),
                    outputJarPath = outputJar.toAbsolutePath().normalize().toString(),
                    passes = passSpecs,
                    allowRedundantPasses = true,
                    allowOptInPasses = true,
                ),
                configPath = configPath,
            )
        } finally {
            Files.deleteIfExists(configPath)
            Files.deleteIfExists(inputJar)
            Files.deleteIfExists(outputJar)
        }
    }

    private fun assertIncompatibleCombination(
        passes: List<String>,
        expectedMessagePart: String = "incompatible passes",
        allowOptInPasses: Boolean = false,
    ) {
        val passSpecs = passes.map { passId -> PassSpec(id = passId, enabled = true, params = emptyMap()) }
        val configPath = Files.createTempFile("javashroud-pass-compat", ".json")
        val inputJar = Files.createTempFile("javashroud-pass-compat-input", ".jar")
        val outputJar = Files.createTempFile("javashroud-pass-compat-output", ".jar")
        JarOutputStream(Files.newOutputStream(inputJar)).use { }
        val error = try {
            assertThrows<IllegalArgumentException> {
                validateConfig(
                    config = testConfig(
                        inputJarPath = inputJar.toAbsolutePath().normalize().toString(),
                        outputJarPath = outputJar.toAbsolutePath().normalize().toString(),
                        passes = passSpecs,
                        allowOptInPasses = allowOptInPasses,
                    ),
                    configPath = configPath,
                )
            }
        } finally {
            Files.deleteIfExists(configPath)
            Files.deleteIfExists(inputJar)
            Files.deleteIfExists(outputJar)
        }
        assertTrue(
            error.message?.contains(expectedMessagePart) == true,
            "Expected error containing '$expectedMessagePart', actual=${error.message}",
        )
    }

    private fun assertOptInRejected(passes: List<String>) {
        val passSpecs = passes.map { passId -> PassSpec(id = passId, enabled = true, params = emptyMap()) }
        val configPath = Files.createTempFile("javashroud-pass-optin", ".json")
        val inputJar = Files.createTempFile("javashroud-pass-optin-input", ".jar")
        val outputJar = Files.createTempFile("javashroud-pass-optin-output", ".jar")
        JarOutputStream(Files.newOutputStream(inputJar)).use { }
        val error = try {
            assertThrows<IllegalArgumentException> {
                validateConfig(
                    config = testConfig(
                        inputJarPath = inputJar.toAbsolutePath().normalize().toString(),
                        outputJarPath = outputJar.toAbsolutePath().normalize().toString(),
                        passes = passSpecs,
                    ),
                    configPath = configPath,
                )
            }
        } finally {
            Files.deleteIfExists(configPath)
            Files.deleteIfExists(inputJar)
            Files.deleteIfExists(outputJar)
        }
        assertTrue(
            error.message?.contains("require explicit opt-in") == true,
            "Expected opt-in rejection, actual=${error.message}",
        )
    }
}
