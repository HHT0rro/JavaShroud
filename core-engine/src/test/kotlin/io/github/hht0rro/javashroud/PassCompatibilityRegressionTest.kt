package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.config.validateConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.nio.file.Files
import java.util.jar.JarOutputStream

class PassCompatibilityRegressionTest {

    @Test
    fun class_encryption_loader_and_method_virtualization_remain_hard_conflicted() {
        assertIncompatibleCombination(
            listOf("class-encryption-loader", "method-virtualization"),
            allowOptInPasses = true,
        )
    }

    @Test
    fun method_body_delayed_decryption_and_method_virtualization_remain_hard_conflicted() {
        assertIncompatibleCombination(
            listOf("method-body-delayed-decryption", "method-virtualization"),
            allowOptInPasses = true,
        )
    }

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
    fun class_encryption_loader_and_string_encryption_allowed() {
        assertCompatibleCombination(listOf("class-encryption-loader", "string-encryption"), allowOptInPasses = true)
    }

    @Test
    fun class_encryption_loader_and_field_string_encryption_allowed() {
        assertCompatibleCombination(listOf("class-encryption-loader", "field-string-encryption"), allowOptInPasses = true)
    }

    @Test
    fun anti_instrumentation_auto_includes_jni_microkernel_loader() {
        assertAutoIncludedJniLoaderDependency("anti-instrumentation")
    }

    @Test
    fun environment_bound_keys_auto_includes_jni_microkernel_loader() {
        assertAutoIncludedJniLoaderDependency("environment-bound-keys")
    }

    @Test
    fun class_encryption_loader_auto_includes_jni_microkernel_loader() {
        assertAutoIncludedJniLoaderDependency("class-encryption-loader")
    }

    @Test
    fun string_encryption_auto_includes_jni_microkernel_loader() {
        assertAutoIncludedJniLoaderDependency("string-encryption")
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
    fun high_risk_passes_require_explicit_opt_in() {
        assertOptInRejected(listOf("class-encryption-loader"))
        assertCompatibleCombination(listOf("class-encryption-loader"), allowOptInPasses = true)
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
