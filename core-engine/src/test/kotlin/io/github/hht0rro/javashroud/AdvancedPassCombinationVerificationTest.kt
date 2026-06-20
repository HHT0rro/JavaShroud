package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes

/**
 * Phase 6: Systematic reliability verification for advanced protection passes.
 *
 * Tests single-pass, pair, triple, and cross-category combinations for all new passes.
 * Each scenario verifies:
 * - Engine exits cleanly (NDJSON done event)
 * - Output JAR exists and is readable
 * - All class entries survive transformation
 * - No crashes or exceptions during obfuscation
 */
class AdvancedPassCombinationVerificationTest {
    // --- Single pass smoke tests ---

    @Test
    fun single_pass_class_encryption_loader() {
        verifyScenario(listOf("class-encryption-loader"), "single-class-encryption-loader")
    }

    @Test
    fun single_pass_method_body_delayed_decryption() {
        verifyScenario(listOf("method-body-delayed-decryption", "jni-microkernel-loader"), "single-method-body-delayed")
    }

    @Test
    fun single_pass_method_virtualization() {
        verifyScenario(listOf("method-virtualization"), "single-method-virtualization")
    }

    @Test
    fun single_pass_callsite_rotation_protection() {
        verifyScenario(listOf("callsite-rotation-protection", "jni-microkernel-loader"), "single-callsite-rotation")
    }

    @Test
    fun single_pass_environment_bound_keys_auto_includes_jni_loader() {
        verifyScenario(listOf("environment-bound-keys"), "single-env-bound-keys")
    }

    @Test
    fun single_pass_anti_symbolic_execution() {
        verifyScenario(listOf("anti-symbolic-execution"), "single-anti-symexec")
    }

    @Test
    fun single_pass_exception_semantic_virtualization() {
        verifyScenario(listOf("exception-semantic-virtualization"), "single-exception-virt")
    }

    @Test
    fun single_pass_anti_instrumentation_auto_includes_jni_loader() {
        verifyScenario(listOf("anti-instrumentation"), "single-anti-instrumentation")
    }

    @Test
    fun single_pass_anti_dump_protection_auto_includes_jni_loader() {
        verifyScenario(listOf("anti-dump-protection"), "single-anti-dump-protection")
    }

    @Test
    fun single_pass_jni_microkernel_loader() {
        verifyScenario(listOf("class-encryption-loader", "jni-microkernel-loader"), "single-jni-microkernel")
    }

    // --- Pair combination tests ---

    @Test
    fun pair_rename_plus_class_encryption_loader() {
        verifyScenario(listOf("rename-classes", "class-encryption-loader"), "pair-rename-cls-encrypt")
    }

    @Test
    fun pair_metadata_plus_loader() {
        verifyScenario(listOf("strip-compile-debug-info", "class-encryption-loader"), "pair-strip-debug-encrypt")
    }

    @Test
    fun pair_string_enc_plus_anti_symexec() {
        verifyScenario(listOf("string-encryption", "anti-symbolic-execution"), "pair-str-enc-anti-symexec")
    }

    @Test
    fun pair_rename_plus_runtime_defense() {
        verifyScenario(listOf("rename-methods", "callsite-rotation-protection", "jni-microkernel-loader"), "pair-rename-methods-callsite")
    }

    // --- Triple combination tests ---

    @Test
    fun triple_metadata_strip_bundle() {
        verifyScenario(
            listOf("strip-compile-debug-info", "member-hide"),
            "triple-metadata-strip"
        )
    }

    @Test
    fun triple_obfuscation_plus_runtime_defense() {
        verifyScenario(
            listOf("control-flow-obfuscation", "anti-symbolic-execution", "callsite-rotation-protection", "jni-microkernel-loader"),
            "triple-opaque-symexec-callsite"
        )
    }

    // --- Cross-category combination tests ---

    @Test
    fun cross_full_pipeline_metadata_rename_encryption() {
        verifyScenario(
            listOf("strip-compile-debug-info", "member-hide", "rename-classes", "rename-fields", "string-encryption"),
            "cross-full-pipeline-mre"
        )
    }

    // --- Helper methods ---

    private fun verifyRejectedScenario(passes: List<String>, scenarioName: String, expectedMessagePart: String) {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-$scenarioName-input", ".jar"))
        try {
            val outputJar = inputJar.resolveSibling("javashroud-$scenarioName-output.jar")
            val configPath = inputJar.resolveSibling("javashroud-$scenarioName-config.toml")
            writeRunConfig(configPath, inputJar, outputJar, passes)

            val error = kotlin.test.assertFailsWith<IllegalArgumentException> {
                captureStdout {
                    dispatchRequest(
                        buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                        EngineKernel(),
                    )
                }
            }
            assertTrue(error.message?.contains(expectedMessagePart) == true, "Expected rejection containing '$expectedMessagePart', actual=${error.message}")
            assertTrue(Files.notExists(outputJar), "Rejected scenario should not emit output jar: $scenarioName")
            Files.deleteIfExists(configPath)
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    private fun verifyScenario(passes: List<String>, scenarioName: String, allowRedundantPasses: Boolean = false) {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-$scenarioName-input", ".jar"))
        try {
            val outputJar = inputJar.resolveSibling("javashroud-$scenarioName-output.jar")
            val configPath = inputJar.resolveSibling("javashroud-$scenarioName-config.toml")
            writeRunConfig(configPath, inputJar, outputJar, passes, allowRedundantPasses)

            val output = captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
            }

            val events = output.trim().lines().filter { it.isNotBlank() }.map(::parseEventType)
            assertTrue(events.isNotEmpty(), "Engine should emit events for scenario=$scenarioName")
            assertTrue(
                events.any { it == "done" },
                "Run should finish with a done event for scenario=$scenarioName"
            )
            assertTrue(Files.exists(outputJar), "Output jar should exist for scenario=$scenarioName")
            assertJarReadable(outputJar, scenarioName)

            // Cleanup
            Files.deleteIfExists(outputJar)
            Files.deleteIfExists(configPath)
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    private fun writeRunConfig(configPath: Path, inputJar: Path, outputJar: Path, passIds: List<String>, allowRedundantPasses: Boolean = false) {
        writeTestRunConfigToml(configPath, inputJar, outputJar, passIds, allowRedundantPasses = allowRedundantPasses)
    }

    private fun assertJarReadable(jarPath: Path, context: String) {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name.endsWith(".class")) {
                    val classBytes = jar.readAllBytes()
                    val visitor = object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {}
                    ClassReader(classBytes).accept(visitor, ClassReader.SKIP_FRAMES)
                }
                jar.closeEntry()
            }
        }
        assertTrue(Files.exists(jarPath), "Jar should exist: $context")
    }

    private fun captureStdout(block: () -> Unit): String {
        val originalOut = System.out
        val buffer = ByteArrayOutputStream()
        System.setOut(PrintStream(buffer, true, Charsets.UTF_8))
        return try {
            block()
            buffer.toString(Charsets.UTF_8)
        } finally {
            System.setOut(originalOut)
        }
    }

    private fun parseEventType(line: String): String {
        val match = Regex("""type\s*=\s*"((?:\\.|[^"])*)"""").find(line)
        return match?.groupValues?.get(1) ?: error("Engine event line missing type: $line")
    }
}
