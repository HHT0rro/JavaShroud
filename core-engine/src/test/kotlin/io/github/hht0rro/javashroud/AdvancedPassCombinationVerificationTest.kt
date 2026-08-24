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
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes

/**
 * Current-format reliability coverage for the retained protection pipeline.
 * Every scenario emits a readable JAR and exercises only supported pass IDs.
 */
class AdvancedPassCombinationVerificationTest {
    @Test
    fun single_pass_method_virtualization() {
        verifyScenario(listOf("method-virtualization"), "single-method-virtualization")
    }

    @Test
    fun single_pass_callsite_rotation_protection() {
        verifyScenario(listOf("callsite-rotation-protection"), "single-callsite-rotation")
    }

    @Test
    fun single_pass_os_anti_debug_auto_includes_jni_loader() {
        verifyScenario(listOf("os-anti-debug"), "single-os-anti-debug")
    }

    @Test
    fun single_pass_os_anti_vm_auto_includes_jni_loader() {
        verifyScenario(listOf("os-anti-vm"), "single-os-anti-vm")
    }

    @Test
    fun single_pass_exception_semantic_virtualization() {
        verifyScenario(listOf("exception-semantic-virtualization"), "single-exception-virt")
    }

    @Test
    fun pair_rename_plus_native_vm_route() {
        verifyScenario(listOf("rename-classes", "method-virtualization"), "pair-rename-native-vm")
    }

    @Test
    fun pair_metadata_plus_native_string_route() {
        verifyScenario(listOf("strip-compile-debug-info", "string-encryption"), "pair-strip-native-string")
    }

    @Test
    fun pair_rename_plus_runtime_defense() {
        verifyScenario(listOf("rename-methods", "callsite-rotation-protection"), "pair-rename-methods-callsite")
    }

    @Test
    fun triple_metadata_strip_bundle() {
        verifyScenario(
            listOf("strip-compile-debug-info", "member-hide"),
            "triple-metadata-strip",
        )
    }

    @Test
    fun triple_vm_plus_unified_defense() {
        verifyScenario(
            listOf("method-virtualization", "os-anti-debug", "os-anti-vm"),
            "triple-vm-unified-defense",
        )
    }

    @Test
    fun cross_full_pipeline_metadata_rename_encryption() {
        verifyScenario(
            listOf("strip-compile-debug-info", "member-hide", "rename-classes", "rename-fields", "string-encryption"),
            "cross-full-pipeline-mre",
        )
    }

    private fun verifyScenario(passes: List<String>, scenarioName: String, allowRedundantPasses: Boolean = false) {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-$scenarioName-input", ".jar"))
        try {
            val outputJar = inputJar.resolveSibling("javashroud-$scenarioName-output.jar")
            val configPath = inputJar.resolveSibling("javashroud-$scenarioName-config.toml")
            writeRunConfig(configPath, inputJar, outputJar, passes, allowRedundantPasses)

            val output = withTestBootSecret {
                captureStdout {
                    dispatchRequest(
                        buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                        EngineKernel(),
                    )
                }
            }

            val events = output.trim().lines().filter { it.isNotBlank() }.map(::parseEventType)
            assertTrue(events.isNotEmpty(), "Engine should emit events for scenario=$scenarioName")
            assertTrue(
                events.any { it == "done" },
                "Run should finish with a done event for scenario=$scenarioName",
            )
            assertTrue(Files.exists(outputJar), "Output jar should exist for scenario=$scenarioName")
            assertJarReadable(outputJar, scenarioName)

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
