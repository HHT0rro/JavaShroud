package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.hardening.QpTargetRewriter
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.URLClassLoader
import java.nio.file.Path
import java.util.jar.JarFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class RenamePassChainingRegressionTest {
    @Test
    fun explicit_rule_matches_follow_renamed_classes_between_passes(@TempDir directory: Path) {
        val inputJar = buildDiverseFixtureJar(directory.resolve("input.jar"))
        val outputJar = directory.resolve("output.jar")
        val configPath = directory.resolve("config.toml")
        writeRunConfig(configPath, inputJar, outputJar)

        val output = captureStdout {
            dispatchRequest(
                buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                EngineKernel(),
            )
        }

        val events = output.trim().lines().filter { it.isNotBlank() }
        assertTrue(events.any { it.contains("type = \"done\"") }, "Run should finish with done event")

        val inputClasses = loadJarClassBytes(inputJar).keys
        val outputClasses = loadJarClassBytes(outputJar).keys
        assertTrue(QpTargetRewriter.BOOTSTRAP_OWNER in outputClasses, "Release bootstrap should be present")
        val renamedClasses = outputClasses - QpTargetRewriter.BOOTSTRAP_OWNER
        assertEquals(inputClasses.size, renamedClasses.size, "Every fixture class should survive the rename chain")
        val renamedPackage = renamedClasses.map { it.substringBeforeLast('/', "") }.toSet().single()
        assertTrue(renamedPackage.isNotEmpty() && renamedPackage != "e2e", "Package rule should follow the renamed classes")
        assertTrue(
            renamedClasses.map { it.substringAfterLast('/') }.intersect(inputClasses.map { it.substringAfterLast('/') }.toSet()).isEmpty(),
            "Class rename must change the fixture's simple names before package rename",
        )

        val mainClass = JarFile(outputJar.toFile()).use { jar ->
            assertNotNull(jar.manifest.mainAttributes.getValue("Main-Class"))
        }
        assertTrue(mainClass.replace('.', '/') in renamedClasses, "Main-Class must resolve to a renamed fixture class")
        URLClassLoader(arrayOf(outputJar.toUri().toURL()), null).use { loader ->
            assertEquals(1, loader.loadClass(mainClass).getMethod("call").invoke(null))
        }
    }

    private fun writeRunConfig(configPath: Path, inputJar: Path, outputJar: Path) {
        val rules = listOf(
            RuleSpec(target = "e2e/*", action = "rename-classes"),
            RuleSpec(target = "e2e/*", action = "rename-packages"),
        )
        writeTestRunConfigToml(configPath, inputJar, outputJar, listOf("rename-classes", "rename-packages"), rules)
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
}
