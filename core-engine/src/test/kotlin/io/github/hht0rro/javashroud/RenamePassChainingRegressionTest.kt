package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.config.RuleSpec
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarFile
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertTrue

class RenamePassChainingRegressionTest {
    @Test
    fun explicit_rule_matches_follow_renamed_classes_between_passes() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-rename-chain", ".jar"))
        try {
            val outputJar = inputJar.resolveSibling("javashroud-rename-chain-out.jar")
            val configPath = inputJar.resolveSibling("javashroud-rename-chain-config.toml")
            writeRunConfig(configPath, inputJar, outputJar)

            val output = captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
            }

            val events = output.trim().lines().filter { it.isNotBlank() }
            assertTrue(events.any { it.contains("type = \"done\"") }, "Run should finish with done event")

            val classEntries = loadClassEntries(outputJar)
            assertTrue(classEntries.isNotEmpty(), "Output JAR should contain class entries")
            assertTrue(
                classEntries.all { it.startsWith("p0000/") },
                "Package rename should still apply after class rename. Entries=${classEntries.joinToString()}",
            )

            val manifest = JarFile(outputJar.toFile()).use { jar ->
                jar.manifest.mainAttributes.getValue("Main-Class") ?: ""
            }
            assertTrue(manifest.startsWith("p0000."), "Manifest main class should be package-renamed, actual=$manifest")

            Files.deleteIfExists(outputJar)
            Files.deleteIfExists(configPath)
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    private fun writeRunConfig(configPath: Path, inputJar: Path, outputJar: Path) {
        val rules = listOf(
            RuleSpec(target = "e2e/*", action = "rename-classes"),
            RuleSpec(target = "e2e/*", action = "rename-packages"),
        )
        writeTestRunConfigToml(configPath, inputJar, outputJar, listOf("rename-classes", "rename-packages"), rules)
    }

    private fun loadClassEntries(jarPath: Path): List<String> {
        val entries = mutableListOf<String>()
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name.endsWith(".class")) {
                    entries += entry.name
                }
                jar.closeEntry()
            }
        }
        return entries
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
