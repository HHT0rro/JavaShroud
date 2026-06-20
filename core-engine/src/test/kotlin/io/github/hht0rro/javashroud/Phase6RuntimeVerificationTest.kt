package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import org.objectweb.asm.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Phase 6 comprehensive runtime verification.
 *
 * Tests that obfuscated JARs actually run correctly under various profiles,
 * verifying the end-to-end pipeline from obfuscation through runtime execution.
 *
 * Each test:
 * 1. Builds a fixture JAR
 * 2. Runs the engine with a specific profile
 * 3. Executes the obfuscated JAR with java -jar
 * 4. Verifies exit code = 1 (call() preserved)
 * 5. Scans for prohibited fingerprint leaks
 */
class Phase6RuntimeVerificationTest {
    private val objectMapper = ObjectMapper()

    // Prohibited patterns that must not appear in obfuscated output
    private val prohibitedPatterns = listOf(
        "__js_dispatch_state",
        "__js_iret_",
        "__js_lret_",
        "__js_fret_",
        "__js_dret_",
        "\$_g_id",
        "\$_g_bsm",
        "\$_f_nop",
        "\$_f_bsm",
        "\$_x_id",
        "\$_x_bsm",
    )

    // ── Helpers ─────────────────────────────────────────────────────

    private fun verifyRuntimeBehavior(passIds: List<String>, profileName: String) {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-rtv-$profileName", ".jar"))
        try {
            val outputJar = runEngine(inputJar, passIds, profileName)
            assertTrue(Files.exists(outputJar), "Output JAR should exist for $profileName")

            // Verify output JAR is a valid JAR
            val entries = loadJarEntries(outputJar)
            assertTrue(entries.isNotEmpty(), "Output JAR should have entries for $profileName")
            assertTrue(
                entries.any { it.name.endsWith(".class") },
                "Output JAR should have class files for $profileName"
            )

            // Scan for prohibited fingerprints
            for ((name, bytes) in entries) {
                if (!name.endsWith(".class")) continue
                val text = String(bytes, Charsets.ISO_8859_1)
                for (pattern in prohibitedPatterns) {
                    assertTrue(
                        !text.contains(pattern),
                        "Prohibited pattern '$pattern' found in $name for profile $profileName"
                    )
                }
            }

            // Run the obfuscated JAR
            val process = ProcessBuilder(
                "java", "-jar", outputJar.toAbsolutePath().toString()
            ).redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            assertEquals(
                1, exitCode,
                "Profile '$profileName' should preserve call()=1. Output: ${output.take(500)}"
            )

            Files.deleteIfExists(outputJar)
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    private fun runEngine(inputJar: Path, passIds: List<String>, tag: String): Path {
        val outputJar = inputJar.resolveSibling("javashroud-rtv-out-$tag.jar")
        val configPath = inputJar.resolveSibling("javashroud-rtv-cfg-$tag.toml")
        writeRunConfig(configPath, inputJar, outputJar, passIds)
        try {
            dispatchRequest(
                buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                EngineKernel(),
            )
        } finally {
            Files.deleteIfExists(configPath)
        }
        return outputJar
    }

    private fun writeRunConfig(configPath: Path, inputJar: Path, outputJar: Path, passIds: List<String>) {
        writeTestRunConfigToml(configPath, inputJar, outputJar, passIds)
    }

    private data class JarEntryData(val name: String, val bytes: ByteArray)

    private fun loadJarEntries(jarPath: Path): List<JarEntryData> {
        val entries = mutableListOf<JarEntryData>()
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory) {
                    entries.add(JarEntryData(entry.name, jar.readBytes()))
                }
                jar.closeEntry()
            }
        }
        return entries
    }
}
