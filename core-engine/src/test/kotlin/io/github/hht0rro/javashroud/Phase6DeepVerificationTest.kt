package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertTrue

class Phase6DeepVerificationTest {
    @Test
    fun retained_core_pipeline_runs_end_to_end() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-phase6-input", ".jar"))
        try {
            val outputJar = inputJar.resolveSibling("javashroud-phase6-output.jar")
            val configPath = inputJar.resolveSibling("javashroud-phase6-config.toml")
            writeTestRunConfigToml(
                configPath = configPath,
                inputJar = inputJar,
                outputJar = outputJar,
                passIds = listOf("strip-compile-debug-info", "rename-classes", "string-encryption"),
                allowOptInPasses = true,
            )

            val output = captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
            }

            assertTrue(output.contains("type = \"done\""), "run should emit done event")
            assertTrue(Files.exists(outputJar), "run should emit output jar")
            Files.deleteIfExists(outputJar)
            Files.deleteIfExists(configPath)
        } finally {
            Files.deleteIfExists(inputJar)
        }
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
