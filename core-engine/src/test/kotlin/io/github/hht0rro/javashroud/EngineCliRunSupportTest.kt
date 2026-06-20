package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineRunRequest
import io.github.hht0rro.javashroud.adapters.protocol.buildRunRequest
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertEquals

class EngineCliRunSupportTest {
    @Test
    fun buildRunRequest_loads_validated_config_and_normalizes_paths() {
        val tempDir: Path = Files.createTempDirectory("javashroud-run-request")
        val inputJarPath = tempDir.resolve("input.jar")
        val outputJarPath = tempDir.resolve("output.jar")
        val configPath = tempDir.resolve("config.toml")
        Files.writeString(inputJarPath, "fixture")
        Files.writeString(configPath, buildConfigToml(inputJarPath, outputJarPath))

        try {
            val request: EngineRunRequest = buildRunRequest(arrayOf("-config", configPath.toString()))

            assertEquals(configPath.toAbsolutePath().normalize(), request.configPath)
            assertEquals(inputJarPath.toAbsolutePath().normalize().absolutePathString(), request.config.inputJarPath)
            assertEquals(outputJarPath.toAbsolutePath().normalize().absolutePathString(), request.config.outputJarPath)
            assertEquals("strip-compile-debug-info", request.config.passes.single().id)
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    private fun buildConfigToml(inputJarPath: Path, outputJarPath: Path): String =
        """
        inputJarPath = "${formatTomlPath(inputJarPath)}"
        outputJarPath = "${formatTomlPath(outputJarPath)}"
        allowOptInPasses = true

        [[passes]]
        id = "strip-compile-debug-info"
        enabled = true

        [ruleSet]
        rules = []
        """.trimIndent()

    private fun formatTomlPath(path: Path): String = path.toAbsolutePath().normalize().toString().replace('\\', '/')
}
