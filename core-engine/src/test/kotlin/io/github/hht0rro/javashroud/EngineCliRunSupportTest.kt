package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineRunRequest
import io.github.hht0rro.javashroud.adapters.protocol.buildRunRequest
import io.github.hht0rro.javashroud.adapters.protocol.executeRunRequest
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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

    @Test
    fun buildRunRequest_rejects_removed_boot_key_delivery_before_engine_run() {
        val tempDir: Path = Files.createTempDirectory("javashroud-run-request-aken-v4")
        val inputJarPath = tempDir.resolve("input.jar")
        val outputJarPath = tempDir.resolve("output.jar")
        val configPath = tempDir.resolve("config.toml")
        Files.writeString(inputJarPath, "fixture")
        Files.writeString(configPath, """
            inputJarPath = "${formatTomlPath(inputJarPath)}"
            outputJarPath = "${formatTomlPath(outputJarPath)}"
            allowOptInPasses = true

            [[passes]]
            id = "jni-microkernel-loader"
            enabled = true

            [passes.params]
            nativePackingLevel = "max"
            bootKeyDelivery = "embedded"

            [[passes]]
            id = "method-virtualization"
            enabled = true

            [ruleSet]
            rules = []
        """.trimIndent())

        try {
            val error = assertFailsWith<IllegalArgumentException> {
                buildRunRequest(arrayOf("-config", configPath.toString()))
            }
            assertEquals(
                "jni-microkernel-loader bootKeyDelivery 已由 AKEN v4 移除；删除该配置项后重新构建。",
                error.message,
            )
            assertEquals(false, Files.exists(outputJarPath.resolveSibling("output.jar.boot-secret.hex")))
            assertEquals(false, Files.exists(outputJarPath.resolveSibling("output.jar.boot-kek.jsbk")))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun executeRunRequest_does_not_create_legacy_sidecars() {
        val tempDir = Files.createTempDirectory("javashroud-cli-no-boot-sidecar")
        val output = tempDir.resolve("output.jar")
        val config = testConfig(outputJarPath = output.toString())
        val request = EngineRunRequest(tempDir.resolve("config.toml"), config)

        try {
            executeRunRequest(request, run = { _, _, _ -> })
            assertEquals(false, Files.exists(output.resolveSibling("output.jar.boot-secret.hex")))
            assertEquals(false, Files.exists(output.resolveSibling("output.jar.boot-kek.jsbk")))
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
