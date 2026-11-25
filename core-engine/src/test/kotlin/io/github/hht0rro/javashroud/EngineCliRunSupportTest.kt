package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineRunRequest
import io.github.hht0rro.javashroud.adapters.protocol.buildRunRequest
import io.github.hht0rro.javashroud.adapters.protocol.executeRunRequest
import io.github.hht0rro.javashroud.apk.ApkTestFixtures
import io.github.hht0rro.javashroud.config.parseConfig
import io.github.hht0rro.javashroud.kernel.EngineKernel
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
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
        val tempDir: Path = Files.createTempDirectory("javashroud-run-request-current-format")
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
                "jni-microkernel-loader bootKeyDelivery 已由当前格式移除；删除该配置项后重新构建。",
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

    @Test
    fun runRequest_does_not_write_through_artifact_path_aliases() {
        val tempDir = Files.createTempDirectory("javashroud-run-path-aliases")
        val input = tempDir.resolve("input.jar")
        val alias = tempDir.resolve("alias.jar")
        val output = tempDir.resolve("output.jar")
        val config = tempDir.resolve("bad.toml")
        try {
            Files.writeString(input, "original input")
            Files.createLink(alias, input)

            assertFailsWith<IllegalArgumentException> {
                buildRunRequest(arrayOf("--input", input.toString(), "--output", alias.toString()))
            }
            assertFailsWith<IllegalArgumentException> {
                buildRunRequest(arrayOf("--input", input.toString(), "--output", output.toString(), "--log-file", alias.toString()))
            }
            Files.writeString(config, "invalid [")
            assertFailsWith<Exception> {
                buildRunRequest(arrayOf("-config", config.toString(), "--log-file", input.toString()))
            }

            assertEquals("original input", Files.readString(input))
            assertEquals("original input", Files.readString(alias))
            assertEquals(false, Files.exists(output))
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun jarSidecarsCannotReplaceTheConfigurationOrInput() {
        val directory = Files.createTempDirectory("javashroud-sidecar-protected-input")
        val input = directory.resolve("input.jar")
        val output = directory.resolve("release.jar")
        val config = directory.resolve("release.debugmap")
        try {
            java.util.jar.JarOutputStream(Files.newOutputStream(input)).use { jar ->
                jar.putNextEntry(java.util.jar.JarEntry("asset.txt"))
                jar.write("input resource".toByteArray())
                jar.closeEntry()
            }
            Files.writeString(output, "previous output")
            Files.writeString(config, buildConfigToml(input, output))
            val originalInput = Files.readAllBytes(input)
            val originalConfig = Files.readAllBytes(config)
            assertFailsWith<IllegalArgumentException> {
                buildRunRequest(arrayOf("-config", config.toString()))
            }
            assertFailsWith<IllegalArgumentException> {
                EngineKernel().run(parseConfig(config), config)
            }
            assertContentEquals(originalInput, Files.readAllBytes(input))
            assertContentEquals(originalConfig, Files.readAllBytes(config))
            assertEquals("previous output", Files.readString(output))
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    @Test
    fun earlyFailureLogDoesNotModifySigningKeysOrSidecars() {
        val directory = Files.createTempDirectory("javashroud-failed-log-protected-files")
        val input = directory.resolve("input.apk")
        val output = directory.resolve("output.apk")
        val config = directory.resolve("invalid.toml")
        val keystore = directory.resolve("signing.jks")
        val alias = directory.resolve("signing-alias.jks")
        val sidecar = directory.resolve("output.debugmap")
        try {
            Files.write(input, ApkTestFixtures.syntheticApk())
            Files.writeString(keystore, "original signing identity")
            Files.createLink(alias, keystore)
            Files.writeString(sidecar, "original mapping")
            Files.writeString(config, """
                inputJarPath = '${formatTomlPath(input)}'
                outputJarPath = '${formatTomlPath(output)}'
                artifactFormat = 'apk'
                passes = []
                [apk]
                minApi = 1
                [apk.signing]
                keystorePath = '${formatTomlPath(keystore)}'
            """.trimIndent())
            for (log in listOf(keystore, alias, sidecar)) {
                val error = assertFailsWith<IllegalArgumentException> {
                    buildRunRequest(arrayOf("-config", config.toString(), "--log-file", log.toString()))
                }
                assertTrue(error.message.orEmpty().contains("supported floor"), error.message)
                assertEquals("original signing identity", Files.readString(keystore))
                assertEquals("original signing identity", Files.readString(alias))
                assertEquals("original mapping", Files.readString(sidecar))
                assertTrue(Files.notExists(output))
            }
            Files.writeString(config, Files.readString(config).replace("artifactFormat = 'apk'", "artifactFormat = 'jar'"))
            val forced = assertFailsWith<IllegalArgumentException> {
                buildRunRequest(arrayOf("-config", config.toString(), "--apk", "--log-file", sidecar.toString()))
            }
            assertTrue(forced.message.orEmpty().contains("supported floor"), forced.message)
            assertEquals("original mapping", Files.readString(sidecar))
        } finally {
            directory.toFile().deleteRecursively()
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
