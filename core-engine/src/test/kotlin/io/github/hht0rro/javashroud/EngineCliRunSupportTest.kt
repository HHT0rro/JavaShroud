package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineRunRequest
import io.github.hht0rro.javashroud.adapters.protocol.buildRunRequest
import io.github.hht0rro.javashroud.adapters.protocol.cleanupEmbeddedBootSecretSidecars
import io.github.hht0rro.javashroud.adapters.protocol.installAutoBootSecretIfNeeded
import io.github.hht0rro.javashroud.adapters.protocol.wipeAutoBootSecret
import io.github.hht0rro.javashroud.transforms.protection.BootKekSidecar
import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import java.nio.file.Files
import java.nio.file.Path
import java.util.HexFormat
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
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
    fun install_auto_boot_secret_preserves_an_existing_fixture_provider() {
        val expectedSecret = ByteArray(32) { index -> (index * 13 + 7).toByte() }
        val existingProvider: () -> ByteArray? = { expectedSecret.copyOf() }
        val existingBindingProvider: () -> ByteArray? = { ByteArray(32) { index -> (index * 17 + 3).toByte() } }
        val previousProvider = NativeKernelShellPacker.buildBootSecretProvider
        val previousBindingProvider = BootKekSidecar.buildArtifactBindingProvider
        NativeKernelShellPacker.buildBootSecretProvider = existingProvider
        BootKekSidecar.buildArtifactBindingProvider = existingBindingProvider
        try {
            val maxHardening = com.fasterxml.jackson.databind.ObjectMapper()
                .valueToTree<com.fasterxml.jackson.databind.JsonNode>("max-hardening")
            val config = testConfig(
                passes = listOf(
                    testPassSpec(
                        id = "jni-microkernel-loader",
                        params = mapOf("nativePackingLevel" to maxHardening),
                    ),
                ),
            )

            assertNull(installAutoBootSecretIfNeeded(config))
            assertSame(existingProvider, NativeKernelShellPacker.buildBootSecretProvider)
            assertSame(existingBindingProvider, BootKekSidecar.buildArtifactBindingProvider)
            val returnedSecret = NativeKernelShellPacker.buildBootSecretProvider?.invoke()
            try {
                assertContentEquals(expectedSecret, returnedSecret)
            } finally {
                returnedSecret?.fill(0)
            }
        } finally {
            NativeKernelShellPacker.buildBootSecretProvider = previousProvider
            BootKekSidecar.buildArtifactBindingProvider = previousBindingProvider
            expectedSecret.fill(0)
        }
    }

    @Test
    fun install_auto_boot_secret_writes_hex_sidecar_for_max_and_wipes_lifecycle() {
        val tempDir = Files.createTempDirectory("javashroud-auto-boot-secret")
        val previousProvider = NativeKernelShellPacker.buildBootSecretProvider
        val previousBindingProvider = BootKekSidecar.buildArtifactBindingProvider
        var generated: io.github.hht0rro.javashroud.adapters.protocol.AutoBootSecret? = null
        try {
            NativeKernelShellPacker.buildBootSecretProvider = null
            BootKekSidecar.buildArtifactBindingProvider = null
            val config = testConfig(
                outputJarPath = tempDir.resolve("output.jar").toString(),
                passes = listOf(jniMicrokernelLoaderPass("max")),
            )

            generated = installAutoBootSecretIfNeeded(config, getenv = { null })
            val autoBootSecret = generated ?: error("expected an automatic Boot KEK")

            val sidecar = requireNotNull(autoBootSecret.sidecar)
            assertEquals("output.jar.boot-secret.hex", sidecar.fileName.toString())
            assertEquals(HexFormat.of().formatHex(autoBootSecret.secret), Files.readString(sidecar))
            assertNull(autoBootSecret.artifactBinding)
            val providerSecret = NativeKernelShellPacker.buildBootSecretProvider?.invoke()
            try {
                assertContentEquals(autoBootSecret.secret, providerSecret)
            } finally {
                providerSecret?.fill(0)
            }

            wipeAutoBootSecret(autoBootSecret)
            generated = null
            assertNull(NativeKernelShellPacker.buildBootSecretProvider)
            assertNull(BootKekSidecar.buildArtifactBindingProvider)
            assertTrue(autoBootSecret.secret.all { it == 0.toByte() })
        } finally {
            generated?.let(::wipeAutoBootSecret)
            NativeKernelShellPacker.buildBootSecretProvider = previousProvider
            BootKekSidecar.buildArtifactBindingProvider = previousBindingProvider
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun install_auto_boot_secret_writes_bound_sidecar_for_max_hardening_and_wipes_lifecycle() {
        val tempDir = Files.createTempDirectory("javashroud-auto-hardening-boot-secret")
        val previousProvider = NativeKernelShellPacker.buildBootSecretProvider
        val previousBindingProvider = BootKekSidecar.buildArtifactBindingProvider
        var generated: io.github.hht0rro.javashroud.adapters.protocol.AutoBootSecret? = null
        try {
            NativeKernelShellPacker.buildBootSecretProvider = null
            BootKekSidecar.buildArtifactBindingProvider = null
            val config = testConfig(
                outputJarPath = tempDir.resolve("output.jar").toString(),
                passes = listOf(jniMicrokernelLoaderPass("max-hardening")),
            )

            generated = installAutoBootSecretIfNeeded(config, getenv = { null })
            val autoBootSecret = generated ?: error("expected an automatic Boot KEK")
            val binding = autoBootSecret.artifactBinding ?: error("expected a max-hardening artifact binding")

            val sidecar = requireNotNull(autoBootSecret.sidecar)
            assertEquals("output.jar.boot-kek.jsbk", sidecar.fileName.toString())
            val sidecarText = Files.readString(sidecar)
            assertTrue(sidecarText.startsWith(BootKekSidecar.TEXT_PREFIX))
            val decodedSecret = BootKekSidecar.decodeText(sidecarText, binding)
            try {
                assertContentEquals(autoBootSecret.secret, decodedSecret)
            } finally {
                decodedSecret.fill(0)
            }
            val providerSecret = NativeKernelShellPacker.buildBootSecretProvider?.invoke()
            try {
                assertContentEquals(autoBootSecret.secret, providerSecret)
            } finally {
                providerSecret?.fill(0)
            }
            val providerBinding = BootKekSidecar.buildArtifactBindingProvider?.invoke()
            try {
                assertContentEquals(binding, providerBinding)
            } finally {
                providerBinding?.fill(0)
            }

            wipeAutoBootSecret(autoBootSecret)
            generated = null
            assertNull(NativeKernelShellPacker.buildBootSecretProvider)
            assertNull(BootKekSidecar.buildArtifactBindingProvider)
            assertTrue(autoBootSecret.secret.all { it == 0.toByte() })
            assertTrue(binding.all { it == 0.toByte() })
        } finally {
            generated?.let(::wipeAutoBootSecret)
            NativeKernelShellPacker.buildBootSecretProvider = previousProvider
            BootKekSidecar.buildArtifactBindingProvider = previousBindingProvider
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun install_auto_boot_secret_embedded_mode_keeps_secret_in_memory_and_cleans_scoped_sidecars() {
        val tempDir = Files.createTempDirectory("javashroud-auto-embedded-boot-secret")
        val output = tempDir.resolve("output.jar")
        val legacyHex = tempDir.resolve("output.jar.boot-secret.hex")
        val legacyJsbk = tempDir.resolve("output.jar.boot-kek.jsbk")
        val previousProvider = NativeKernelShellPacker.buildBootSecretProvider
        val previousBindingProvider = BootKekSidecar.buildArtifactBindingProvider
        var generated: io.github.hht0rro.javashroud.adapters.protocol.AutoBootSecret? = null
        try {
            NativeKernelShellPacker.buildBootSecretProvider = null
            BootKekSidecar.buildArtifactBindingProvider = null
            Files.writeString(legacyHex, "stale")
            Files.writeString(legacyJsbk, "stale")
            val config = testConfig(
                outputJarPath = output.toString(),
                passes = listOf(jniMicrokernelLoaderPass("max", BootKekSidecar.DELIVERY_EMBEDDED)),
            )

            generated = installAutoBootSecretIfNeeded(config, getenv = { null })
            val autoBootSecret = generated ?: error("expected an automatic embedded Boot KEK")

            assertNull(autoBootSecret.sidecar)
            assertEquals(BootKekSidecar.DELIVERY_EMBEDDED, autoBootSecret.delivery)
            assertTrue(Files.exists(legacyHex), "stale sidecars are removed only after a successful build")
            assertTrue(Files.exists(legacyJsbk), "stale sidecars are removed only after a successful build")
            cleanupEmbeddedBootSecretSidecars(config)
            assertTrue(Files.notExists(legacyHex))
            assertTrue(Files.notExists(legacyJsbk))
            val providerSecret = NativeKernelShellPacker.buildBootSecretProvider?.invoke()
            try {
                assertContentEquals(autoBootSecret.secret, providerSecret)
            } finally {
                providerSecret?.fill(0)
            }
        } finally {
            generated?.let(::wipeAutoBootSecret)
            NativeKernelShellPacker.buildBootSecretProvider = previousProvider
            BootKekSidecar.buildArtifactBindingProvider = previousBindingProvider
            tempDir.toFile().deleteRecursively()
        }
    }

    private fun jniMicrokernelLoaderPass(
        level: String,
        delivery: String = BootKekSidecar.DELIVERY_EXTERNAL_FILE,
    ) = testPassSpec(
        id = "jni-microkernel-loader",
        params = mapOf(
            "nativePackingLevel" to com.fasterxml.jackson.databind.ObjectMapper()
                .valueToTree<com.fasterxml.jackson.databind.JsonNode>(level),
            "bootKeyDelivery" to com.fasterxml.jackson.databind.ObjectMapper()
                .valueToTree<com.fasterxml.jackson.databind.JsonNode>(delivery),
        ),
    )

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
