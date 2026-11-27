package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.adapters.protocol.buildRunRequest
import io.github.hht0rro.javashroud.config.validateConfig
import io.github.hht0rro.javashroud.model.config.ApkConfig
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.RuleSet
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * minApi derivation for configs that do not pin apk.minApi: the effective
 * value comes from the manifest minSdkVersion (floored at the API-21 multidex
 * minimum), the default pipeline drops invoke-dynamic-indirection below 26,
 * and an explicitly pinned minApi keeps the strict fail-closed cross-check.
 * Also covers the CLI contract that a failed run still writes the detailed
 * --log-file record.
 */
class ApkMinApiDerivationTest {

    private val configPath: Path = Path.of("minapi-derive-test.toml").toAbsolutePath()

    private fun writeApk(minSdk: Int?): Path {
        val apk = Files.createTempFile("minapi-", ".apk")
        Files.write(apk, ApkTestFixtures.syntheticApk(manifestBytes = ApkTestFixtures.binaryManifest("com.example.app", minSdkVersion = minSdk)))
        return apk
    }

    private fun configFor(apk: Path, apkConfig: ApkConfig = ApkConfig()): ObfuscationConfig = ObfuscationConfig(
        inputJarPath = apk.absolutePathString(),
        outputJarPath = apk.resolveSibling("out.apk").toString(),
        passes = emptyList(),
        ruleSet = RuleSet(emptyList()),
        artifactFormat = "auto",
        // Absent profile key: resolves to the APK-visible MINIMAL default,
        // exactly like a direct run or a TOML without protectionProfile.
        protectionProfileExplicit = false,
        apk = apkConfig,
    )

    @Test
    fun deriveUsesManifestFlooredAt21AndExplicitWins() {
        val explicit = ApkConfig(minApi = 26, minApiExplicit = true)
        assertEquals(26, ApkPassPolicy.deriveEffectiveMinApi(explicit, manifestMinSdk = 21), "explicit value wins")
        assertEquals(26, ApkPassPolicy.deriveEffectiveMinApi(explicit, manifestMinSdk = null))
        val implicit = ApkConfig(minApi = 26, minApiExplicit = false)
        assertEquals(21, ApkPassPolicy.deriveEffectiveMinApi(implicit, manifestMinSdk = 21))
        assertEquals(23, ApkPassPolicy.deriveEffectiveMinApi(implicit, manifestMinSdk = 23))
        assertEquals(26, ApkPassPolicy.deriveEffectiveMinApi(implicit, manifestMinSdk = 26))
        assertEquals(28, ApkPassPolicy.deriveEffectiveMinApi(implicit, manifestMinSdk = 28))
        assertEquals(21, ApkPassPolicy.deriveEffectiveMinApi(implicit, manifestMinSdk = 18), "floor at the multidex minimum")
        assertEquals(26, ApkPassPolicy.deriveEffectiveMinApi(implicit, manifestMinSdk = null), "no uses-sdk keeps the 26 default")
    }

    @Test
    fun defaultPipelineOmitsIndyBelow26() {
        val below = ApkPassPolicy.defaultApkPassSpecs(minApi = 21).map { it.id }.toSet()
        assertTrue("invoke-dynamic-indirection" !in below, "indy must be omitted below API 26: $below")
        assertTrue("rename-classes" in below, "renaming stays enabled at minApi 21")
        ApkPassPolicy.forbiddenPassIds.forEach { forbidden ->
            assertTrue(forbidden !in below, "default APK pipeline must not contain $forbidden")
        }
        val at26 = ApkPassPolicy.defaultApkPassSpecs(minApi = 26).map { it.id }.toSet()
        assertTrue("invoke-dynamic-indirection" in at26, "indy stays in the default pipeline at minApi 26")
    }

    @Test
    fun validateConfigDerivesMinApiAndDropsIndyForMinSdk21() {
        val validated = validateConfig(configFor(writeApk(minSdk = 21)), configPath)
        assertEquals(21, validated.apk.minApi, "unspecified minApi derives from manifest minSdk")
        val ids = validated.passes.map { it.id }.toSet()
        assertTrue("invoke-dynamic-indirection" !in ids, "derived minApi 21 cannot verify invoke-custom: $ids")
        assertTrue(validated.passes.isNotEmpty())
    }

    @Test
    fun validateConfigKeepsExplicitMinApiStrict() {
        val apk = writeApk(minSdk = 21)
        val decoded = decodeExplicitMinApi(apk, minApi = 26)
        assertEquals(true, decoded.apk.minApiExplicit, "TOML presence marks the value explicit")
        val error = assertFailsWith<IllegalArgumentException> {
            validateConfig(decoded, configPath)
        }
        assertTrue(error.message!!.contains("minSdkVersion=21") && error.message!!.contains("minApi=26"), error.message)
    }

    @Test
    fun manifestBelow21DerivesMinApi21AndDefersTheBumpToThePipeline() {
        // A config-less run on a minSdk 18 app derives minApi=21 (multidex
        // floor) and no longer fails validation: the pipeline raises the
        // OUTPUT manifest's minSdkVersion to 21 with a warning.
        val validated = validateConfig(configFor(writeApk(minSdk = 18)), configPath)
        assertEquals(21, validated.apk.minApi, "derived minApi floors at 21")
        val ids = validated.passes.map { it.id }.toSet()
        assertTrue("invoke-dynamic-indirection" !in ids, "derived minApi 21 drops the indy pass: $ids")
    }

    @Test
    fun patchMinSdkVersionRoundTripsThroughParse() {
        val manifestBytes = ApkTestFixtures.binaryManifest("com.example.app", minSdkVersion = 17)
        assertEquals(17, ApkBinaryXmlReader.parse(manifestBytes).minSdkVersion)
        val patched = ApkBinaryXmlReader.patchMinSdkVersion(manifestBytes, 21)
        val reparsed = ApkBinaryXmlReader.parse(patched)
        assertEquals(21, reparsed.minSdkVersion, "patched manifest declares the raised floor")
        assertEquals("com.example.app", reparsed.packageName, "patch leaves every other manifest fact intact")
        // Patching to the value already present is a no-op byte-for-byte.
        assertEquals(
            manifestBytes.toList(),
            ApkBinaryXmlReader.patchMinSdkVersion(manifestBytes, 17).toList(),
        )
    }

    @Test
    fun directRunOnMinSdk21ApkValidates() {
        val apk = writeApk(minSdk = 21)
        val request = buildRunRequest(
            arrayOf(
                "--input", apk.toAbsolutePath().toString(),
                "--output", apk.resolveSibling("direct-out.apk").toAbsolutePath().toString(),
            ),
        )
        assertEquals(21, request.config.apk.minApi)
        assertTrue(request.config.passes.map { it.id }.none { it == "invoke-dynamic-indirection" })
    }

    @Test
    fun directRunRejectsMissingManifestMinSdkBeforePublishing() {
        val apk = writeApk(minSdk = null)
        val output = apk.resolveSibling(apk.fileName.toString() + ".out.apk")
        try {
            val error = assertFailsWith<IllegalArgumentException> {
                buildRunRequest(arrayOf("--input", apk.toString(), "--output", output.toString()))
            }
            assertTrue(error.message.orEmpty().contains("declare a numeric minSdkVersion"))
            assertTrue(Files.notExists(output))
        } finally {
            Files.deleteIfExists(apk)
        }
    }

    @Test
    fun failedDirectRunStillWritesRequestedLogFile() {
        val logFile = Files.createTempDirectory("minapi-log-").resolve("nested").resolve("run-fail.log")
        val error = assertFailsWith<IllegalArgumentException> {
            buildRunRequest(
                arrayOf(
                    "--input", "Z:/definitely/missing.apk",
                    "--output", "Z:/definitely/missing-out.apk",
                    "--log-file", logFile.toAbsolutePath().toString(),
                ),
            )
        }
        assertTrue(error.message!!.isNotBlank())
        assertTrue(Files.isRegularFile(logFile), "validation failure must still produce the --log-file record")
        val content = Files.readString(logFile)
        assertTrue("run failed" in content, content)
        assertTrue(content.lineSequence().any { it.contains("ApkMinApiDerivationTest") || it.contains("at ") }, "stack trace expected in the failure log")
    }

    private fun decodeExplicitMinApi(apk: Path, minApi: Int): ObfuscationConfig {
        val mapper = com.fasterxml.jackson.dataformat.toml.TomlMapper()
        val node = mapper.readTree(
            """
            inputJarPath = "placeholder"
            outputJarPath = "placeholder"
            artifactFormat = "apk"
            passes = []
            [apk]
            minApi = $minApi
            """.trimIndent(),
        )
        val decoded = io.github.hht0rro.javashroud.config.decodeConfig(node, Path.of("decode-minapi.toml"))
        return decoded.copy(
            inputJarPath = apk.toAbsolutePath().toString(),
            outputJarPath = apk.resolveSibling("out.apk").toAbsolutePath().toString(),
        )
    }
}
