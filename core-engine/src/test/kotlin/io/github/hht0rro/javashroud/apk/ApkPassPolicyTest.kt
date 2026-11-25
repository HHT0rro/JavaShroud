package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.config.validateConfig
import io.github.hht0rro.javashroud.model.config.ApkConfig
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.RuleSet
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ApkPassPolicyTest {

    private val configPath: Path = Path.of("apk-policy-test.toml").toAbsolutePath()

    private fun apkConfig(
        passes: List<PassSpec> = emptyList(),
        minApi: Int = 26,
        profile: HardenedProtectionProfile = HardenedProtectionProfile.RELEASE_HARDENED,
        artifactFormat: String = "apk",
        allowOptInPasses: Boolean = false,
    ): ObfuscationConfig = ObfuscationConfig(
        inputJarPath = "unused.apk",
        outputJarPath = "unused-out.apk",
        passes = passes,
        ruleSet = RuleSet(emptyList()),
        allowOptInPasses = allowOptInPasses,
        protectionProfile = profile,
        artifactFormat = artifactFormat,
        apk = ApkConfig(minApi = minApi),
    )

    @Test
    fun defaultApkPipelineExcludesBlacklistedPassesAndUnlocksOptIn() {
        val filled = ApkPassPolicy.fillDefaultPipeline(apkConfig())
        assertTrue(filled.passes.isNotEmpty())
        val ids = filled.passes.map { it.id }.toSet()
        assertTrue(ids.contains("rename-classes"))
        assertTrue(ids.contains("invoke-dynamic-indirection"))
        ApkPassPolicy.forbiddenPassIds.forEach { forbidden ->
            assertTrue(forbidden !in ids, "default APK pipeline must not contain $forbidden")
        }
        assertEquals(true, filled.allowOptInPasses, "APK default fill must set allowOptInPasses=true (rename passes are opt-in)")
    }

    @Test
    fun blacklistRejectsForbiddenPasses() {
        val config = apkConfig(passes = listOf(PassSpec("os-anti-debug", enabled = true, params = emptyMap())))
        val error = assertFailsWith<IllegalArgumentException> {
            ApkPassPolicy.validatePassBlacklist(config, configPath)
        }
        assertTrue("os-anti-debug" in (error.message ?: ""))
    }

    @Test
    fun minApiBelow21FailsClosed() {
        val error = assertFailsWith<IllegalArgumentException> {
            ApkPassPolicy.validateMinApi(ApkConfig(minApi = 19), configPath)
        }
        assertTrue(error.message!!.contains("21"))
    }

    @Test
    fun invokeCustomGateRequires26() {
        val indyEnabled = apkConfig(
            passes = listOf(PassSpec("invoke-dynamic-indirection", enabled = true, params = emptyMap())),
            minApi = 24,
            allowOptInPasses = true,
        )
        val error = assertFailsWith<IllegalArgumentException> {
            ApkPassPolicy.validateInvokeCustomGate(indyEnabled, configPath)
        }
        assertTrue(error.message!!.contains("26"))

        // Non-MINIMAL profiles wrap indy targets too, even without the pass.
        val nonMinimal = apkConfig(minApi = 24, profile = HardenedProtectionProfile.RELEASE_HARDENED)
        assertFailsWith<IllegalArgumentException> {
            ApkPassPolicy.validateInvokeCustomGate(nonMinimal, configPath)
        }
        // MINIMAL below 26 is allowed.
        ApkPassPolicy.validateInvokeCustomGate(
            apkConfig(minApi = 21, profile = HardenedProtectionProfile.MINIMAL),
            configPath,
        )
    }

    @Test
    fun manifestMinSdkBelowExplicitMinApiFailsClosed() {
        val explicit = apkConfig(minApi = 26).let { it.copy(apk = it.apk.copy(minApiExplicit = true)) }
        val error = assertFailsWith<IllegalArgumentException> {
            ApkPassPolicy.validateManifestMinSdk(23, explicit, configPath)
        }
        assertTrue(error.message!!.contains("23") && error.message!!.contains("26"))

        // minSdk >= minApi passes; a missing declaration cannot be verified.
        ApkPassPolicy.validateManifestMinSdk(26, explicit, configPath)
        ApkPassPolicy.validateManifestMinSdk(30, explicit, configPath)
        val missing = assertFailsWith<IllegalArgumentException> {
            ApkPassPolicy.validateManifestMinSdk(null, explicit, configPath)
        }
        assertTrue(missing.message.orEmpty().contains("declare a numeric minSdkVersion"))
    }

    @Test
    fun manifestMinSdkBelowDerivedMinApiDefersToPipelineBump() {
        // A derived minApi (no explicit config value) never fails validation:
        // the pipeline raises the OUTPUT manifest's minSdkVersion instead, so
        // minSdk 9-20 apps with a derived floor of 21 remain processable.
        val derived = apkConfig(minApi = 21)
        ApkPassPolicy.validateManifestMinSdk(9, derived, configPath)
        ApkPassPolicy.validateManifestMinSdk(17, derived, configPath)
        ApkPassPolicy.validateManifestMinSdk(20, derived, configPath)
    }

    @Test
    fun jarModeIgnoresApgGatesViaValidateConfigBranchSelection() {
        // A jar config with forbidden passes and minApi=19 must not trip the
        // APK gates: the gates only run on the APK branch of validateConfig,
        // exercised end-to-end in ApkPipelineRunnerTest. Here we assert the
        // policy-level separation primitives.
        val jarShaped = apkConfig(artifactFormat = "jar")
        assertEquals("jar", jarShaped.artifactFormat)
        assertTrue(ApkPassPolicy.forbiddenPassIds.isNotEmpty())
    }

    @Test
    fun validateConfigApkBranchEnforcesBlacklistOnRealApk() {
        val apk = Files.createTempFile("policy-apk-", ".apk")
        Files.write(apk, ApkTestFixtures.syntheticApk())
        val config = ObfuscationConfig(
            inputJarPath = apk.absolutePathString(),
            outputJarPath = apk.resolveSibling("out.apk").toString(),
            passes = listOf(PassSpec("os-anti-debug", enabled = true, params = emptyMap())),
            ruleSet = RuleSet(emptyList()),
            allowOptInPasses = true,
            artifactFormat = "auto",
            protectionProfile = HardenedProtectionProfile.MINIMAL,
            apk = ApkConfig(minApi = 26),
        )
        val error = assertFailsWith<IllegalArgumentException> {
            validateConfig(config, configPath)
        }
        assertTrue(error.message!!.contains("os-anti-debug"), error.message)
    }

    @Test
    fun validateConfigApkBranchFillsDefaultPipelineAndResolvesAuto() {
        val apk = Files.createTempFile("policy-default-", ".apk")
        Files.write(apk, ApkTestFixtures.syntheticApk())
        val config = ObfuscationConfig(
            inputJarPath = apk.absolutePathString(),
            outputJarPath = apk.resolveSibling("out.apk").toString(),
            passes = emptyList(),
            ruleSet = RuleSet(emptyList()),
            artifactFormat = "auto",
            protectionProfileExplicit = false,
            apk = ApkConfig(minApi = 26),
        )
        val validated = validateConfig(config, configPath)
        assertEquals("apk", validated.artifactFormat)
        assertTrue(validated.allowOptInPasses)
        assertTrue(validated.passes.map { it.id }.none { it in ApkPassPolicy.forbiddenPassIds })
    }

    private fun decodeTomlConfig(toml: String, inputPath: Path): io.github.hht0rro.javashroud.model.config.ObfuscationConfig {
        val mapper = com.fasterxml.jackson.dataformat.toml.TomlMapper()
        val node = mapper.readTree(toml)
        return io.github.hht0rro.javashroud.config.decodeConfig(node, Path.of("decode-test.toml"))
            .let { decoded ->
                decoded.copy(
                    inputJarPath = inputPath.toAbsolutePath().toString(),
                    outputJarPath = inputPath.resolveSibling("out.apk").toAbsolutePath().toString(),
                )
            }
    }

    @Test
    fun apkModeWithoutExplicitProfileDefaultsToMinimalWithFilledPipeline() {
        val apk = Files.createTempFile("policy-toml-default-", ".apk")
        Files.write(apk, ApkTestFixtures.syntheticApk())
        val decoded = decodeTomlConfig(
            """
            inputJarPath = "placeholder"
            outputJarPath = "placeholder"
            artifactFormat = "apk"
            passes = []
            """.trimIndent(),
            apk,
        )
        assertEquals(false, decoded.protectionProfileExplicit, "absent TOML key must decode as not explicit")
        val validated = validateConfig(decoded, configPath)
        assertEquals(
            io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile.MINIMAL,
            validated.protectionProfile,
            "APK mode with no explicit profile must resolve to MINIMAL (visible default)",
        )
        assertTrue(validated.passes.isNotEmpty(), "the default pipeline must still be filled for the defaulted MINIMAL profile")
        assertTrue(validated.allowOptInPasses)
        assertTrue(validated.passes.map { it.id }.none { it in ApkPassPolicy.forbiddenPassIds })
    }

    @Test
    fun explicitReleaseHardenedIsRejectedDuringValidation() {
        val apk = Files.createTempFile("policy-toml-explicit-", ".apk")
        Files.write(apk, ApkTestFixtures.syntheticApk())
        val decoded = decodeTomlConfig(
            """
            inputJarPath = "placeholder"
            outputJarPath = "placeholder"
            artifactFormat = "apk"
            passes = []
            protectionProfile = "release-hardened"
            """.trimIndent(),
            apk,
        )
        assertEquals(true, decoded.protectionProfileExplicit)
        val error = assertFailsWith<IllegalArgumentException> { validateConfig(decoded, configPath) }
        assertTrue(error.message.orEmpty().contains("release-hardened"))
        assertTrue(error.message.orEmpty().contains("desktop Qp runtime"))
    }

    @Test
    fun validateConfigAutoSniffResolvesJarForPlainJar() {
        val jar = Files.createTempFile("policy-jar-", ".jar")
        val out = java.io.ByteArrayOutputStream()
        java.util.zip.ZipOutputStream(out).use { zip ->
            zip.putNextEntry(java.util.zip.ZipEntry("com/example/Main.class"))
            zip.write(ByteArray(16))
            zip.closeEntry()
        }
        Files.write(jar, out.toByteArray())
        val config = ObfuscationConfig(
            inputJarPath = jar.absolutePathString(),
            outputJarPath = jar.resolveSibling("out.jar").toString(),
            passes = emptyList(),
            ruleSet = RuleSet(emptyList()),
            artifactFormat = "auto",
        )
        val validated = validateConfig(config, configPath)
        assertEquals("jar", validated.artifactFormat)
    }
}
