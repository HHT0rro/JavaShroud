package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.model.config.ApkSigningConfig
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ApkSignerServiceTest {

    private fun tempDir(): Path = Files.createTempDirectory("signer-test-")

    @Test
    fun signsAndVerifiesWithDebugKeystoreV1AndV2() {
        val dir = tempDir()
        val unsigned = ApkTestFixtures.writeApk(dir.resolve("unsigned.apk"), ApkTestFixtures.syntheticApk())
        val finalApk = dir.resolve("signed.apk")
        val log = mutableListOf<String>()

        val outcome = ApkSignerService.sign(
            unsignedApk = unsigned,
            finalApk = finalApk,
            signing = ApkSigningConfig(),
            minApi = 26,
            soPageSize = 4096,
            log = log::add,
        )

        assertTrue(Files.isRegularFile(finalApk))
        assertEquals(true, outcome.usedDebugKeystore)
        assertEquals(true, outcome.v1Enabled)
        assertEquals(true, outcome.v2Enabled)
        assertTrue(log.none { it.contains("javashroud-debug", ignoreCase = true) && it.contains("storepass") })

        ApkSignerService.verify(finalApk, ApkSigningConfig(), 26) {}
        assertFailsWith<IllegalArgumentException> {
            ApkSignerService.verifyWithCertificate(finalApk, ApkSigningConfig(), 26, "00".repeat(32)) {}
        }
    }

    @Test
    fun signsAndVerifiesEitherSupportedSchemeByItself() {
        val dir = tempDir()
        val unsigned = ApkTestFixtures.writeApk(dir.resolve("unsigned.apk"), ApkTestFixtures.syntheticApk())
        for ((index, signing) in listOf(ApkSigningConfig(v2Enabled = false), ApkSigningConfig(v1Enabled = false)).withIndex()) {
            val output = dir.resolve("signed-$index.apk")
            ApkSignerService.sign(unsigned, output, signing, 26, 4096) {}
            ApkSignerService.verify(output, signing, 26) {}
        }
    }

    @Test
    fun tamperedApkFailsVerification() {
        val dir = tempDir()
        val unsigned = ApkTestFixtures.writeApk(dir.resolve("unsigned-2.apk"), ApkTestFixtures.syntheticApk())
        val finalApk = dir.resolve("signed-2.apk")
        ApkSignerService.sign(unsigned, finalApk, ApkSigningConfig(), minApi = 26, soPageSize = 4096) {}

        val tampered = dir.resolve("tampered.apk")
        val bytes = Files.readAllBytes(finalApk)
        bytes[bytes.size / 2] = (bytes[bytes.size / 2].toInt() xor 0x5A).toByte()
        Files.write(tampered, bytes)

        assertFailsWith<IllegalArgumentException> {
            ApkSignerService.verify(tampered, ApkSigningConfig(), 26) {}
        }
    }

    @Test
    fun explicitMissingKeystoreFailsClosed() {
        val dir = tempDir()
        val unsigned = ApkTestFixtures.writeApk(dir.resolve("unsigned-3.apk"), ApkTestFixtures.syntheticApk())
        val error = assertFailsWith<IllegalArgumentException> {
            ApkSignerService.sign(
                unsignedApk = unsigned,
                finalApk = dir.resolve("never.apk"),
                signing = ApkSigningConfig(keystorePath = dir.resolve("missing.keystore").toString()),
                minApi = 26,
                soPageSize = 4096,
            ) {}
        }
        assertTrue(error.message!!.contains("keystorePath"))
        assertTrue(!Files.isRegularFile(dir.resolve("never.apk")), "no half-signed artifact may survive")
    }

    @Test
    fun rejectsOutputAliasAndUnsupportedSchemeCombinationsWithoutWriting() {
        val dir = tempDir()
        val unsigned = ApkTestFixtures.writeApk(dir.resolve("unsigned.apk"), ApkTestFixtures.syntheticApk())
        val alias = Files.createLink(dir.resolve("alias.apk"), unsigned)
        val oldBytes = Files.readAllBytes(unsigned)
        assertFailsWith<IllegalArgumentException> {
            ApkSignerService.sign(unsigned, alias, ApkSigningConfig(), 26, 4096) {}
        }
        val output = dir.resolve("missing.apk")
        for ((signing, api) in listOf(
            ApkSigningConfig(v1Enabled = false, v2Enabled = false) to 26,
            ApkSigningConfig(v1Enabled = false) to 23,
        )) {
            assertFailsWith<IllegalArgumentException> { ApkSignerService.sign(unsigned, output, signing, api, 4096) {} }
        }
        assertContentEquals(oldBytes, Files.readAllBytes(unsigned))
        assertContentEquals(oldBytes, Files.readAllBytes(alias))
        assertTrue(!Files.exists(output))
    }

    @Test
    fun cancellationAtSignatureVerificationPreservesOldOutputAndDoesNotTouchFixedTempName() {
        val dir = tempDir()
        val unsigned = ApkTestFixtures.writeApk(dir.resolve("unsigned.apk"), ApkTestFixtures.syntheticApk())
        val output = Files.writeString(dir.resolve("signed.apk"), "old output")
        val userFile = Files.writeString(dir.resolve("signed.apk.javashroud-signing.tmp"), "user data")

        assertFailsWith<CancellationException> {
            ApkSignerService.sign(unsigned, output, ApkSigningConfig(), 26, 4096) { line ->
                if (line.startsWith("ApkVerifier passed")) throw CancellationException("cancel signing")
            }
        }

        assertEquals("old output", Files.readString(output))
        assertEquals("user data", Files.readString(userFile))
        assertTrue(Files.list(dir).use { stream -> stream.noneMatch { it.fileName.toString().startsWith(".javashroud-signing-") } })
    }
}
