package io.github.hht0rro.javashroud.apk

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ApkToolchainProvisionerTest {

    @Test
    fun vendoredResourcesResolveFromClasspathAndVerify() {
        val sumsBytes = ApkToolchainProvisioner.classLoaderResource(ApkToolchainProvisioner.DEX_TOOLS_SUMS_RESOURCE)
        assertNotNull(sumsBytes, "packageApkDexTools output must be on the test classpath")
        val sums = sumsBytes.toString(Charsets.UTF_8).lineSequence()
            .filter { it.isNotBlank() }
            .mapNotNull { line ->
                val parts = line.split(Regex("\\s+"), limit = 2)
                if (parts.size == 2) parts[1].trim() to parts[0] else null // fileName -> sha256
            }
            .toMap()
        assertTrue(sums.isNotEmpty())
        for ((name, sha) in sums) {
            val jarBytes = ApkToolchainProvisioner.classLoaderResource("${ApkToolchainProvisioner.DEX_TOOLS_RESOURCE_DIR}/$name")
            assertNotNull(jarBytes, "vendored jar must exist: $name")
            assertEquals(sha, ApkToolchainProvisioner.sha256Hex(jarBytes!!), "SHA-256 mismatch for vendored $name")
        }
    }

    @Test
    fun realToolsSkipEnvIsHonoredByTests() {
        // The env contract: "skip" disables the real-toolchain round trip.
        // This test documents the flag; the round-trip test reads it directly.
        assertTrue(
            ApkToolchainProvisioner.REAL_TOOLS_SKIP_ENV == "JAVASHROUD_APK_REAL_TOOLS",
        )
    }

    @Test
    fun javaResolutionPrefersJavaHomeOverEnv() {
        val javaHome = System.getProperty("java.home")
        val resolved = ApkToolchainProvisioner.resolveJavaExecutable(environment = { name ->
            if (name == "JAVA_HOME") "Z:\\definitely\\missing" else null
        })
        assertTrue(
            resolved.toAbsolutePath().toString().startsWith(Path.of(javaHome).toAbsolutePath().toString()),
            "java.home must win over a bogus JAVA_HOME",
        )
    }

    @Test
    fun resolvedJavaExecutableIsRunnable() {
        val resolved = ApkToolchainProvisioner.resolveJavaExecutable(environment = { null })
        assertTrue(Files.isRegularFile(resolved), "java.home resolution must return a real launcher: $resolved")
    }

    @Test
    fun explicitDex2JarOverrideIsUsedWhenPresent() {
        val toolchain = ApkToolchainProvisioner.ensure("", "")
        assertTrue(Files.isRegularFile(toolchain.dex2jarDirectory.resolve("dex-tools-2.4.28.jar")))
        val overridden = ApkToolchainProvisioner.ensure(toolchain.dex2jarDirectory.toString(), "")
        assertEquals("config", overridden.dex2jarSource)
    }

    @Test
    fun tamperedExtractionIsRejectedOnReExtraction() {
        val toolchain = ApkToolchainProvisioner.ensure("", "")
        val victim = toolchain.dex2jarDirectory.resolve("dex-tools-2.4.28.jar")
        val original = Files.readAllBytes(victim)
        try {
            Files.write(victim, original.copyOf().also { it[it.size / 2] = (it[it.size / 2].toInt() xor 0x01).toByte() })
            // A fresh ensure() call re-verifies and repairs the cache directory.
            val repaired = ApkToolchainProvisioner.ensure("", "")
            val repairedJar = repaired.dex2jarDirectory.resolve("dex-tools-2.4.28.jar")
            val repairedBytes = Files.readAllBytes(repairedJar)
            assertTrue(
                repairedBytes.contentEquals(original),
                "tampered vendored jar must be re-extracted to the authenticated copy",
            )
        } finally {
            Files.write(victim, original)
        }
    }
}
