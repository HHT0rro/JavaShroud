package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EmbeddedBootKeySealingTest {
    @Test
    fun sealing_discards_legacy_boot_resources_instead_of_renaming_them() {
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        val helperBytes = requireNotNull(javaClass.classLoader.getResourceAsStream("$helperName.class")).use { it.readBytes() }
        val bootMaterial = "retired-jsbm-v3-material".toByteArray(Charsets.US_ASCII)
        val bootKek = "retired-jsbk1-sidecar".toByteArray(Charsets.US_ASCII)
        val helperArtifact = testClassArtifact(internalName = helperName, bytes = helperBytes)
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(helperArtifact),
            jarEntries = listOf(
                JarEntryData(helperArtifact.entryName, helperBytes),
                JarEntryData("META-INF/.r/boot.dat", bootMaterial),
                JarEntryData("META-INF/.r/kek.dat", bootKek),
            ),
        )

        val sealed = withVbc4BuildContext(defaultVbc4BuildContext()) {
            RuntimeArtifactSealing.seal(artifact, seed = 0x454D4245444C, rewritesVmRuntime = false)
        }

        assertFalse(sealed.jarEntries.any { it.name == "META-INF/.r/boot.dat" })
        assertFalse(sealed.jarEntries.any { it.name == "META-INF/.r/kek.dat" })
        assertFalse(sealed.jarEntries.any { it.bytes.contentEquals(bootMaterial) })
        assertFalse(sealed.jarEntries.any { it.bytes.contentEquals(bootKek) })
    }

    @Test
    fun sealing_discards_legacy_boot_resources_on_the_otherwise_fast_path() {
        val artifact = testAttachedArtifact(
            classArtifacts = emptyList(),
            jarEntries = listOf(
                JarEntryData("META-INF/.r/boot.dat", "legacy-envelope".toByteArray(Charsets.US_ASCII)),
                JarEntryData("META-INF/.r/kek.dat", "legacy-sidecar".toByteArray(Charsets.US_ASCII)),
            ),
        )

        val sealed = withVbc4BuildContext(defaultVbc4BuildContext()) {
            RuntimeArtifactSealing.seal(artifact, seed = 0x454D4245444C, rewritesVmRuntime = false)
        }

        assertTrue(sealed.jarEntries.isEmpty())
    }
}
