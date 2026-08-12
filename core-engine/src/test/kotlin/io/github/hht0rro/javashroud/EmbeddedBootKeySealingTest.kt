package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.BootKekSidecar
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class EmbeddedBootKeySealingTest {
    @Test
    fun embedded_boot_kek_path_is_randomized_and_rewritten_in_runtime_helper() {
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        val helperBytes = requireNotNull(javaClass.classLoader.getResourceAsStream("$helperName.class")).use { it.readBytes() }
        val embeddedBytes = "0123456789abcdef".repeat(4).toByteArray(Charsets.US_ASCII)
        val helperArtifact = testClassArtifact(internalName = helperName, bytes = helperBytes)
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(helperArtifact),
            jarEntries = listOf(
                JarEntryData(helperArtifact.entryName, helperBytes),
                JarEntryData(BootKekSidecar.EMBEDDED_RESOURCE_PATH, embeddedBytes),
            ),
        )

        val sealed = withVbc4BuildContext(defaultVbc4BuildContext()) {
            RuntimeArtifactSealing.seal(artifact, seed = 0x454D4245444C, rewritesVmRuntime = false)
        }

        assertFalse(sealed.jarEntries.any { it.name == BootKekSidecar.EMBEDDED_RESOURCE_PATH })
        val embeddedEntry = sealed.jarEntries.singleOrNull { it.bytes.contentEquals(embeddedBytes) }
        assertNotNull(embeddedEntry)
        assertNotEquals(BootKekSidecar.EMBEDDED_RESOURCE_PATH, embeddedEntry.name)
        assertFalse(embeddedEntry.name.contains("boot", ignoreCase = true))
        assertFalse(embeddedEntry.name.contains("kek", ignoreCase = true))

        val rewrittenHelper = sealed.classArtifacts.single { it.summary.internalName.startsWith("r/") }
        val helperText = String(rewrittenHelper.bytes, Charsets.ISO_8859_1)
        assertFalse(helperText.contains(BootKekSidecar.EMBEDDED_RESOURCE_PATH))
        assertTrue(helperText.contains(embeddedEntry.name))
    }

    @Test
    fun embedded_boot_kek_is_renamed_even_without_helper_classes() {
        val embeddedBytes = "0123456789abcdef".repeat(4).toByteArray(Charsets.US_ASCII)
        val artifact = testAttachedArtifact(
            classArtifacts = emptyList(),
            jarEntries = listOf(JarEntryData(BootKekSidecar.EMBEDDED_RESOURCE_PATH, embeddedBytes)),
        )

        val sealed = withVbc4BuildContext(defaultVbc4BuildContext()) {
            RuntimeArtifactSealing.seal(artifact, seed = 0x454D4245444C, rewritesVmRuntime = false)
        }

        assertFalse(sealed.jarEntries.any { it.name == BootKekSidecar.EMBEDDED_RESOURCE_PATH })
        val embeddedEntry = sealed.jarEntries.singleOrNull { it.bytes.contentEquals(embeddedBytes) }
        assertNotNull(embeddedEntry)
        assertFalse(embeddedEntry.name.contains("boot", ignoreCase = true))
        assertFalse(embeddedEntry.name.contains("kek", ignoreCase = true))
    }
}
