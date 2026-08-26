package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.emptyTestArtifact
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.FinalNativeBinding
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.RuntimeBindingDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenR1CatalogSidecarTest {
    @Test
    fun attach_accepts_nonzero_binding_and_skips_without_layout() {
        val binding = FinalNativeBinding(
            nativeSha256 = ByteArray(32) { (it + 1).toByte() },
            abiDigest = ByteArray(32) { (it + 33).toByte() },
            targetTriple = RuntimeBindingDigest.TARGET_WINDOWS_GNU,
            specializationDigest = ByteArray(32) { (it + 65).toByte() },
            payloadProfile = "aken-r1-rust-ffi-v1",
        )
        try {
            assertTrue(binding.nativeSha256.any { it != 0.toByte() })
            assertTrue(binding.abiDigest.any { it != 0.toByte() })
            assertTrue(binding.specializationDigest.any { it != 0.toByte() })
            assertEquals("aken-r1-rust-ffi-v1", binding.payloadProfile)
            val artifact = emptyTestArtifact()
            val result = attachAkenR1CatalogSidecar(artifact, binding)
            assertFalse(result.jarEntries.any { it.name == "META-INF/jsrt/catalog.index" })
            assertEquals(artifact.jarEntries, result.jarEntries)
        } finally {
            binding.wipe()
        }
    }
}
