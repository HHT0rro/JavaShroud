package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.emptyTestArtifact
import io.github.hht0rro.javashroud.transforms.protection.qp.catalog.FinalRuntimeBinding
import io.github.hht0rro.javashroud.transforms.protection.qp.catalog.RuntimeBindingDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpCatalogEmitterTest {
    @Test
    fun attach_accepts_nonzero_binding_and_skips_without_layout() {
        val binding = FinalRuntimeBinding(
            nativeSha256 = ByteArray(32) { (it + 1).toByte() },
            abiDigest = ByteArray(32) { (it + 33).toByte() },
            targetTriple = RuntimeBindingDigest.TARGET_WINDOWS_GNU,
            specializationDigest = ByteArray(32) { (it + 65).toByte() },
            payloadProfile = "qp-rust-ffi-v1",
        )
        try {
            assertTrue(binding.nativeSha256.any { it != 0.toByte() })
            assertTrue(binding.abiDigest.any { it != 0.toByte() })
            assertTrue(binding.specializationDigest.any { it != 0.toByte() })
            assertEquals("qp-rust-ffi-v1", binding.payloadProfile)
            val artifact = emptyTestArtifact()
            val result = attachQpCatalogEmitter(artifact, binding)
            assertFalse(result.jarEntries.any { it.name.endsWith("/catalog.index") })
            assertEquals(artifact.jarEntries, result.jarEntries)
        } finally {
            binding.wipe()
        }
    }

    @Test
    fun catalog_index_records_are_fixed_length_and_pathless() {
        val records = listOf(
            catalogIndexRecord(CATALOG_INDEX_KIND_BUNDLE, CATALOG_INDEX_PLATFORM_NONE, "bundleTok"),
            catalogIndexRecord(CATALOG_INDEX_KIND_DIRECTORY, CATALOG_INDEX_PLATFORM_NONE, "dirToken1"),
            catalogIndexRecord(CATALOG_INDEX_KIND_PACK, CATALOG_INDEX_PLATFORM_WINDOWS, "pk0123456789ab"),
        )
        val encoded = encodeCatalogIndex(records)
        assertEquals(0x6C, encoded[0].toInt() and 0xFF)
        assertEquals(1, encoded[1].toInt())
        assertFalse(encoded.decodeToString().contains("META-INF/"))
        assertFalse(encoded.decodeToString().contains("pack|"))
        val decoded = decodeCatalogIndex(encoded)
        assertEquals(3, decoded.size)
        assertEquals("bundleTok", decoded[0].token)
        assertEquals("dirToken1", decoded[1].token)
        assertEquals("windows-x64", catalogIndexPlatformKey(decoded[2].platform))
        assertEquals("pk0123456789ab", decoded[2].token)
    }
}
