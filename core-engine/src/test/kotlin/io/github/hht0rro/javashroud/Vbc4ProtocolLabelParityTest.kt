package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Vbc4ProtocolLabelParityTest {
    @Test
    fun current_kotlin_serializer_and_native_kernel_use_identical_vbc4_domains() {
        val serializer = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt")
        val innerMaterial = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/AkenVbc4InnerMaterial.kt")
        val nativeCore = source("src/main/native/js_vm_core.c")
        val nativeSymbols = source("src/main/native/js_vm_symbol.c")

        val sharedDomains = listOf(
            "javashroud-aken-v4-vbc4-inner-crypto-v2" to (innerMaterial to nativeCore),
            "javashroud-vbc4-cp-string-key-v2" to (serializer to nativeSymbols),
            "javashroud-vbc4-cp-string-iv-v2" to (serializer to nativeSymbols),
            "javashroud-vbc4-cp-string-tag-v2" to (serializer to nativeSymbols),
        )
        sharedDomains.forEach { (domain, pair) ->
            assertTrue(domain in pair.first, "Kotlin production material is missing current domain '$domain'")
            assertTrue(domain in pair.second, "Native production kernel is missing current domain '$domain'")
        }

        val production = listOf(serializer, innerMaterial, nativeCore, nativeSymbols).joinToString("\n")
        listOf(
            "VBCX",
            "inner-crypto-public-v1",
            "\"cp-string-key\"",
            "\"cp-string-iv\"",
            "\"cp-string-tag\"",
        ).forEach { stale ->
            assertFalse(stale in production, "Current production sources must not retain stale protocol label '$stale'")
        }
        assertTrue("private const val VBC4_CURRENT_MAGIC = \"VBC4\"" in serializer)
        assertTrue(
            nativeCore.contains("uint32_t magic = ((uint32_t)data[0] << 24)") &&
                nativeCore.contains("if (magic != 0x56424334u) JS_VM_PARSE_FAIL"),
            "Native parser must recognize the same VBC4 magic emitted by Kotlin",
        )
    }

    @Test
    fun vbc4_mac_trailer_is_exactly_32_bytes_without_bucket_marker() {
        val serializer = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt")
        val nativeCore = source("src/main/native/js_vm_core.c")
        assertTrue(
            serializer.contains("out.write(vbc4Hmac(payload, cryptoSeed, nonce))"),
            "Kotlin serializer must append the 32-byte HMAC directly",
        )
        assertTrue(
            nativeCore.contains("if (len - pos != 32) JS_VM_PARSE_FAIL") &&
                nativeCore.contains("data + len - 32"),
            "Native parser must consume exactly the direct 32-byte HMAC trailer",
        )
        val production = serializer + "\n" + nativeCore
        listOf(
            "data[len - 1] == 32",
            "data[len-1] == 32",
            "len - pos == 33",
            "len-pos == 33",
            "out.write(32)",
        ).forEach { bucketMarker ->
            assertFalse(bucketMarker in production, "VBC4 MAC layout must not expose bucket marker '$bucketMarker'")
        }
    }

    private fun source(relativePath: String): String {
        val direct = Path.of(relativePath)
        val path = if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
        return Files.readString(path)
    }
}
