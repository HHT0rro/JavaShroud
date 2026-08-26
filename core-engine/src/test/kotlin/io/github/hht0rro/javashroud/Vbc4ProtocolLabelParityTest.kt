package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Vbc4ProtocolLabelParityTest {
    @Test
    fun current_kotlin_serializer_and_rust_kernel_use_identical_vbc4_magic() {
        val serializer = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt")
        val rustVm = source("src/main/rust/crates/jsrt-vm/src/lib.rs")
        assertTrue("private const val VBC4_CURRENT_MAGIC = \"VBC5\"" in serializer)
        assertTrue("pub const VBC4_MAGIC: [u8; 4] = *b\"VBC5\";" in rustVm)
        assertTrue("pub const VBC4_AUTH_TAG_SIZE: usize = 32;" in rustVm)
        val production = serializer + "\n" + rustVm
        listOf("VBCX", "inner-crypto-public-v1").forEach { stale ->
            assertFalse(stale in production, "Current production sources must not retain stale protocol label '$stale'")
        }
        assertFalse(Files.exists(resolve("src/main/native/js_vm_core.c")))
    }

    @Test
    fun vbc4_mac_trailer_is_exactly_32_bytes_without_bucket_marker() {
        val serializer = source("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt")
        val rustVm = source("src/main/rust/crates/jsrt-vm/src/lib.rs")
        assertTrue(
            serializer.contains("out.write(vbc4Hmac(payload, cryptoSeed, nonce))"),
            "Kotlin serializer must append the 32-byte HMAC directly",
        )
        assertTrue(rustVm.contains("VBC4_AUTH_TAG_SIZE: usize = 32"))
        listOf(
            "data[len - 1] == 32",
            "data[len-1] == 32",
            "len - pos == 33",
            "len-pos == 33",
            "out.write(32)",
        ).forEach { bucketMarker ->
            assertFalse(bucketMarker in serializer, "VBC4 MAC layout must not expose bucket marker '$bucketMarker'")
        }
    }

    private fun source(relativePath: String): String = Files.readString(resolve(relativePath))

    private fun resolve(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
