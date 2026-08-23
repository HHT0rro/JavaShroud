package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeRuntimeMultiPageDifferentialTest {
    @Test
    fun c_crypto_benchmark_probe_is_retired_in_favor_of_rust_crypto() {
        assertFalse(Files.exists(resolveSource("src/main/native")))
        assertFalse(Files.exists(resolveSource("src/test/native/native_runtime_benchmark.c")))
        val crypto = Files.readString(resolveSource("src/main/rust/crates/jsrt-crypto/src/lib.rs"))
        assertTrue(crypto.contains("aes256_gcm_decrypt"))
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
