package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeRuntimeJniCacheProductionBenchmarkTest {
    @Test
    fun c_jni_cache_probe_is_retired_in_favor_of_the_rust_runtime() {
        assertFalse(Files.exists(resolveSource("src/main/native")))
        assertFalse(Files.exists(resolveSource("src/test/native/jni_cache_production_benchmark_probe.c")))
        val ffi = Files.readString(resolveSource("src/main/rust/crates/jsrt-ffi/src/lib.rs"))
        assertTrue(ffi.contains("RegisterNatives"))
        assertTrue(ffi.contains("JNI_OnLoad"))
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
