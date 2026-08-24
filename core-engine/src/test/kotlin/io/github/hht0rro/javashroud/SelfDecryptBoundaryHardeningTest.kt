package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SelfDecryptBoundaryHardeningTest {
    @Test
    fun current_format_boundary_is_the_typed_unified_native_route() {
        val kernelHelper = source("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java")
        val ffi = source("src/main/rust/crates/jsrt-ffi/src/lib.rs")

        for (entry in listOf(
            "nativeExecuteAkenVmPage",
            "nativeOpenAkenString",
            "nativeInitializeDefense",
            "nativeProbeDefense",
            "nativeTransformDefense",
        )) {
            assertTrue(entry in kernelHelper, "Current JNI helper must declare $entry")
            assertTrue(entry in ffi, "Rust FFI must register $entry")
        }
        assertTrue("RegisterNatives" in ffi, "Current runtime must use typed RegisterNatives registration")
        assertFalse("jsn_k14" in ffi, "Retired native bridge identifiers must not survive")
        assertFalse(Files.exists(resolveSource("src/main/native/js_vm_core.c")))
    }

    private fun source(relative: String): String = Files.readString(resolveSource(relative))

    private fun resolveSource(relative: String): Path {
        val direct = Path.of(relative)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relative)
    }
}
