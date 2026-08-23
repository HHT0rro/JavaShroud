package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeParserDiagnosticsTest {
    @Test
    fun rust_vbc4_parser_keeps_deidentified_fail_closed_diagnostics() {
        assertFalse(Files.exists(resolveSource("src/main/native/js_vm_core.c")))
        val vm = Files.readString(resolveSource("src/main/rust/crates/jsrt-vm/src/lib.rs"))
        val ffi = Files.readString(resolveSource("src/main/rust/crates/jsrt-ffi/src/lib.rs"))
        assertTrue(vm.contains("VBC4_MAGIC"))
        assertTrue(vm.contains("AuthenticationFailed") || vm.contains("InvalidRow"))
        assertFalse(ffi.contains("build_seed"))
        assertFalse(ffi.contains("plaintext"))
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
