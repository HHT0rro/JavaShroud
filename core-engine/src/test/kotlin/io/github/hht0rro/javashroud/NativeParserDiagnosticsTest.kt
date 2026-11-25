package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeParserDiagnosticsTest {
    @Test
    fun rust_native_parser_keeps_deidentified_fail_closed_diagnostics() {
        assertFalse(Files.exists(resolveSource("src/main/native/js_vm_core.c")))
        val vm = Files.readString(resolveSource("src/main/rust/crates/qp-vm/src/lib.rs"))
        val ffi = Files.readString(resolveSource("src/main/rust/crates/qp-ffi/src/lib.rs"))
        assertTrue(vm.contains("qp_magic") || vm.contains("derived_vm_magic"))
        assertTrue(vm.contains("AuthenticationFailed") || vm.contains("InvalidRow"))
        assertFalse(ffi.contains("build_seed"))

        // Decrypted data may be processed locally. Native validation errors must carry fixed diagnostics.
        val tokenOpen = ffi.substringAfter("fn open_target_token(", "").substringBefore("unsafe fn get_method_id(")
        for ((operation, diagnostic) in listOf(
            "plaintext_result" to "Qp target token authentication failed",
            "SensitiveMemoryLease::new(plaintext)" to "Qp target token plaintext lease is invalid",
        )) {
            val rejection = Regex(
                Regex.escape(operation) + """\s*\.map_err\(\|_\|\s*""" +
                    Regex.escape("""BridgeFailure("$diagnostic")""") + """\)\?;""",
            )
            assertTrue(rejection.containsMatchIn(tokenOpen), "Token rejection must emit only: $diagnostic")
        }
        val invoke = ffi.substringAfter("fn native_invoke_site(", "").substringBefore("fn native_execute_vm_page(")
        assertTrue(
            Regex("""if !exception_pending\(env\)\s*\{\s*throw_new\(env, failure\.0\.as_bytes\(\)\);\s*}\s*core::ptr::null_mut\(\)""")
                .containsMatchIn(invoke),
            "Native target validation failure must throw and return no value",
        )
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
