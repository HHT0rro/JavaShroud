package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeRuntimeMultiPageAuthDifferentialTest {
    @Test
    fun c_page_auth_probe_is_retired_in_favor_of_rust_page_authentication() {
        assertFalse(Files.exists(resolveSource("src/main/native")))
        assertFalse(Files.exists(resolveSource("src/test/native/aken_page_auth_differential_probe.c")))
        val page = Files.readString(resolveSource("src/main/rust/crates/jsrt-page/src/lib.rs"))
        assertTrue(page.contains("AuthenticationFailed") || page.contains("authenticate"))
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
