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
        val retiredProbe = ascii("616b656e5f706167655f617574685f646966666572656e7469616c5f70726f62652e63")
        assertFalse(Files.exists(resolveSource("src/test/native/$retiredProbe")))
        val page = Files.readString(resolveSource("src/main/rust/crates/qp-page/src/lib.rs"))
        assertTrue(page.contains("AuthenticationFailed") || page.contains("authenticate"))
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }

    private fun ascii(hex: String): String = ByteArray(hex.length / 2) { index ->
        hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }.toString(Charsets.US_ASCII)
}
