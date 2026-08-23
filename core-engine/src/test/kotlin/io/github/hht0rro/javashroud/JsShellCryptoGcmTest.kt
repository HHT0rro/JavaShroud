package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JsShellCryptoGcmTest {
    @Test
    fun retired_shell_source_contains_no_runnable_packer_or_payload_surface() {
        val source = Files.readString(workspacePath(
            "core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeKernelShellPacker.kt",
        ))

        assertTrue(source.contains("performs no"))
        assertTrue(source.contains("packing, loading,"))
        assertTrue(source.contains("extraction, or fallback"))
        for (retiredMarker in listOf(
            "fun pack(",
            "MAX_PAYLOAD",
            "buildMaxPayloadBundle",
            "renderMaxPayloadHeader",
            "JAVASHROUD_BOOT_SECRET",
            "META-INF/js-native",
            ".dylib",
        )) {
            assertFalse(source.contains(retiredMarker), "retired shell surface leaked: $retiredMarker")
        }
    }

    private fun workspacePath(relative: String): Path {
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val candidate = current.resolve(relative)
            if (Files.exists(candidate)) return candidate
            current = current.parent ?: break
        }
        error("Unable to locate workspace file: $relative")
    }
}
