package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JsShellCryptoGcmTest {
    @Test
    fun retired_shell_source_contains_no_runnable_packer_or_payload_surface() {
        val packer = workspacePath(
            "core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeKernelShellPacker.kt",
        )
        val packingLevel = workspacePath(
            "core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpPackingLevel.kt",
        )
        assertFalse(Files.exists(packer), "retired NativeKernelShellPacker must stay deleted")
        assertFalse(Files.exists(packingLevel), "retired QpPackingLevel must stay deleted")
        val source = Files.readString(workspacePath(
            "core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeShroudPacker.kt",
        ))
        assertTrue(source.contains("External packing handoff"))
        // External Xenolith CLI spawn is the sanctioned contract; the engine must
        // never auto-discover a packer on its own — cliPath is explicit only.
        assertFalse(source.contains("defaultSiblingCli"))
        for (retiredMarker in listOf(
            "nativeshroud-pack",
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
            if (Files.exists(current.resolve("settings.gradle.kts")) ||
                Files.exists(current.resolve("core-engine/src/main/rust/Cargo.toml"))
            ) {
                return candidate
            }
            current = current.parent ?: return Path.of("").toAbsolutePath().resolve(relative)
        }
    }
}
