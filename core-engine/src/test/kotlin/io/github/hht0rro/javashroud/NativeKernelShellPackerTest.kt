package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse

class NativeKernelShellPackerTest {
    @Test
    fun retired_packing_identity_files_are_gone() {
        assertFalse(Files.exists(workspacePath(
            "core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeKernelShellPacker.kt",
        )))
        assertFalse(Files.exists(workspacePath(
            "core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/QpPackingLevel.kt",
        )))
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
