package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse

class NativeProtectedSectionPackerTest {
    @Test
    fun retired_section_packer_source_is_removed_from_the_production_tree() {
        val root = workspaceRoot()
        assertFalse(
            Files.exists(root.resolve("core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeProtectedSectionPacker.kt")),
            "the retired native section packer must not remain as a production Kotlin source",
        )
    }

    private fun workspaceRoot(): Path {
        var current = Path.of("").toAbsolutePath()
        while (!Files.isDirectory(current.resolve("core-engine")) && current.parent != null) {
            current = current.parent
        }
        return current
    }
}
