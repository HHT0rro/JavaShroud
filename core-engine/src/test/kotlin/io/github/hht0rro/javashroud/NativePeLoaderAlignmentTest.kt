package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativePeLoaderAlignmentTest {
    @Test
    fun rust_pe_and_elf_parsers_copy_bounded_headers_without_c_overlays() {
        val pe = Files.readString(resolveSource("src/main/rust/crates/jsrt-shell/src/pe.rs"))
        val elf = Files.readString(resolveSource("src/main/rust/crates/jsrt-shell/src/elf.rs"))
        assertTrue(pe.contains("pub fn parse(bytes: &[u8])"))
        assertTrue(elf.contains("pub fn parse(bytes: &[u8])"))
        assertFalse(pe.contains("(const IMAGE_DOS_HEADER *)"))
        assertFalse(elf.contains("mmap("))
        assertFalse(Files.exists(resolveSource("src/main/native/js_shell_loader_pe.c")))
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
