package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativePeLoaderAlignmentTest {

    @Test
    fun windows_pe_loader_copies_unaligned_input_headers_before_field_access() {
        val source = Files.readString(resolveSource("src/main/native/js_shell_loader_pe.c"))
        val loader = source.substringAfter("int js_shell_load_inner_image")

        assertTrue(loader.contains("IMAGE_DOS_HEADER dos;"))
        assertTrue(loader.contains("memcpy(&dos, bytes, sizeof(dos));"))
        assertTrue(loader.contains("js_shell_pe_headers headers;"))
        assertTrue(loader.contains("memcpy(&headers.nt, bytes + dos.e_lfanew, sizeof(headers.nt));"))
        assertTrue(loader.contains("headers.sections,"))
        assertTrue(loader.contains("const IMAGE_NT_HEADERS64 *nt_src = &headers.nt;"))
        assertFalse(loader.contains("(const IMAGE_DOS_HEADER *)bytes"))
        assertFalse(loader.contains("(const IMAGE_NT_HEADERS64 *)(bytes +"))
    }

    @Test
    fun windows_pe_loader_uses_copy_based_access_for_unaligned_metadata_tables() {
        val source = Files.readString(resolveSource("src/main/native/js_shell_loader_pe.c"))

        assertTrue(source.contains("static DWORD js_shell_read_dword(const void *source)"))
        assertTrue(source.contains("static uintptr_t js_shell_read_uintptr(const void *source)"))
        assertTrue(source.contains("js_shell_write_uintptr(slot, js_shell_read_uintptr(slot) + delta);"))
        assertTrue(source.contains("memcpy(&desc, desc_bytes, sizeof(desc));"))
        assertTrue(source.contains("memcpy(&tls, tls_bytes, sizeof(tls));"))
        assertTrue(source.contains("memcpy(&exports, export_bytes, sizeof(exports));"))
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
