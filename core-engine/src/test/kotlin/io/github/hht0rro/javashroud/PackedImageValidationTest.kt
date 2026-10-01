package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.PackedImageValidation
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PackedImageValidationTest {
    @Test
    fun synthetic_packed_dll_passes_validation() {
        PackedImageValidation.validateWindowsPackedDll(SyntheticPackedImages.windowsPackedDll())
        PackedImageValidation.validateLinuxPackedSo(SyntheticPackedImages.linuxPackedSo())
    }

    @Test
    fun missing_js_measurement_section_is_a_named_failure() {
        for (section in listOf(".jsms", ".jsmk")) {
            val error = assertFailsWith<IllegalStateException> {
                PackedImageValidation.validateWindowsPackedDll(
                    SyntheticPackedImages.windowsPackedDll(dropSection = section),
                )
            }
            assertTrue(error.message.orEmpty().contains(section), "expected $section in: ${error.message}")
        }
    }

    @Test
    fun missing_optional_jsmd_section_still_passes_validation() {
        // .jsmd is optional at JSIM bind time; a packer may not carry it.
        PackedImageValidation.validateWindowsPackedDll(
            SyntheticPackedImages.windowsPackedDll(dropSection = ".jsmd"),
        )
    }

    @Test
    fun missing_bridge_export_is_a_named_failure() {
        val error = assertFailsWith<IllegalStateException> {
            PackedImageValidation.validateWindowsPackedDll(
                SyntheticPackedImages.windowsPackedDll(dropExport = "JNI_OnLoad"),
            )
        }
        assertTrue(error.message.orEmpty().contains("JNI_OnLoad"))
        val qpError = assertFailsWith<IllegalStateException> {
            PackedImageValidation.validateWindowsPackedDll(
                SyntheticPackedImages.windowsPackedDll(dropExport = "qp_r1_runtime_binding_digest"),
            )
        }
        assertTrue(qpError.message.orEmpty().contains("qp_r1_runtime_binding_digest"))
    }

    @Test
    fun non_dll_or_non_pe_images_are_named_failures() {
        val exeError = assertFailsWith<IllegalStateException> {
            PackedImageValidation.validateWindowsPackedDll(
                SyntheticPackedImages.windowsPackedDll(plainExeCharacteristics = true),
            )
        }
        assertTrue(exeError.message.orEmpty().contains("not flagged as a DLL"))

        val garbageError = assertFailsWith<IllegalStateException> {
            PackedImageValidation.validateWindowsPackedDll(ByteArray(64) { 0x41 })
        }
        assertTrue(garbageError.message.orEmpty().contains("MZ"))

        val truncatedError = assertFailsWith<IllegalStateException> {
            PackedImageValidation.validateWindowsPackedDll(
                SyntheticPackedImages.windowsPackedDll().copyOfRange(0, 0x200),
            )
        }
        assertTrue(truncatedError.message.orEmpty().contains("truncated") || truncatedError.message.orEmpty().contains("bounds"))
    }

    @Test
    fun malformed_elf_is_a_named_failure() {
        val notElf = ByteArray(64) { 0x42 }
        val error = assertFailsWith<IllegalStateException> {
            PackedImageValidation.validateLinuxPackedSo(notElf)
        }
        assertTrue(error.message.orEmpty().contains("ELF"))

        val elf32 = SyntheticPackedImages.linuxPackedSo().also { it[4] = 1 }
        val classError = assertFailsWith<IllegalStateException> {
            PackedImageValidation.validateLinuxPackedSo(elf32)
        }
        assertTrue(classError.message.orEmpty().contains("ELF64"))
    }
}
