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
    fun all_input_measurement_sections_must_survive_byte_identical() {
        val original = SyntheticPackedImages.windowsPackedDll()
        PackedImageValidation.validateWindowsPackedDll(original.copyOf(), original)
        val table = 0x80 + 4 + 20 + 0xF0
        fun readLe32(bytes: ByteArray, offset: Int): Int =
            (bytes[offset].toInt() and 255) or ((bytes[offset + 1].toInt() and 255) shl 8) or
                ((bytes[offset + 2].toInt() and 255) shl 16) or ((bytes[offset + 3].toInt() and 255) shl 24)
        for ((index, section) in listOf(".jsms", ".jsmk", ".jsmd").withIndex()) {
            val header = table + (index + 1) * 40
            val rawOffset = readLe32(original, header + 20)
            val changed = original.copyOf().also { it[rawOffset] = 1 }
            val error = assertFailsWith<IllegalStateException> {
                PackedImageValidation.validateWindowsPackedDll(changed, original)
            }
            assertTrue(error.message.orEmpty().contains(section) && error.message.orEmpty().contains("raw bytes"))
        }
        val dropped = assertFailsWith<IllegalStateException> {
            PackedImageValidation.validateWindowsPackedDll(SyntheticPackedImages.windowsPackedDll(dropSection = ".jsmd"), original)
        }
        assertTrue(dropped.message.orEmpty().contains(".jsmd"))
        val withoutDialect = SyntheticPackedImages.windowsPackedDll(dropSection = ".jsmd")
        PackedImageValidation.validateWindowsPackedDll(withoutDialect.copyOf(), withoutDialect)
    }

    @Test
    fun measurement_sections_can_move_on_disk_but_not_change_rva_or_size() {
        val original = SyntheticPackedImages.windowsPackedDll()
        val table = 0x80 + 4 + 20 + 0xF0
        val moved = original.copyOf(original.size + 64)
        fun writeLe32(offset: Int, value: Int) {
            repeat(4) { moved[offset + it] = (value ushr (it * 8)).toByte() }
        }
        for (index in 1..3) {
            writeLe32(table + index * 40 + 20, original.size + (index - 1) * 16)
        }
        PackedImageValidation.validateWindowsPackedDll(moved, original)
        writeLe32(table + 40 + 12, 0x5000)
        val error = assertFailsWith<IllegalStateException> {
            PackedImageValidation.validateWindowsPackedDll(moved, original)
        }
        assertTrue(error.message.orEmpty().contains(".jsms") && error.message.orEmpty().contains("RVA or size"))
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
