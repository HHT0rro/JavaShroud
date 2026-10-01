package io.github.hht0rro.javashroud.transforms.protection

/**
 * Pre-bind validation for externally packed Qp native images. Applied to every
 * packed source (Xenolith CLI spawn, packedPath file, desktop handoff reply)
 * before [QpNativeCompilerPass.bindImageMeasurement] runs, so a packer that
 * drops a JS measurement section or a JNI bridge export fails with a named
 * diagnostic instead of a late seal error.
 *
 * Windows PE64 DLLs are checked structurally: AMD64 DLL magic, the JS
 * measurement sections the binder patches in place (.jsms HMAC slot and .jsmk
 * shard-mask rows; .jsmd is optional at bind time), and the JNI bridge export
 * names. Linux ELF64 images get a magic/machine check only; the default Linux
 * flow ships the unpacked .so and the JSIM binder rejects missing sections
 * itself.
 */
internal object PackedImageValidation {
    private const val PE_MACHINE_AMD64 = 0x8664
    private const val PE_CHARACTERISTICS_DLL = 0x2000
    private const val PE32_PLUS_MAGIC = 0x20B
    private const val PE_DOS_MAGIC = 0x5A4D
    private const val PE_OPTIONAL_DATA_DIRECTORY_OFFSET = 112
    private const val PE_COFF_SIZE = 20
    private const val PE_SECTION_HEADER_SIZE = 40
    private val JS_MEASUREMENT_SECTIONS = listOf(".jsms", ".jsmk")
    private val REQUIRED_BRIDGE_EXPORTS = listOf(
        "JNI_OnLoad",
        "JNI_OnUnload",
        "qp_r1_open_frame",
        "qp_r1_runtime_binding_digest",
    )

    private const val ELF_MAGIC = 0x7F
    private const val ELF_CLASS_64 = 2
    private const val ELF_MACHINE_X86_64 = 0x3E

    internal fun validateWindowsPackedDll(bytes: ByteArray) {
        try {
            validateWindowsPackedDllStrict(bytes)
        } catch (error: IndexOutOfBoundsException) {
            throw validationError("packed Windows image is truncated (${error.message.orEmpty()})")
        }
    }

    private fun validateWindowsPackedDllStrict(bytes: ByteArray) {
        val peOffset = requirePeHeaders(bytes)
        val coffOffset = peOffset + 4
        val machine = readLe16(bytes, coffOffset)
        if (machine != PE_MACHINE_AMD64) {
            throw validationError("packed Windows image is not AMD64 PE64 (machine=0x${machine.toString(16)})")
        }
        val characteristics = readLe16(bytes, coffOffset + 18)
        if (characteristics and PE_CHARACTERISTICS_DLL == 0) {
            throw validationError("packed Windows image is not flagged as a DLL; a wrapped executable cannot replace qp_ffi.dll")
        }
        val optionalOffset = coffOffset + PE_COFF_SIZE
        val optionalMagic = readLe16(bytes, optionalOffset)
        if (optionalMagic != PE32_PLUS_MAGIC) {
            throw validationError("packed Windows image optional header is not PE32+ (magic=0x${optionalMagic.toString(16)})")
        }
        val sectionCount = readLe16(bytes, coffOffset + 2)
        val optionalSize = readLe16(bytes, coffOffset + 16)
        val sectionTableOffset = optionalOffset + optionalSize
        val sections = parseSections(bytes, sectionTableOffset, sectionCount)

        val missingSections = JS_MEASUREMENT_SECTIONS.filterNot { name -> sections.any { it.name == name } }
        if (missingSections.isNotEmpty()) {
            throw validationError(
                "packed Windows image lost required section(s) ${missingSections.joinToString(", ")}; " +
                    "the packer must preserve the JS measurement sections (.jsms/.jsmk) byte-for-byte on disk so JSIM binding can run after packing",
            )
        }

        val exportNames = parseExportNames(bytes, optionalOffset, sections)
        val missingExports = REQUIRED_BRIDGE_EXPORTS.filterNot(exportNames::contains)
        if (missingExports.isNotEmpty()) {
            throw validationError(
                "packed Windows image lost required bridge export(s) ${missingExports.joinToString(", ")}; " +
                    "JNI_OnLoad/JNI_OnUnload and qp_r1_* exports must survive packing",
            )
        }
    }

    internal fun validateLinuxPackedSo(bytes: ByteArray) {
        if (bytes.size < 20 || bytes[0].toInt() and 0xFF != ELF_MAGIC ||
            bytes[1] != 'E'.code.toByte() || bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            throw validationError("packed Linux image is not an ELF file")
        }
        if (bytes[4].toInt() != ELF_CLASS_64) {
            throw validationError("packed Linux image is not ELF64 (class=${bytes[4]})")
        }
        val machine = readLe16(bytes, 18)
        if (machine != ELF_MACHINE_X86_64) {
            throw validationError("packed Linux image is not AMD64 ELF (machine=0x${machine.toString(16)})")
        }
    }

    private fun requirePeHeaders(bytes: ByteArray): Int {
        if (bytes.size < 64 || readLe16(bytes, 0) != PE_DOS_MAGIC) {
            throw validationError("packed Windows image has no MZ DOS header")
        }
        val peOffset = readLe32(bytes, 0x3C)
        if (peOffset <= 0 || peOffset + 4 + PE_COFF_SIZE + 4 > bytes.size) {
            throw validationError("packed Windows image PE header offset is out of bounds")
        }
        if (bytes[peOffset] != 'P'.code.toByte() || bytes[peOffset + 1] != 'E'.code.toByte() ||
            bytes[peOffset + 2] != 0.toByte() || bytes[peOffset + 3] != 0.toByte()
        ) {
            throw validationError("packed Windows image has no PE signature")
        }
        return peOffset
    }

    private data class PeSection(
        val name: String,
        val virtualAddress: Int,
        val virtualSize: Int,
        val sizeOfRawData: Int,
        val pointerToRawData: Int,
    )

    private fun parseSections(bytes: ByteArray, tableOffset: Int, count: Int): List<PeSection> {
        if (count <= 0 || count > 96) {
            throw validationError("packed Windows image section count is out of range ($count)")
        }
        if (tableOffset + count * PE_SECTION_HEADER_SIZE > bytes.size) {
            throw validationError("packed Windows image section table is truncated")
        }
        return (0 until count).map { index ->
            val header = tableOffset + index * PE_SECTION_HEADER_SIZE
            val nameBytes = bytes.copyOfRange(header, header + 8)
            val nameLength = nameBytes.indexOf(0.toByte()).takeIf { it >= 0 } ?: 8
            PeSection(
                name = String(nameBytes, 0, nameLength, Charsets.US_ASCII),
                virtualAddress = readLe32(bytes, header + 12),
                virtualSize = readLe32(bytes, header + 8),
                sizeOfRawData = readLe32(bytes, header + 16),
                pointerToRawData = readLe32(bytes, header + 20),
            )
        }
    }

    private fun parseExportNames(
        bytes: ByteArray,
        optionalOffset: Int,
        sections: List<PeSection>,
    ): Set<String> {
        if (optionalOffset + PE_OPTIONAL_DATA_DIRECTORY_OFFSET + 8 > bytes.size) {
            throw validationError("packed Windows image optional header is truncated")
        }
        val exportRva = readLe32(bytes, optionalOffset + PE_OPTIONAL_DATA_DIRECTORY_OFFSET)
        val exportSize = readLe32(bytes, optionalOffset + PE_OPTIONAL_DATA_DIRECTORY_OFFSET + 4)
        if (exportRva == 0 || exportSize == 0) {
            throw validationError("packed Windows image has no export directory; bridge exports cannot resolve")
        }
        val directory = rvaToFileOffset(exportRva, sections)
            ?: throw validationError("packed Windows image export directory RVA 0x${exportRva.toString(16)} maps to no section")
        if (directory + 40 > bytes.size) {
            throw validationError("packed Windows image export directory is truncated")
        }
        val nameCount = readLe32(bytes, directory + 24)
        val namesRva = readLe32(bytes, directory + 32)
        if (nameCount <= 0 || nameCount > 65536) {
            throw validationError("packed Windows image export name count is out of range ($nameCount)")
        }
        val namesTable = rvaToFileOffset(namesRva, sections)
            ?: throw validationError("packed Windows image export name table RVA maps to no section")
        val names = mutableSetOf<String>()
        for (index in 0 until nameCount) {
            val entryOffset = namesTable + index * 4
            if (entryOffset + 4 > bytes.size) {
                throw validationError("packed Windows image export name table is truncated")
            }
            val nameRva = readLe32(bytes, entryOffset)
            val nameOffset = rvaToFileOffset(nameRva, sections) ?: continue
            var end = nameOffset
            while (end < bytes.size && bytes[end] != 0.toByte()) end++
            if (end > nameOffset) {
                names.add(String(bytes, nameOffset, end - nameOffset, Charsets.US_ASCII))
            }
        }
        return names
    }

    private fun rvaToFileOffset(rva: Int, sections: List<PeSection>): Int? {
        for (section in sections) {
            val span = maxOf(section.virtualSize, section.sizeOfRawData)
            if (span > 0 && rva >= section.virtualAddress && rva < section.virtualAddress + span) {
                return section.pointerToRawData + (rva - section.virtualAddress)
            }
        }
        return null
    }

    private fun validationError(message: String): IllegalStateException =
        IllegalStateException("nativeshroud packed image validation failed: $message")

    private fun readLe16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)

    private fun readLe32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
}
