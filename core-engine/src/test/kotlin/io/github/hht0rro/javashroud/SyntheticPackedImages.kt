package io.github.hht0rro.javashroud

import java.io.ByteArrayOutputStream

/**
 * Synthetic packed native images for nativeshroud tests: minimal but
 * structurally valid PE64 DLL / ELF64 SO shapes that satisfy
 * [io.github.hht0rro.javashroud.transforms.protection.PackedImageValidation].
 */
internal object SyntheticPackedImages {
    private val BRIDGE_EXPORTS = listOf(
        "JNI_OnLoad",
        "JNI_OnUnload",
        "qp_r1_open_frame",
        "qp_r1_runtime_binding_digest",
    )

    internal fun windowsPackedDll(
        dropSection: String? = null,
        dropExport: String? = null,
        plainExeCharacteristics: Boolean = false,
    ): ByteArray {
        val exportNames = if (dropExport == null) BRIDGE_EXPORTS else BRIDGE_EXPORTS - dropExport
        val strings = exportNames.joinToString("") { "$it\u0000" }.toByteArray(Charsets.US_ASCII)
        val namesArraySize = exportNames.size * 4
        val exportDirSize = 40
        val edataSize = exportDirSize + namesArraySize + strings.size

        val peOffset = 0x80
        val optionalSize = 0xF0
        val sectionCount = 4
        val sectionTableOffset = peOffset + 4 + 20 + optionalSize
        val dataOffset = sectionTableOffset + sectionCount * 40
        val jsSize = 16
        val js1Offset = dataOffset + edataSize
        val js2Offset = js1Offset + jsSize
        val js3Offset = js2Offset + jsSize
        val totalSize = js3Offset + jsSize

        val out = ByteArrayOutputStream()
        fun byte(value: Int) = out.write(value and 0xFF)
        fun bytes(value: ByteArray) = out.write(value)
        fun pad(count: Int) = repeat(count) { byte(0) }
        fun le16(value: Int) {
            byte(value)
            byte(value ushr 8)
        }
        fun le32(value: Int) {
            le16(value and 0xFFFF)
            le16((value ushr 16) and 0xFFFF)
        }

        // DOS header
        byte('M'.code)
        byte('Z'.code)
        pad(0x3A)
        le32(peOffset)
        pad(peOffset - 0x40)

        // PE signature + COFF header
        byte('P'.code)
        byte('E'.code)
        byte(0)
        byte(0)
        le16(0x8664)
        le16(sectionCount)
        le32(0)
        le32(0)
        le32(0)
        le16(optionalSize)
        le16(if (plainExeCharacteristics) 0x0002 else 0x2022)

        // PE32+ optional header
        le16(0x20B)
        pad(106)
        le32(16)
        le32(0x1000)
        le32(edataSize)
        pad(optionalSize - 120)

        fun sectionHeader(name: String, virtualAddress: Int, pointerToRawData: Int, sizeOfRawData: Int, named: Boolean = true) {
            val nameBytes = if (named) name.toByteArray(Charsets.US_ASCII) else ByteArray(0)
            bytes(nameBytes)
            pad(8 - nameBytes.size)
            le32(sizeOfRawData)
            le32(virtualAddress)
            le32(sizeOfRawData)
            le32(pointerToRawData)
            pad(16)
        }
        sectionHeader(".edata", 0x1000, dataOffset, edataSize)
        sectionHeader(".jsms", 0x2000, js1Offset, jsSize, named = dropSection != ".jsms")
        sectionHeader(".jsmk", 0x3000, js2Offset, jsSize, named = dropSection != ".jsmk")
        sectionHeader(".jsmd", 0x4000, js3Offset, jsSize, named = dropSection != ".jsmd")

        // .edata: export directory + name RVAs + names
        le32(0)
        le32(0)
        le16(0)
        le16(0)
        le32(0x999)
        le32(0x999)
        le32(exportNames.size)
        le32(exportNames.size)
        le32(0x999)
        le32(0x1000 + exportDirSize)
        le32(0x999)
        var nameRva = 0x1000 + exportDirSize + namesArraySize
        exportNames.forEach { name ->
            le32(nameRva)
            nameRva += name.length + 1
        }
        bytes(strings)

        pad(js1Offset - out.size())
        pad(jsSize)
        pad(jsSize)
        pad(jsSize)
        check(out.size() == totalSize) { "synthetic PE fixture size mismatch: ${out.size()} != $totalSize" }
        return out.toByteArray()
    }

    internal fun linuxPackedSo(): ByteArray {
        val bytes = ByteArray(64)
        bytes[0] = 0x7F
        bytes[1] = 'E'.code.toByte()
        bytes[2] = 'L'.code.toByte()
        bytes[3] = 'F'.code.toByte()
        bytes[4] = 2
        bytes[5] = 1
        bytes[6] = 1
        bytes[16] = 3
        bytes[17] = 0
        bytes[18] = 0x3E
        bytes[19] = 0
        return bytes
    }
}
