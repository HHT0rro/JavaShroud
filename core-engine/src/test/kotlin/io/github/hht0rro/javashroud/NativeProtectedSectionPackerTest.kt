package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeProtectedSectionPacker
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

/**
 * Item #4 contract: the build-time native patcher must (a) encrypt the ".jsx"
 * protected code section in place, (b) flip the in-binary seal marker so the load-time
 * constructor knows to decrypt, and (c) fail open (return the input unchanged) when
 * the section/marker is absent or relocations overlap the protected section. The
 * keystream must match the C decrypt path (block i = SHA-256(key || le32(i))), so
 * XOR-ing twice restores the plaintext.
 */
class NativeProtectedSectionPackerTest {
    private val sealMagic = byteArrayOf(0x4A, 0x53, 0x58, 0x53, 0x45, 0x41, 0x4C, 0x31)

    @Test
    fun seals_pe_jsx_section_and_flips_marker_with_reversible_keystream() {
        val key = ByteArray(32) { (it * 7 + 3).toByte() }
        val jsxPlain = ByteArray(0x80) { (it * 13 + 5).toByte() }
        val pe = MinimalPe.build(jsxPlain)
        val sealed = NativeProtectedSectionPacker.sealIfPossible(pe.bytes, key)

        assertFalse(sealed.contentEquals(pe.bytes), "Sealing must modify the binary")
        assertEquals(1, readLe32(sealed, pe.markerStateOffset), "Seal marker state must be set to 1")
        assertEquals(pe.jsxRva, readLe32(sealed, pe.markerStateOffset + 4), "PE marker must record .jsx RVA")
        assertEquals(jsxPlain.size, readLe32(sealed, pe.markerStateOffset + 8), "PE marker must record encrypted length")
        val sealedBody = sealed.copyOfRange(pe.jsxRawPtr, pe.jsxRawPtr + jsxPlain.size)
        assertFalse(sealedBody.contentEquals(jsxPlain), "Protected section body must be encrypted")
        val recovered = sealedBody.copyOf()
        xorKeystream(recovered, key)
        assertTrue(recovered.contentEquals(jsxPlain), "Keystream must be reversible and match the C decrypt path")
    }

    @Test
    fun seals_elf64_jsx_section_records_runtime_bounds_and_uses_reversible_keystream() {
        val key = ByteArray(32) { (it * 11 + 1).toByte() }
        val jsxPlain = ByteArray(0x70) { (it * 17 + 9).toByte() }
        val elf = MinimalElf64.build(jsxPlain)
        val sealed = NativeProtectedSectionPacker.sealIfPossible(elf.bytes, key)

        assertFalse(sealed.contentEquals(elf.bytes), "ELF64 sealing must modify the binary")
        assertEquals(1, readLe32(sealed, elf.markerStateOffset), "ELF seal marker state must be set to 1")
        assertEquals(elf.jsxAddress.toInt(), readLe32(sealed, elf.markerStateOffset + 4), "ELF marker must record .jsx RVA")
        assertEquals(jsxPlain.size, readLe32(sealed, elf.markerStateOffset + 8), "ELF marker must record encrypted length")
        val sealedBody = sealed.copyOfRange(elf.jsxRawPtr, elf.jsxRawPtr + jsxPlain.size)
        assertFalse(sealedBody.contentEquals(jsxPlain), "ELF protected section body must be encrypted")
        val recovered = sealedBody.copyOf()
        xorKeystream(recovered, key)
        assertTrue(recovered.contentEquals(jsxPlain), "ELF keystream must be reversible and match the C decrypt path")
    }

    @Test
    fun fails_open_for_non_native_input() {
        val key = ByteArray(32)
        val notNative = ByteArray(256) { it.toByte() }
        val out = NativeProtectedSectionPacker.sealIfPossible(notNative, key)
        assertTrue(out.contentEquals(notNative), "Unsupported input must be returned unchanged (fail open)")
    }

    @Test
    fun fails_open_when_no_jsx_section() {
        val key = ByteArray(32)
        val pe = MinimalPe.build(ByteArray(0x40) { 1 }, includeJsx = false)
        val out = NativeProtectedSectionPacker.sealIfPossible(pe.bytes, key)
        assertTrue(out.contentEquals(pe.bytes), "PE without .jsx must be returned unchanged (fail open)")
    }

    @Test
    fun fails_open_when_elf_relocation_targets_jsx_section() {
        val key = ByteArray(32)
        val elf = MinimalElf64.build(ByteArray(0x40) { (it + 3).toByte() }, includeRelocationOverlap = true)
        val out = NativeProtectedSectionPacker.sealIfPossible(elf.bytes, key)
        assertTrue(out.contentEquals(elf.bytes), "ELF relocation overlap must fail open")
    }

    @Test
    fun fails_open_when_pe_relocation_targets_jsx_section() {
        val key = ByteArray(32)
        val pe = MinimalPe.build(ByteArray(0x40) { (it + 5).toByte() }, includeRelocationOverlap = true)
        val out = NativeProtectedSectionPacker.sealIfPossible(pe.bytes, key)
        assertTrue(out.contentEquals(pe.bytes), "PE relocation overlap must fail open")
    }

    private fun xorKeystream(buf: ByteArray, key: ByteArray) {
        var produced = 0
        var counter = 0
        val digest = MessageDigest.getInstance("SHA-256")
        while (produced < buf.size) {
            digest.reset()
            digest.update(key)
            digest.update(byteArrayOf(
                (counter and 0xFF).toByte(),
                ((counter ushr 8) and 0xFF).toByte(),
                ((counter ushr 16) and 0xFF).toByte(),
                ((counter ushr 24) and 0xFF).toByte(),
            ))
            val block = digest.digest()
            val chunk = minOf(buf.size - produced, 32)
            for (i in 0 until chunk) buf[produced + i] = (buf[produced + i].toInt() xor block[i].toInt()).toByte()
            produced += chunk
            counter++
        }
    }

    private fun readLe32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or
            ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)

    /**
     * Minimal-but-valid PE32+ image with a writable .data section carrying the seal
     * marker and a .jsx code section carrying the supplied "protected" body. Enough of
     * the structure is populated for the packer's parser (DOS+NT headers, section table,
     * data directories) while staying small and deterministic.
     */
    private object MinimalPe {
        class Result(
            val bytes: ByteArray,
            val jsxRawPtr: Int,
            val jsxRva: Int,
            val markerStateOffset: Int,
        )

        private val sealMagic = byteArrayOf(0x4A, 0x53, 0x58, 0x53, 0x45, 0x41, 0x4C, 0x31)

        fun build(jsxBody: ByteArray, includeJsx: Boolean = true, includeRelocationOverlap: Boolean = false): Result {
            val fileAlign = 0x200
            val sectionAlign = 0x1000
            val dosSize = 0x40
            val ntOff = dosSize
            val sizeOfOptionalHeader = 240
            val numSections = (if (includeJsx) 2 else 1) + if (includeRelocationOverlap) 1 else 0
            val secTableOff = ntOff + 24 + sizeOfOptionalHeader
            val headersEnd = secTableOff + numSections * 40
            val firstRawPtr = align(headersEnd, fileAlign)

            val dataBody = ByteArray(0x40)
            val markerInData = 0x10
            System.arraycopy(sealMagic, 0, dataBody, markerInData, 8)

            val dataRawPtr = firstRawPtr
            val dataRawSize = align(dataBody.size, fileAlign)
            val jsxRawPtr = dataRawPtr + dataRawSize
            val jsxRawSize = if (includeJsx) align(jsxBody.size, fileAlign) else 0
            val relocRawPtr = jsxRawPtr + jsxRawSize
            val relocRawSize = if (includeRelocationOverlap) align(0x10, fileAlign) else 0
            val total = relocRawPtr + relocRawSize
            val buf = ByteArray(total)

            buf[0] = 'M'.code.toByte(); buf[1] = 'Z'.code.toByte()
            writeLe32(buf, 0x3C, ntOff)
            buf[ntOff] = 'P'.code.toByte(); buf[ntOff + 1] = 'E'.code.toByte()
            val coff = ntOff + 4
            writeLe16(buf, coff + 0, 0x8664)
            writeLe16(buf, coff + 2, numSections)
            writeLe16(buf, coff + 16, sizeOfOptionalHeader)
            writeLe16(buf, coff + 18, 0x2022)
            val opt = coff + 20
            writeLe16(buf, opt + 0, 0x20b)
            writeLe32(buf, opt + 16, 0x1000)
            writeLe32(buf, opt + 108, 16)

            var rva = sectionAlign
            putName(buf, secTableOff, ".data")
            writeLe32(buf, secTableOff + 8, dataBody.size)
            writeLe32(buf, secTableOff + 12, rva)
            writeLe32(buf, secTableOff + 16, dataRawSize)
            writeLe32(buf, secTableOff + 20, dataRawPtr)
            writeLe32(buf, secTableOff + 36, 0xC0000040.toInt())
            System.arraycopy(dataBody, 0, buf, dataRawPtr, dataBody.size)
            val markerStateOffset = dataRawPtr + markerInData + 8

            var jsxRva = 0
            if (includeJsx) {
                rva += align(dataBody.size, sectionAlign)
                jsxRva = rva
                val o = secTableOff + 40
                putName(buf, o, ".jsx")
                writeLe32(buf, o + 8, jsxBody.size)
                writeLe32(buf, o + 12, rva)
                writeLe32(buf, o + 16, jsxRawSize)
                writeLe32(buf, o + 20, jsxRawPtr)
                writeLe32(buf, o + 36, 0x60000020)
                System.arraycopy(jsxBody, 0, buf, jsxRawPtr, jsxBody.size)
            }
            if (includeRelocationOverlap) {
                rva += if (includeJsx) align(jsxBody.size, sectionAlign) else align(dataBody.size, sectionAlign)
                val relocRva = rva
                val relocSectionOff = secTableOff + (numSections - 1) * 40
                putName(buf, relocSectionOff, ".reloc")
                writeLe32(buf, relocSectionOff + 8, 0x10)
                writeLe32(buf, relocSectionOff + 12, relocRva)
                writeLe32(buf, relocSectionOff + 16, relocRawSize)
                writeLe32(buf, relocSectionOff + 20, relocRawPtr)
                writeLe32(buf, relocSectionOff + 36, 0x42000040)
                writeLe32(buf, opt + 112 + 5 * 8, relocRva)
                writeLe32(buf, opt + 112 + 5 * 8 + 4, 0x0A)
                writeLe32(buf, relocRawPtr, jsxRva)
                writeLe32(buf, relocRawPtr + 4, 0x0A)
                writeLe16(buf, relocRawPtr + 8, 0xA004)
            }
            return Result(buf, jsxRawPtr, jsxRva, markerStateOffset)
        }
    }

    /** Minimal ELF64 little-endian shared object section table for packer tests. */
    private object MinimalElf64 {
        class Result(
            val bytes: ByteArray,
            val jsxRawPtr: Int,
            val jsxAddress: Long,
            val markerStateOffset: Int,
        )

        private val sealMagic = byteArrayOf(0x4A, 0x53, 0x58, 0x53, 0x45, 0x41, 0x4C, 0x31)

        fun build(jsxBody: ByteArray, includeRelocationOverlap: Boolean = false): Result {
            val dataBody = ByteArray(0x40)
            val markerInData = 0x10
            System.arraycopy(sealMagic, 0, dataBody, markerInData, 8)
            val dataOff = align(0x40, 0x100)
            val jsxOff = align(dataOff + dataBody.size, 0x100)
            val relaOff = align(jsxOff + jsxBody.size, 0x100)
            val shstr = buildStringTable()
            val shstrOff = align(relaOff + if (includeRelocationOverlap) 24 else 0, 0x100)
            val shOff = align(shstrOff + shstr.bytes.size, 0x100)
            val sectionCount = if (includeRelocationOverlap) 5 else 4
            val total = shOff + sectionCount * 64
            val buf = ByteArray(total)
            val dataAddress = 0x3000L
            val jsxAddress = 0x1000L

            buf[0] = 0x7F; buf[1] = 'E'.code.toByte(); buf[2] = 'L'.code.toByte(); buf[3] = 'F'.code.toByte()
            buf[4] = 2; buf[5] = 1; buf[6] = 1
            writeLe16(buf, 0x10, 3)
            writeLe16(buf, 0x12, 62)
            writeLe32(buf, 0x14, 1)
            writeLe64(buf, 0x28, shOff.toLong())
            writeLe16(buf, 0x34, 64)
            writeLe16(buf, 0x3A, 64)
            writeLe16(buf, 0x3C, sectionCount)
            writeLe16(buf, 0x3E, sectionCount - 1)

            System.arraycopy(dataBody, 0, buf, dataOff, dataBody.size)
            System.arraycopy(jsxBody, 0, buf, jsxOff, jsxBody.size)
            if (includeRelocationOverlap) {
                writeLe64(buf, relaOff, jsxAddress + 4)
                writeLe64(buf, relaOff + 8, 0)
                writeLe64(buf, relaOff + 16, 0)
            }
            System.arraycopy(shstr.bytes, 0, buf, shstrOff, shstr.bytes.size)

            writeSection(buf, shOff + 64, shstr.dataName, 1, 0x3, dataAddress, dataOff, dataBody.size)
            writeSection(buf, shOff + 128, shstr.jsxName, 1, 0x6, jsxAddress, jsxOff, jsxBody.size)
            if (includeRelocationOverlap) {
                writeSection(buf, shOff + 192, shstr.relaName, 4, 0x0, 0, relaOff, 24, info = 2, entrySize = 24)
                writeSection(buf, shOff + 256, shstr.shstrName, 3, 0x0, 0, shstrOff, shstr.bytes.size)
            } else {
                writeSection(buf, shOff + 192, shstr.shstrName, 3, 0x0, 0, shstrOff, shstr.bytes.size)
            }
            return Result(buf, jsxOff, jsxAddress, dataOff + markerInData + 8)
        }

        private class StringTable(
            val bytes: ByteArray,
            val dataName: Int,
            val jsxName: Int,
            val relaName: Int,
            val shstrName: Int,
        )

        private fun buildStringTable(): StringTable {
            val names = mutableListOf(0.toByte())
            fun add(name: String): Int {
                val offset = names.size
                names += name.toByteArray(Charsets.US_ASCII).toList()
                names += 0
                return offset
            }
            val dataName = add(".data")
            val jsxName = add(".jsx")
            val relaName = add(".rela.jsx")
            val shstrName = add(".shstrtab")
            return StringTable(names.toByteArray(), dataName, jsxName, relaName, shstrName)
        }
    }

    private companion object {
        fun align(v: Int, a: Int): Int = (v + a - 1) / a * a

        fun putName(buf: ByteArray, off: Int, name: String) {
            val b = name.toByteArray(Charsets.US_ASCII)
            System.arraycopy(b, 0, buf, off, b.size)
        }

        fun writeSection(
            buf: ByteArray,
            off: Int,
            name: Int,
            type: Int,
            flags: Long,
            address: Long,
            rawOffset: Int,
            rawSize: Int,
            info: Int = 0,
            entrySize: Int = 0,
        ) {
            writeLe32(buf, off, name)
            writeLe32(buf, off + 4, type)
            writeLe64(buf, off + 8, flags)
            writeLe64(buf, off + 16, address)
            writeLe64(buf, off + 24, rawOffset.toLong())
            writeLe64(buf, off + 32, rawSize.toLong())
            writeLe32(buf, off + 44, info)
            writeLe64(buf, off + 56, entrySize.toLong())
        }

        fun writeLe16(b: ByteArray, o: Int, v: Int) {
            b[o] = (v and 0xFF).toByte(); b[o + 1] = ((v ushr 8) and 0xFF).toByte()
        }

        fun writeLe32(b: ByteArray, o: Int, v: Int) {
            b[o] = (v and 0xFF).toByte(); b[o + 1] = ((v ushr 8) and 0xFF).toByte()
            b[o + 2] = ((v ushr 16) and 0xFF).toByte(); b[o + 3] = ((v ushr 24) and 0xFF).toByte()
        }

        fun writeLe64(b: ByteArray, o: Int, v: Long) {
            for (i in 0 until 8) b[o + i] = ((v ushr (8 * i)) and 0xFF).toByte()
        }
    }

    @Test
    fun fail_closed_throws_for_pe_without_jsx() {
        val key = ByteArray(32)
        val pe = MinimalPe.build(ByteArray(0x40) { 1 }, includeJsx = false)
        assertFailsWith<NativeProtectedSectionPacker.NativeProtectedSectionSealException> {
            NativeProtectedSectionPacker.sealIfPossible(pe.bytes, key, failClosed = true)
        }
    }

    @Test
    fun fail_closed_throws_when_elf_relocation_targets_jsx() {
        val key = ByteArray(32)
        val elf = MinimalElf64.build(ByteArray(0x40) { (it + 3).toByte() }, includeRelocationOverlap = true)
        assertFailsWith<NativeProtectedSectionPacker.NativeProtectedSectionSealException> {
            NativeProtectedSectionPacker.sealIfPossible(elf.bytes, key, failClosed = true)
        }
    }

    @Test
    fun fail_closed_throws_when_pe_relocation_targets_jsx() {
        val key = ByteArray(32)
        val pe = MinimalPe.build(ByteArray(0x40) { (it + 5).toByte() }, includeRelocationOverlap = true)
        assertFailsWith<NativeProtectedSectionPacker.NativeProtectedSectionSealException> {
            NativeProtectedSectionPacker.sealIfPossible(pe.bytes, key, failClosed = true)
        }
    }

    @Test
    fun fail_closed_does_not_throw_for_non_pe_elf_input() {
        val key = ByteArray(32)
        val machoLike = ByteArray(0x80) { (it + 7).toByte() }.also { it[0] = 0xCF.toByte(); it[1] = 0xFA.toByte() }
        val out = NativeProtectedSectionPacker.sealIfPossible(machoLike, key, failClosed = true)
        assertTrue(out.contentEquals(machoLike), "Non-PE/ELF (e.g. Mach-O) must stay fail-open even under failClosed")
    }

    @Test
    fun fail_closed_still_seals_a_valid_pe_jsx_section() {
        val key = ByteArray(32) { (it * 5 + 2).toByte() }
        val jsxPlain = ByteArray(0x60) { (it * 3 + 1).toByte() }
        val pe = MinimalPe.build(jsxPlain)
        val sealed = NativeProtectedSectionPacker.sealIfPossible(pe.bytes, key, failClosed = true)
        assertFalse(sealed.contentEquals(pe.bytes), "A sealable PE must still be sealed under failClosed")
        assertEquals(1, readLe32(sealed, pe.markerStateOffset), "Seal marker must be set")
    }

}
