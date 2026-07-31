package io.github.hht0rro.javashroud.transforms.protection

import java.security.MessageDigest

/**
 * Build-time encryptor for the native critical-region protected section.
 *
 * The recompiled JNI kernel emits selected pure, relocation-free hot functions into a
 * dedicated, page-isolated protected code section. Runtime wrappers decrypt that section
 * only while protected calls are active, then re-encrypt and remove execute permission.
 * This packer performs the matching build-time step on produced native libraries:
 *
 *  1. Parse PE or ELF64 headers and locate the protected ".jsx" section.
 *  2. Verify no relocation entries point into the protected section.
 *  3. XOR-encrypt the section's on-disk body with a SHA-256 keystream derived from the
 *     same 32-byte key embedded in the binary (`JS_PROTECTED_SECTION_KEY`).
 *  4. Write the protected section RVA/size into the in-binary seal marker and arm its
 *     `state` field so the guarded runtime lifecycle can open it on demand.
 *
 * Callers choose whether a structural failure stays fail-open (diagnostic tooling) or
 * fails the protected build. Production PE/ELF recompilation uses fail-closed sealing.
 */
internal object NativeProtectedSectionPacker {
    private const val SECTION_NAME = ".jsx"
    private val SEAL_MAGIC = byteArrayOf(0x4A, 0x53, 0x58, 0x53, 0x45, 0x41, 0x4C, 0x31) // "JSXSEAL1"
    private const val PE_SIGNATURE = 0x00004550 // "PE\0\0" little-endian as int via LE read
    private const val PT_LOAD = 1
    private const val PF_EXECUTE = 0x1
    private const val PF_WRITE = 0x2
    private const val PF_READ = 0x4
    private val ELF_MAGIC = byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
    private const val MIN_RUNTIME_PAGE_SIZE = 0x1000L

    /** SEC-005/DEC-002: raised when a PE/ELF native kernel that requires
     * protection cannot have its .jsx section sealed, so the build fails closed
     * instead of silently shipping unsealed (plaintext) native code. */
    class NativeProtectedSectionSealException(message: String, cause: Throwable? = null) :
        RuntimeException(message, cause)

    fun sealIfPossible(
        bytes: ByteArray,
        key: ByteArray,
        report: (NativeToolchainProvisioner.ResolutionMessage) -> Unit = {},
        failClosed: Boolean = false,
    ): ByteArray {
        return try {
            val sealed = trySeal(bytes, key)
            if (sealed != null) {
                report(NativeToolchainProvisioner.ResolutionMessage("info", "Sealed native protected code section (.jsx)", 94))
                sealed
            } else if (failClosed && isPackerResponsibleFormat(bytes)) {
                throw NativeProtectedSectionSealException(
                    "native protected section (.jsx) is missing or unsealable in a PE/ELF kernel that requires protection",
                )
            } else {
                bytes
            }
        } catch (ex: NativeProtectedSectionSealException) {
            throw ex
        } catch (ex: Exception) {
            if (failClosed && isPackerResponsibleFormat(bytes)) {
                throw NativeProtectedSectionSealException("native protected section sealing failed: ${ex.message}", ex)
            }
            report(NativeToolchainProvisioner.ResolutionMessage("warn", "Protected-section sealing skipped: ${ex.message}", 94))
            bytes
        }
    }

    /** The packer seals only PE and ELF64 .jsx sections. Mach-O kernels carry no
     * .jsx section by design, so they are never treated as a fail-closed gap. */
    private fun isPackerResponsibleFormat(bytes: ByteArray): Boolean = when {
        bytes.size < 0x40 -> false
        bytes[0] == 'M'.code.toByte() && bytes[1] == 'Z'.code.toByte() -> true
        bytes.startsWith(ELF_MAGIC) -> true
        else -> false
    }

    private fun trySeal(bytes: ByteArray, key: ByteArray): ByteArray? = when {
        bytes.size < 0x40 -> null
        bytes[0] == 'M'.code.toByte() && bytes[1] == 'Z'.code.toByte() -> trySealPe(bytes, key)
        bytes.startsWith(ELF_MAGIC) -> trySealElf64(bytes, key)
        else -> null
    }

    private fun trySealPe(bytes: ByteArray, key: ByteArray): ByteArray? {
        val eLfanew = readLe32(bytes, 0x3C)
        if (eLfanew <= 0 || eLfanew + 24 > bytes.size) return null
        if (readLe32(bytes, eLfanew) != PE_SIGNATURE) return null
        val coff = eLfanew + 4
        val numSections = readLe16(bytes, coff + 2)
        val optSize = readLe16(bytes, coff + 16)
        val optOff = coff + 20
        if (optOff + optSize > bytes.size) return null
        val optMagic = readLe16(bytes, optOff)
        val is64 = optMagic == 0x20b
        val secTableOff = optOff + optSize
        val sectionAlignment = readLe32(bytes, optOff + 32).toLong() and 0xFFFFFFFFL
        if (!isPowerOfTwo(sectionAlignment) || sectionAlignment < MIN_RUNTIME_PAGE_SIZE) return null

        var jsxVaddr = -1; var jsxVsize = 0; var jsxRawPtr = -1; var jsxRawSize = 0
        val allocSections = mutableListOf<Pair<Long, Long>>()
        for (i in 0 until numSections) {
            val o = secTableOff + i * 40
            if (o + 40 > bytes.size) return null
            val name = String(bytes, o, 8, Charsets.US_ASCII).trimEnd('\u0000')
            val virtualSize = readLe32(bytes, o + 8).toLong() and 0xFFFFFFFFL
            val virtualAddress = readLe32(bytes, o + 12).toLong() and 0xFFFFFFFFL
            val rawSize = readLe32(bytes, o + 16).toLong() and 0xFFFFFFFFL
            if (name != SECTION_NAME) {
                val span = maxOf(virtualSize, rawSize)
                if (span > 0L) allocSections += virtualAddress to span
            }
            if (name == SECTION_NAME) {
                jsxVsize = readLe32(bytes, o + 8)
                jsxVaddr = readLe32(bytes, o + 12)
                jsxRawSize = readLe32(bytes, o + 16)
                jsxRawPtr = readLe32(bytes, o + 20)
            }
        }
        if (jsxVaddr < 0 || jsxRawPtr < 0) return null
        val encLen = minOf(jsxVsize, jsxRawSize)
        if (encLen <= 0 || jsxRawPtr + encLen > bytes.size) return null
        val jsxStart = jsxVaddr.toLong() and 0xFFFFFFFFL
        val jsxEnd = checkedEnd(jsxStart, encLen.toLong()) ?: return null
        val protectedPageEnd = alignUp(checkedEnd(jsxStart, maxOf(jsxVsize, jsxRawSize).toLong()) ?: return null, sectionAlignment) ?: return null
        if (jsxStart % sectionAlignment != 0L || jsxEnd > protectedPageEnd) return null
        if (allocSections.any { (start, size) -> rangesOverlap(jsxStart, protectedPageEnd, start, checkedEnd(start, size) ?: return null) }) return null

        val dirCount = readLe32(bytes, optOff + (if (is64) 108 else 92))
        if (dirCount > 5) {
            val ddOff = optOff + (if (is64) 112 else 96)
            val relocRva = readLe32(bytes, ddOff + 5 * 8)
            val relocSize = readLe32(bytes, ddOff + 5 * 8 + 4)
            if (relocRva != 0 && relocSize != 0) {
                if (relocOverlapsPeSection(bytes, secTableOff, numSections, relocRva, relocSize, jsxVaddr, jsxVsize)) {
                    return null
                }
            }
        }

        val out = bytes.copyOf()
        val markerOff = findSealMarkerInPeWritableData(out, secTableOff, numSections) ?: return null
        val stateOff = markerOff + 8
        if (stateOff + 12 > out.size) return null
        if (readLe32(out, stateOff) != 0) return null

        xorKeystream(out, jsxRawPtr, encLen, key)
        writeLe32(out, stateOff, 1)
        writeLe32(out, stateOff + 4, jsxVaddr)
        writeLe32(out, stateOff + 8, encLen)
        return out
    }

    private data class ElfSection(
        val index: Int,
        val name: String,
        val type: Int,
        val flags: Long,
        val address: Long,
        val offset: Int,
        val size: Int,
        val info: Int,
        val entrySize: Int,
    )

    private data class ElfProgramHeader(
        val type: Int,
        val flags: Int,
        val offset: Long,
        val virtualAddress: Long,
        val fileSize: Long,
        val memorySize: Long,
        val alignment: Long,
    )

    private fun trySealElf64(bytes: ByteArray, key: ByteArray): ByteArray? {
        val sections = readElf64Sections(bytes) ?: return null
        val jsx = sections.firstOrNull { it.name == SECTION_NAME } ?: return null
        val shfWrite = 0x1L
        val shfAlloc = 0x2L
        val shfExecInstr = 0x4L
        val shtNoBits = 8
        if (jsx.type == shtNoBits || jsx.size <= 0) return null
        if ((jsx.flags and shfAlloc) == 0L || (jsx.flags and shfExecInstr) == 0L) return null
        if (jsx.offset + jsx.size > bytes.size) return null
        if (!elfProtectedPagesAreIsolated(bytes, sections, jsx, shfAlloc)) return null
        if (elfRelocationOverlapsSection(bytes, sections, jsx)) return null

        val out = bytes.copyOf()
        val markerOff = findSealMarkerInElfWritableData(out, sections, shfWrite, shtNoBits) ?: return null
        val stateOff = markerOff + 8
        if (stateOff + 12 > out.size) return null
        if (readLe32(out, stateOff) != 0) return null

        if (jsx.address <= 0 || jsx.address > 0xFFFFFFFFL) return null
        xorKeystream(out, jsx.offset, jsx.size, key)
        writeLe32(out, stateOff, 1)
        writeLe32(out, stateOff + 4, jsx.address.toInt())
        writeLe32(out, stateOff + 8, jsx.size)
        return out
    }

    private fun readElf64Sections(bytes: ByteArray): List<ElfSection>? {
        if (bytes.size < 64 || !bytes.startsWith(ELF_MAGIC)) return null
        val elfClass64 = 2.toByte()
        val elfDataLittleEndian = 1.toByte()
        if (bytes[4] != elfClass64 || bytes[5] != elfDataLittleEndian) return null
        val sectionHeaderOffset = readLe64(bytes, 0x28)
        val sectionHeaderEntrySize = readLe16(bytes, 0x3A)
        val sectionCount = readLe16(bytes, 0x3C)
        val sectionStringIndex = readLe16(bytes, 0x3E)
        if (sectionHeaderOffset <= 0 || sectionHeaderOffset > Int.MAX_VALUE) return null
        if (sectionHeaderEntrySize < 64 || sectionCount <= 0 || sectionStringIndex !in 0 until sectionCount) return null
        val sectionTableEnd = sectionHeaderOffset + sectionHeaderEntrySize.toLong() * sectionCount.toLong()
        if (sectionTableEnd > bytes.size) return null

        fun sectionFieldOffset(index: Int): Int = sectionHeaderOffset.toInt() + index * sectionHeaderEntrySize
        val shstrOff = sectionFieldOffset(sectionStringIndex)
        val shstrType = readLe32(bytes, shstrOff + 4)
        val shstrRawOffset = readLe64(bytes, shstrOff + 24)
        val shstrSize = readLe64(bytes, shstrOff + 32)
        if (shstrType != 3 || shstrRawOffset < 0 || shstrSize <= 0) return null
        if (shstrRawOffset > Int.MAX_VALUE || shstrSize > Int.MAX_VALUE) return null
        if (shstrRawOffset + shstrSize > bytes.size) return null

        val sections = mutableListOf<ElfSection>()
        for (index in 0 until sectionCount) {
            val off = sectionFieldOffset(index)
            val nameOffset = readLe32(bytes, off)
            val type = readLe32(bytes, off + 4)
            val flags = readLe64(bytes, off + 8)
            val address = readLe64(bytes, off + 16)
            val rawOffset = readLe64(bytes, off + 24)
            val rawSize = readLe64(bytes, off + 32)
            val info = readLe32(bytes, off + 44)
            val entrySize = readLe64(bytes, off + 56)
            if (rawOffset < 0 || rawSize < 0 || rawOffset > Int.MAX_VALUE || rawSize > Int.MAX_VALUE) return null
            if (entrySize < 0 || entrySize > Int.MAX_VALUE) return null
            if (type != 8 && rawSize > 0 && rawOffset + rawSize > bytes.size) return null
            val name = readCString(bytes, shstrRawOffset.toInt(), shstrSize.toInt(), nameOffset) ?: return null
            sections += ElfSection(
                index = index,
                name = name,
                type = type,
                flags = flags,
                address = address,
                offset = rawOffset.toInt(),
                size = rawSize.toInt(),
                info = info,
                entrySize = entrySize.toInt(),
            )
        }
        return sections
    }

    private fun readElf64ProgramHeaders(bytes: ByteArray): List<ElfProgramHeader>? {
        val tableOffset = readLe64(bytes, 0x20)
        val entrySize = readLe16(bytes, 0x36)
        val count = readLe16(bytes, 0x38)
        if (tableOffset < 0L || tableOffset > Int.MAX_VALUE || entrySize < 56 || count <= 0) return null
        val tableEnd = tableOffset + entrySize.toLong() * count.toLong()
        if (tableEnd < tableOffset || tableEnd > bytes.size) return null
        return (0 until count).map { index ->
            val offset = tableOffset.toInt() + index * entrySize
            ElfProgramHeader(
                type = readLe32(bytes, offset),
                flags = readLe32(bytes, offset + 4),
                offset = readLe64(bytes, offset + 8),
                virtualAddress = readLe64(bytes, offset + 16),
                fileSize = readLe64(bytes, offset + 32),
                memorySize = readLe64(bytes, offset + 40),
                alignment = readLe64(bytes, offset + 48),
            )
        }
    }

    private fun elfProtectedPagesAreIsolated(
        bytes: ByteArray,
        sections: List<ElfSection>,
        jsx: ElfSection,
        shfAlloc: Long,
    ): Boolean {
        val programHeaders = readElf64ProgramHeaders(bytes) ?: return false
        val load = programHeaders.filter { header ->
            header.type == PT_LOAD &&
                header.virtualAddress <= jsx.address &&
                checkedEnd(header.virtualAddress, header.memorySize)?.let { end ->
                    checkedEnd(jsx.address, jsx.size.toLong())?.let { jsxEnd -> jsxEnd <= end }
                } == true
        }.singleOrNull() ?: return false
        if (load.flags and (PF_READ or PF_EXECUTE) != (PF_READ or PF_EXECUTE) || load.flags and PF_WRITE != 0) return false
        val pageSize = load.alignment
        if (!isPowerOfTwo(pageSize) || pageSize < MIN_RUNTIME_PAGE_SIZE) return false
        val jsxStart = jsx.address
        val jsxEnd = checkedEnd(jsxStart, jsx.size.toLong()) ?: return false
        if (jsxStart % pageSize != 0L || jsxEnd % pageSize != 0L) return false
        if (jsx.offset.toLong() % pageSize != jsxStart % pageSize) return false
        if (load.offset % pageSize != load.virtualAddress % pageSize) return false
        return sections.none { section ->
            if (section.index == jsx.index || section.size <= 0 || section.flags and shfAlloc == 0L) return@none false
            val sectionEnd = checkedEnd(section.address, section.size.toLong()) ?: return false
            rangesOverlap(jsxStart, jsxEnd, section.address, sectionEnd)
        }
    }

    private fun elfRelocationOverlapsSection(bytes: ByteArray, sections: List<ElfSection>, target: ElfSection): Boolean {
        val shtRela = 4
        val shtRel = 9
        val targetStart = target.address
        val targetEnd = target.address + target.size.toLong()
        for (section in sections) {
            val entrySize = when (section.type) {
                shtRela -> if (section.entrySize > 0) section.entrySize else 24
                shtRel -> if (section.entrySize > 0) section.entrySize else 16
                else -> continue
            }
            if (entrySize <= 0 || section.size % entrySize != 0) return true
            if (section.offset + section.size > bytes.size) return true
            val count = section.size / entrySize
            for (entry in 0 until count) {
                val entryOffset = section.offset + entry * entrySize
                val relocationOffset = readLe64(bytes, entryOffset)
                val sectionRelativeHit = section.info == target.index && relocationOffset >= 0 && relocationOffset < target.size.toLong()
                val virtualAddressHit = relocationOffset >= targetStart && relocationOffset < targetEnd
                if (sectionRelativeHit || virtualAddressHit) return true
            }
        }
        return false
    }

    private fun relocOverlapsPeSection(
        bytes: ByteArray,
        secTableOff: Int,
        numSections: Int,
        relocRva: Int,
        relocSize: Int,
        jsxVaddr: Int,
        jsxVsize: Int,
    ): Boolean {
        val relocOff = rvaToOffset(bytes, secTableOff, numSections, relocRva) ?: return true
        var off = relocOff
        val end = relocOff + relocSize
        val jsxEnd = jsxVaddr + jsxVsize
        while (off + 8 <= end && off + 8 <= bytes.size) {
            val pageRva = readLe32(bytes, off)
            val blockSize = readLe32(bytes, off + 4)
            if (blockSize < 8) break
            val entries = (blockSize - 8) / 2
            for (k in 0 until entries) {
                val entOff = off + 8 + k * 2
                if (entOff + 2 > bytes.size) return true
                val ent = readLe16(bytes, entOff)
                val type = ent ushr 12
                if (type == 0) continue
                val target = pageRva + (ent and 0xFFF)
                if (target in jsxVaddr until jsxEnd) return true
            }
            off += blockSize
        }
        return false
    }

    private fun rvaToOffset(bytes: ByteArray, secTableOff: Int, numSections: Int, rva: Int): Int? {
        for (i in 0 until numSections) {
            val o = secTableOff + i * 40
            if (o + 40 > bytes.size) return null
            val vaddr = readLe32(bytes, o + 12)
            val vsize = readLe32(bytes, o + 8)
            val rawPtr = readLe32(bytes, o + 20)
            val rawSize = readLe32(bytes, o + 16)
            val span = maxOf(vsize, rawSize)
            if (rva in vaddr until (vaddr + span)) return rawPtr + (rva - vaddr)
        }
        return null
    }

    private fun checkedEnd(start: Long, size: Long): Long? {
        if (start < 0L || size < 0L || size > Long.MAX_VALUE - start) return null
        return start + size
    }

    private fun isPowerOfTwo(value: Long): Boolean = value > 0L && value and (value - 1L) == 0L

    private fun alignUp(value: Long, alignment: Long): Long? {
        if (!isPowerOfTwo(alignment) || value > Long.MAX_VALUE - (alignment - 1L)) return null
        return (value + alignment - 1L) and -alignment
    }

    private fun rangesOverlap(firstStart: Long, firstEnd: Long, secondStart: Long, secondEnd: Long): Boolean =
        firstStart < secondEnd && secondStart < firstEnd

    /** Keystream block i = SHA-256(KEY || le32(i)); identical to the C decrypt path. */
    private fun xorKeystream(buf: ByteArray, offset: Int, length: Int, key: ByteArray) {
        var produced = 0
        var counter = 0
        val digest = MessageDigest.getInstance("SHA-256")
        while (produced < length) {
            digest.reset()
            digest.update(key)
            digest.update(byteArrayOf(
                (counter and 0xFF).toByte(),
                ((counter ushr 8) and 0xFF).toByte(),
                ((counter ushr 16) and 0xFF).toByte(),
                ((counter ushr 24) and 0xFF).toByte(),
            ))
            val block = digest.digest()
            val chunk = minOf(length - produced, 32)
            for (i in 0 until chunk) {
                buf[offset + produced + i] = (buf[offset + produced + i].toInt() xor block[i].toInt()).toByte()
            }
            produced += chunk
            counter++
        }
    }

    private fun findSealMarkerInPeWritableData(bytes: ByteArray, secTableOff: Int, numSections: Int): Int? {
        val imageScnMemWrite = 0x80000000.toInt()
        val imageScnCntInitialized = 0x00000040
        var fallback: Int? = null
        for (i in 0 until numSections) {
            val o = secTableOff + i * 40
            if (o + 40 > bytes.size) return fallback
            val rawSize = readLe32(bytes, o + 16)
            val rawPtr = readLe32(bytes, o + 20)
            val chars = readLe32(bytes, o + 36)
            if (rawPtr <= 0 || rawSize <= 0 || rawPtr + rawSize > bytes.size) continue
            val writable = (chars and imageScnMemWrite) != 0
            val initialized = (chars and imageScnCntInitialized) != 0
            val hit = indexOfRange(bytes, SEAL_MAGIC, rawPtr, rawPtr + rawSize)
            if (hit != null) {
                if (writable && initialized) return hit
                if (fallback == null) fallback = hit
            }
        }
        return fallback
    }

    private fun findSealMarkerInElfWritableData(
        bytes: ByteArray,
        sections: List<ElfSection>,
        shfWrite: Long,
        shtNoBits: Int,
    ): Int? {
        for (section in sections) {
            if (section.type == shtNoBits || section.size <= 0) continue
            if ((section.flags and shfWrite) == 0L) continue
            if (section.offset <= 0 || section.offset + section.size > bytes.size) continue
            val hit = indexOfRange(bytes, SEAL_MAGIC, section.offset, section.offset + section.size)
            if (hit != null) return hit
        }
        return null
    }

    private fun indexOfRange(haystack: ByteArray, needle: ByteArray, from: Int, to: Int): Int? {
        if (needle.isEmpty()) return null
        val last = minOf(to, haystack.size) - needle.size
        if (from > last) return null
        for (start in from..last) {
            var matched = true
            for (j in needle.indices) {
                if (haystack[start + j] != needle[j]) { matched = false; break }
            }
            if (matched) return start
        }
        return null
    }

    private fun readCString(bytes: ByteArray, tableOffset: Int, tableSize: Int, stringOffset: Int): String? {
        if (stringOffset < 0 || stringOffset >= tableSize) return null
        val absoluteOffset = tableOffset + stringOffset
        val tableEnd = tableOffset + tableSize
        var end = absoluteOffset
        while (end < tableEnd && bytes[end] != 0.toByte()) end++
        return String(bytes, absoluteOffset, end - absoluteOffset, Charsets.US_ASCII)
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (size < prefix.size) return false
        for (index in prefix.indices) {
            if (this[index] != prefix[index]) return false
        }
        return true
    }

    private fun readLe16(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)

    private fun readLe32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or
            ((b[o + 1].toInt() and 0xFF) shl 8) or
            ((b[o + 2].toInt() and 0xFF) shl 16) or
            ((b[o + 3].toInt() and 0xFF) shl 24)

    private fun readLe64(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 0xFFL) or
            ((b[o + 1].toLong() and 0xFFL) shl 8) or
            ((b[o + 2].toLong() and 0xFFL) shl 16) or
            ((b[o + 3].toLong() and 0xFFL) shl 24) or
            ((b[o + 4].toLong() and 0xFFL) shl 32) or
            ((b[o + 5].toLong() and 0xFFL) shl 40) or
            ((b[o + 6].toLong() and 0xFFL) shl 48) or
            ((b[o + 7].toLong() and 0xFFL) shl 56)

    private fun writeLe32(b: ByteArray, o: Int, v: Int) {
        b[o] = (v and 0xFF).toByte()
        b[o + 1] = ((v ushr 8) and 0xFF).toByte()
        b[o + 2] = ((v ushr 16) and 0xFF).toByte()
        b[o + 3] = ((v ushr 24) and 0xFF).toByte()
    }
}
