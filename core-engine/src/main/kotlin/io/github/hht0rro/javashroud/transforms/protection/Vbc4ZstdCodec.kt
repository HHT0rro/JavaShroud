package io.github.hht0rro.javashroud.transforms.protection

internal object Vbc4ZstdCodec {
    const val CompressionLevel: Int = 22

    private const val Magic = 0xFD2FB528.toInt()
    private const val SingleSegmentFlag = 0x20
    private const val ContentChecksumFlag = 0x04
    private const val BlockLastFlag = 0x01
    private const val BlockRawType = 0x00
    private const val BlockRleType = 0x01
    private const val MaxBlockSize = 128 * 1024

    fun compress(bytes: ByteArray): ByteArray {
        val out = java.io.ByteArrayOutputStream(bytes.size + 32 + bytes.size / MaxBlockSize * 3)
        writeLe32(out, Magic)
        writeFrameHeader(out, bytes.size)
        var offset = 0
        if (bytes.isEmpty()) {
            writeBlockHeader(out, last = true, blockType = BlockRawType, blockSize = 0)
        } else {
            while (offset < bytes.size) {
                val blockSize = minOf(MaxBlockSize, bytes.size - offset)
                val last = offset + blockSize == bytes.size
                if (isRepeatedByteBlock(bytes, offset, blockSize)) {
                    writeBlockHeader(out, last, BlockRleType, blockSize)
                    out.write(bytes[offset].toInt() and 0xFF)
                } else {
                    writeBlockHeader(out, last, BlockRawType, blockSize)
                    out.write(bytes, offset, blockSize)
                }
                offset += blockSize
            }
        }
        val compressed = out.toByteArray()
        return if (compressed.size < bytes.size) compressed else bytes
    }

    fun decompress(bytes: ByteArray, expectedLength: Int): ByteArray? {
        if (expectedLength < 0 || bytes.size < 7) return null
        var offset = 0
        if (readLe32(bytes, offset) != Magic) return null
        offset += 4
        val descriptor = bytes[offset++].toInt() and 0xFF
        if ((descriptor and 0x08) != 0 || (descriptor and 0x03) != 0) return null
        val frameContentSizeFlag = descriptor ushr 6
        val singleSegment = (descriptor and SingleSegmentFlag) != 0
        val checksum = (descriptor and ContentChecksumFlag) != 0
        if (!singleSegment) {
            if (offset >= bytes.size) return null
            offset++
        }
        val contentSizeLength = when (frameContentSizeFlag) {
            0 -> if (singleSegment) 1 else 0
            1 -> 2
            2 -> 4
            else -> 8
        }
        val declaredLength = readFrameContentSize(bytes, offset, contentSizeLength) ?: return null
        offset += contentSizeLength
        if (declaredLength != expectedLength.toLong()) return null

        val out = java.io.ByteArrayOutputStream(expectedLength)
        var sawLast = false
        while (!sawLast) {
            if (offset + 3 > bytes.size) return null
            val header = (bytes[offset].toInt() and 0xFF) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 16)
            offset += 3
            sawLast = (header and BlockLastFlag) != 0
            val blockType = (header ushr 1) and 0x03
            val blockSize = header ushr 3
            when (blockType) {
                BlockRawType -> {
                    if (offset + blockSize > bytes.size) return null
                    out.write(bytes, offset, blockSize)
                    offset += blockSize
                }
                BlockRleType -> {
                    if (offset >= bytes.size) return null
                    repeat(blockSize) { out.write(bytes[offset].toInt() and 0xFF) }
                    offset++
                }
                else -> return null
            }
            if (out.size() > expectedLength) return null
        }
        if (checksum) {
            if (offset + 4 > bytes.size) return null
            offset += 4
        }
        if (offset != bytes.size) return null
        val decoded = out.toByteArray()
        return if (decoded.size == expectedLength) decoded else null
    }

    private fun writeFrameHeader(out: java.io.ByteArrayOutputStream, contentSize: Int) {
        when {
            contentSize <= 0xFF -> {
                out.write(SingleSegmentFlag)
                out.write(contentSize)
            }
            contentSize <= 0xFFFF + 256 -> {
                out.write(SingleSegmentFlag or 0x40)
                writeLe16(out, contentSize - 256)
            }
            else -> {
                out.write(SingleSegmentFlag or 0x80)
                writeLe32(out, contentSize)
            }
        }
    }

    private fun writeBlockHeader(out: java.io.ByteArrayOutputStream, last: Boolean, blockType: Int, blockSize: Int) {
        val header = (if (last) BlockLastFlag else 0) or (blockType shl 1) or (blockSize shl 3)
        out.write(header and 0xFF)
        out.write((header ushr 8) and 0xFF)
        out.write((header ushr 16) and 0xFF)
    }


    private fun isRepeatedByteBlock(bytes: ByteArray, offset: Int, length: Int): Boolean {
        if (length <= 1) return false
        val first = bytes[offset]
        for (index in 1 until length) {
            if (bytes[offset + index] != first) return false
        }
        return true
    }
    private fun readFrameContentSize(bytes: ByteArray, offset: Int, length: Int): Long? {
        if (offset + length > bytes.size) return null
        return when (length) {
            0 -> null
            1 -> (bytes[offset].toInt() and 0xFF).toLong()
            2 -> ((bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)).toLong() + 256L
            4 -> readLe32(bytes, offset).toLong() and 0xFFFF_FFFFL
            8 -> {
                var value = 0L
                for (index in 0 until 8) value = value or ((bytes[offset + index].toLong() and 0xFFL) shl (8 * index))
                value
            }
            else -> null
        }
    }

    private fun writeLe16(out: java.io.ByteArrayOutputStream, value: Int) {
        out.write(value and 0xFF)
        out.write((value ushr 8) and 0xFF)
    }

    private fun writeLe32(out: java.io.ByteArrayOutputStream, value: Int) {
        out.write(value and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 24) and 0xFF)
    }

    private fun readLe32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
}
