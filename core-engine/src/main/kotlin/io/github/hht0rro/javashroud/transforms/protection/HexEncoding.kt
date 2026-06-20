package io.github.hht0rro.javashroud.transforms.protection

private val LOWER_HEX_DIGITS = "0123456789abcdef".toCharArray()
private val UPPER_HEX_DIGITS = "0123456789ABCDEF".toCharArray()

internal fun ByteArray.toHexLower(): String = toHexString(LOWER_HEX_DIGITS)

internal fun ByteArray.toCByteArrayLiteral(): String = joinToString(", ") { byte ->
    val value = byte.toInt() and 0xFF
    "0x${UPPER_HEX_DIGITS[value ushr 4]}${UPPER_HEX_DIGITS[value and 0x0F]}u"
}

internal fun Int.toFixedHexLower(width: Int): String {
    val chars = CharArray(width)
    for (index in 0 until width) {
        val shift = (width - index - 1) * 4
        chars[index] = LOWER_HEX_DIGITS[(this ushr shift) and 0x0F]
    }
    return String(chars)
}

private fun ByteArray.toHexString(digits: CharArray): String {
    val chars = CharArray(size * 2)
    for (index in indices) {
        val value = this[index].toInt() and 0xFF
        chars[index * 2] = digits[value ushr 4]
        chars[index * 2 + 1] = digits[value and 0x0F]
    }
    return String(chars)
}