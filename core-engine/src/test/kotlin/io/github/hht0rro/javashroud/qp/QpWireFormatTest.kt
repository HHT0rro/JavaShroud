package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpCursor
import io.github.hht0rro.javashroud.transforms.protection.qp.QpFrameWriter
import io.github.hht0rro.javashroud.transforms.protection.qp.QpWireException
import io.github.hht0rro.javashroud.transforms.protection.qp.QpWireFormat
import io.github.hht0rro.javashroud.transforms.protection.qp.RuntimeBindingDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpWireFormatTest {
    @Test
    fun rust_binding_digest_vector_is_stable() {
        val digest = QpWireFormat.runtimeBindingDigest("binding".encodeToByteArray())

        assertFalse(
            digest.asBytes().contentEquals(hex("45a9b7e01030eaeb2a9abd080287f1018a9d7d06ed25faa60f325e390c3976fa")),
        )
        assertEquals(digest, RuntimeBindingDigest.compute("binding".encodeToByteArray()))
        assertNotEquals(
            digest,
            QpWireFormat.runtimeBindingDigest("other".encodeToByteArray()),
        )
    }

    @Test
    fun rust_full_frame_vector_round_trips_without_format_translation() {
        val binding = "binding".encodeToByteArray()
        val payload = "payload".encodeToByteArray()
        val frame = QpWireFormat.encode(binding, payload)
        assertFalse(frame.copyOf(4).contentEquals(byteArrayOf(0x4a, 0x53, 0x52, 0x31)))
        assertContentEquals(io.github.hht0rro.javashroud.transforms.protection.qp.derivedFrameMagic(), frame.copyOf(4))

        val opened = QpWireFormat.open(binding, frame)
        assertContentEquals(payload, opened.payload)
        assertEquals(
            QpWireFormat.runtimeBindingDigest(binding),
            opened.bindingDigest,
        )
    }

    @Test
    fun cursor_and_writer_are_explicit_and_bounds_checked() {
        val writer = QpFrameWriter(32)
        writer.writeU8(0xA5)
        writer.writeU16Be(0x1234)
        writer.writeFrame("payload".encodeToByteArray())

        val cursor = QpCursor(writer.finish())
        assertEquals(0xA5, cursor.readU8())
        assertEquals(0x1234, cursor.readU16Be())
        assertContentEquals("payload".encodeToByteArray(), cursor.readFrame(7))
        cursor.requireEmpty()
        assertTrue(cursor.remaining == 0)

        val truncated = assertFailsWith<QpWireException> {
            QpCursor(byteArrayOf(1)).readU32Be()
        }
        assertEquals(QpWireException.Code.TRUNCATED, truncated.code)
    }

    @Test
    fun tampering_retired_headers_and_trailing_bytes_fail_closed() {
        val binding = "binding".encodeToByteArray()
        val original = QpWireFormat.encode(binding, "payload".encodeToByteArray())

        val tagTampered = original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertCode(QpWireException.Code.AUTHENTICATION_FAILED) {
            QpWireFormat.open(binding, tagTampered)
        }

        val payloadTampered = original.copyOf().also {
            it[QpWireFormat.HEADER_SIZE] = (it[QpWireFormat.HEADER_SIZE].toInt() xor 0x20).toByte()
        }
        assertCode(QpWireException.Code.AUTHENTICATION_FAILED) {
            QpWireFormat.open(binding, payloadTampered)
        }

        val digestTampered = original.copyOf().also {
            it[QpWireFormat.HEADER_SIZE - QpWireFormat.DIGEST_SIZE] =
                (it[QpWireFormat.HEADER_SIZE - QpWireFormat.DIGEST_SIZE].toInt() xor 0x40).toByte()
        }
        assertCode(QpWireException.Code.AUTHENTICATION_FAILED) {
            QpWireFormat.open(binding, digestTampered)
        }

        val badVersion = original.copyOf().also { it[4] = 0 }
        assertCode(QpWireException.Code.UNSUPPORTED_VERSION) {
            QpWireFormat.open(binding, badVersion)
        }
        val retiredVersion = original.copyOf().also { it[4] = 1 }
        assertCode(QpWireException.Code.UNSUPPORTED_VERSION) {
            QpWireFormat.open(binding, retiredVersion)
        }

        val badMagic = original.copyOf().also { it[0] = 'X'.code.toByte() }
        assertCode(QpWireException.Code.INVALID_MAGIC) {
            QpWireFormat.open(binding, badMagic)
        }

        assertCode(QpWireException.Code.TRAILING_BYTES) {
            QpWireFormat.open(binding, original + 0x55)
        }
    }

    @Test
    fun binding_payload_and_declared_lengths_are_bounded() {
        assertCode(QpWireException.Code.INVALID_INPUT) {
            RuntimeBindingDigest.compute(ByteArray(0))
        }
        assertCode(QpWireException.Code.FRAME_TOO_LARGE) {
            RuntimeBindingDigest.compute(ByteArray(QpWireFormat.MAX_BINDING_SIZE + 1))
        }
        assertCode(QpWireException.Code.FRAME_TOO_LARGE) {
            QpWireFormat.encode(byteArrayOf(1), ByteArray(QpWireFormat.MAX_PAYLOAD_SIZE + 1))
        }

        val badLength = QpWireFormat.encode(byteArrayOf(1), byteArrayOf())
        for (index in 5..8) badLength[index] = 0xFF.toByte()
        assertCode(QpWireException.Code.FRAME_TOO_LARGE) {
            QpWireFormat.open(byteArrayOf(1), badLength)
        }
    }

    @Test
    fun authenticated_frame_exposes_only_defensive_copies() {
        val frame = QpWireFormat.open(
            byteArrayOf(1, 2, 3),
            QpWireFormat.encode(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6)),
        )
        val payload = frame.payload
        val digest = frame.bindingDigest.asBytes()
        payload[0] = 0
        digest[0] = 0

        assertContentEquals(byteArrayOf(4, 5, 6), frame.payload)
        assertContentEquals(
            QpWireFormat.runtimeBindingDigest(byteArrayOf(1, 2, 3)).asBytes(),
            frame.bindingDigest.asBytes(),
        )
    }

    private fun assertCode(expected: QpWireException.Code, block: () -> Unit) {
        val error = assertFailsWith<QpWireException>(block = block)
        assertEquals(expected, error.code)
    }

    private fun hex(value: String): ByteArray {
        val clean = value.filterNot(Char::isWhitespace)
        require(clean.length % 2 == 0)
        return ByteArray(clean.length / 2) { index ->
            clean.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
