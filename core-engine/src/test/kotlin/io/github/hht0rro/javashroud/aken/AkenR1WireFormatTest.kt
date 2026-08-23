package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenR1Cursor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenR1FrameWriter
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenR1WireException
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenR1WireFormat
import io.github.hht0rro.javashroud.transforms.protection.aken.RuntimeBindingDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AkenR1WireFormatTest {
    @Test
    fun rust_binding_digest_vector_is_stable() {
        val digest = AkenR1WireFormat.runtimeBindingDigest("binding".encodeToByteArray())

        assertContentEquals(
            hex("611e402b187c76217b735b5a28eb713929647213ca597fa26bf537c41450fee4"),
            digest.asBytes(),
        )
        assertEquals(digest, RuntimeBindingDigest.compute("binding".encodeToByteArray()))
        assertNotEquals(
            digest,
            AkenR1WireFormat.runtimeBindingDigest("other".encodeToByteArray()),
        )
    }

    @Test
    fun rust_full_frame_vector_round_trips_without_format_translation() {
        val binding = "binding".encodeToByteArray()
        val payload = "payload".encodeToByteArray()
        val frame = AkenR1WireFormat.encode(binding, payload)

        assertContentEquals(
            hex(
                "4a5352310100000007" +
                    "611e402b187c76217b735b5a28eb713929647213ca597fa26bf537c41450fee4" +
                    "7061796c6f6164" +
                    "9f96b0ef983abda70e08cd6e9138fab33d5d2baaef18e287ec24e5591b80d166",
            ),
            frame,
        )

        val opened = AkenR1WireFormat.open(binding, frame)
        assertContentEquals(payload, opened.payload)
        assertEquals(
            AkenR1WireFormat.runtimeBindingDigest(binding),
            opened.bindingDigest,
        )
    }

    @Test
    fun cursor_and_writer_are_explicit_and_bounds_checked() {
        val writer = AkenR1FrameWriter(32)
        writer.writeU8(0xA5)
        writer.writeU16Be(0x1234)
        writer.writeFrame("payload".encodeToByteArray())

        val cursor = AkenR1Cursor(writer.finish())
        assertEquals(0xA5, cursor.readU8())
        assertEquals(0x1234, cursor.readU16Be())
        assertContentEquals("payload".encodeToByteArray(), cursor.readFrame(7))
        cursor.requireEmpty()
        assertTrue(cursor.remaining == 0)

        val truncated = assertFailsWith<AkenR1WireException> {
            AkenR1Cursor(byteArrayOf(1)).readU32Be()
        }
        assertEquals(AkenR1WireException.Code.TRUNCATED, truncated.code)
    }

    @Test
    fun tampering_retired_headers_and_trailing_bytes_fail_closed() {
        val binding = "binding".encodeToByteArray()
        val original = AkenR1WireFormat.encode(binding, "payload".encodeToByteArray())

        val tagTampered = original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertCode(AkenR1WireException.Code.AUTHENTICATION_FAILED) {
            AkenR1WireFormat.open(binding, tagTampered)
        }

        val payloadTampered = original.copyOf().also {
            it[AkenR1WireFormat.HEADER_SIZE] = (it[AkenR1WireFormat.HEADER_SIZE].toInt() xor 0x20).toByte()
        }
        assertCode(AkenR1WireException.Code.AUTHENTICATION_FAILED) {
            AkenR1WireFormat.open(binding, payloadTampered)
        }

        val digestTampered = original.copyOf().also {
            it[AkenR1WireFormat.HEADER_SIZE - AkenR1WireFormat.DIGEST_SIZE] =
                (it[AkenR1WireFormat.HEADER_SIZE - AkenR1WireFormat.DIGEST_SIZE].toInt() xor 0x40).toByte()
        }
        assertCode(AkenR1WireException.Code.AUTHENTICATION_FAILED) {
            AkenR1WireFormat.open(binding, digestTampered)
        }

        val badVersion = original.copyOf().also { it[4] = 0 }
        assertCode(AkenR1WireException.Code.UNSUPPORTED_VERSION) {
            AkenR1WireFormat.open(binding, badVersion)
        }

        val badMagic = original.copyOf().also { it[0] = 'X'.code.toByte() }
        assertCode(AkenR1WireException.Code.INVALID_MAGIC) {
            AkenR1WireFormat.open(binding, badMagic)
        }

        assertCode(AkenR1WireException.Code.TRAILING_BYTES) {
            AkenR1WireFormat.open(binding, original + 0x55)
        }
    }

    @Test
    fun binding_payload_and_declared_lengths_are_bounded() {
        assertCode(AkenR1WireException.Code.INVALID_INPUT) {
            RuntimeBindingDigest.compute(ByteArray(0))
        }
        assertCode(AkenR1WireException.Code.FRAME_TOO_LARGE) {
            RuntimeBindingDigest.compute(ByteArray(AkenR1WireFormat.MAX_BINDING_SIZE + 1))
        }
        assertCode(AkenR1WireException.Code.FRAME_TOO_LARGE) {
            AkenR1WireFormat.encode(byteArrayOf(1), ByteArray(AkenR1WireFormat.MAX_PAYLOAD_SIZE + 1))
        }

        val badLength = AkenR1WireFormat.encode(byteArrayOf(1), byteArrayOf())
        for (index in 5..8) badLength[index] = 0xFF.toByte()
        assertCode(AkenR1WireException.Code.FRAME_TOO_LARGE) {
            AkenR1WireFormat.open(byteArrayOf(1), badLength)
        }
    }

    @Test
    fun authenticated_frame_exposes_only_defensive_copies() {
        val frame = AkenR1WireFormat.open(
            byteArrayOf(1, 2, 3),
            AkenR1WireFormat.encode(byteArrayOf(1, 2, 3), byteArrayOf(4, 5, 6)),
        )
        val payload = frame.payload
        val digest = frame.bindingDigest.asBytes()
        payload[0] = 0
        digest[0] = 0

        assertContentEquals(byteArrayOf(4, 5, 6), frame.payload)
        assertContentEquals(
            AkenR1WireFormat.runtimeBindingDigest(byteArrayOf(1, 2, 3)).asBytes(),
            frame.bindingDigest.asBytes(),
        )
    }

    private fun assertCode(expected: AkenR1WireException.Code, block: () -> Unit) {
        val error = assertFailsWith<AkenR1WireException>(block = block)
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
