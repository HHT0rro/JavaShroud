package io.github.hht0rro.javashroud.transforms.protection.aken

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Arrays

/**
 * The single AKEN-R1 runtime frame grammar shared with the Rust runtime.
 *
 * Payload bytes are opaque to this package. The parser validates only the
 * bounded frame envelope, and [open] does not copy or expose payload bytes
 * until the binding digest and authentication tag both match.
 */
object AkenR1WireFormat {
    const val MAGIC: String = "JSR1"
    const val VERSION: Int = 2
    const val DIGEST_SIZE: Int = 32
    const val AUTH_TAG_SIZE: Int = DIGEST_SIZE
    const val MAX_BINDING_SIZE: Int = 4 * 1024
    const val MAX_PAYLOAD_SIZE: Int = 16 * 1024 * 1024
    const val HEADER_SIZE: Int = 4 + 1 + 4 + DIGEST_SIZE
    const val MIN_FRAME_SIZE: Int = HEADER_SIZE + AUTH_TAG_SIZE
    const val MAX_FRAME_SIZE: Int = MIN_FRAME_SIZE + MAX_PAYLOAD_SIZE

    private val MAGIC_BYTES = MAGIC.toByteArray(Charsets.US_ASCII)
    internal val RUNTIME_BINDING_DOMAIN =
        "JavaShroud/AKEN-R2/RuntimeBindingDigest/v2".toByteArray(Charsets.US_ASCII)
    private val AUTHENTICATION_DOMAIN =
        "JavaShroud/AKEN-R2/AuthenticatedFrame/v2".toByteArray(Charsets.US_ASCII)

    /** Computes the domain-separated SHA-256 runtime binding digest. */
    fun runtimeBindingDigest(binding: ByteArray): RuntimeBindingDigest = RuntimeBindingDigest.compute(binding)

    /** Computes the frame tag for an already computed 32-byte binding digest. */
    fun authenticationTag(bindingDigest: ByteArray, payload: ByteArray): ByteArray {
        requireDigest(bindingDigest)
        requirePayload(payload)
        return digest(AUTHENTICATION_DOMAIN, bindingDigest, payload)
    }

    /** Encodes the current R1 frame; no retired format is accepted or emitted. */
    fun encode(binding: ByteArray, payload: ByteArray): ByteArray {
        requireBinding(binding)
        requirePayload(payload)
        val bindingDigest = RuntimeBindingDigest.compute(binding)
        val digestBytes = bindingDigest.asBytes()
        val tag = authenticationTag(digestBytes, payload)
        val writer = AkenR1FrameWriter(MAX_FRAME_SIZE)
        return try {
            writer.writeBytes(MAGIC_BYTES)
            writer.writeU8(VERSION)
            writer.writeU32Be(payload.size.toLong())
            writer.writeBytes(digestBytes)
            writer.writeBytes(payload)
            writer.writeBytes(tag)
            writer.finish()
        } finally {
            writer.close()
            Arrays.fill(digestBytes, 0)
            Arrays.fill(tag, 0)
        }
    }

    /**
     * Strictly opens one current R1 frame. Structural fields are located first,
     * but payload bytes are not copied or interpreted until authentication has
     * succeeded.
     */
    fun open(binding: ByteArray, frame: ByteArray): AkenR1AuthenticatedFrame {
        requireBinding(binding)
        val view = locate(frame)
        val expectedDigest = RuntimeBindingDigest.compute(binding)
        val expectedDigestBytes = expectedDigest.asBytes()
        var suppliedDigest: ByteArray? = null
        var suppliedTag: ByteArray? = null
        var expectedTag: ByteArray? = null
        try {
            suppliedDigest = frame.copyOfRange(view.digestOffset, view.digestOffset + DIGEST_SIZE)
            suppliedTag = frame.copyOfRange(view.authTagOffset, view.authTagOffset + AUTH_TAG_SIZE)
            expectedTag = authenticationTag(
                expectedDigestBytes,
                frame,
                view.payloadOffset,
                view.payloadLength,
            )
            val digestMatches = MessageDigest.isEqual(expectedDigestBytes, checkNotNull(suppliedDigest))
            val tagMatches = MessageDigest.isEqual(checkNotNull(expectedTag), checkNotNull(suppliedTag))
            if (!digestMatches || !tagMatches) {
                throw AkenR1WireException(
                    AkenR1WireException.Code.AUTHENTICATION_FAILED,
                    "AKEN-R1 runtime frame authentication failed",
                )
            }
            return AkenR1AuthenticatedFrame(
                bindingDigest = expectedDigest,
                payload = frame.copyOfRange(view.payloadOffset, view.payloadOffset + view.payloadLength),
            )
        } finally {
            Arrays.fill(expectedDigestBytes, 0)
            suppliedDigest?.let { Arrays.fill(it, 0) }
            suppliedTag?.let { Arrays.fill(it, 0) }
            expectedTag?.let { Arrays.fill(it, 0) }
        }
    }

    private fun locate(frame: ByteArray): FrameView {
        if (frame.size > MAX_FRAME_SIZE) {
            throw AkenR1WireException(
                AkenR1WireException.Code.FRAME_TOO_LARGE,
                "AKEN-R1 runtime frame is too large: ${frame.size} > $MAX_FRAME_SIZE",
            )
        }
        val cursor = AkenR1Cursor(frame)
        val magic = cursor.readFixed(MAGIC_BYTES.size)
        if (!magic.contentEquals(MAGIC_BYTES)) {
            throw AkenR1WireException(
                AkenR1WireException.Code.INVALID_MAGIC,
                "AKEN-R1 runtime frame magic is invalid",
            )
        }
        val version = cursor.readU8()
        if (version != VERSION) {
            throw AkenR1WireException(
                AkenR1WireException.Code.UNSUPPORTED_VERSION,
                "AKEN-R1 runtime frame version is unsupported: $version",
            )
        }
        val payloadLength = cursor.readU32Be()
        if (payloadLength > MAX_PAYLOAD_SIZE.toLong()) {
            throw AkenR1WireException(
                AkenR1WireException.Code.FRAME_TOO_LARGE,
                "AKEN-R1 runtime payload is too large: $payloadLength > $MAX_PAYLOAD_SIZE",
            )
        }
        val digestOffset = cursor.position
        cursor.skip(DIGEST_SIZE)
        val payloadOffset = cursor.position
        cursor.skip(payloadLength.toInt())
        val authTagOffset = cursor.position
        cursor.skip(AUTH_TAG_SIZE)
        cursor.requireEmpty()
        return FrameView(
            digestOffset = digestOffset,
            payloadOffset = payloadOffset,
            payloadLength = payloadLength.toInt(),
            authTagOffset = authTagOffset,
        )
    }

    private fun requireBinding(binding: ByteArray) {
        if (binding.isEmpty()) {
            throw AkenR1WireException(
                AkenR1WireException.Code.INVALID_INPUT,
                "AKEN-R1 runtime binding must not be empty",
            )
        }
        if (binding.size > MAX_BINDING_SIZE) {
            throw AkenR1WireException(
                AkenR1WireException.Code.FRAME_TOO_LARGE,
                "AKEN-R1 runtime binding is too large: ${binding.size} > $MAX_BINDING_SIZE",
            )
        }
    }

    private fun requirePayload(payload: ByteArray) {
        if (payload.size > MAX_PAYLOAD_SIZE) {
            throw AkenR1WireException(
                AkenR1WireException.Code.FRAME_TOO_LARGE,
                "AKEN-R1 runtime payload is too large: ${payload.size} > $MAX_PAYLOAD_SIZE",
            )
        }
    }

    private fun requireDigest(bindingDigest: ByteArray) {
        if (bindingDigest.size != DIGEST_SIZE) {
            throw AkenR1WireException(
                AkenR1WireException.Code.INVALID_INPUT,
                "AKEN-R1 runtime binding digest must be $DIGEST_SIZE bytes",
            )
        }
    }

    private fun authenticationTag(
        bindingDigest: ByteArray,
        frame: ByteArray,
        payloadOffset: Int,
        payloadLength: Int,
    ): ByteArray {
        requireDigest(bindingDigest)
        require(payloadOffset >= 0 && payloadLength >= 0 && payloadOffset <= frame.size - payloadLength) {
            "AKEN-R1 runtime payload range is invalid"
        }
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(AUTHENTICATION_DOMAIN)
        updateU32(digest, bindingDigest.size.toLong())
        digest.update(bindingDigest)
        updateU32(digest, payloadLength.toLong())
        digest.update(frame, payloadOffset, payloadLength)
        return digest.digest()
    }

    private fun digest(domain: ByteArray, vararg fields: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(domain)
        fields.forEach { field ->
            updateU32(digest, field.size.toLong())
            digest.update(field)
        }
        return digest.digest()
    }

    private fun updateU32(digest: MessageDigest, value: Long) {
        require(value in 0..0xFFFF_FFFFL) { "AKEN-R1 framed length exceeds u32" }
        digest.update(
            byteArrayOf(
                (value ushr 24).toByte(),
                (value ushr 16).toByte(),
                (value ushr 8).toByte(),
                value.toByte(),
            ),
        )
    }

    private data class FrameView(
        val digestOffset: Int,
        val payloadOffset: Int,
        val payloadLength: Int,
        val authTagOffset: Int,
    )
}

/** Immutable 32-byte SHA-256 runtime binding digest. */
class RuntimeBindingDigest private constructor(bytes: ByteArray) {
    private val value = bytes.copyOf()

    init {
        require(value.size == AkenR1WireFormat.DIGEST_SIZE) {
            "AKEN-R1 runtime binding digest must be ${AkenR1WireFormat.DIGEST_SIZE} bytes"
        }
    }

    fun asBytes(): ByteArray = value.copyOf()

    val bytes: ByteArray
        get() = asBytes()

    override fun equals(other: Any?): Boolean =
        other is RuntimeBindingDigest && MessageDigest.isEqual(value, other.value)

    override fun hashCode(): Int = value.contentHashCode()

    override fun toString(): String = "RuntimeBindingDigest(${value.size} bytes)"

    companion object {
        fun compute(binding: ByteArray): RuntimeBindingDigest {
            if (binding.isEmpty()) {
                throw AkenR1WireException(
                    AkenR1WireException.Code.INVALID_INPUT,
                    "AKEN-R1 runtime binding must not be empty",
                )
            }
            if (binding.size > AkenR1WireFormat.MAX_BINDING_SIZE) {
                throw AkenR1WireException(
                    AkenR1WireException.Code.FRAME_TOO_LARGE,
                    "AKEN-R1 runtime binding is too large: ${binding.size} > ${AkenR1WireFormat.MAX_BINDING_SIZE}",
                )
            }
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(AkenR1WireFormat.RUNTIME_BINDING_DOMAIN)
            digest.update(
                byteArrayOf(
                    (binding.size ushr 24).toByte(),
                    (binding.size ushr 16).toByte(),
                    (binding.size ushr 8).toByte(),
                    binding.size.toByte(),
                ),
            )
            digest.update(binding)
            return RuntimeBindingDigest(digest.digest())
        }
    }
}

/** Authenticated R1 payload; all returned byte arrays are defensive copies. */
class AkenR1AuthenticatedFrame internal constructor(
    bindingDigest: RuntimeBindingDigest,
    payload: ByteArray,
) : AutoCloseable {
    private val bindingDigestValue = bindingDigest
    // The authenticated frame takes ownership of the one payload copy made by
    // open(). Avoid a second plaintext copy that would have no owner to wipe.
    private val payloadValue = payload
    @Volatile
    private var wiped = false

    val bindingDigest: RuntimeBindingDigest
        get() = bindingDigestValue

    val payload: ByteArray
        get() = copyPayload()

    fun copyPayload(): ByteArray {
        check(!wiped) { "AKEN-R1 authenticated payload has been wiped" }
        return payloadValue.copyOf()
    }

    fun intoPayload(): ByteArray = copyPayload()

    fun wipe() {
        if (wiped) return
        Arrays.fill(payloadValue, 0)
        wiped = true
    }

    override fun close() = wipe()
}

private class WipableByteArrayOutputStream(initialSize: Int) : ByteArrayOutputStream(initialSize) {
    fun wipe() {
        Arrays.fill(buf, 0)
        count = 0
    }
}

/** Bounds-checked reader used by every Kotlin R1 wire parser. */
class AkenR1Cursor(private val bytes: ByteArray) {
    var position: Int = 0
        private set

    val remaining: Int
        get() = bytes.size - position

    fun readU8(): Int {
        requireRemaining(1)
        return bytes[position++].toInt() and 0xFF
    }

    fun readU16Be(): Int {
        return (readU8() shl 8) or readU8()
    }

    fun readU32Be(): Long {
        return (readU8().toLong() shl 24) or
            (readU8().toLong() shl 16) or
            (readU8().toLong() shl 8) or
            readU8().toLong()
    }

    fun readFixed(length: Int): ByteArray {
        requireRemaining(length)
        return bytes.copyOfRange(position, position + length).also { position += length }
    }

    fun readBytes(length: Int): ByteArray = readFixed(length)

    fun readFrame(maxLength: Int): ByteArray {
        require(maxLength >= 0) { "AKEN-R1 frame maximum length is invalid" }
        val length = readU32Be()
        if (length > maxLength.toLong()) {
            throw AkenR1WireException(
                AkenR1WireException.Code.FRAME_TOO_LARGE,
                "AKEN-R1 framed field is too large: $length > $maxLength",
            )
        }
        return readFixed(length.toInt())
    }

    fun skip(length: Int) {
        requireRemaining(length)
        position += length
    }

    fun requireEmpty() {
        if (remaining != 0) {
            throw AkenR1WireException(
                AkenR1WireException.Code.TRAILING_BYTES,
                "AKEN-R1 runtime frame has $remaining trailing bytes",
            )
        }
    }

    private fun requireRemaining(length: Int) {
        if (length < 0 || position > bytes.size || length > bytes.size - position) {
            throw AkenR1WireException(
                AkenR1WireException.Code.TRUNCATED,
                "AKEN-R1 wire input is truncated at $position: requested $length, remaining $remaining",
            )
        }
    }
}

/** Explicit bounded writer used for the fixed R1 frame. */
class AkenR1FrameWriter(private val maxSize: Int) : AutoCloseable {
    private val bytes = WipableByteArrayOutputStream(minOf(maxSize.coerceAtLeast(0), 1024))
    @Volatile
    private var closed = false

    init {
        require(maxSize >= 0) { "AKEN-R1 writer maximum size is invalid" }
    }

    val position: Int
        get() = bytes.size()

    fun writeU8(value: Int) {
        requireOpen()
        require(value in 0..0xFF) { "AKEN-R1 u8 value is invalid" }
        ensureCapacity(1)
        bytes.write(value)
    }

    fun writeU16Be(value: Int) {
        requireOpen()
        require(value in 0..0xFFFF) { "AKEN-R1 u16 value is invalid" }
        ensureCapacity(2)
        bytes.write((value ushr 8) and 0xFF)
        bytes.write(value and 0xFF)
    }

    fun writeU32Be(value: Long) {
        requireOpen()
        require(value in 0..0xFFFF_FFFFL) { "AKEN-R1 u32 value is invalid" }
        ensureCapacity(4)
        bytes.write((value ushr 24).toInt() and 0xFF)
        bytes.write((value ushr 16).toInt() and 0xFF)
        bytes.write((value ushr 8).toInt() and 0xFF)
        bytes.write(value.toInt() and 0xFF)
    }

    fun writeBytes(value: ByteArray) {
        requireOpen()
        ensureCapacity(value.size)
        bytes.write(value)
    }

    fun writeFrame(value: ByteArray) {
        requireOpen()
        val total = value.size.toLong() + 4L
        if (total > Int.MAX_VALUE.toLong()) {
            throw AkenR1WireException(
                AkenR1WireException.Code.LENGTH_OVERFLOW,
                "AKEN-R1 framed field length overflows JVM bounds",
            )
        }
        ensureCapacity(total.toInt())
        writeU32Be(value.size.toLong())
        writeBytes(value)
    }

    /** Returns an owned copy and wipes the writer's backing buffer. */
    fun finish(): ByteArray {
        requireOpen()
        val result = bytes.toByteArray()
        close()
        return result
    }

    override fun close() {
        if (closed) return
        bytes.wipe()
        closed = true
    }

    private fun requireOpen() {
        check(!closed) { "AKEN-R1 writer has been closed" }
    }

    private fun ensureCapacity(additional: Int) {
        requireOpen()
        if (additional < 0 || bytes.size().toLong() + additional.toLong() > maxSize.toLong()) {
            val requested = bytes.size().toLong() + additional.toLong()
            throw AkenR1WireException(
                AkenR1WireException.Code.FRAME_TOO_LARGE,
                "AKEN-R1 writer exceeds its bound: $requested > $maxSize",
            )
        }
    }
}

class AkenR1WireException(
    val code: Code,
    message: String,
) : IllegalArgumentException(message) {
    enum class Code {
        INVALID_INPUT,
        TRUNCATED,
        INVALID_MAGIC,
        UNSUPPORTED_VERSION,
        LENGTH_OVERFLOW,
        FRAME_TOO_LARGE,
        TRAILING_BYTES,
        AUTHENTICATION_FAILED,
    }
}
