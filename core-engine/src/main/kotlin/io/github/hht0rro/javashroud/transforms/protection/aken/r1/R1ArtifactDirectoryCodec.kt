package io.github.hht0rro.javashroud.transforms.protection.aken.r1

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays

/** Current-only serializer for one authenticated AKEN-R1 artifact directory. */
object R1ArtifactDirectorySerializer {
    const val MAGIC: String = "JSR2DIR"
    const val DIGEST_SIZE: Int = R1_DIGEST_SIZE
    const val MAX_ENTRIES: Int = 4096
    const val MAX_PATH_SIZE: Int = 4096
    const val MAX_DESCRIPTOR_SIZE: Int = 384 * 1024
    const val MAX_ENVELOPE_SIZE: Int = 4096
    const val MAX_STORED_LENGTH: Int = 16 * 1024 * 1024 + 1024
    const val MAX_DIRECTORY_SIZE: Int = 64 * 1024 * 1024

    private val magicBytes = MAGIC.toByteArray(StandardCharsets.US_ASCII)

    fun encode(directory: R1ArtifactDirectory): ByteArray {
        val entries = directory.entriesForWire()
        val runtime = directory.runtimeBindingForWire()
        val totalSize = encodedSize(runtime, entries)
        val writer = R1Writer(totalSize)
        var root: ByteArray? = null
        return try {
            root = computeDirectoryRootDigest(runtime, entries)
            writer.write(magicBytes)
            writer.writeU32(entries.size.toLong())
            writeRuntime(writer, runtime)
            entries.forEach { writePage(writer, it) }
            writer.write(checkNotNull(root))
            writer.finish()
        } finally {
            root?.let { Arrays.fill(it, 0) }
            writer.close()
        }
    }

    fun encode(
        runtimeBindingDigest: RuntimeBindingDigest,
        entries: Iterable<R1ArtifactDirectoryEntry>,
    ): ByteArray {
        val directory = R1ArtifactDirectory.create(runtimeBindingDigest, entries)
        return try {
            encode(directory)
        } finally {
            directory.wipe()
        }
    }

    fun serialize(directory: R1ArtifactDirectory): ByteArray = encode(directory)

    fun serialize(
        runtimeBindingDigest: RuntimeBindingDigest,
        entries: Iterable<R1ArtifactDirectoryEntry>,
    ): ByteArray = encode(runtimeBindingDigest, entries)

    internal fun encodedSize(
        runtime: RuntimeBindingDigest,
        entries: List<R1ArtifactPage>,
    ): Int {
        if (entries.size > MAX_ENTRIES) {
            R1ArtifactDirectoryException.fail(
                R1ArtifactDirectoryException.Code.FIELD_TOO_LARGE,
                "directory contains too many entries",
            )
        }
        val target = runtime.targetTriple.toByteArray(StandardCharsets.US_ASCII)
        val profile = runtime.payloadProfile.toByteArray(StandardCharsets.US_ASCII)
        var total = MAGIC_BYTES_SIZE + Int.SIZE_BYTES +
            4 * R1_DIGEST_SIZE + Int.SIZE_BYTES + target.size + Int.SIZE_BYTES + profile.size +
            R1_DIGEST_SIZE + R1_DIGEST_SIZE
        try {
            entries.forEach { entry ->
                val path = entry.copyPathBytesForWire()
                val descriptor = entry.copyDescriptorForWire()
                val envelope = entry.copyEnvelopeForWire()
                try {
                    val record = R1_PAGE_KEY_SIZE.toLong() +
                        Int.SIZE_BYTES.toLong() + path.size.toLong() +
                        Int.SIZE_BYTES.toLong() + Int.SIZE_BYTES.toLong() +
                        Int.SIZE_BYTES.toLong() + descriptor.size.toLong() +
                        Int.SIZE_BYTES.toLong() + envelope.size.toLong() + R1_DIGEST_SIZE.toLong()
                    total = checkedLength(total.toLong() + record, "artifact directory encoding")
                } finally {
                    Arrays.fill(path, 0)
                    Arrays.fill(descriptor, 0)
                    Arrays.fill(envelope, 0)
                }
            }
            return total
        } finally {
            Arrays.fill(target, 0)
            Arrays.fill(profile, 0)
        }
    }

    private fun writeRuntime(writer: R1Writer, runtime: RuntimeBindingDigest) {
        val artifact = runtime.artifactCommitment
        val native = runtime.nativeSha256
        val abi = runtime.abiDigest
        val specialization = runtime.specializationDigest
        val target = runtime.targetTriple.toByteArray(StandardCharsets.US_ASCII)
        val profile = runtime.payloadProfile.toByteArray(StandardCharsets.US_ASCII)
        val digest = runtime.copyDigestForWire()
        try {
            writer.write(artifact)
            writer.write(native)
            writer.write(abi)
            writer.writeFrame(target)
            writer.write(specialization)
            writer.writeFrame(profile)
            writer.write(digest)
        } finally {
            Arrays.fill(artifact, 0)
            Arrays.fill(native, 0)
            Arrays.fill(abi, 0)
            Arrays.fill(specialization, 0)
            Arrays.fill(target, 0)
            Arrays.fill(profile, 0)
            Arrays.fill(digest, 0)
        }
    }

    private fun writePage(writer: R1Writer, page: R1ArtifactPage) {
        val key = page.copyKeyBytesForWire()
        val path = page.copyPathBytesForWire()
        val descriptor = page.copyDescriptorForWire()
        val envelope = page.copyEnvelopeForWire()
        val binding = page.copyBindingForWire()
        try {
            writer.write(key)
            writer.writeFrame(path)
            writer.writeI32(page.offset)
            writer.writeI32(page.storedLength)
            writer.writeFrame(descriptor)
            writer.writeFrame(envelope)
            writer.write(binding)
        } finally {
            Arrays.fill(key, 0)
            Arrays.fill(path, 0)
            Arrays.fill(descriptor, 0)
            Arrays.fill(envelope, 0)
            Arrays.fill(binding, 0)
        }
    }

    internal const val MAGIC_BYTES_SIZE: Int = 7
}

/** Strict two-pass parser for one complete current AKEN-R1 directory. */
object R1ArtifactDirectoryParser {
    fun decode(encoded: ByteArray): R1ArtifactDirectory = decodeInternal(encoded, null)

    fun decode(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest,
    ): R1ArtifactDirectory = decodeInternal(encoded, expectedRuntimeBinding)

    fun parse(encoded: ByteArray): R1ArtifactDirectory = decode(encoded)

    fun parse(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest,
    ): R1ArtifactDirectory = decode(encoded, expectedRuntimeBinding)

    private fun decodeInternal(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest?,
    ): R1ArtifactDirectory {
        if (encoded.size > R1ArtifactDirectorySerializer.MAX_DIRECTORY_SIZE) {
            R1ArtifactDirectoryException.fail(
                R1ArtifactDirectoryException.Code.FIELD_TOO_LARGE,
                "artifact directory exceeds its bounded size",
            )
        }
        val cursor = R1Cursor(encoded)
        var artifactCommitment: ByteArray? = null
        var nativeSha256: ByteArray? = null
        var abiDigest: ByteArray? = null
        var specializationDigest: ByteArray? = null
        var suppliedRuntimeDigest: ByteArray? = null
        var runtime: RuntimeBindingDigest? = null
        var suppliedRootDigest: ByteArray? = null
        val views = ArrayList<RecordView>()
        val pages = ArrayList<R1ArtifactPage>()
        var transferred = false
        return try {
            cursor.readMagic()
            val count = cursor.readU32("directory entry count")
            if (count > R1ArtifactDirectorySerializer.MAX_ENTRIES.toLong()) {
                R1ArtifactDirectoryException.fail(
                    R1ArtifactDirectoryException.Code.FIELD_TOO_LARGE,
                    "directory entry count exceeds its bound",
                )
            }

            artifactCommitment = cursor.readFixed(R1_DIGEST_SIZE, "artifact commitment")
            nativeSha256 = cursor.readFixed(R1_DIGEST_SIZE, "native SHA-256")
            abiDigest = cursor.readFixed(R1_DIGEST_SIZE, "ABI digest")
            val targetBytes = cursor.readFrame(
                RuntimeBindingDigest.MAX_TARGET_TRIPLE_BYTES,
                "target triple",
                allowEmpty = false,
            )
            val targetTriple = try {
                decodeAscii(targetBytes, "target triple")
            } finally {
                Arrays.fill(targetBytes, 0)
            }
            specializationDigest = cursor.readFixed(R1_DIGEST_SIZE, "specialization digest")
            val profileBytes = cursor.readFrame(
                RuntimeBindingDigest.MAX_PAYLOAD_PROFILE_BYTES,
                "payload profile",
                allowEmpty = false,
            )
            val payloadProfile = try {
                decodeAscii(profileBytes, "payload profile")
            } finally {
                Arrays.fill(profileBytes, 0)
            }
            suppliedRuntimeDigest = cursor.readFixed(R1_DIGEST_SIZE, "runtime binding digest")
            runtime = RuntimeBindingDigest.fromWire(
                checkNotNull(artifactCommitment),
                checkNotNull(nativeSha256),
                checkNotNull(abiDigest),
                targetTriple,
                checkNotNull(specializationDigest),
                payloadProfile,
                checkNotNull(suppliedRuntimeDigest),
            )
            verifyExpectedRuntime(runtime, expectedRuntimeBinding)

            var previousKeyOffset = -1
            repeat(count.toInt()) {
                val keyOffset = cursor.position
                validateWireKey(encoded, keyOffset)
                cursor.skip(R1_PAGE_KEY_SIZE, "page key")
                if (previousKeyOffset >= 0) {
                    val comparison = compareUnsignedRanges(
                        encoded,
                        previousKeyOffset,
                        keyOffset,
                        R1_PAGE_KEY_SIZE,
                    )
                    if (comparison >= 0) {
                        R1ArtifactDirectoryException.fail(
                            if (comparison == 0) {
                                R1ArtifactDirectoryException.Code.DUPLICATE_KEY
                            } else {
                                R1ArtifactDirectoryException.Code.NON_CANONICAL_ORDER
                            },
                            "directory page keys are not strictly unsigned-sorted",
                        )
                    }
                }
                previousKeyOffset = keyOffset
                val pathRange = cursor.readFrameRange(
                    R1ArtifactDirectorySerializer.MAX_PATH_SIZE,
                    "relative path",
                    allowEmpty = false,
                )
                validateWirePath(encoded, pathRange)
                val offset = cursor.readI32("page offset")
                val storedLength = cursor.readI32("stored length")
                if (offset < 0 || storedLength <= 0 ||
                    storedLength > R1ArtifactDirectorySerializer.MAX_STORED_LENGTH
                ) {
                    R1ArtifactDirectoryException.fail(
                        R1ArtifactDirectoryException.Code.INVALID_INPUT,
                        "page offset/length is outside its bounded non-negative range",
                    )
                }
                val descriptorRange = cursor.readFrameRange(
                    R1ArtifactDirectorySerializer.MAX_DESCRIPTOR_SIZE,
                    "descriptor",
                    allowEmpty = false,
                )
                val envelopeRange = cursor.readFrameRange(
                    R1ArtifactDirectorySerializer.MAX_ENVELOPE_SIZE,
                    "envelope",
                    allowEmpty = false,
                )
                val bindingOffset = cursor.position
                cursor.skip(R1_DIGEST_SIZE, "record binding digest")
                views += RecordView(
                    keyOffset,
                    pathRange,
                    offset,
                    storedLength,
                    descriptorRange,
                    envelopeRange,
                    bindingOffset,
                )
            }
            suppliedRootDigest = cursor.readFixed(R1_DIGEST_SIZE, "directory root digest")
            cursor.requireEmpty()

            val runtimeDigest = runtime.copyDigestForWire()
            try {
                views.forEach { view ->
                    val expectedBinding = computeRecordBindingFromWire(runtimeDigest, encoded, view)
                    try {
                        if (!constantTimeRangeEquals(expectedBinding, encoded, view.bindingOffset)) {
                            R1ArtifactDirectoryException.fail(
                                R1ArtifactDirectoryException.Code.AUTHENTICATION_FAILED,
                                "record binding digest does not match its opaque fields",
                            )
                        }
                    } finally {
                        Arrays.fill(expectedBinding, 0)
                    }
                }
            } finally {
                Arrays.fill(runtimeDigest, 0)
            }

            val expectedRoot = computeDirectoryRootDigestFromWire(
                runtime,
                suppliedRuntimeDigest,
                encoded,
                count.toInt(),
                views,
            )
            try {
                if (!constantTimeEquals(expectedRoot, checkNotNull(suppliedRootDigest))) {
                    R1ArtifactDirectoryException.fail(
                        R1ArtifactDirectoryException.Code.AUTHENTICATION_FAILED,
                        "directory root digest does not match its authenticated body",
                    )
                }
            } finally {
                Arrays.fill(expectedRoot, 0)
            }

            // Second pass: only now copy opaque descriptor/envelope ranges into owners.
            views.forEach { view ->
                var key: PageKey? = null
                var descriptor: ByteArray? = null
                var envelope: ByteArray? = null
                var binding: ByteArray? = null
                var pathBytes: ByteArray? = null
                var page: R1ArtifactPage? = null
                try {
                    val keyBytes = encoded.copyOfRange(view.keyOffset, view.keyOffset + R1_PAGE_KEY_SIZE)
                    key = try {
                        PageKey.fromBytes(keyBytes)
                    } finally {
                        Arrays.fill(keyBytes, 0)
                    }
                    pathBytes = encoded.copyOfRange(
                        view.pathRange.offset,
                        view.pathRange.offset + view.pathRange.length,
                    )
                    val path = decodeUtf8(checkNotNull(pathBytes), "relative path")
                    descriptor = encoded.copyOfRange(
                        view.descriptorRange.offset,
                        view.descriptorRange.offset + view.descriptorRange.length,
                    )
                    envelope = encoded.copyOfRange(
                        view.envelopeRange.offset,
                        view.envelopeRange.offset + view.envelopeRange.length,
                    )
                    binding = encoded.copyOfRange(view.bindingOffset, view.bindingOffset + R1_DIGEST_SIZE)
                    page = R1ArtifactPage.fromVerified(
                        checkNotNull(key),
                        path,
                        view.offset,
                        view.storedLength,
                        checkNotNull(descriptor),
                        checkNotNull(envelope),
                        checkNotNull(binding),
                    )
                    pages += checkNotNull(page)
                    key = null
                    descriptor = null
                    envelope = null
                    binding = null
                    page = null
                } finally {
                    key?.wipe()
                    descriptor?.let { Arrays.fill(it, 0) }
                    envelope?.let { Arrays.fill(it, 0) }
                    binding?.let { Arrays.fill(it, 0) }
                    pathBytes?.let { Arrays.fill(it, 0) }
                    page?.wipe()
                }
            }

            val result = R1ArtifactDirectory.fromDecoded(
                checkNotNull(runtime),
                pages,
                checkNotNull(suppliedRootDigest),
            )
            transferred = true
            result
        } finally {
            artifactCommitment?.let { Arrays.fill(it, 0) }
            nativeSha256?.let { Arrays.fill(it, 0) }
            abiDigest?.let { Arrays.fill(it, 0) }
            specializationDigest?.let { Arrays.fill(it, 0) }
            suppliedRuntimeDigest?.let { Arrays.fill(it, 0) }
            if (!transferred) {
                runtime?.wipe()
                pages.forEach { it.wipe() }
                suppliedRootDigest?.let { Arrays.fill(it, 0) }
            }
        }
    }

    private fun verifyExpectedRuntime(
        actual: RuntimeBindingDigest,
        expected: RuntimeBindingDigest?,
    ) {
        if (expected == null) return
        val actualDigest = actual.copyDigestForWire()
        val expectedDigest = expected.asBytes()
        try {
            if (!MessageDigest.isEqual(actualDigest, expectedDigest)) {
                R1ArtifactDirectoryException.fail(
                    R1ArtifactDirectoryException.Code.RUNTIME_BINDING_MISMATCH,
                    "directory runtime binding does not match the expected runtime",
                )
            }
        } finally {
            Arrays.fill(actualDigest, 0)
            Arrays.fill(expectedDigest, 0)
        }
    }

    internal data class RecordView(
        val keyOffset: Int,
        val pathRange: ByteRange,
        val offset: Int,
        val storedLength: Int,
        val descriptorRange: ByteRange,
        val envelopeRange: ByteRange,
        val bindingOffset: Int,
    )

    internal data class ByteRange(val offset: Int, val length: Int)

    private class R1Cursor(private val bytes: ByteArray) {
        var position: Int = 0
            private set

        fun readMagic() {
            requireRemaining(R1ArtifactDirectorySerializer.MAGIC_BYTES_SIZE, "directory magic")
            for (index in 0 until R1ArtifactDirectorySerializer.MAGIC_BYTES_SIZE) {
                if (bytes[position + index] != R1ArtifactDirectorySerializer.MAGIC[index].code.toByte()) {
                    R1ArtifactDirectoryException.fail(
                        R1ArtifactDirectoryException.Code.INVALID_MAGIC,
                        "AKEN-R1 artifact directory magic is invalid",
                    )
                }
            }
            position += R1ArtifactDirectorySerializer.MAGIC_BYTES_SIZE
        }

        fun readU32(field: String): Long {
            requireRemaining(Int.SIZE_BYTES, field)
            val value =
                ((bytes[position].toLong() and 0xFFL) shl 24) or
                    ((bytes[position + 1].toLong() and 0xFFL) shl 16) or
                    ((bytes[position + 2].toLong() and 0xFFL) shl 8) or
                    (bytes[position + 3].toLong() and 0xFFL)
            position += Int.SIZE_BYTES
            return value
        }

        fun readI32(field: String): Int = readU32(field).toInt()

        fun readFixed(length: Int, field: String): ByteArray {
            requireRemaining(length, field)
            return bytes.copyOfRange(position, position + length).also { position += length }
        }

        fun readFrame(maximum: Int, field: String, allowEmpty: Boolean): ByteArray {
            val range = readFrameRange(maximum, field, allowEmpty)
            return bytes.copyOfRange(range.offset, range.offset + range.length)
        }

        fun readFrameRange(maximum: Int, field: String, allowEmpty: Boolean): ByteRange {
            val length = readU32("$field length")
            if (length > maximum.toLong() || (!allowEmpty && length == 0L)) {
                R1ArtifactDirectoryException.fail(
                    if (length > maximum.toLong()) {
                        R1ArtifactDirectoryException.Code.FIELD_TOO_LARGE
                    } else {
                        R1ArtifactDirectoryException.Code.INVALID_INPUT
                    },
                    "$field length is outside its bound",
                )
            }
            if (length > Int.MAX_VALUE.toLong()) {
                R1ArtifactDirectoryException.fail(
                    R1ArtifactDirectoryException.Code.LENGTH_OVERFLOW,
                    "$field length overflows JVM bounds",
                )
            }
            val intLength = length.toInt()
            requireRemaining(intLength, field)
            return ByteRange(position, intLength).also { position += intLength }
        }

        fun skip(length: Int, field: String) {
            requireRemaining(length, field)
            position += length
        }

        fun requireEmpty() {
            if (position != bytes.size) {
                R1ArtifactDirectoryException.fail(
                    R1ArtifactDirectoryException.Code.TRAILING_BYTES,
                    "artifact directory has ${bytes.size - position} trailing bytes",
                )
            }
        }

        private fun requireRemaining(length: Int, field: String) {
            if (length < 0 || position < 0 || position > bytes.size || length > bytes.size - position) {
                R1ArtifactDirectoryException.fail(
                    R1ArtifactDirectoryException.Code.TRUNCATED,
                    "$field is truncated",
                )
            }
        }
    }
}

/** Convenience facade exposing the same current-only serializer/parser pair. */
object R1ArtifactDirectoryWireFormat {
    const val MAGIC: String = R1ArtifactDirectorySerializer.MAGIC

    fun encode(directory: R1ArtifactDirectory): ByteArray = R1ArtifactDirectorySerializer.encode(directory)

    fun encode(
        runtimeBindingDigest: RuntimeBindingDigest,
        entries: Iterable<R1ArtifactDirectoryEntry>,
    ): ByteArray = R1ArtifactDirectorySerializer.encode(runtimeBindingDigest, entries)

    fun decode(encoded: ByteArray): R1ArtifactDirectory = R1ArtifactDirectoryParser.decode(encoded)

    fun decode(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest,
    ): R1ArtifactDirectory = R1ArtifactDirectoryParser.decode(encoded, expectedRuntimeBinding)
}

object R1ArtifactDirectoryCodec {
    fun encode(directory: R1ArtifactDirectory): ByteArray = R1ArtifactDirectorySerializer.encode(directory)

    fun decode(encoded: ByteArray): R1ArtifactDirectory = R1ArtifactDirectoryParser.decode(encoded)

    fun decode(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest,
    ): R1ArtifactDirectory = R1ArtifactDirectoryParser.decode(encoded, expectedRuntimeBinding)
}

internal fun computeRecordBinding(
    runtimeBindingDigest: RuntimeBindingDigest,
    key: PageKey,
    relativePath: String,
    offset: Int,
    storedLength: Int,
    descriptor: ByteArray,
    envelope: ByteArray,
): ByteArray {
    validatePageFields(relativePath, offset, storedLength, descriptor, envelope)
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(RECORD_BINDING_DOMAIN)
    val runtimeBytes = runtimeBindingDigest.copyDigestForWire()
    val pathBytes = relativePath.toByteArray(StandardCharsets.UTF_8)
    try {
        digest.update(runtimeBytes)
        key.updateDigest(digest)
        updateFramed(digest, pathBytes)
        updateI32(digest, offset)
        updateI32(digest, storedLength)
        updateFramed(digest, descriptor)
        updateFramed(digest, envelope)
        return digest.digest()
    } finally {
        Arrays.fill(runtimeBytes, 0)
        Arrays.fill(pathBytes, 0)
    }
}

private fun computeRecordBindingFromWire(
    runtimeDigest: ByteArray,
    bytes: ByteArray,
    view: R1ArtifactDirectoryParser.RecordView,
): ByteArray = MessageDigest.getInstance("SHA-256").also { digest ->
    digest.update(RECORD_BINDING_DOMAIN)
    digest.update(runtimeDigest)
    digest.update(bytes, view.keyOffset, R1_PAGE_KEY_SIZE)
    updateFramedRange(digest, bytes, view.pathRange)
    updateI32(digest, view.offset)
    updateI32(digest, view.storedLength)
    updateFramedRange(digest, bytes, view.descriptorRange)
    updateFramedRange(digest, bytes, view.envelopeRange)
}.digest()

internal fun computeDirectoryRootDigest(
    runtime: RuntimeBindingDigest,
    entries: List<R1ArtifactPage>,
): ByteArray = MessageDigest.getInstance("SHA-256").also { digest ->
    digest.update(ROOT_BINDING_DOMAIN)
    updateU32(digest, entries.size.toLong())
    runtime.updateCanonical(digest)
    val runtimeDigest = runtime.copyDigestForWire()
    try {
        digest.update(runtimeDigest)
        entries.forEach { it.updateRootDigest(digest) }
    } finally {
        Arrays.fill(runtimeDigest, 0)
    }
}.digest()

private fun computeDirectoryRootDigestFromWire(
    runtime: RuntimeBindingDigest,
    suppliedRuntimeDigest: ByteArray?,
    bytes: ByteArray,
    count: Int,
    views: List<R1ArtifactDirectoryParser.RecordView>,
): ByteArray = MessageDigest.getInstance("SHA-256").also { digest ->
    digest.update(ROOT_BINDING_DOMAIN)
    updateU32(digest, count.toLong())
    runtime.updateCanonical(digest)
    digest.update(checkNotNull(suppliedRuntimeDigest))
    views.forEach { view ->
        digest.update(bytes, view.keyOffset, R1_PAGE_KEY_SIZE)
        updateFramedRange(digest, bytes, view.pathRange)
        updateI32(digest, view.offset)
        updateI32(digest, view.storedLength)
        updateFramedRange(digest, bytes, view.descriptorRange)
        updateFramedRange(digest, bytes, view.envelopeRange)
        digest.update(bytes, view.bindingOffset, R1_DIGEST_SIZE)
    }
}.digest()

private fun updateFramedRange(
    digest: MessageDigest,
    bytes: ByteArray,
    range: R1ArtifactDirectoryParser.ByteRange,
) {
    updateU32(digest, range.length.toLong())
    digest.update(bytes, range.offset, range.length)
}

private fun validateWireKey(bytes: ByteArray, offset: Int) {
    if (offset < 0 || offset > bytes.size - R1_PAGE_KEY_SIZE) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.TRUNCATED,
            "page key is truncated",
        )
    }
    if (io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind.fromId(bytes[offset].toInt() and 0xFF) == null) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.INVALID_INPUT,
            "page key resource kind is unknown",
        )
    }
    val pageIndex =
        ((bytes[offset + 1].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 8) or
            (bytes[offset + 4].toInt() and 0xFF)
    if (pageIndex < 0) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.INVALID_INPUT,
            "page index must be non-negative",
        )
    }
}

private fun validateWirePath(bytes: ByteArray, range: R1ArtifactDirectoryParser.ByteRange) {
    val pathBytes = bytes.copyOfRange(range.offset, range.offset + range.length)
    try {
        validateNormalizedRelativePath(decodeUtf8(pathBytes, "relative path"))
    } finally {
        Arrays.fill(pathBytes, 0)
    }
}

private fun decodeAscii(bytes: ByteArray, field: String): String {
    if (bytes.isEmpty() || bytes.any { it.toInt() !in 0x20..0x7E }) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.INVALID_INPUT,
            "$field must be printable ASCII",
        )
    }
    return String(bytes, StandardCharsets.US_ASCII)
}

private fun decodeUtf8(bytes: ByteArray, field: String): String {
    return try {
        StandardCharsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: CharacterCodingException) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.INVALID_INPUT,
            "$field is not valid UTF-8",
        )
    }
}

private fun constantTimeEquals(left: ByteArray, right: ByteArray): Boolean =
    MessageDigest.isEqual(left, right)

private fun constantTimeRangeEquals(expected: ByteArray, source: ByteArray, offset: Int): Boolean {
    if (offset < 0 || offset > source.size - expected.size) return false
    var difference = 0
    for (index in expected.indices) {
        difference = difference or ((expected[index].toInt() xor source[offset + index].toInt()) and 0xFF)
    }
    return difference == 0
}

private fun compareUnsignedRanges(bytes: ByteArray, leftOffset: Int, rightOffset: Int, length: Int): Int {
    for (index in 0 until length) {
        val left = bytes[leftOffset + index].toInt() and 0xFF
        val right = bytes[rightOffset + index].toInt() and 0xFF
        if (left != right) return left.compareTo(right)
    }
    return 0
}

private class R1Writer(private val maximum: Int) : AutoCloseable {
    private val bytes = ByteArray(maximum)
    private var position = 0
    private var closed = false

    fun write(value: ByteArray) {
        requireOpen()
        ensure(value.size)
        value.copyInto(bytes, position)
        position += value.size
    }

    fun writeU32(value: Long) {
        requireOpen()
        ensure(Int.SIZE_BYTES)
        writeU32Into(bytes, position, value)
        position += Int.SIZE_BYTES
    }

    fun writeI32(value: Int) = writeU32(value.toLong() and 0xFFFF_FFFFL)

    fun writeFrame(value: ByteArray) {
        writeU32(value.size.toLong())
        write(value)
    }

    fun finish(): ByteArray {
        requireOpen()
        val result = bytes.copyOf(position)
        close()
        return result
    }

    override fun close() {
        if (closed) return
        Arrays.fill(bytes, 0)
        position = 0
        closed = true
    }

    private fun ensure(additional: Int) {
        if (additional < 0 || position > maximum - additional) {
            R1ArtifactDirectoryException.fail(
                R1ArtifactDirectoryException.Code.LENGTH_OVERFLOW,
                "artifact directory writer exceeded its checked bound",
            )
        }
    }

    private fun requireOpen() {
        check(!closed) { "artifact directory writer has been closed" }
    }
}

private const val RECORD_BINDING_DOMAIN_TEXT = "JavaShroud/AKEN-R2/ArtifactDirectory/RecordBinding"
private val RECORD_BINDING_DOMAIN = RECORD_BINDING_DOMAIN_TEXT.toByteArray(StandardCharsets.US_ASCII)
private val ROOT_BINDING_DOMAIN =
    "JavaShroud/AKEN-R2/ArtifactDirectory/RootBinding".toByteArray(StandardCharsets.US_ASCII)
