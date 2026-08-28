package io.github.hht0rro.javashroud.transforms.protection.qp.catalog

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays

/** Current-only serializer for one authenticated AKEN-R1 artifact directory. */
object QpDirectorySerializer {
    const val FORMAT_VERSION: Int = io.github.hht0rro.javashroud.transforms.protection.hardening.ProtectionFormat.CURRENT
    const val DIGEST_SIZE: Int = QP_DIGEST_SIZE
    const val MAX_ENTRIES: Int = 4096
    const val MAX_PATH_SIZE: Int = 4096
    const val MAX_DESCRIPTOR_SIZE: Int = 384 * 1024
    const val MAX_ENVELOPE_SIZE: Int = 4096
    const val MAX_STORED_LENGTH: Int = 16 * 1024 * 1024 + 1024
    const val MAX_DIRECTORY_SIZE: Int = 64 * 1024 * 1024

    fun encode(directory: QpArtifactDirectory): ByteArray {
        val entries = directory.entriesForWire()
        val runtime = directory.runtimeBindingForWire()
        val nameSeed = directory.copyNameSeed()
        val totalSize = encodedSize(runtime, entries)
        val writer = QpDirectoryWriter(totalSize)
        var root: ByteArray? = null
        var magic: ByteArray? = null
        return try {
            val commitment = runtime.artifactCommitment
            val schedule = io.github.hht0rro.javashroud.transforms.protection.qp.qpNameSchedule(commitment, nameSeed)
            try {
                magic = schedule.deriveMagic(io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_DIRECTORY)
                root = computeDirectoryRootDigest(runtime, entries)
            } finally {
                schedule.close()
                java.util.Arrays.fill(commitment, 0)
            }
            writer.writeU8(FORMAT_VERSION)
            writer.writeU8(io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.CURRENT_VERSION)
            writer.write(nameSeed)
            writer.write(checkNotNull(magic))
            writer.writeU32(entries.size.toLong())
            writeRuntime(writer, runtime)
            val blobs = uniquePathBlobs(entries)
            writer.writeU32(blobs.size.toLong())
            blobs.forEach { writer.writeFrame(it) }
            val blobIndex = blobIndexByPath(blobs)
            entries.forEach { writePage(writer, it, blobIndex) }
            blobs.forEach { Arrays.fill(it, 0) }
            writer.write(checkNotNull(root))
            writer.finish()
        } finally {
            root?.let { Arrays.fill(it, 0) }
            magic?.let { Arrays.fill(it, 0) }
            Arrays.fill(nameSeed, 0)
            writer.close()
        }
    }

    fun encode(
        runtimeBindingDigest: RuntimeBindingDigest,
        entries: Iterable<QpDirectoryEntry>,
    ): ByteArray {
        val directory = QpArtifactDirectory.create(runtimeBindingDigest, entries)
        return try {
            encode(directory)
        } finally {
            directory.wipe()
        }
    }

    fun serialize(directory: QpArtifactDirectory): ByteArray = encode(directory)

    fun serialize(
        runtimeBindingDigest: RuntimeBindingDigest,
        entries: Iterable<QpDirectoryEntry>,
    ): ByteArray = encode(runtimeBindingDigest, entries)

    internal fun encodedSize(
        runtime: RuntimeBindingDigest,
        entries: List<QpArtifactPage>,
    ): Int {
        if (entries.size > MAX_ENTRIES) {
            QpDirectoryException.fail(
                QpDirectoryException.Code.FIELD_TOO_LARGE,
                "directory contains too many entries",
            )
        }
        val target = runtime.targetTriple.toByteArray(StandardCharsets.US_ASCII)
        val profile = runtime.payloadProfile.toByteArray(StandardCharsets.US_ASCII)
        var total = MAGIC_BYTES_SIZE + Int.SIZE_BYTES +
            4 * QP_DIGEST_SIZE + Int.SIZE_BYTES + target.size + Int.SIZE_BYTES + profile.size +
            QP_DIGEST_SIZE + QP_DIGEST_SIZE + Int.SIZE_BYTES
        try {
            val blobs = uniquePathBlobs(entries)
            blobs.forEach { path ->
                total = checkedLength(
                    total.toLong() + Int.SIZE_BYTES.toLong() + path.size.toLong(),
                    "artifact directory encoding",
                )
            }
            entries.forEach { entry ->
                val descriptor = entry.copyDescriptorForWire()
                val envelope = entry.copyEnvelopeForWire()
                try {
                    val record = QP_PAGE_KEY_SIZE.toLong() +
                        2L +
                        Int.SIZE_BYTES.toLong() + Int.SIZE_BYTES.toLong() +
                        Int.SIZE_BYTES.toLong() + descriptor.size.toLong() +
                        Int.SIZE_BYTES.toLong() + envelope.size.toLong() + QP_DIGEST_SIZE.toLong()
                    total = checkedLength(total.toLong() + record, "artifact directory encoding")
                } finally {
                    Arrays.fill(descriptor, 0)
                    Arrays.fill(envelope, 0)
                }
            }
            blobs.forEach { Arrays.fill(it, 0) }
            return total
        } finally {
            Arrays.fill(target, 0)
            Arrays.fill(profile, 0)
        }
    }

    private fun writeRuntime(writer: QpDirectoryWriter, runtime: RuntimeBindingDigest) {
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

    private fun writePage(
        writer: QpDirectoryWriter,
        page: QpArtifactPage,
        blobIndex: Map<String, Int>,
    ) {
        val key = page.copyKeyBytesForWire()
        val path = page.copyPathBytesForWire()
        val descriptor = page.copyDescriptorForWire()
        val envelope = page.copyEnvelopeForWire()
        val binding = page.copyBindingForWire()
        try {
            val index = blobIndex[String(path, StandardCharsets.UTF_8)]
                ?: QpDirectoryException.fail(
                    QpDirectoryException.Code.INVALID_INPUT,
                    "directory path blob is missing",
                )
            writer.write(key)
            writer.writeU16(index)
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

    private fun uniquePathBlobs(entries: List<QpArtifactPage>): List<ByteArray> {
        val blobs = LinkedHashMap<String, ByteArray>()
        entries.forEach { page ->
            val path = page.copyPathBytesForWire()
            val key = String(path, StandardCharsets.UTF_8)
            if (key in blobs) {
                Arrays.fill(path, 0)
            } else {
                blobs[key] = path
            }
        }
        if (blobs.size > 0xFFFF) {
            QpDirectoryException.fail(
                QpDirectoryException.Code.FIELD_TOO_LARGE,
                "directory path blob count exceeds its bound",
            )
        }
        return blobs.values.toList()
    }

    private fun blobIndexByPath(blobs: List<ByteArray>): Map<String, Int> =
        blobs.withIndex().associate { (index, path) -> String(path, StandardCharsets.UTF_8) to index }

    internal const val MAGIC_BYTES_SIZE: Int = 1 + 1 + 16 + 4
}

/** Strict two-pass parser for one complete current AKEN-R1 directory. */
object QpDirectoryParser {
    fun decode(encoded: ByteArray): QpArtifactDirectory = decodeInternal(encoded, null)

    fun decode(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest,
    ): QpArtifactDirectory = decodeInternal(encoded, expectedRuntimeBinding)

    fun parse(encoded: ByteArray): QpArtifactDirectory = decode(encoded)

    fun parse(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest,
    ): QpArtifactDirectory = decode(encoded, expectedRuntimeBinding)

    private fun decodeInternal(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest?,
    ): QpArtifactDirectory {
        if (encoded.size > QpDirectorySerializer.MAX_DIRECTORY_SIZE) {
            QpDirectoryException.fail(
                QpDirectoryException.Code.FIELD_TOO_LARGE,
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
        val pages = ArrayList<QpArtifactPage>()
        var transferred = false
        return try {
            cursor.rejectRetiredDirectoryMagic()
            val formatVersion = cursor.readU8("directory format version")
            if (formatVersion != QpDirectorySerializer.FORMAT_VERSION) {
                QpDirectoryException.fail(
                    QpDirectoryException.Code.INVALID_MAGIC,
                    "directory format version is unsupported",
                )
            }
            val scheduleVersion = cursor.readU8("name schedule version")
            if (scheduleVersion != io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.CURRENT_VERSION) {
                QpDirectoryException.fail(
                    QpDirectoryException.Code.INVALID_MAGIC,
                    "name schedule version is unsupported",
                )
            }
            val nameSeed = cursor.readFixed(16, "name seed")
            val claimedMagic = cursor.readFixed(4, "derived directory magic")
            val count = cursor.readU32("directory entry count")
            if (count > QpDirectorySerializer.MAX_ENTRIES.toLong()) {
                QpDirectoryException.fail(
                    QpDirectoryException.Code.FIELD_TOO_LARGE,
                    "directory entry count exceeds its bound",
                )
            }

            artifactCommitment = cursor.readFixed(QP_DIGEST_SIZE, "artifact commitment")
            nativeSha256 = cursor.readFixed(QP_DIGEST_SIZE, "native SHA-256")
            abiDigest = cursor.readFixed(QP_DIGEST_SIZE, "ABI digest")
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
            specializationDigest = cursor.readFixed(QP_DIGEST_SIZE, "specialization digest")
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
            suppliedRuntimeDigest = cursor.readFixed(QP_DIGEST_SIZE, "runtime binding digest")
            runtime = RuntimeBindingDigest.fromWire(
                checkNotNull(artifactCommitment),
                checkNotNull(nativeSha256),
                checkNotNull(abiDigest),
                targetTriple,
                checkNotNull(specializationDigest),
                payloadProfile,
                checkNotNull(suppliedRuntimeDigest),
                nameSeed,
            )
            verifyExpectedRuntime(runtime, expectedRuntimeBinding)
            val schedule = io.github.hht0rro.javashroud.transforms.protection.qp.qpNameSchedule(
                checkNotNull(runtime).artifactCommitment,
                nameSeed,
            )
            val recordDomain = schedule.deriveDomain(
                io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_DIRECTORY,
                io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.LANE_DIR_RECORD,
            )
            val rootDomain = schedule.deriveDomain(
                io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_DIRECTORY,
                io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.LANE_DIR_ROOT,
            )
            val expectedMagic = schedule.deriveMagic(
                io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_DIRECTORY,
            )
            try {
                if (!java.security.MessageDigest.isEqual(claimedMagic, expectedMagic)) {
                    QpDirectoryException.fail(
                        QpDirectoryException.Code.AUTHENTICATION_FAILED,
                        "derived directory magic does not match name seed",
                    )
                }
            } finally {
                java.util.Arrays.fill(expectedMagic, 0)
            }
            schedule.close()

            val blobCount = cursor.readU32("directory path blob count")
            if (blobCount > QpDirectorySerializer.MAX_ENTRIES.toLong()) {
                QpDirectoryException.fail(
                    QpDirectoryException.Code.FIELD_TOO_LARGE,
                    "directory path blob count exceeds its bound",
                )
            }
            val blobRanges = ArrayList<ByteRange>(blobCount.toInt())
            repeat(blobCount.toInt()) {
                blobRanges += cursor.readFrameRange(
                    QpDirectorySerializer.MAX_PATH_SIZE,
                    "path blob",
                    allowEmpty = false,
                )
                validateWirePath(encoded, blobRanges.last())
            }

            var previousKeyOffset = -1
            repeat(count.toInt()) {
                val keyOffset = cursor.position
                validateWireKey(encoded, keyOffset)
                cursor.skip(QP_PAGE_KEY_SIZE, "page key")
                if (previousKeyOffset >= 0) {
                    val comparison = compareUnsignedRanges(
                        encoded,
                        previousKeyOffset,
                        keyOffset,
                        QP_PAGE_KEY_SIZE,
                    )
                    if (comparison >= 0) {
                        QpDirectoryException.fail(
                            if (comparison == 0) {
                                QpDirectoryException.Code.DUPLICATE_KEY
                            } else {
                                QpDirectoryException.Code.NON_CANONICAL_ORDER
                            },
                            "directory page keys are not strictly unsigned-sorted",
                        )
                    }
                }
                previousKeyOffset = keyOffset
                val blobIndex = cursor.readU16("path blob index")
                if (blobIndex >= blobRanges.size) {
                    QpDirectoryException.fail(
                        QpDirectoryException.Code.INVALID_INPUT,
                        "directory path blob index is out of range",
                    )
                }
                val pathRange = blobRanges[blobIndex]
                val offset = cursor.readI32("page offset")
                val storedLength = cursor.readI32("stored length")
                if (offset < 0 || storedLength <= 0 ||
                    storedLength > QpDirectorySerializer.MAX_STORED_LENGTH
                ) {
                    QpDirectoryException.fail(
                        QpDirectoryException.Code.INVALID_INPUT,
                        "page offset/length is outside its bounded non-negative range",
                    )
                }
                val descriptorRange = cursor.readFrameRange(
                    QpDirectorySerializer.MAX_DESCRIPTOR_SIZE,
                    "descriptor",
                    allowEmpty = false,
                )
                val envelopeRange = cursor.readFrameRange(
                    QpDirectorySerializer.MAX_ENVELOPE_SIZE,
                    "envelope",
                    allowEmpty = false,
                )
                val bindingOffset = cursor.position
                cursor.skip(QP_DIGEST_SIZE, "record binding digest")
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
            suppliedRootDigest = cursor.readFixed(QP_DIGEST_SIZE, "directory root digest")
            cursor.requireEmpty()

            val runtimeDigest = runtime.copyDigestForWire()
            try {
                views.forEach { view ->
                    val expectedBinding = computeRecordBindingFromWire(runtimeDigest, encoded, view, recordDomain)
                    try {
                        if (!constantTimeRangeEquals(expectedBinding, encoded, view.bindingOffset)) {
                            QpDirectoryException.fail(
                                QpDirectoryException.Code.AUTHENTICATION_FAILED,
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
                rootDomain,
            )
            try {
                if (!constantTimeEquals(expectedRoot, checkNotNull(suppliedRootDigest))) {
                    QpDirectoryException.fail(
                        QpDirectoryException.Code.AUTHENTICATION_FAILED,
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
                var page: QpArtifactPage? = null
                try {
                    val keyBytes = encoded.copyOfRange(view.keyOffset, view.keyOffset + QP_PAGE_KEY_SIZE)
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
                    binding = encoded.copyOfRange(view.bindingOffset, view.bindingOffset + QP_DIGEST_SIZE)
                    page = QpArtifactPage.fromVerified(
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

            val result = QpArtifactDirectory.fromDecoded(
                checkNotNull(runtime),
                pages,
                checkNotNull(suppliedRootDigest),
                nameSeed,
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
                QpDirectoryException.fail(
                    QpDirectoryException.Code.RUNTIME_BINDING_MISMATCH,
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

        fun readU8(field: String): Int {
            requireRemaining(1, field)
            val value = bytes[position].toInt() and 0xFF
            position += 1
            return value
        }

        fun rejectRetiredDirectoryMagic() {
            val retired = hexBytes(
                io.github.hht0rro.javashroud.transforms.protection.hardening.ProtectionFormat.RETIRED_DIRECTORY_MAGIC_HEX,
            )
            if (bytes.size >= retired.size) {
                var same = true
                for (index in retired.indices) {
                    if (bytes[index] != retired[index]) {
                        same = false
                        break
                    }
                }
                if (same) {
                    QpDirectoryException.fail(
                        QpDirectoryException.Code.INVALID_MAGIC,
                        "retired directory magic is rejected",
                    )
                }
            }
        }

        fun readU16(field: String): Int {
            requireRemaining(2, field)
            val value =
                ((bytes[position].toInt() and 0xFF) shl 8) or
                    (bytes[position + 1].toInt() and 0xFF)
            position += 2
            return value
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
                QpDirectoryException.fail(
                    if (length > maximum.toLong()) {
                        QpDirectoryException.Code.FIELD_TOO_LARGE
                    } else {
                        QpDirectoryException.Code.INVALID_INPUT
                    },
                    "$field length is outside its bound",
                )
            }
            if (length > Int.MAX_VALUE.toLong()) {
                QpDirectoryException.fail(
                    QpDirectoryException.Code.LENGTH_OVERFLOW,
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
                QpDirectoryException.fail(
                    QpDirectoryException.Code.TRAILING_BYTES,
                    "artifact directory has ${bytes.size - position} trailing bytes",
                )
            }
        }

        private fun requireRemaining(length: Int, field: String) {
            if (length < 0 || position < 0 || position > bytes.size || length > bytes.size - position) {
                QpDirectoryException.fail(
                    QpDirectoryException.Code.TRUNCATED,
                    "$field is truncated",
                )
            }
        }
    }
}

/** Convenience facade exposing the same current-only serializer/parser pair. */
object QpDirectoryWireFormat {
    const val FORMAT_VERSION: Int = QpDirectorySerializer.FORMAT_VERSION

    fun encode(directory: QpArtifactDirectory): ByteArray = QpDirectorySerializer.encode(directory)

    fun encode(
        runtimeBindingDigest: RuntimeBindingDigest,
        entries: Iterable<QpDirectoryEntry>,
    ): ByteArray = QpDirectorySerializer.encode(runtimeBindingDigest, entries)

    fun decode(encoded: ByteArray): QpArtifactDirectory = QpDirectoryParser.decode(encoded)

    fun decode(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest,
    ): QpArtifactDirectory = QpDirectoryParser.decode(encoded, expectedRuntimeBinding)
}

object QpDirectoryCodec {
    fun encode(directory: QpArtifactDirectory): ByteArray = QpDirectorySerializer.encode(directory)

    fun decode(encoded: ByteArray): QpArtifactDirectory = QpDirectoryParser.decode(encoded)

    fun decode(
        encoded: ByteArray,
        expectedRuntimeBinding: RuntimeBindingDigest,
    ): QpArtifactDirectory = QpDirectoryParser.decode(encoded, expectedRuntimeBinding)
}

private fun hexBytes(hex: String): ByteArray = ByteArray(hex.length / 2) { index ->
    hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
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
    val commitment = runtimeBindingDigest.artifactCommitment
    val schedule = io.github.hht0rro.javashroud.transforms.protection.qp.qpNameSchedule(commitment)
    val domain = schedule.deriveDomain(
        io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_DIRECTORY,
        io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.LANE_DIR_RECORD,
    )
    digest.update(domain)
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
        Arrays.fill(domain, 0)
        Arrays.fill(commitment, 0)
        schedule.close()
    }
}

private fun computeRecordBindingFromWire(
    runtimeDigest: ByteArray,
    bytes: ByteArray,
    view: QpDirectoryParser.RecordView,
    recordDomain: ByteArray,
): ByteArray = MessageDigest.getInstance("SHA-256").also { digest ->
    digest.update(recordDomain)
    digest.update(runtimeDigest)
    digest.update(bytes, view.keyOffset, QP_PAGE_KEY_SIZE)
    updateFramedRange(digest, bytes, view.pathRange)
    updateI32(digest, view.offset)
    updateI32(digest, view.storedLength)
    updateFramedRange(digest, bytes, view.descriptorRange)
    updateFramedRange(digest, bytes, view.envelopeRange)
}.digest()

internal fun computeDirectoryRootDigest(
    runtime: RuntimeBindingDigest,
    entries: List<QpArtifactPage>,
): ByteArray = MessageDigest.getInstance("SHA-256").also { digest ->
    val commitment = runtime.artifactCommitment
    val schedule = io.github.hht0rro.javashroud.transforms.protection.qp.qpNameSchedule(commitment)
    val domain = schedule.deriveDomain(
        io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_DIRECTORY,
        io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.LANE_DIR_ROOT,
    )
    try {
        digest.update(domain)
    } finally {
        Arrays.fill(domain, 0)
        Arrays.fill(commitment, 0)
        schedule.close()
    }
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
    views: List<QpDirectoryParser.RecordView>,
    rootDomain: ByteArray,
): ByteArray = MessageDigest.getInstance("SHA-256").also { digest ->
    digest.update(rootDomain)
    updateU32(digest, count.toLong())
    runtime.updateCanonical(digest)
    digest.update(checkNotNull(suppliedRuntimeDigest))
    views.forEach { view ->
        digest.update(bytes, view.keyOffset, QP_PAGE_KEY_SIZE)
        updateFramedRange(digest, bytes, view.pathRange)
        updateI32(digest, view.offset)
        updateI32(digest, view.storedLength)
        updateFramedRange(digest, bytes, view.descriptorRange)
        updateFramedRange(digest, bytes, view.envelopeRange)
        digest.update(bytes, view.bindingOffset, QP_DIGEST_SIZE)
    }
}.digest()

private fun updateFramedRange(
    digest: MessageDigest,
    bytes: ByteArray,
    range: QpDirectoryParser.ByteRange,
) {
    updateU32(digest, range.length.toLong())
    digest.update(bytes, range.offset, range.length)
}

private fun validateWireKey(bytes: ByteArray, offset: Int) {
    if (offset < 0 || offset > bytes.size - QP_PAGE_KEY_SIZE) {
        QpDirectoryException.fail(
            QpDirectoryException.Code.TRUNCATED,
            "page key is truncated",
        )
    }
    if (io.github.hht0rro.javashroud.transforms.protection.qp.QpResourceKind.fromId(bytes[offset].toInt() and 0xFF) == null) {
        QpDirectoryException.fail(
            QpDirectoryException.Code.INVALID_INPUT,
            "page key resource kind is unknown",
        )
    }
    val pageIndex =
        ((bytes[offset + 1].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 8) or
            (bytes[offset + 4].toInt() and 0xFF)
    if (pageIndex < 0) {
        QpDirectoryException.fail(
            QpDirectoryException.Code.INVALID_INPUT,
            "page index must be non-negative",
        )
    }
}

private fun validateWirePath(bytes: ByteArray, range: QpDirectoryParser.ByteRange) {
    val pathBytes = bytes.copyOfRange(range.offset, range.offset + range.length)
    try {
        validateNormalizedRelativePath(decodeUtf8(pathBytes, "relative path"))
    } finally {
        Arrays.fill(pathBytes, 0)
    }
}

private fun decodeAscii(bytes: ByteArray, field: String): String {
    if (bytes.isEmpty() || bytes.any { it.toInt() !in 0x20..0x7E }) {
        QpDirectoryException.fail(
            QpDirectoryException.Code.INVALID_INPUT,
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
        QpDirectoryException.fail(
            QpDirectoryException.Code.INVALID_INPUT,
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

private class QpDirectoryWriter(private val maximum: Int) : AutoCloseable {
    private val bytes = ByteArray(maximum)
    private var position = 0
    private var closed = false

    fun write(value: ByteArray) {
        requireOpen()
        ensure(value.size)
        value.copyInto(bytes, position)
        position += value.size
    }

    fun writeU8(value: Int) {
        requireOpen()
        ensure(1)
        bytes[position] = (value and 0xFF).toByte()
        position += 1
    }

    fun writeU16(value: Int) {
        requireOpen()
        require(value in 0..0xFFFF) { "directory u16 is out of range" }
        ensure(2)
        bytes[position] = ((value ushr 8) and 0xFF).toByte()
        bytes[position + 1] = (value and 0xFF).toByte()
        position += 2
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
            QpDirectoryException.fail(
                QpDirectoryException.Code.LENGTH_OVERFLOW,
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
