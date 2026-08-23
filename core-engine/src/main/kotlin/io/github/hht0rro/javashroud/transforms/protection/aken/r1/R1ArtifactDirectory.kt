package io.github.hht0rro.javashroud.transforms.protection.aken.r1

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays

internal const val R1_DIGEST_SIZE: Int = 32
internal const val R1_ENCODED_HANDLE_SIZE: Int = 24
internal const val R1_LOCATOR_TOKEN_SIZE: Int = 16
internal const val R1_PAGE_KEY_SIZE: Int = 1 + Int.SIZE_BYTES + R1_ENCODED_HANDLE_SIZE + R1_LOCATOR_TOKEN_SIZE

/**
 * The six fields that identify the runtime expected to consume one directory.
 * The computed digest is the SHA-256 of the canonical field encoding.
 */
class RuntimeBindingDigest(
    artifactCommitment: ByteArray,
    nativeSha256: ByteArray,
    abiDigest: ByteArray,
    targetTriple: String,
    specializationDigest: ByteArray,
    payloadProfile: String,
) : AutoCloseable {
    private var artifactCommitmentValue = artifactCommitment.copyOf()
    private var nativeSha256Value = nativeSha256.copyOf()
    private var abiDigestValue = abiDigest.copyOf()
    private var targetTripleValue = targetTriple
    private var specializationDigestValue = specializationDigest.copyOf()
    private var payloadProfileValue = payloadProfile
    private lateinit var digestValue: ByteArray
    @Volatile
    private var wiped = false

    init {
        requireDigest(artifactCommitmentValue, "artifact commitment")
        requireDigest(nativeSha256Value, "native SHA-256")
        requireDigest(abiDigestValue, "ABI digest")
        requireTarget(targetTripleValue)
        requireDigest(specializationDigestValue, "specialization digest")
        requireProfile(payloadProfileValue)
        digestValue = computeDigest(
            artifactCommitmentValue,
            nativeSha256Value,
            abiDigestValue,
            targetTripleValue,
            specializationDigestValue,
            payloadProfileValue,
        )
    }

    val artifactCommitment: ByteArray
        get() = artifactCommitmentValue.copyLive("runtime binding digest")

    val nativeSha256: ByteArray
        get() = nativeSha256Value.copyLive("runtime binding digest")

    val abiDigest: ByteArray
        get() = abiDigestValue.copyLive("runtime binding digest")

    val targetTriple: String
        get() {
            requireLive("runtime binding digest")
            return targetTripleValue
        }

    val specializationDigest: ByteArray
        get() = specializationDigestValue.copyLive("runtime binding digest")

    val payloadProfile: String
        get() {
            requireLive("runtime binding digest")
            return payloadProfileValue
        }

    /** The stored SHA-256 over the canonical six-field encoding. */
    val digest: ByteArray
        get() = digestValue.copyLive("runtime binding digest")

    val bytes: ByteArray
        get() = digest

    fun asBytes(): ByteArray = digest

    /** Returns the canonical field encoding, without the computed digest. */
    fun canonicalEncoding(): ByteArray {
        requireLive("runtime binding digest")
        val targetBytes = targetTripleValue.toByteArray(StandardCharsets.US_ASCII)
        val profileBytes = payloadProfileValue.toByteArray(StandardCharsets.US_ASCII)
        return try {
            val size = checkedLength(
                4 * R1_DIGEST_SIZE + 2 * Int.SIZE_BYTES + targetBytes.size + profileBytes.size,
                "runtime binding canonical encoding",
            )
            val encoded = ByteArray(size)
            var offset = 0
            artifactCommitmentValue.copyInto(encoded, offset)
            offset += R1_DIGEST_SIZE
            nativeSha256Value.copyInto(encoded, offset)
            offset += R1_DIGEST_SIZE
            abiDigestValue.copyInto(encoded, offset)
            offset += R1_DIGEST_SIZE
            writeU32Into(encoded, offset, targetBytes.size.toLong())
            offset += Int.SIZE_BYTES
            targetBytes.copyInto(encoded, offset)
            offset += targetBytes.size
            specializationDigestValue.copyInto(encoded, offset)
            offset += R1_DIGEST_SIZE
            writeU32Into(encoded, offset, profileBytes.size.toLong())
            offset += Int.SIZE_BYTES
            profileBytes.copyInto(encoded, offset)
            encoded
        } finally {
            Arrays.fill(targetBytes, 0)
            Arrays.fill(profileBytes, 0)
        }
    }

    /** Recomputes and compares a wire-stored digest in constant time. */
    internal fun verifyStoredDigest(supplied: ByteArray) {
        requireLive("runtime binding digest")
        val expected = digestValue.copyOf()
        try {
            if (!MessageDigest.isEqual(expected, supplied)) {
                R1ArtifactDirectoryException.fail(
                    R1ArtifactDirectoryException.Code.AUTHENTICATION_FAILED,
                    "runtime binding digest does not match its canonical fields",
                )
            }
        } finally {
            Arrays.fill(expected, 0)
        }
    }

    internal fun updateCanonical(digest: MessageDigest) {
        requireLive("runtime binding digest")
        updateRuntimeCanonical(
            digest,
            artifactCommitmentValue,
            nativeSha256Value,
            abiDigestValue,
            targetTripleValue,
            specializationDigestValue,
            payloadProfileValue,
        )
    }

    internal fun copyForDirectory(): RuntimeBindingDigest {
        requireLive("runtime binding digest")
        return RuntimeBindingDigest(
            artifactCommitmentValue,
            nativeSha256Value,
            abiDigestValue,
            targetTripleValue,
            specializationDigestValue,
            payloadProfileValue,
        )
    }

    internal fun copyDigestForWire(): ByteArray = digestValue.copyLive("runtime binding digest")

    fun wipe() {
        if (wiped) return
        Arrays.fill(artifactCommitmentValue, 0)
        Arrays.fill(nativeSha256Value, 0)
        Arrays.fill(abiDigestValue, 0)
        Arrays.fill(specializationDigestValue, 0)
        Arrays.fill(digestValue, 0)
        artifactCommitmentValue = ByteArray(0)
        nativeSha256Value = ByteArray(0)
        abiDigestValue = ByteArray(0)
        specializationDigestValue = ByteArray(0)
        digestValue = ByteArray(0)
        targetTripleValue = ""
        payloadProfileValue = ""
        wiped = true
    }

    override fun close() = wipe()

    override fun equals(other: Any?): Boolean =
        other is RuntimeBindingDigest &&
            !wiped &&
            !other.wiped &&
            MessageDigest.isEqual(digestValue, other.digestValue)

    override fun hashCode(): Int {
        requireLive("runtime binding digest")
        return digestValue.contentHashCode()
    }

    override fun toString(): String = "RuntimeBindingDigest(target=$targetTripleValue, profile=$payloadProfileValue)"

    private fun requireLive(label: String) {
        check(!wiped) { "$label has been wiped" }
    }

    companion object {
        const val DIGEST_SIZE: Int = R1_DIGEST_SIZE
        const val MAX_TARGET_TRIPLE_BYTES: Int = 64
        const val MAX_PAYLOAD_PROFILE_BYTES: Int = 256
        const val TARGET_WINDOWS_GNU: String = "x86_64-pc-windows-gnu"
        const val TARGET_LINUX_GNU_217: String = "x86_64-unknown-linux-gnu.2.17"

        fun create(
            artifactCommitment: ByteArray,
            nativeSha256: ByteArray,
            abiDigest: ByteArray,
            targetTriple: String,
            specializationDigest: ByteArray,
            payloadProfile: String,
        ): RuntimeBindingDigest = RuntimeBindingDigest(
            artifactCommitment,
            nativeSha256,
            abiDigest,
            targetTriple,
            specializationDigest,
            payloadProfile,
        )

        fun compute(
            artifactCommitment: ByteArray,
            nativeSha256: ByteArray,
            abiDigest: ByteArray,
            targetTriple: String,
            specializationDigest: ByteArray,
            payloadProfile: String,
        ): RuntimeBindingDigest = create(
            artifactCommitment,
            nativeSha256,
            abiDigest,
            targetTriple,
            specializationDigest,
            payloadProfile,
        )

        internal fun fromWire(
            artifactCommitment: ByteArray,
            nativeSha256: ByteArray,
            abiDigest: ByteArray,
            targetTriple: String,
            specializationDigest: ByteArray,
            payloadProfile: String,
            suppliedDigest: ByteArray,
        ): RuntimeBindingDigest {
            val result = RuntimeBindingDigest(
                artifactCommitment,
                nativeSha256,
                abiDigest,
                targetTriple,
                specializationDigest,
                payloadProfile,
            )
            return try {
                result.verifyStoredDigest(suppliedDigest)
                result
            } catch (error: Throwable) {
                result.wipe()
                throw error
            }
        }

        private fun requireDigest(value: ByteArray, field: String) {
            if (value.size != R1_DIGEST_SIZE) {
                R1ArtifactDirectoryException.fail(
                    R1ArtifactDirectoryException.Code.INVALID_INPUT,
                    "$field must be $R1_DIGEST_SIZE bytes",
                )
            }
        }

        private fun requireTarget(value: String) {
            val bytes = value.toByteArray(StandardCharsets.US_ASCII)
            try {
                if (value !in setOf(TARGET_WINDOWS_GNU, TARGET_LINUX_GNU_217) ||
                    bytes.size > MAX_TARGET_TRIPLE_BYTES ||
                    !isAscii(value)
                ) {
                    R1ArtifactDirectoryException.fail(
                        R1ArtifactDirectoryException.Code.UNSUPPORTED_TARGET,
                        "unsupported AKEN-R1 runtime target: $value",
                    )
                }
            } finally {
                Arrays.fill(bytes, 0)
            }
        }

        private fun requireProfile(value: String) {
            val bytes = value.toByteArray(StandardCharsets.US_ASCII)
            try {
                if (bytes.isEmpty() || bytes.size > MAX_PAYLOAD_PROFILE_BYTES || !isAscii(value)) {
                    R1ArtifactDirectoryException.fail(
                        R1ArtifactDirectoryException.Code.INVALID_INPUT,
                        "runtime payload profile must be bounded printable ASCII",
                    )
                }
            } finally {
                Arrays.fill(bytes, 0)
            }
        }

        private fun isAscii(value: String): Boolean = value.all { it.code in 0x20..0x7E }

        private fun computeDigest(
            artifactCommitment: ByteArray,
            nativeSha256: ByteArray,
            abiDigest: ByteArray,
            targetTriple: String,
            specializationDigest: ByteArray,
            payloadProfile: String,
        ): ByteArray = MessageDigest.getInstance("SHA-256").also { digest ->
            digest.update(R1_RUNTIME_BINDING_DOMAIN)
            updateRuntimeCanonical(
                digest,
                artifactCommitment,
                nativeSha256,
                abiDigest,
                targetTriple,
                specializationDigest,
                payloadProfile,
            )
        }.digest()
    }
}

/** Exactly the current Rust page-key byte shape. */
class PageKey private constructor(
    private var resourceKindValue: AkenResourceKind,
    private var pageIndexValue: Int,
    private var rawValue: ByteArray,
) : Comparable<PageKey>, AutoCloseable {
    @Volatile
    private var wiped = false

    constructor(
        resourceKind: AkenResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
        locatorToken: ByteArray,
    ) : this(
        resourceKind,
        pageIndex,
        encodePageKey(resourceKind, pageIndex, encodedHandle, locatorToken),
    )

    init {
        if (rawValue.size != R1_PAGE_KEY_SIZE) {
            R1ArtifactDirectoryException.fail(
                R1ArtifactDirectoryException.Code.INVALID_INPUT,
                "page key must be exactly $R1_PAGE_KEY_SIZE bytes",
            )
        }
        if (pageIndexValue < 0) {
            R1ArtifactDirectoryException.fail(
                R1ArtifactDirectoryException.Code.INVALID_INPUT,
                "page index must be non-negative",
            )
        }
    }

    val resourceKind: AkenResourceKind
        get() {
            requireLive("page key")
            return resourceKindValue
        }

    val kind: AkenResourceKind
        get() = resourceKind

    val pageIndex: Int
        get() {
            requireLive("page key")
            return pageIndexValue
        }

    val encodedHandle: ByteArray
        get() = copyFixedKeyPart(1 + Int.SIZE_BYTES, R1_ENCODED_HANDLE_SIZE)

    val locatorToken: ByteArray
        get() = copyFixedKeyPart(1 + Int.SIZE_BYTES + R1_ENCODED_HANDLE_SIZE, R1_LOCATOR_TOKEN_SIZE)

    fun asBytes(): ByteArray {
        requireLive("page key")
        return rawValue.copyOf()
    }

    fun copyBytes(): ByteArray = asBytes()

    internal fun copyOfKey(): PageKey {
        requireLive("page key")
        return PageKey(resourceKindValue, pageIndexValue, rawValue.copyOf())
    }

    internal fun updateDigest(digest: MessageDigest) {
        requireLive("page key")
        digest.update(rawValue)
    }

    internal fun compareRaw(other: PageKey): Int {
        requireLive("page key")
        other.requireLive("page key")
        return compareUnsigned(rawValue, other.rawValue)
    }

    fun wipe() {
        if (wiped) return
        Arrays.fill(rawValue, 0)
        rawValue = ByteArray(0)
        pageIndexValue = 0
        wiped = true
    }

    override fun close() = wipe()

    override fun compareTo(other: PageKey): Int = compareRaw(other)

    override fun equals(other: Any?): Boolean =
        other is PageKey &&
            !wiped &&
            !other.wiped &&
            MessageDigest.isEqual(rawValue, other.rawValue)

    override fun hashCode(): Int {
        requireLive("page key")
        return rawValue.contentHashCode()
    }

    override fun toString(): String = "PageKey(kind=$resourceKindValue, page=$pageIndexValue)"

    private fun copyFixedKeyPart(offset: Int, length: Int): ByteArray {
        requireLive("page key")
        return rawValue.copyOfRange(offset, offset + length)
    }

    private fun requireLive(label: String) {
        check(!wiped) { "$label has been wiped" }
    }

    companion object {
        fun create(
            resourceKind: AkenResourceKind,
            pageIndex: Int,
            encodedHandle: ByteArray,
            locatorToken: ByteArray,
        ): PageKey = PageKey(resourceKind, pageIndex, encodedHandle, locatorToken)

        fun fromHandle(handle: AkenHandle): PageKey {
            var encoded: ByteArray? = null
            var locator: ByteArray? = null
            return try {
                encoded = handle.encoded
                locator = handle.locatorToken
                PageKey(handle.resourceKind, handle.pageIndex, checkNotNull(encoded), checkNotNull(locator))
            } finally {
                encoded?.let { Arrays.fill(it, 0) }
                locator?.let { Arrays.fill(it, 0) }
            }
        }

        fun fromBytes(bytes: ByteArray): PageKey {
            if (bytes.size != R1_PAGE_KEY_SIZE) {
                R1ArtifactDirectoryException.fail(
                    R1ArtifactDirectoryException.Code.INVALID_INPUT,
                    "page key must be exactly $R1_PAGE_KEY_SIZE bytes",
                )
            }
            val copy = bytes.copyOf()
            return try {
                val kind = AkenResourceKind.fromId(copy[0].toInt() and 0xFF)
                    ?: R1ArtifactDirectoryException.fail(
                        R1ArtifactDirectoryException.Code.INVALID_INPUT,
                        "page key resource kind is unknown",
                    )
                val pageIndex = readI32(copy, 1)
                if (pageIndex < 0) {
                    R1ArtifactDirectoryException.fail(
                        R1ArtifactDirectoryException.Code.INVALID_INPUT,
                        "page index must be non-negative",
                    )
                }
                PageKey(kind, pageIndex, copy)
            } catch (error: Throwable) {
                // The successful PageKey takes ownership of copy.
                Arrays.fill(copy, 0)
                throw error
            }
        }
    }
}

/** One opaque, authenticated current-page directory entry. */
class R1ArtifactPage private constructor(
    private var keyValue: PageKey,
    private var relativePathValue: String,
    private var offsetValue: Int,
    private var storedLengthValue: Int,
    private var descriptorValue: ByteArray,
    private var envelopeValue: ByteArray,
    private var bindingDigestValue: ByteArray,
) : AutoCloseable {
    @Volatile
    private var wiped = false

    init {
        validatePageFields(relativePathValue, offsetValue, storedLengthValue, descriptorValue, envelopeValue)
        if (bindingDigestValue.size != R1_DIGEST_SIZE) {
            R1ArtifactDirectoryException.fail(
                R1ArtifactDirectoryException.Code.INVALID_INPUT,
                "page binding digest must be $R1_DIGEST_SIZE bytes",
            )
        }
    }

    val key: PageKey
        get() {
            requireLive("artifact page")
            return keyValue.copyOfKey()
        }

    val resourceKind: AkenResourceKind
        get() = keyValue.resourceKind

    val pageIndex: Int
        get() = keyValue.pageIndex

    val relativePath: String
        get() {
            requireLive("artifact page")
            return relativePathValue
        }

    val resourcePath: String
        get() = relativePath

    val offset: Int
        get() {
            requireLive("artifact page")
            return offsetValue
        }

    val storedLength: Int
        get() {
            requireLive("artifact page")
            return storedLengthValue
        }

    val descriptor: ByteArray
        get() {
            requireLive("artifact page")
            return descriptorValue.copyOf()
        }

    val descriptorBytes: ByteArray
        get() = descriptor

    val envelope: ByteArray
        get() {
            requireLive("artifact page")
            return envelopeValue.copyOf()
        }

    val envelopeBytes: ByteArray
        get() = envelope

    val bindingDigest: ByteArray
        get() {
            requireLive("artifact page")
            return bindingDigestValue.copyOf()
        }

    val recordBindingDigest: ByteArray
        get() = bindingDigest

    val isWiped: Boolean
        get() = wiped

    internal fun compareKey(other: R1ArtifactPage): Int = keyValue.compareRaw(other.keyValue)

    internal fun keyForLookup(): PageKey {
        requireLive("artifact page")
        return keyValue
    }

    internal fun matchesRuntimeDigest(runtimeBindingDigest: RuntimeBindingDigest): Boolean {
        requireLive("artifact page")
        val expected = computeRecordBinding(
            runtimeBindingDigest,
            keyValue,
            relativePathValue,
            offsetValue,
            storedLengthValue,
            descriptorValue,
            envelopeValue,
        )
        return try {
            MessageDigest.isEqual(bindingDigestValue, expected)
        } finally {
            Arrays.fill(expected, 0)
        }
    }

    internal fun updateRootDigest(digest: MessageDigest) {
        requireLive("artifact page")
        keyValue.updateDigest(digest)
        val pathBytes = relativePathValue.toByteArray(StandardCharsets.UTF_8)
        try {
            updateFramed(digest, pathBytes)
        } finally {
            Arrays.fill(pathBytes, 0)
        }
        updateI32(digest, offsetValue)
        updateI32(digest, storedLengthValue)
        updateFramed(digest, descriptorValue)
        updateFramed(digest, envelopeValue)
        digest.update(bindingDigestValue)
    }

    internal fun copyForDirectory(): R1ArtifactPage {
        requireLive("artifact page")
        return fromVerified(
            keyValue.copyOfKey(),
            relativePathValue,
            offsetValue,
            storedLengthValue,
            descriptorValue.copyOf(),
            envelopeValue.copyOf(),
            bindingDigestValue.copyOf(),
        )
    }

    internal fun copyKeyBytesForWire(): ByteArray = keyValue.asBytes()

    internal fun copyPathBytesForWire(): ByteArray {
        requireLive("artifact page")
        return relativePathValue.toByteArray(StandardCharsets.UTF_8)
    }

    internal fun copyDescriptorForWire(): ByteArray {
        requireLive("artifact page")
        return descriptorValue.copyOf()
    }

    internal fun copyEnvelopeForWire(): ByteArray {
        requireLive("artifact page")
        return envelopeValue.copyOf()
    }

    internal fun copyBindingForWire(): ByteArray {
        requireLive("artifact page")
        return bindingDigestValue.copyOf()
    }

    fun copy(): R1ArtifactPage = copyForDirectory()

    fun wipe() {
        if (wiped) return
        keyValue.wipe()
        Arrays.fill(descriptorValue, 0)
        Arrays.fill(envelopeValue, 0)
        Arrays.fill(bindingDigestValue, 0)
        descriptorValue = ByteArray(0)
        envelopeValue = ByteArray(0)
        bindingDigestValue = ByteArray(0)
        relativePathValue = ""
        offsetValue = 0
        storedLengthValue = 0
        wiped = true
    }

    override fun close() = wipe()

    override fun equals(other: Any?): Boolean =
        other is R1ArtifactPage &&
            !wiped &&
            !other.wiped &&
            keyValue == other.keyValue &&
            relativePathValue == other.relativePathValue &&
            offsetValue == other.offsetValue &&
            storedLengthValue == other.storedLengthValue &&
            MessageDigest.isEqual(descriptorValue, other.descriptorValue) &&
            MessageDigest.isEqual(envelopeValue, other.envelopeValue) &&
            MessageDigest.isEqual(bindingDigestValue, other.bindingDigestValue)

    override fun hashCode(): Int {
        requireLive("artifact page")
        var result = keyValue.hashCode()
        result = 31 * result + relativePathValue.hashCode()
        result = 31 * result + offsetValue
        result = 31 * result + storedLengthValue
        result = 31 * result + descriptorValue.contentHashCode()
        result = 31 * result + envelopeValue.contentHashCode()
        return 31 * result + bindingDigestValue.contentHashCode()
    }

    override fun toString(): String =
        "R1ArtifactPage(kind=$resourceKind, page=$pageIndex, path=$relativePathValue)"

    private fun requireLive(label: String) {
        check(!wiped) { "$label has been wiped" }
    }

    companion object {
        fun create(
            key: PageKey,
            relativePath: String,
            offset: Int,
            storedLength: Int,
            descriptor: ByteArray,
            envelope: ByteArray,
            runtimeBindingDigest: RuntimeBindingDigest,
        ): R1ArtifactPage {
            val expected = computeRecordBinding(
                runtimeBindingDigest,
                key,
                relativePath,
                offset,
                storedLength,
                descriptor,
                envelope,
            )
            return try {
                R1ArtifactPage(
                    key.copyOfKey(),
                    relativePath,
                    offset,
                    storedLength,
                    descriptor.copyOf(),
                    envelope.copyOf(),
                    expected.copyOf(),
                )
            } finally {
                Arrays.fill(expected, 0)
            }
        }

        fun fromRuntime(
            runtimeBindingDigest: RuntimeBindingDigest,
            key: PageKey,
            relativePath: String,
            offset: Int,
            storedLength: Int,
            descriptor: ByteArray,
            envelope: ByteArray,
        ): R1ArtifactPage = create(
            key,
            relativePath,
            offset,
            storedLength,
            descriptor,
            envelope,
            runtimeBindingDigest,
        )

        fun fromHandle(
            runtimeBindingDigest: RuntimeBindingDigest,
            handle: AkenHandle,
            relativePath: String,
            offset: Int,
            storedLength: Int,
            descriptor: ByteArray,
            envelope: ByteArray,
        ): R1ArtifactPage {
            val key = PageKey.fromHandle(handle)
            return try {
                create(
                    key,
                    relativePath,
                    offset,
                    storedLength,
                    descriptor,
                    envelope,
                    runtimeBindingDigest,
                )
            } finally {
                key.wipe()
            }
        }

        internal fun fromVerified(
            key: PageKey,
            relativePath: String,
            offset: Int,
            storedLength: Int,
            descriptor: ByteArray,
            envelope: ByteArray,
            bindingDigest: ByteArray,
        ): R1ArtifactPage = R1ArtifactPage(
            key,
            relativePath,
            offset,
            storedLength,
            descriptor,
            envelope,
            bindingDigest,
        )
    }
}

typealias R1ArtifactDirectoryEntry = R1ArtifactPage

/** Canonically sorted collection of current AKEN-R1 page records. */
class R1ArtifactDirectory private constructor(
    private var runtimeBindingValue: RuntimeBindingDigest,
    private var entriesValue: MutableList<R1ArtifactPage>,
    private var rootDigestValue: ByteArray,
) : AutoCloseable {
    @Volatile
    private var wiped = false

    init {
        if (rootDigestValue.size != R1_DIGEST_SIZE) {
            R1ArtifactDirectoryException.fail(
                R1ArtifactDirectoryException.Code.INVALID_INPUT,
                "directory root digest must be $R1_DIGEST_SIZE bytes",
            )
        }
    }

    val runtimeBindingDigest: RuntimeBindingDigest
        get() {
            requireLive()
            return runtimeBindingValue.copyForDirectory()
        }

    val runtimeBinding: RuntimeBindingDigest
        get() = runtimeBindingDigest

    val entries: List<R1ArtifactDirectoryEntry>
        get() {
            requireLive()
            return entriesValue.toList()
        }

    val pages: List<R1ArtifactPage>
        get() = entries

    val size: Int
        get() {
            requireLive()
            return entriesValue.size
        }

    val isEmpty: Boolean
        get() = size == 0

    val rootDigest: ByteArray
        get() {
            requireLive()
            return rootDigestValue.copyOf()
        }

    val isWiped: Boolean
        get() = wiped

    fun encode(): ByteArray = R1ArtifactDirectorySerializer.encode(this)

    fun lookup(key: PageKey): R1ArtifactDirectoryEntry? {
        requireLive()
        var low = 0
        var high = entriesValue.size - 1
        while (low <= high) {
            val middle = (low + high) ushr 1
            val comparison = entriesValue[middle].keyForLookup().compareRaw(key)
            when {
                comparison < 0 -> low = middle + 1
                comparison > 0 -> high = middle - 1
                else -> return entriesValue[middle]
            }
        }
        return null
    }

    fun copy(): R1ArtifactDirectory = R1ArtifactDirectory.create(
        runtimeBindingDigest,
        entriesValue.map { it.copy() },
    )

    internal fun runtimeBindingForWire(): RuntimeBindingDigest {
        requireLive()
        return runtimeBindingValue
    }

    internal fun entriesForWire(): List<R1ArtifactPage> {
        requireLive()
        return entriesValue
    }

    internal fun rootDigestForWire(): ByteArray {
        requireLive()
        return rootDigestValue.copyOf()
    }

    fun wipe() {
        if (wiped) return
        entriesValue.forEach { it.wipe() }
        entriesValue.clear()
        runtimeBindingValue.wipe()
        Arrays.fill(rootDigestValue, 0)
        rootDigestValue = ByteArray(0)
        wiped = true
    }

    override fun close() = wipe()

    override fun equals(other: Any?): Boolean =
        other is R1ArtifactDirectory &&
            !wiped &&
            !other.wiped &&
            runtimeBindingValue == other.runtimeBindingValue &&
            rootDigestValue.contentEquals(other.rootDigestValue) &&
            entriesValue == other.entriesValue

    override fun hashCode(): Int {
        requireLive()
        var result = runtimeBindingValue.hashCode()
        result = 31 * result + entriesValue.hashCode()
        return 31 * result + rootDigestValue.contentHashCode()
    }

    override fun toString(): String = "R1ArtifactDirectory(entries=${entriesValue.size})"

    private fun requireLive() {
        check(!wiped) { "AKEN-R1 artifact directory has been wiped" }
    }

    companion object {
        const val MAGIC: String = R1ArtifactDirectorySerializer.MAGIC

        fun create(
            runtimeBindingDigest: RuntimeBindingDigest,
            entries: Iterable<R1ArtifactDirectoryEntry>,
        ): R1ArtifactDirectory {
            val runtime = runtimeBindingDigest.copyForDirectory()
            val copies = ArrayList<R1ArtifactPage>()
            var transferred = false
            return try {
                entries.forEach { entry ->
                    val copy = entry.copyForDirectory()
                    if (!copy.matchesRuntimeDigest(runtime)) {
                        copy.wipe()
                        R1ArtifactDirectoryException.fail(
                            R1ArtifactDirectoryException.Code.AUTHENTICATION_FAILED,
                            "page binding digest does not match runtime binding",
                        )
                    }
                    copies += copy
                }
                if (copies.size > R1ArtifactDirectorySerializer.MAX_ENTRIES) {
                    R1ArtifactDirectoryException.fail(
                        R1ArtifactDirectoryException.Code.FIELD_TOO_LARGE,
                        "directory contains too many entries",
                    )
                }
                copies.sortWith { left, right -> left.compareKey(right) }
                copies.zipWithNext().forEach { (left, right) ->
                    if (left.compareKey(right) == 0) {
                        R1ArtifactDirectoryException.fail(
                            R1ArtifactDirectoryException.Code.DUPLICATE_KEY,
                            "directory contains a duplicate page key",
                        )
                    }
                }
                val root = computeDirectoryRootDigest(runtime, copies)
                val result = R1ArtifactDirectory(runtime, copies, root)
                transferred = true
                result
            } finally {
                if (!transferred) {
                    copies.forEach { it.wipe() }
                    runtime.wipe()
                }
            }
        }

        fun fromPages(
            runtimeBindingDigest: RuntimeBindingDigest,
            pages: Iterable<R1ArtifactPage>,
        ): R1ArtifactDirectory = create(runtimeBindingDigest, pages)

        fun decode(encoded: ByteArray): R1ArtifactDirectory = R1ArtifactDirectoryParser.decode(encoded)

        fun decode(
            encoded: ByteArray,
            expectedRuntimeBinding: RuntimeBindingDigest,
        ): R1ArtifactDirectory = R1ArtifactDirectoryParser.decode(encoded, expectedRuntimeBinding)

        fun parse(encoded: ByteArray): R1ArtifactDirectory = decode(encoded)

        internal fun fromDecoded(
            runtimeBindingDigest: RuntimeBindingDigest,
            entries: MutableList<R1ArtifactPage>,
            rootDigest: ByteArray,
        ): R1ArtifactDirectory = R1ArtifactDirectory(runtimeBindingDigest, entries, rootDigest)
    }
}

internal fun validatePageFields(
    relativePath: String,
    offset: Int,
    storedLength: Int,
    descriptor: ByteArray,
    envelope: ByteArray,
) {
    validateNormalizedRelativePath(relativePath)
    if (offset < 0 || storedLength <= 0 || storedLength > R1ArtifactDirectorySerializer.MAX_STORED_LENGTH) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.INVALID_INPUT,
            "page offset/length is outside the bounded non-negative range",
        )
    }
    if (descriptor.isEmpty() || descriptor.size > R1ArtifactDirectorySerializer.MAX_DESCRIPTOR_SIZE) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.FIELD_TOO_LARGE,
            "page descriptor length is outside its bound",
        )
    }
    if (envelope.isEmpty() || envelope.size > R1ArtifactDirectorySerializer.MAX_ENVELOPE_SIZE) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.FIELD_TOO_LARGE,
            "page envelope length is outside its bound",
        )
    }
}

internal fun validateNormalizedRelativePath(value: String) {
    val bytes = value.toByteArray(StandardCharsets.UTF_8)
    try {
        if (bytes.isEmpty() || bytes.size > R1ArtifactDirectorySerializer.MAX_PATH_SIZE ||
            '\u0000' in value || '\\' in value || value.startsWith('/') || value.endsWith('/') ||
            value.split('/').any { it.isEmpty() || it == "." || it == ".." }
        ) {
            R1ArtifactDirectoryException.fail(
                R1ArtifactDirectoryException.Code.INVALID_PATH,
                "path is not a normalized relative entry name",
            )
        }
    } finally {
        Arrays.fill(bytes, 0)
    }
}

internal fun updateRuntimeCanonical(
    digest: MessageDigest,
    artifactCommitment: ByteArray,
    nativeSha256: ByteArray,
    abiDigest: ByteArray,
    targetTriple: String,
    specializationDigest: ByteArray,
    payloadProfile: String,
) {
    digest.update(artifactCommitment)
    digest.update(nativeSha256)
    digest.update(abiDigest)
    val targetBytes = targetTriple.toByteArray(StandardCharsets.US_ASCII)
    val profileBytes = payloadProfile.toByteArray(StandardCharsets.US_ASCII)
    try {
        updateFramed(digest, targetBytes)
        digest.update(specializationDigest)
        updateFramed(digest, profileBytes)
    } finally {
        Arrays.fill(targetBytes, 0)
        Arrays.fill(profileBytes, 0)
    }
}

internal fun updateFramed(digest: MessageDigest, value: ByteArray) {
    updateU32(digest, value.size.toLong())
    digest.update(value)
}

internal fun updateI32(digest: MessageDigest, value: Int) {
    updateU32(digest, value.toLong() and 0xFFFF_FFFFL)
}

internal fun updateU32(digest: MessageDigest, value: Long) {
    if (value !in 0..0xFFFF_FFFFL) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.LENGTH_OVERFLOW,
            "value does not fit in an unsigned big-endian u32",
        )
    }
    digest.update(
        byteArrayOf(
            (value ushr 24).toByte(),
            (value ushr 16).toByte(),
            (value ushr 8).toByte(),
            value.toByte(),
        ),
    )
}

internal fun writeU32Into(output: ByteArray, offset: Int, value: Long) {
    if (value !in 0..0xFFFF_FFFFL || offset < 0 || offset > output.size - Int.SIZE_BYTES) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.LENGTH_OVERFLOW,
            "u32 write is outside output bounds",
        )
    }
    output[offset] = (value ushr 24).toByte()
    output[offset + 1] = (value ushr 16).toByte()
    output[offset + 2] = (value ushr 8).toByte()
    output[offset + 3] = value.toByte()
}

internal fun checkedLength(value: Int, field: String): Int {
    if (value < 0 || value > R1ArtifactDirectorySerializer.MAX_DIRECTORY_SIZE) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.LENGTH_OVERFLOW,
            "$field exceeds JVM bounds",
        )
    }
    return value
}

internal fun checkedLength(value: Long, field: String): Int {
    if (value < 0L || value > Int.MAX_VALUE.toLong() || value > R1ArtifactDirectorySerializer.MAX_DIRECTORY_SIZE.toLong()) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.LENGTH_OVERFLOW,
            "$field exceeds JVM bounds",
        )
    }
    return value.toInt()
}

internal fun requireLiveCopy(value: ByteArray, label: String): ByteArray {
    if (value.isEmpty()) check(false) { "$label has been wiped" }
    return value.copyOf()
}

private fun ByteArray.copyLive(label: String): ByteArray = requireLiveCopy(this, label)

private fun encodePageKey(
    resourceKind: AkenResourceKind,
    pageIndex: Int,
    encodedHandle: ByteArray,
    locatorToken: ByteArray,
): ByteArray {
    if (pageIndex < 0) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.INVALID_INPUT,
            "page index must be non-negative",
        )
    }
    if (encodedHandle.size != R1_ENCODED_HANDLE_SIZE || locatorToken.size != R1_LOCATOR_TOKEN_SIZE) {
        R1ArtifactDirectoryException.fail(
            R1ArtifactDirectoryException.Code.INVALID_INPUT,
            "page key handle or locator length is invalid",
        )
    }
    val output = ByteArray(R1_PAGE_KEY_SIZE)
    output[0] = resourceKind.id.toByte()
    writeU32Into(output, 1, pageIndex.toLong())
    encodedHandle.copyInto(output, 1 + Int.SIZE_BYTES)
    locatorToken.copyInto(output, 1 + Int.SIZE_BYTES + R1_ENCODED_HANDLE_SIZE)
    return output
}

private fun readI32(bytes: ByteArray, offset: Int): Int =
    ((bytes[offset].toInt() and 0xFF) shl 24) or
        ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
        ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
        (bytes[offset + 3].toInt() and 0xFF)

private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
    val length = minOf(left.size, right.size)
    for (index in 0 until length) {
        val comparison = (left[index].toInt() and 0xFF).compareTo(right[index].toInt() and 0xFF)
        if (comparison != 0) return comparison
    }
    return left.size.compareTo(right.size)
}

private val R1_RUNTIME_BINDING_DOMAIN =
    "JavaShroud/AKEN-R1/ArtifactDirectory/RuntimeBindingDigest".toByteArray(StandardCharsets.US_ASCII)
