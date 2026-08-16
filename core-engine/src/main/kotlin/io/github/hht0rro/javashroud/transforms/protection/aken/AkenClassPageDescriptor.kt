package io.github.hht0rro.javashroud.transforms.protection.aken

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Arrays
import java.util.Base64

/**
 * Build-only, class-local routing descriptor for AKEN EncryptedClassPage
 * material.  It describes exactly one logical class and deliberately contains
 * no resource path, DEK, evaluator state, catalog entry, or cross-class index.
 *
 * The final runtime consumes the compact binary form only in the scope of the
 * class currently being defined.  Child-loader lookup can derive this class's
 * own descriptor resource route from [internalName] without enumerating a
 * global encrypted-class manifest.
 */
internal class AkenClassPageDescriptor private constructor(
    val internalName: String,
    private var pagesValue: List<AkenClassPageDescriptorPage>,
) : AutoCloseable {
    @Volatile
    private var wiped: Boolean = false

    init {
        require(isValidInternalName(internalName)) { "AKEN ClassPage descriptor internal name is invalid" }
        require(pagesValue.isNotEmpty() && pagesValue.size <= MAX_PAGE_COUNT) {
            "AKEN ClassPage descriptor page count is invalid"
        }
        pagesValue.forEachIndexed { expectedIndex, page ->
            require(page.pageIndex == expectedIndex) {
                "AKEN ClassPage descriptor pages must use contiguous zero-based indices"
            }
        }
    }

    val pageCount: Int
        get() {
            requireLive()
            return pagesValue.size
        }

    val isWiped: Boolean
        get() = wiped

    /**
     * Returns the deterministic, per-class descriptor resource route.  This
     * path is not a catalog: it is computable only for the current class name
     * and points to exactly one class-local page binding descriptor.
     */
    fun resourcePathForBuild(): String {
        requireLive()
        val digest = descriptorDigest(DESCRIPTOR_ROUTE_DOMAIN, internalName)
        return try {
            descriptorRouteFromDigest(digest)
        } finally {
            Arrays.fill(digest, 0)
        }
    }

    /**
     * A class-local public marker embedded by the generated stub.  The shared
     * child loader uses it only to distinguish a missing/tampered descriptor
     * from an ordinary parent-loaded class; it is neither a key nor a locator.
     */
    fun markerForBuild(): String {
        requireLive()
        val digest = descriptorDigest(DESCRIPTOR_MARKER_DOMAIN, internalName)
        return try {
            Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        } finally {
            Arrays.fill(digest, 0)
        }
    }

    /** Serializes only this class's page handles and call-site proofs. */
    fun copyEncodedForBuild(): ByteArray {
        requireLive()
        val nameBytes = internalName.toByteArray(Charsets.UTF_8)
        require(nameBytes.size in 1..MAX_INTERNAL_NAME_BYTES) {
            "AKEN ClassPage descriptor internal name encoding is invalid"
        }
        val output = ByteArrayOutputStream(nameBytes.size + pagesValue.size * MIN_PAGE_RECORD_BYTES + 4)
        try {
            writeUnsignedShort(output, nameBytes.size)
            output.write(nameBytes)
            writeUnsignedShort(output, pagesValue.size)
            pagesValue.forEach { page ->
                val handle = page.copyEncodedHandleForBuild()
                val proof = page.copyCallSiteProofForBuild()
                try {
                    writeInt(output, page.pageIndex)
                    output.write(handle)
                    writeUnsignedShort(output, proof.size)
                    output.write(proof)
                } finally {
                    Arrays.fill(handle, 0)
                    Arrays.fill(proof, 0)
                }
            }
            return output.toByteArray().also { encoded ->
                require(encoded.size <= MAX_ENCODED_SIZE) { "AKEN ClassPage descriptor encoding is too large" }
            }
        } finally {
            Arrays.fill(nameBytes, 0)
        }
    }

    /**
     * Produces bounded Base64URL chunks suitable for string constants in a
     * generated stub.  The content is public routing material, never a DEK.
     */
    fun copyBase64UrlChunksForBuild(maxChunkChars: Int = DEFAULT_BASE64_CHUNK_CHARS): List<String> {
        requireLive()
        require(maxChunkChars in MIN_BASE64_CHUNK_CHARS..MAX_BASE64_CHUNK_CHARS) {
            "AKEN ClassPage descriptor Base64 chunk limit is invalid"
        }
        val encoded = copyEncodedForBuild()
        return try {
            val text = Base64.getUrlEncoder().withoutPadding().encodeToString(encoded)
            text.chunked(maxChunkChars)
        } finally {
            Arrays.fill(encoded, 0)
        }
    }

    /** Supplies deep, scoped page-binding copies to a build-only caller. */
    fun <T> withPagesForBuild(block: (List<AkenClassPageDescriptorPage>) -> T): T {
        requireLive()
        val copies = pagesValue.map { it.copyForBuild() }
        try {
            return block(copies.toList())
        } finally {
            copies.forEach { it.wipe() }
        }
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        pagesValue.forEach { it.wipe() }
        pagesValue = emptyList()
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN ClassPage descriptor has been wiped" }
    }

    companion object {
        const val DEFAULT_BASE64_CHUNK_CHARS: Int = 12 * 1024
        private const val MIN_BASE64_CHUNK_CHARS: Int = 4
        private const val MAX_BASE64_CHUNK_CHARS: Int = 32 * 1024
        private const val MAX_INTERNAL_NAME_BYTES: Int = 4096
        private const val MAX_PAGE_COUNT: Int = 8192
        private const val MAX_ENCODED_SIZE: Int = 32 * 1024 * 1024
        private const val MAX_CALL_SITE_PROOF_SIZE: Int = 4096
        private const val MIN_PAGE_RECORD_BYTES: Int = Int.SIZE_BYTES + AkenHandle.ENCODED_HANDLE_SIZE + Short.SIZE_BYTES + 1

        fun create(
            internalName: String,
            pages: Iterable<AkenClassPageDescriptorPage>,
        ): AkenClassPageDescriptor {
            val copies = pages.map { it.copyForBuild() }
            return try {
                AkenClassPageDescriptor(internalName, copies)
            } catch (error: Throwable) {
                copies.forEach { it.wipe() }
                throw error
            }
        }

        /** Strictly decodes one class-local descriptor; trailing data is rejected. */
        fun decodeForBuild(encoded: ByteArray): AkenClassPageDescriptor {
            require(encoded.isNotEmpty() && encoded.size <= MAX_ENCODED_SIZE) {
                "AKEN ClassPage descriptor encoding length is invalid"
            }
            val reader = DescriptorReader(encoded)
            val nameBytes = reader.readExact(reader.readUnsignedShort("internal name length"), "internal name")
            val internalName = try {
                String(nameBytes, Charsets.UTF_8)
            } finally {
                Arrays.fill(nameBytes, 0)
            }
            require(isValidInternalName(internalName)) { "AKEN ClassPage descriptor internal name is invalid" }
            val pageCount = reader.readUnsignedShort("page count")
            require(pageCount in 1..MAX_PAGE_COUNT) { "AKEN ClassPage descriptor page count is invalid" }
            val pages = ArrayList<AkenClassPageDescriptorPage>(pageCount)
            try {
                repeat(pageCount) { expectedIndex ->
                    val pageIndex = reader.readInt("page index")
                    require(pageIndex == expectedIndex) {
                        "AKEN ClassPage descriptor pages must use contiguous zero-based indices"
                    }
                    val handle = reader.readExact(AkenHandle.ENCODED_HANDLE_SIZE, "page handle")
                    val proof = reader.readExact(reader.readUnsignedShort("call-site proof length"), "call-site proof")
                    try {
                        pages += AkenClassPageDescriptorPage.create(
                            pageIndex = pageIndex,
                            encodedHandle = handle,
                            callSiteProof = proof,
                        )
                    } finally {
                        Arrays.fill(handle, 0)
                        Arrays.fill(proof, 0)
                    }
                }
                require(reader.isAtEnd) { "AKEN ClassPage descriptor has trailing bytes" }
                return AkenClassPageDescriptor(internalName, pages)
            } catch (error: Throwable) {
                pages.forEach { it.wipe() }
                throw error
            }
        }
    }
}

/** One owned handle/proof binding within an [AkenClassPageDescriptor]. */
internal class AkenClassPageDescriptorPage private constructor(
    val pageIndex: Int,
    encodedHandle: ByteArray,
    callSiteProof: ByteArray,
) : AutoCloseable {
    private var encodedHandleValue: ByteArray = encodedHandle.copyOf()
    private var callSiteProofValue: ByteArray = callSiteProof.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(pageIndex >= 0) { "AKEN ClassPage descriptor page index is invalid" }
        require(encodedHandleValue.size == AkenHandle.ENCODED_HANDLE_SIZE) {
            "AKEN ClassPage descriptor handle length is invalid"
        }
        require(callSiteProofValue.isNotEmpty() && callSiteProofValue.size <= MAX_CALL_SITE_PROOF_SIZE) {
            "AKEN ClassPage descriptor call-site proof length is invalid"
        }
    }

    val isWiped: Boolean
        get() = wiped

    fun copyEncodedHandleForBuild(): ByteArray {
        requireLive()
        return encodedHandleValue.copyOf()
    }

    fun copyCallSiteProofForBuild(): ByteArray {
        requireLive()
        return callSiteProofValue.copyOf()
    }

    fun copyForBuild(): AkenClassPageDescriptorPage {
        requireLive()
        return AkenClassPageDescriptorPage(pageIndex, encodedHandleValue, callSiteProofValue)
    }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        Arrays.fill(encodedHandleValue, 0)
        Arrays.fill(callSiteProofValue, 0)
        encodedHandleValue = ByteArray(0)
        callSiteProofValue = ByteArray(0)
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN ClassPage descriptor page binding has been wiped" }
    }

    companion object {
        private const val MAX_CALL_SITE_PROOF_SIZE: Int = 4096

        fun create(
            pageIndex: Int,
            encodedHandle: ByteArray,
            callSiteProof: ByteArray,
        ): AkenClassPageDescriptorPage = AkenClassPageDescriptorPage(
            pageIndex = pageIndex,
            encodedHandle = encodedHandle,
            callSiteProof = callSiteProof,
        )
    }
}

private val DESCRIPTOR_ROUTE_DOMAIN = "AKEN-v4-class-page-descriptor-route-v1".toByteArray(Charsets.US_ASCII)
private val DESCRIPTOR_MARKER_DOMAIN = "AKEN-v4-class-page-descriptor-marker-v1".toByteArray(Charsets.US_ASCII)
private val DESCRIPTOR_ROUTE_ROOTS = arrayOf(
    "META-INF/.a4/c",
    "META-INF/.r4/p",
    "assets/.a4/c",
    "META-INF/.j4/r",
)
private val DESCRIPTOR_ROUTE_SUFFIXES = arrayOf(".bin", ".dat", ".p", ".r")

private fun descriptorDigest(domain: ByteArray, internalName: String): ByteArray {
    val nameBytes = internalName.toByteArray(Charsets.UTF_8)
    return try {
        MessageDigest.getInstance("SHA-256").apply {
            update(domain)
            updateDescriptorInt(nameBytes.size)
            update(nameBytes)
        }.digest()
    } finally {
        Arrays.fill(nameBytes, 0)
    }
}

private fun MessageDigest.updateDescriptorInt(value: Int) {
    update((value ushr 24).toByte())
    update((value ushr 16).toByte())
    update((value ushr 8).toByte())
    update(value.toByte())
}

private fun descriptorRouteFromDigest(digest: ByteArray): String {
    require(digest.size >= 3) { "AKEN ClassPage descriptor route digest is invalid" }
    val token = Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    val root = DESCRIPTOR_ROUTE_ROOTS[(digest[0].toInt() and 0xFF) % DESCRIPTOR_ROUTE_ROOTS.size]
    val prefixLength = 2 + ((digest[1].toInt() and 0xFF) % 3)
    val suffix = DESCRIPTOR_ROUTE_SUFFIXES[(digest[2].toInt() and 0xFF) % DESCRIPTOR_ROUTE_SUFFIXES.size]
    return "$root/${token.substring(0, prefixLength)}/${token.substring(prefixLength)}$suffix"
}

private fun isValidInternalName(value: String): Boolean {
    if (value.isEmpty() || value.length > 4096 || value.startsWith('/') || value.endsWith('/')) return false
    return value.split('/').all { segment ->
        segment.isNotEmpty() &&
            segment != "." &&
            segment != ".." &&
            segment.none { char -> char == '.' || char == ';' || char == '[' || char == '\u0000' || char.isISOControl() }
    }
}

private fun writeUnsignedShort(output: ByteArrayOutputStream, value: Int) {
    require(value in 0..0xFFFF) { "AKEN ClassPage descriptor unsigned-short value is invalid" }
    output.write((value ushr 8) and 0xFF)
    output.write(value and 0xFF)
}

private fun writeInt(output: ByteArrayOutputStream, value: Int) {
    output.write((value ushr 24) and 0xFF)
    output.write((value ushr 16) and 0xFF)
    output.write((value ushr 8) and 0xFF)
    output.write(value and 0xFF)
}

private class DescriptorReader(private val source: ByteArray) {
    private var offset: Int = 0

    val isAtEnd: Boolean
        get() = offset == source.size

    fun readUnsignedShort(label: String): Int {
        requireRemaining(Short.SIZE_BYTES, label)
        val result = ((source[offset].toInt() and 0xFF) shl 8) or (source[offset + 1].toInt() and 0xFF)
        offset += Short.SIZE_BYTES
        return result
    }

    fun readInt(label: String): Int {
        requireRemaining(Int.SIZE_BYTES, label)
        val result =
            ((source[offset].toInt() and 0xFF) shl 24) or
                ((source[offset + 1].toInt() and 0xFF) shl 16) or
                ((source[offset + 2].toInt() and 0xFF) shl 8) or
                (source[offset + 3].toInt() and 0xFF)
        offset += Int.SIZE_BYTES
        return result
    }

    fun readExact(size: Int, label: String): ByteArray {
        require(size >= 0) { "AKEN ClassPage descriptor $label size is invalid" }
        requireRemaining(size, label)
        return source.copyOfRange(offset, offset + size).also { offset += size }
    }

    private fun requireRemaining(size: Int, label: String) {
        require(size <= source.size - offset) { "AKEN ClassPage descriptor $label is truncated" }
    }
}
