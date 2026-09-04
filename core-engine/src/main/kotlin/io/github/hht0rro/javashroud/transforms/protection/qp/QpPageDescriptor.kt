package io.github.hht0rro.javashroud.transforms.protection.qp

import java.io.ByteArrayOutputStream
import java.util.Arrays

/**
 * Runtime-neutral metadata for exactly one high-value Qp current format page.
 *
 * It combines one opaque handle binding, the corresponding logical identity,
 * one route, one integrity/call-site proof, and the native secret-pack slot
 * that owns the page's key derivation material. It offers no directory,
 * traversal, or arbitrary-resource decoding surface.
 */
class QpPageDescriptor private constructor(
    private val leafIdentityValue: QpLeafIdentity,
    private val routeValue: QpRouteMetadata,
    private val proofValue: QpProofMetadata,
    val targetPageSize: Int,
    val secretSlot: Int,
) {
    init {
        validateBinding(leafIdentityValue, routeValue, proofValue, targetPageSize, secretSlot)
    }

    val resourceKind: QpResourceKind
        get() = leafIdentityValue.resourceKind

    val pageIndex: Int
        get() = leafIdentityValue.pageIndex

    val logicalIdentity: ByteArray
        get() = leafIdentityValue.logicalIdentity

    /** A fresh opaque handle for this descriptor's only page binding. */
    val handle: QpHandle
        get() = handleFromIdentity(leafIdentityValue)

    val route: QpRouteMetadata
        get() = routeValue

    val proof: QpProofMetadata
        get() = proofValue

    fun matches(candidate: QpHandle): Boolean = leafIdentityValue.matches(candidate)

    /**
     * Compact current-format locator: version, route, proof, target size, and
     * the native secret slot. No evaluator plan, DEK, or page material is
     * serialized; older descriptor encodings fail on the leading version byte.
     */
    fun encode(): ByteArray = ByteArrayOutputStream().use { out ->
        val route = routeValue.encode()
        val proof = proofValue.encode()
        try {
            out.write(CURRENT_DESCRIPTOR_VERSION)
            writeRuntimeFramed(out, route)
            writeRuntimeFramed(out, proof)
            writeRuntimeInt(out, targetPageSize)
            writeRuntimeInt(out, secretSlot)
            out.toByteArray().also {
                require(it.size <= MAX_DESCRIPTOR_ENCODING_SIZE) {
                    "Qp runtime page descriptor encoding is too large"
                }
            }
        } finally {
            Arrays.fill(route, 0)
            Arrays.fill(proof, 0)
        }
    }

    override fun toString(): String =
        "QpPageDescriptor(kind=" + resourceKind.logicalName + ", page=" + pageIndex + ")"

    companion object {
        private const val MAX_DESCRIPTOR_ENCODING_SIZE = 384 * 1024
        private const val MAX_ROUTE_ENCODING_SIZE = 128 * 1024
        private const val MAX_PROOF_ENCODING_SIZE = 160 * 1024
        private val MAX_SECRET_SLOT: Int = QP_SECRET_PACK_MAX_SLOTS - 1

        /** Current compact descriptor layout; older encodings are rejected fail-closed. */
        internal const val CURRENT_DESCRIPTOR_VERSION: Int = 3

        fun create(
            handle: QpHandle,
            logicalIdentity: ByteArray,
            route: QpRouteMetadata,
            proof: QpProofMetadata,
            targetPageSize: Int,
            secretSlot: Int,
        ): QpPageDescriptor {
            val identity = QpLeafIdentity.fromHandle(handle, logicalIdentity)
            return fromMetadata(identity, route, proof, targetPageSize, secretSlot)
        }

        fun decode(encoded: ByteArray): QpPageDescriptor {
            require(encoded.isNotEmpty() && encoded.size <= MAX_DESCRIPTOR_ENCODING_SIZE) {
                "Qp runtime page descriptor encoding length is invalid"
            }
            val reader = QpRuntimeDescriptorReader(encoded)
            var routeBytes: ByteArray? = null
            var proofBytes: ByteArray? = null
            return try {
                val version = reader.readUnsignedByte("Qp runtime page descriptor version")
                require(version == CURRENT_DESCRIPTOR_VERSION) {
                    "Qp runtime page descriptor version is not current"
                }
                routeBytes = reader.readFramed(MAX_ROUTE_ENCODING_SIZE, "Qp runtime page route", allowEmpty = false)
                val route = QpRouteMetadata.decode(checkNotNull(routeBytes))
                proofBytes = reader.readFramed(MAX_PROOF_ENCODING_SIZE, "Qp runtime page proof", allowEmpty = false)
                val proof = QpProofMetadata.decode(checkNotNull(proofBytes))
                val targetPageSize = reader.readInt("Qp runtime target page size")
                val secretSlot = reader.readInt("Qp runtime secret slot")
                require(secretSlot in 0..MAX_SECRET_SLOT) {
                    "Qp runtime secret slot is invalid"
                }
                reader.requireFullyRead("Qp runtime page descriptor")
                fromMetadata(route.leafIdentity, route, proof, targetPageSize, secretSlot)
            } finally {
                routeBytes?.let { Arrays.fill(it, 0) }
                proofBytes?.let { Arrays.fill(it, 0) }
            }
        }

        private fun fromMetadata(
            identity: QpLeafIdentity,
            route: QpRouteMetadata,
            proof: QpProofMetadata,
            targetPageSize: Int,
            secretSlot: Int,
        ): QpPageDescriptor = QpPageDescriptor(
            identity,
            route,
            proof,
            targetPageSize,
            secretSlot,
        )

        private fun validateBinding(
            identity: QpLeafIdentity,
            route: QpRouteMetadata,
            proof: QpProofMetadata,
            targetPageSize: Int,
            secretSlot: Int,
        ) {
            require(route.leafIdentity == identity) { "Qp runtime route does not bind the current page" }
            require(proof.leafIdentity == identity) { "Qp runtime proof does not bind the current page" }
            require(route.codecVariant == proof.codecVariant) { "Qp runtime route/proof codec mismatch" }
            require(route.layoutVariant == proof.layoutVariant) { "Qp runtime route/proof layout mismatch" }
            require(targetPageSize > 0) { "Qp runtime target page size is invalid" }
            require(secretSlot in 0..MAX_SECRET_SLOT) { "Qp runtime secret slot is invalid" }
        }

        private fun handleFromIdentity(identity: QpLeafIdentity): QpHandle {
            var encoded: ByteArray? = null
            var locator: ByteArray? = null
            var fingerprint: ByteArray? = null
            return try {
                encoded = identity.handleEncoding
                locator = identity.locatorToken
                fingerprint = identity.evaluatorFingerprint
                QpHandle.create(
                    identity.resourceKind,
                    identity.pageIndex,
                    checkNotNull(encoded),
                    checkNotNull(locator),
                    checkNotNull(fingerprint),
                )
            } finally {
                encoded?.let { Arrays.fill(it, 0) }
                locator?.let { Arrays.fill(it, 0) }
                fingerprint?.let { Arrays.fill(it, 0) }
            }
        }
    }
}

private fun writeRuntimeInt(out: ByteArrayOutputStream, value: Int) {
    out.write((value ushr 24) and 0xFF)
    out.write((value ushr 16) and 0xFF)
    out.write((value ushr 8) and 0xFF)
    out.write(value and 0xFF)
}

private fun writeRuntimeFramed(out: ByteArrayOutputStream, value: ByteArray) {
    writeRuntimeInt(out, value.size)
    out.write(value)
}

private class QpRuntimeDescriptorReader(private val bytes: ByteArray) {
    private var offset = 0

    fun readUnsignedByte(label: String): Int {
        requireRemaining(1, label)
        return bytes[offset++].toInt() and 0xFF
    }

    fun readInt(label: String): Int {
        requireRemaining(Int.SIZE_BYTES, label)
        val value =
            ((bytes[offset].toInt() and 0xFF) shl 24) or
                ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
                ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
                (bytes[offset + 3].toInt() and 0xFF)
        offset += Int.SIZE_BYTES
        return value
    }

    fun readFixed(length: Int, label: String): ByteArray {
        require(length >= 0) { "Qp runtime fixed length must be non-negative" }
        requireRemaining(length, label)
        return bytes.copyOfRange(offset, offset + length).also { offset += length }
    }

    fun readFramed(maximumLength: Int, label: String, allowEmpty: Boolean = true): ByteArray {
        val length = readInt("$label length")
        require(length >= 0 && length <= maximumLength && (allowEmpty || length > 0)) {
            "$label length is invalid"
        }
        return readFixed(length, label)
    }

    fun requireFullyRead(label: String) {
        require(offset == bytes.size) { "$label contains trailing bytes" }
    }

    private fun requireRemaining(length: Int, label: String) {
        require(length >= 0 && offset <= bytes.size - length) { "$label is truncated" }
    }
}
