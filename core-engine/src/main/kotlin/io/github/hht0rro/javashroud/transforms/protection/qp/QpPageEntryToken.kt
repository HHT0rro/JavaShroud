package io.github.hht0rro.javashroud.transforms.protection.qp

import java.security.MessageDigest
import java.util.Arrays

/**
 * Public, deterministic locator key derivation for typed non-Qp VM Qp page
 * bridges.  It is a route binding only: it derives no DEK and carries no
 * authority outside the exact kind/page/handle tuple.
 *
 * Qp VM keeps its existing explicit method entry token because VM dispatch is
 * keyed by that method identity.  String, encrypted-class, and native-chunk
 * bridges receive only a handle, page index, and call-site proof, so they use
 * this artifact-local key to select exactly one compiled locator record.
 */
internal object QpPageEntryToken {
    private val ENTRY_TOKEN_DOMAIN =
        "javashroud-qp-typed-page-entry-token-v1".toByteArray(Charsets.US_ASCII)
    private val PAGE_BINDING_DOMAIN =
        "javashroud-qp-typed-page-route-binding-v1".toByteArray(Charsets.US_ASCII)

    fun derive(
        resourceKind: QpResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
    ): Long {
        requireTypedRequest(resourceKind, pageIndex, encodedHandle)

        val digest = MessageDigest.getInstance("SHA-256").apply {
            update(ENTRY_TOKEN_DOMAIN)
            update(resourceKind.id.toByte())
            updateInt(this, pageIndex)
            update(encodedHandle)
        }.digest()
        try {
            var token = 0L
            for (index in 0 until Long.SIZE_BYTES) {
                token = (token shl 8) or (digest[index].toLong() and 0xFFL)
            }
            return token
        } finally {
            Arrays.fill(digest, 0)
        }
    }

    /**
     * Compiler-record binding material for one non-Qp VM typed route.  It is
     * public integrity data and stays separate from the Qp VM state-layout
     * digest carried by legacy-compatible Qp VM records on the same wire format.
     */
    fun pageBinding(
        resourceKind: QpResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
        routeEncoding: ByteArray,
    ): ByteArray {
        requireTypedRequest(resourceKind, pageIndex, encodedHandle)
        require(routeEncoding.isNotEmpty()) { "Qp typed page route binding is empty" }
        return MessageDigest.getInstance("SHA-256").apply {
            update(PAGE_BINDING_DOMAIN)
            update(resourceKind.id.toByte())
            updateInt(this, pageIndex)
            updateInt(this, encodedHandle.size)
            update(encodedHandle)
            updateInt(this, routeEncoding.size)
            update(routeEncoding)
        }.digest()
    }

    private fun requireTypedRequest(
        resourceKind: QpResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
    ) {
        require(resourceKind != QpResourceKind.QpMethod) {
            "Qp typed page entry-token derivation does not apply to Qp VM"
        }
        require(pageIndex >= 0) { "Qp typed page entry-token page index is invalid" }
        require(encodedHandle.size == QpHandle.ENCODED_HANDLE_SIZE) {
            "Qp typed page entry-token handle length is invalid"
        }
    }

    private fun updateInt(digest: MessageDigest, value: Int) {
        digest.update((value ushr 24).toByte())
        digest.update((value ushr 16).toByte())
        digest.update((value ushr 8).toByte())
        digest.update(value.toByte())
    }
}
