package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.MessageDigest
import java.util.Arrays

/**
 * Public, deterministic locator key derivation for typed non-VBC4 AKEN page
 * bridges.  It is a route binding only: it derives no DEK and carries no
 * authority outside the exact kind/page/handle tuple.
 *
 * VBC4 keeps its existing explicit method entry token because VM dispatch is
 * keyed by that method identity.  String, encrypted-class, and native-chunk
 * bridges receive only a handle, page index, and call-site proof, so they use
 * this artifact-local key to select exactly one compiled locator record.
 */
internal object AkenTypedPageEntryToken {
    private val ENTRY_TOKEN_DOMAIN =
        "AKEN-v4-typed-page-entry-token-v1".toByteArray(Charsets.US_ASCII)
    private val PAGE_BINDING_DOMAIN =
        "AKEN-v4-typed-page-route-binding-v1".toByteArray(Charsets.US_ASCII)

    fun derive(
        resourceKind: AkenResourceKind,
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
     * Compiler-record binding material for one non-VBC4 typed route.  It is
     * public integrity data and stays separate from the VBC4 state-layout
     * digest carried by legacy-compatible VBC4 records on the same wire format.
     */
    fun pageBinding(
        resourceKind: AkenResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
        routeEncoding: ByteArray,
    ): ByteArray {
        requireTypedRequest(resourceKind, pageIndex, encodedHandle)
        require(routeEncoding.isNotEmpty()) { "AKEN typed page route binding is empty" }
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
        resourceKind: AkenResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
    ) {
        require(resourceKind != AkenResourceKind.Vbc4Method) {
            "AKEN typed page entry-token derivation does not apply to VBC4"
        }
        require(pageIndex >= 0) { "AKEN typed page entry-token page index is invalid" }
        require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) {
            "AKEN typed page entry-token handle length is invalid"
        }
    }

    private fun updateInt(digest: MessageDigest, value: Int) {
        digest.update((value ushr 24).toByte())
        digest.update((value ushr 16).toByte())
        digest.update((value ushr 8).toByte())
        digest.update(value.toByte())
    }
}
