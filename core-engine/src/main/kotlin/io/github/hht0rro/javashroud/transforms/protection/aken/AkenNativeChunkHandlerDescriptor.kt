package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.MessageDigest
import java.util.Arrays

/**
 * Build-only binary contract for the fixed native loader-handler action.
 *
 * The descriptor is page plaintext only until the AKEN current-page opener
 * authenticates it inside the native kernel.  It is not a locator, a page
 * catalog, or a cryptographic key: the handle/proof fields merely make the
 * one native-private action reject a descriptor replayed through another
 * typed NativeChunk route.
 */
internal object AkenNativeChunkHandlerDescriptor {
    internal const val ENCODED_SIZE: Int = 192
    internal const val IDENTITY_SIZE: Int = 32
    internal const val ENCODED_HANDLE_SIZE: Int = AkenHandle.ENCODED_HANDLE_SIZE
    internal const val CALL_SITE_PROOF_SIZE: Int = 32
    internal const val NONCE_SIZE: Int = 32

    private const val HEADER_SIZE: Int = 8
    private const val IDENTITY_OFFSET: Int = HEADER_SIZE
    private const val HANDLE_OFFSET: Int = IDENTITY_OFFSET + IDENTITY_SIZE
    private const val PROOF_OFFSET: Int = HANDLE_OFFSET + ENCODED_HANDLE_SIZE
    private const val NONCE_OFFSET: Int = PROOF_OFFSET + CALL_SITE_PROOF_SIZE
    private const val TERMINAL_BINDING_OFFSET: Int = NONCE_OFFSET + NONCE_SIZE
    private const val ACTION_TAG_OFFSET: Int = TERMINAL_BINDING_OFFSET + IDENTITY_SIZE

    private val HEADER = byteArrayOf(
        0xA4.toByte(),
        0x5E,
        0x13,
        0xC7.toByte(),
        0x01,
        0x41,
        0xD9.toByte(),
        0x6B,
    )
    private val TERMINAL_BINDING_DOMAIN =
        "AKEN-v4-native-handler-terminal-binding-v1".toByteArray(Charsets.US_ASCII)
    private val ACTION_TAG_DOMAIN =
        "AKEN-v4-native-handler-action-tag-v1".toByteArray(Charsets.US_ASCII)

    init {
        check(ACTION_TAG_OFFSET + IDENTITY_SIZE == ENCODED_SIZE) {
            "AKEN native handler descriptor layout is inconsistent"
        }
    }

    fun createLoaderAttestation(
        logicalIdentity: ByteArray,
        encodedHandle: ByteArray,
        callSiteProof: ByteArray,
        nonce: ByteArray,
    ): ByteArray {
        require(logicalIdentity.size == IDENTITY_SIZE) {
            "AKEN native handler descriptor identity length is invalid"
        }
        require(encodedHandle.size == ENCODED_HANDLE_SIZE) {
            "AKEN native handler descriptor handle length is invalid"
        }
        require(callSiteProof.size == CALL_SITE_PROOF_SIZE) {
            "AKEN native handler descriptor call-site proof length is invalid"
        }
        require(nonce.size == NONCE_SIZE) {
            "AKEN native handler descriptor nonce length is invalid"
        }

        val descriptor = ByteArray(ENCODED_SIZE)
        var terminalBinding: ByteArray? = null
        var actionTag: ByteArray? = null
        try {
            System.arraycopy(HEADER, 0, descriptor, 0, HEADER_SIZE)
            System.arraycopy(logicalIdentity, 0, descriptor, IDENTITY_OFFSET, IDENTITY_SIZE)
            System.arraycopy(encodedHandle, 0, descriptor, HANDLE_OFFSET, ENCODED_HANDLE_SIZE)
            System.arraycopy(callSiteProof, 0, descriptor, PROOF_OFFSET, CALL_SITE_PROOF_SIZE)
            System.arraycopy(nonce, 0, descriptor, NONCE_OFFSET, NONCE_SIZE)
            terminalBinding = digest(
                domain = TERMINAL_BINDING_DOMAIN,
                HEADER,
                logicalIdentity,
                encodedHandle,
                callSiteProof,
                nonce,
            )
            System.arraycopy(
                checkNotNull(terminalBinding),
                0,
                descriptor,
                TERMINAL_BINDING_OFFSET,
                IDENTITY_SIZE,
            )
            actionTag = digest(
                domain = ACTION_TAG_DOMAIN,
                HEADER,
                logicalIdentity,
                encodedHandle,
                callSiteProof,
                nonce,
                checkNotNull(terminalBinding),
            )
            System.arraycopy(checkNotNull(actionTag), 0, descriptor, ACTION_TAG_OFFSET, IDENTITY_SIZE)
            return descriptor
        } catch (error: Throwable) {
            Arrays.fill(descriptor, 0)
            throw error
        } finally {
            terminalBinding?.let { Arrays.fill(it, 0) }
            actionTag?.let { Arrays.fill(it, 0) }
        }
    }

    /**
     * Build/test-side validation of the exact native descriptor layout.  This
     * mirrors the native terminal checks while retaining no runtime parser or
     * generic NativeChunk decode surface in Java.
     */
    fun isLoaderAttestationForBuild(
        encoded: ByteArray,
        logicalIdentity: ByteArray,
        encodedHandle: ByteArray,
        callSiteProof: ByteArray,
    ): Boolean {
        if (
            encoded.size != ENCODED_SIZE ||
            logicalIdentity.size != IDENTITY_SIZE ||
            encodedHandle.size != ENCODED_HANDLE_SIZE ||
            callSiteProof.size != CALL_SITE_PROOF_SIZE ||
            !matchesAt(encoded, 0, HEADER) ||
            !matchesAt(encoded, IDENTITY_OFFSET, logicalIdentity) ||
            !matchesAt(encoded, HANDLE_OFFSET, encodedHandle) ||
            !matchesAt(encoded, PROOF_OFFSET, callSiteProof)
        ) {
            return false
        }

        val nonce = encoded.copyOfRange(NONCE_OFFSET, NONCE_OFFSET + NONCE_SIZE)
        val terminalBinding = encoded.copyOfRange(
            TERMINAL_BINDING_OFFSET,
            TERMINAL_BINDING_OFFSET + IDENTITY_SIZE,
        )
        val actionTag = encoded.copyOfRange(ACTION_TAG_OFFSET, ACTION_TAG_OFFSET + IDENTITY_SIZE)
        var expectedTerminalBinding: ByteArray? = null
        var expectedActionTag: ByteArray? = null
        try {
            expectedTerminalBinding = digest(
                domain = TERMINAL_BINDING_DOMAIN,
                HEADER,
                logicalIdentity,
                encodedHandle,
                callSiteProof,
                nonce,
            )
            if (!MessageDigest.isEqual(terminalBinding, checkNotNull(expectedTerminalBinding))) return false
            expectedActionTag = digest(
                domain = ACTION_TAG_DOMAIN,
                HEADER,
                logicalIdentity,
                encodedHandle,
                callSiteProof,
                nonce,
                checkNotNull(expectedTerminalBinding),
            )
            return MessageDigest.isEqual(actionTag, checkNotNull(expectedActionTag))
        } finally {
            Arrays.fill(nonce, 0)
            Arrays.fill(terminalBinding, 0)
            Arrays.fill(actionTag, 0)
            expectedTerminalBinding?.let { Arrays.fill(it, 0) }
            expectedActionTag?.let { Arrays.fill(it, 0) }
        }
    }

    private fun digest(domain: ByteArray, vararg parts: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        updateFramed(digest, domain)
        parts.forEach { part -> updateFramed(digest, part) }
        return digest.digest()
    }

    private fun updateFramed(digest: MessageDigest, bytes: ByteArray) {
        val size = bytes.size
        digest.update((size ushr 24).toByte())
        digest.update((size ushr 16).toByte())
        digest.update((size ushr 8).toByte())
        digest.update(size.toByte())
        digest.update(bytes)
    }

    private fun matchesAt(source: ByteArray, offset: Int, expected: ByteArray): Boolean {
        if (offset < 0 || source.size - offset < expected.size) return false
        var difference = 0
        expected.indices.forEach { index ->
            difference = difference or ((source[offset + index].toInt() xor expected[index].toInt()) and 0xFF)
        }
        return difference == 0
    }
}
