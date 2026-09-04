package io.github.hht0rro.javashroud.transforms.protection.qp

import java.util.Arrays
import java.util.Base64

/**
 * Opaque locator for exactly one Qp page.
 *
 * It deliberately carries no catalog or traversal API. Callers can only give
 * this handle back to the build plan that minted it. The 32-byte commitment
 * field binds the page's derived key: it is the secret-pack commitment over
 * the page DEK and is verified by the native open path before decryption.
 */
class QpHandle internal constructor(
    val resourceKind: QpResourceKind,
    val pageIndex: Int,
    encoded: ByteArray,
    locatorToken: ByteArray,
    keyCommitmentFingerprint: ByteArray,
) {
    private var encodedValue = encoded.copyOf()
    private var locatorValue = locatorToken.copyOf()
    private var commitmentValue = keyCommitmentFingerprint.copyOf()
    private var wiped = false

    init {
        require(pageIndex >= 0) { "Qp page index must be non-negative" }
        require(encodedValue.size == ENCODED_HANDLE_SIZE) {
            "Qp handle encoding has an invalid length"
        }
        require(locatorValue.size == LOCATOR_TOKEN_SIZE) {
            "Qp locator token has an invalid length"
        }
        require(commitmentValue.size == FINGERPRINT_SIZE) {
            "Qp key commitment has an invalid length"
        }
    }

    val encoded: ByteArray
        get() {
            requireLive()
            return encodedValue.copyOf()
        }

    val locatorToken: ByteArray
        get() {
            requireLive()
            return locatorValue.copyOf()
        }

    /** Secret-pack commitment over this page's derived key. */
    val keyCommitmentFingerprint: ByteArray
        get() {
            requireLive()
            return commitmentValue.copyOf()
        }

    internal fun encodedKey(): String {
        requireLive()
        return Base64.getUrlEncoder().withoutPadding().encodeToString(encodedValue)
    }

    internal fun copyLocatorTokenForBuild(): ByteArray {
        requireLive()
        return locatorValue.copyOf()
    }

    internal fun wipe() {
        if (wiped) return
        Arrays.fill(encodedValue, 0)
        Arrays.fill(locatorValue, 0)
        Arrays.fill(commitmentValue, 0)
        encodedValue = ByteArray(0)
        locatorValue = ByteArray(0)
        commitmentValue = ByteArray(0)
        wiped = true
    }

    override fun equals(other: Any?): Boolean =
        other is QpHandle &&
            resourceKind == other.resourceKind &&
            pageIndex == other.pageIndex &&
            !wiped &&
            !other.wiped &&
            Arrays.equals(encodedValue, other.encodedValue)

    override fun hashCode(): Int {
        requireLive()
        return 31 * (31 * resourceKind.hashCode() + pageIndex) + encodedValue.contentHashCode()
    }

    override fun toString(): String =
        "QpHandle(kind=" + resourceKind.logicalName + ", page=" + pageIndex + ")"

    private fun requireLive() {
        check(!wiped) { "Qp handle has been wiped" }
    }

    internal companion object {
        const val ENCODED_HANDLE_SIZE: Int = 24
        const val LOCATOR_TOKEN_SIZE: Int = 16
        const val FINGERPRINT_SIZE: Int = 32

        fun create(
            resourceKind: QpResourceKind,
            pageIndex: Int,
            encoded: ByteArray,
            locatorToken: ByteArray,
            keyCommitmentFingerprint: ByteArray,
        ): QpHandle = QpHandle(
            resourceKind = resourceKind,
            pageIndex = pageIndex,
            encoded = encoded,
            locatorToken = locatorToken,
            keyCommitmentFingerprint = keyCommitmentFingerprint,
        )
    }
}
