package io.github.hht0rro.javashroud.transforms.protection.aken

import java.util.Arrays
import java.util.Base64

/**
 * Opaque locator for exactly one AKEN page.
 *
 * It deliberately carries no catalog or traversal API. Callers can only give
 * this handle back to the build plan that minted it.
 */
class AkenHandle internal constructor(
    val resourceKind: AkenResourceKind,
    val pageIndex: Int,
    encoded: ByteArray,
    locatorToken: ByteArray,
    evaluatorFingerprint: ByteArray,
) {
    private var encodedValue = encoded.copyOf()
    private var locatorValue = locatorToken.copyOf()
    private var fingerprintValue = evaluatorFingerprint.copyOf()
    private var wiped = false

    init {
        require(pageIndex >= 0) { "AKEN page index must be non-negative" }
        require(encodedValue.size == ENCODED_HANDLE_SIZE) {
            "AKEN handle encoding has an invalid length"
        }
        require(locatorValue.size == LOCATOR_TOKEN_SIZE) {
            "AKEN locator token has an invalid length"
        }
        require(fingerprintValue.size == FINGERPRINT_SIZE) {
            "AKEN evaluator fingerprint has an invalid length"
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

    val evaluatorPlanFingerprint: ByteArray
        get() {
            requireLive()
            return fingerprintValue.copyOf()
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
        Arrays.fill(fingerprintValue, 0)
        encodedValue = ByteArray(0)
        locatorValue = ByteArray(0)
        fingerprintValue = ByteArray(0)
        wiped = true
    }

    override fun equals(other: Any?): Boolean =
        other is AkenHandle &&
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
        "AkenHandle(kind=" + resourceKind.logicalName + ", page=" + pageIndex + ")"

    private fun requireLive() {
        check(!wiped) { "AKEN handle has been wiped" }
    }

    internal companion object {
        const val ENCODED_HANDLE_SIZE: Int = 24
        const val LOCATOR_TOKEN_SIZE: Int = 16
        const val FINGERPRINT_SIZE: Int = 32

        fun create(
            resourceKind: AkenResourceKind,
            pageIndex: Int,
            encoded: ByteArray,
            locatorToken: ByteArray,
            evaluatorFingerprint: ByteArray,
        ): AkenHandle = AkenHandle(
            resourceKind = resourceKind,
            pageIndex = pageIndex,
            encoded = encoded,
            locatorToken = locatorToken,
            evaluatorFingerprint = evaluatorFingerprint,
        )
    }
}
