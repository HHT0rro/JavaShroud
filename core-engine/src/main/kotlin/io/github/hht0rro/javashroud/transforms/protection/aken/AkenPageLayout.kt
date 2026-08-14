package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64

/**
 * Build-specific physical framing for one AKEN v4 encrypted page.
 *
 * The logical AKEN header stays fixed-size so native and Java emitters can share
 * a compact codec contract. The header is nevertheless placed in a randomized
 * physical frame: every build chooses prefix/suffix lengths, a header position,
 * and an opaque routing marker. The complete descriptor is authenticated by the
 * page AEAD and is available to sealing/runtime emitters through [variant].
 */
class AkenPageLayout private constructor(
    private val familyValue: String,
    val prefixLength: Int,
    val suffixLength: Int,
    private val headerAfterBodyValue: Boolean,
    marker: ByteArray,
) {
    private var markerValue: ByteArray = marker.copyOf()

    @Volatile
    private var wiped: Boolean = false

    init {
        require(FAMILY_PATTERN.matches(familyValue)) {
            "AKEN layout family must match " + FAMILY_PATTERN.pattern
        }
        require(prefixLength in MIN_PREFIX_LENGTH..MAX_PREFIX_LENGTH) {
            "AKEN prefix length is outside the supported frame range"
        }
        require(suffixLength in MIN_SUFFIX_LENGTH..MAX_SUFFIX_LENGTH) {
            "AKEN suffix length is outside the supported frame range"
        }
        require(markerValue.size == ROUTING_MARKER_SIZE) {
            "AKEN layout routing marker has an invalid length"
        }
    }

    val family: String
        get() {
            requireLive()
            return familyValue
        }

    /** True when the encrypted body is physically stored before the header. */
    val headerAfterBody: Boolean
        get() {
            requireLive()
            return headerAfterBodyValue
        }

    /** Defensive-copy view of the per-build public routing marker. */
    val routingMarker: ByteArray
        get() {
            requireLive()
            return markerValue.copyOf()
        }

    /**
     * Stable serializable descriptor for this physical frame. It is not a
     * secret, but it is part of both the evaluator fingerprint and page AAD.
     */
    val variant: String
        get() {
            requireLive()
            val position = if (headerAfterBodyValue) POSITION_TAIL else POSITION_HEAD
            val marker = Base64.getUrlEncoder().withoutPadding().encodeToString(markerValue)
            return "$FORMAT_PREFIX:$familyValue:$prefixLength:$suffixLength:$position:$marker"
        }

    /** Locate the fixed logical header in a complete encoded page. */
    fun headerOffset(totalLength: Int): Int {
        requireLive()
        require(totalLength >= minimumEncodedLength()) {
            "AKEN encoded page is shorter than its configured frame"
        }
        return if (headerAfterBodyValue) {
            totalLength - suffixLength - AkenResourceCodec.LOGICAL_HEADER_SIZE
        } else {
            prefixLength
        }
    }

    /** Locate the encrypted body in a complete encoded page. */
    fun bodyOffset(): Int {
        requireLive()
        return if (headerAfterBodyValue) {
            prefixLength
        } else {
            prefixLength + AkenResourceCodec.LOGICAL_HEADER_SIZE
        }
    }

    /** Total encoded-page length for a body that already includes the GCM tag. */
    fun encodedLength(ciphertextWithTagLength: Int): Int {
        requireLive()
        require(ciphertextWithTagLength >= AkenResourceCodec.GCM_TAG_SIZE) {
            "AKEN ciphertext must include a GCM tag"
        }
        val total = prefixLength.toLong() +
            AkenResourceCodec.LOGICAL_HEADER_SIZE.toLong() +
            ciphertextWithTagLength.toLong() +
            suffixLength.toLong()
        require(total <= Int.MAX_VALUE) { "AKEN encoded page is too large" }
        return total.toInt()
    }

    internal fun copyForBuild(): AkenPageLayout {
        requireLive()
        return AkenPageLayout(
            familyValue = familyValue,
            prefixLength = prefixLength,
            suffixLength = suffixLength,
            headerAfterBodyValue = headerAfterBodyValue,
            marker = markerValue,
        )
    }

    internal fun wipe() {
        if (wiped) return
        Arrays.fill(markerValue, 0)
        markerValue = ByteArray(0)
        wiped = true
    }

    private fun minimumEncodedLength(): Int = encodedLength(AkenResourceCodec.GCM_TAG_SIZE)

    private fun requireLive() {
        check(!wiped) { "AKEN page layout has been wiped" }
    }

    companion object {
        private const val FORMAT_PREFIX = "aken4-frame1"
        private const val POSITION_HEAD = "head"
        private const val POSITION_TAIL = "tail"
        private const val ROUTING_MARKER_SIZE = 8
        private const val MIN_PREFIX_LENGTH = 12
        private const val MAX_PREFIX_LENGTH = 60
        private const val MIN_SUFFIX_LENGTH = 8
        private const val MAX_SUFFIX_LENGTH = 40
        private val FAMILY_PATTERN = Regex("[a-z0-9][a-z0-9._-]{0,31}")

        /** Mint a new physical frame for one build page. */
        internal fun create(family: String, random: SecureRandom): AkenPageLayout {
            // A finalization reservation chooses the physical frame before the
            // artifact commitment exists, then passes its exact serialized
            // variant into AkenBuildPlan after that commitment is known.  Keep
            // that replay narrow and explicit: ordinary callers still provide a
            // family name, while only a valid full frame descriptor can request
            // a pre-reserved layout.
            val requested = family.trim()
            if (requested.startsWith("$FORMAT_PREFIX:")) return fromVariant(requested)
            val normalizedFamily = normalizeFamily(requested)
            val marker = ByteArray(ROUTING_MARKER_SIZE).also(random::nextBytes)
            return try {
                AkenPageLayout(
                    familyValue = normalizedFamily,
                    prefixLength = MIN_PREFIX_LENGTH +
                        random.nextInt(((MAX_PREFIX_LENGTH - MIN_PREFIX_LENGTH) / 4) + 1) * 4,
                    suffixLength = MIN_SUFFIX_LENGTH +
                        random.nextInt(((MAX_SUFFIX_LENGTH - MIN_SUFFIX_LENGTH) / 4) + 1) * 4,
                    headerAfterBodyValue = random.nextBoolean(),
                    marker = marker,
                )
            } finally {
                Arrays.fill(marker, 0)
            }
        }

        /** Rehydrate a serialized layout descriptor for a sealing/runtime consumer. */
        fun fromVariant(variant: String): AkenPageLayout {
            val parts = variant.split(':')
            require(parts.size == 6 && parts[0] == FORMAT_PREFIX) {
                "AKEN layout variant has an invalid format"
            }
            val prefix = parts[2].toIntOrNull()
                ?: throw IllegalArgumentException("AKEN layout prefix is invalid")
            val suffix = parts[3].toIntOrNull()
                ?: throw IllegalArgumentException("AKEN layout suffix is invalid")
            val headerAfterBody = when (parts[4]) {
                POSITION_HEAD -> false
                POSITION_TAIL -> true
                else -> throw IllegalArgumentException("AKEN layout header position is invalid")
            }
            val marker = try {
                Base64.getUrlDecoder().decode(parts[5])
            } catch (error: IllegalArgumentException) {
                throw IllegalArgumentException("AKEN layout routing marker is invalid", error)
            }
            return try {
                AkenPageLayout(
                    familyValue = normalizeFamily(parts[1]),
                    prefixLength = prefix,
                    suffixLength = suffix,
                    headerAfterBodyValue = headerAfterBody,
                    marker = marker,
                )
            } finally {
                Arrays.fill(marker, 0)
            }
        }

        private fun normalizeFamily(family: String): String {
            val normalized = family.trim().lowercase()
            require(FAMILY_PATTERN.matches(normalized)) {
                "AKEN layout family must match " + FAMILY_PATTERN.pattern
            }
            return normalized
        }
    }
}
