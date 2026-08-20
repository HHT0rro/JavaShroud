package io.github.hht0rro.javashroud.transforms.protection.aken

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

private const val BOUND_DIGEST_SIZE: Int = 32
private const val BOUND_LANE_COUNT: Int = 8
private const val BOUND_WORD_FAMILY_COUNT: Int = 8
private const val BOUND_PLAN_NONCE_SIZE: Int = 16
private const val BOUND_LANE_SALT_SIZE: Int = 16
private const val BOUND_MIN_TOKEN_SIZE: Int = 17
private const val BOUND_MAX_TOKEN_SIZE: Int = 48

/**
 * Build-only seed for one page-bound native decryptor.
 *
 * The seed never stores a raw page key after construction.  Instead it owns
 * eight independently encoded word lanes, each authenticated against the
 * page's static binding.  The final runtime descriptor adds the route and
 * call-site proof binding immediately before materialization.
 */
internal class AkenBoundDecryptorCore private constructor(
    pageNonce: ByteArray,
    planNonce: ByteArray,
    dispatchVariant: Int,
    staticBinding: ByteArray,
    laneRecords: List<LaneRecord>,
) : AutoCloseable {
    private var dispatchVariantValue = dispatchVariant
    private var staticBindingValue = staticBinding.copyOf()
    private var pageNonceValue = pageNonce.copyOf()
    private var planNonceValue = planNonce.copyOf()
    private var laneRecordsValue = laneRecords

    @Volatile
    private var wiped = false

    init {
        require(pageNonceValue.size == AkenResourceCodec.NONCE_SIZE) { "AKEN bound page nonce length is invalid" }
        require(planNonceValue.size == BOUND_PLAN_NONCE_SIZE) { "AKEN bound plan nonce length is invalid" }
        require(dispatchVariantValue in 0..0xFF) { "AKEN bound dispatcher variant is invalid" }
        require(staticBindingValue.size == BOUND_DIGEST_SIZE) { "AKEN bound static binding length is invalid" }
        require(laneRecordsValue.size == BOUND_LANE_COUNT) { "AKEN bound lane count is invalid" }
        require(laneRecordsValue.map { it.wordIndex }.toSet() == (0 until BOUND_LANE_COUNT).toSet()) {
            "AKEN bound lanes do not cover the page schedule"
        }
    }

    internal fun copyPageNonceForCodec(): ByteArray {
        requireLive()
        return pageNonceValue.copyOf()
    }

    /**
     * Seal the build-only seed into the opaque descriptor frame consumed by the
     * native current-page terminal.  This operation has no raw-key output.
     */
    internal fun finalizeForRuntime(
        route: AkenRoutingMetadata,
        callSiteProof: ByteArray,
    ): AkenBoundDecryptorPlan {
        requireLive()
        require(callSiteProof.isNotEmpty()) { "AKEN bound call-site proof must not be empty" }
        laneRecordsValue.forEach { lane ->
            val expected = AkenBoundDecryptorPlan.laneTag(
                staticBindingValue,
                lane.wordIndex,
                lane.family,
                lane.token,
                lane.salt,
                lane.encodedWord,
            )
            try {
                require(MessageDigest.isEqual(expected, lane.tag)) { "AKEN bound core lane authentication failed" }
            } finally {
                Arrays.fill(expected, 0)
            }
        }
        val routeBytes = route.encode()
        var finalBinding: ByteArray? = null
        var encoded: ByteArray? = null
        try {
            finalBinding = AkenBoundDecryptorPlan.finalBinding(staticBindingValue, routeBytes, callSiteProof)
            encoded = AkenBoundDecryptorPlan.encodeOpaque(
                dispatchVariant = dispatchVariantValue,
                pageNonce = pageNonceValue,
                planNonce = planNonceValue,
                staticBinding = staticBindingValue,
                finalBinding = checkNotNull(finalBinding),
                lanes = laneRecordsValue,
            )
            return AkenBoundDecryptorPlan.fromOpaque(checkNotNull(encoded))
        } finally {
            Arrays.fill(routeBytes, 0)
            finalBinding?.let { Arrays.fill(it, 0) }
            encoded?.let { Arrays.fill(it, 0) }
        }
    }

    override fun close() = wipe()

    internal fun wipe() {
        if (wiped) return
        Arrays.fill(pageNonceValue, 0)
        Arrays.fill(planNonceValue, 0)
        Arrays.fill(staticBindingValue, 0)
        laneRecordsValue.forEach { it.wipe() }
        pageNonceValue = ByteArray(0)
        planNonceValue = ByteArray(0)
        staticBindingValue = ByteArray(0)
        laneRecordsValue = emptyList()
        dispatchVariantValue = 0
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN bound decryptor core has been wiped" }
    }

    companion object {
        internal fun compile(
            dek: ByteArray,
            resourceKind: AkenResourceKind,
            logicalIdentity: ByteArray,
            pageIndex: Int,
            targetPageSize: Int,
            codecVariant: String,
            layoutVariant: String,
            encodedHandle: ByteArray,
            locatorToken: ByteArray,
            evaluatorFingerprint: ByteArray,
            artifactCanonicalCommitment: ByteArray,
            pageNonce: ByteArray,
            random: SecureRandom,
        ): AkenBoundDecryptorCore {
            require(dek.size == AkenEvaluatorState.STATE_WIDTH) { "AKEN bound page material length is invalid" }
            require(pageNonce.size == AkenResourceCodec.NONCE_SIZE) { "AKEN bound page nonce length is invalid" }
            require(evaluatorFingerprint.size == BOUND_DIGEST_SIZE) { "AKEN bound evaluator fingerprint length is invalid" }
            require(artifactCanonicalCommitment.size == BOUND_DIGEST_SIZE) { "AKEN bound artifact commitment length is invalid" }

            val planNonce = ByteArray(BOUND_PLAN_NONCE_SIZE).also(random::nextBytes)
            val dispatchVariant = random.nextInt(256)
            var staticBinding: ByteArray? = null
            val lanes = ArrayList<LaneRecord>(BOUND_LANE_COUNT)
            var completed = false
            try {
                staticBinding = AkenBoundDecryptorPlan.staticBinding(
                    resourceKind = resourceKind,
                    logicalIdentity = logicalIdentity,
                    pageIndex = pageIndex,
                    targetPageSize = targetPageSize,
                    codecVariant = codecVariant,
                    layoutVariant = layoutVariant,
                    encodedHandle = encodedHandle,
                    locatorToken = locatorToken,
                    evaluatorFingerprint = evaluatorFingerprint,
                    artifactCanonicalCommitment = artifactCanonicalCommitment,
                    pageNonce = pageNonce,
                    planNonce = planNonce,
                    dispatchVariant = dispatchVariant,
                )
                val order = IntArray(BOUND_LANE_COUNT) { it }
                for (index in order.lastIndex downTo 1) {
                    val other = random.nextInt(index + 1)
                    val swap = order[index]
                    order[index] = order[other]
                    order[other] = swap
                }
                order.forEach { wordIndex ->
                    val family = random.nextInt(BOUND_WORD_FAMILY_COUNT)
                    val token = ByteArray(BOUND_MIN_TOKEN_SIZE + random.nextInt(BOUND_MAX_TOKEN_SIZE - BOUND_MIN_TOKEN_SIZE + 1)).also(random::nextBytes)
                    val salt = ByteArray(BOUND_LANE_SALT_SIZE).also(random::nextBytes)
                    var tag: ByteArray? = null
                    try {
                        val value = AkenBoundDecryptorPlan.readWord(dek, wordIndex * Int.SIZE_BYTES)
                        val mask = AkenBoundDecryptorPlan.laneMask(checkNotNull(staticBinding), wordIndex, family, token, salt)
                        val encodedWord = AkenBoundDecryptorPlan.encodeWord(value, mask, family, wordIndex)
                        tag = AkenBoundDecryptorPlan.laneTag(checkNotNull(staticBinding), wordIndex, family, token, salt, encodedWord)
                        lanes += LaneRecord(wordIndex, family, token, salt, encodedWord, checkNotNull(tag))
                    } finally {
                        Arrays.fill(token, 0)
                        Arrays.fill(salt, 0)
                        tag?.let { Arrays.fill(it, 0) }
                    }
                }
                completed = true
                return AkenBoundDecryptorCore(
                    pageNonce = pageNonce,
                    planNonce = planNonce,
                    dispatchVariant = dispatchVariant,
                    staticBinding = checkNotNull(staticBinding),
                    laneRecords = lanes,
                )
            } finally {
                Arrays.fill(planNonce, 0)
                staticBinding?.let { Arrays.fill(it, 0) }
                if (!completed) lanes.forEach { it.wipe() }
            }
        }
    }
}

/**
 * Opaque, page-specific runtime descriptor for one AES-GCM terminal.
 *
 * It intentionally has no key getter, no generic resource input, and no
 * runtime decode routine.  The native terminal receives this descriptor only
 * after the locator has selected and authenticated the current page.
 */
internal class AkenBoundDecryptorPlan private constructor(opaque: ByteArray) {
    private val opaqueValue = opaque.copyOf()

    init {
        validateStandalone(opaqueValue)
    }

    internal val encodedSize: Int
        get() = opaqueValue.size

    internal fun copyOpaqueForNative(): ByteArray = opaqueValue.copyOf()

    internal fun matchesPageBinding(
        resourceKind: AkenResourceKind,
        logicalIdentity: ByteArray,
        pageIndex: Int,
        targetPageSize: Int,
        codecVariant: String,
        layoutVariant: String,
        handleEncoding: ByteArray,
        locatorToken: ByteArray,
        evaluatorFingerprint: ByteArray,
        artifactCanonicalCommitment: ByteArray,
        route: AkenRoutingMetadata,
        callSiteProof: ByteArray,
    ): Boolean {
        var parsed: ParsedPlan? = null
        var expectedStatic: ByteArray? = null
        var expectedFinal: ByteArray? = null
        var routeBytes: ByteArray? = null
        try {
            parsed = parse(opaqueValue)
            expectedStatic = staticBinding(
                resourceKind = resourceKind,
                logicalIdentity = logicalIdentity,
                pageIndex = pageIndex,
                targetPageSize = targetPageSize,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
                encodedHandle = handleEncoding,
                locatorToken = locatorToken,
                evaluatorFingerprint = evaluatorFingerprint,
                artifactCanonicalCommitment = artifactCanonicalCommitment,
                pageNonce = checkNotNull(parsed).pageNonce,
                planNonce = checkNotNull(parsed).planNonce,
                dispatchVariant = checkNotNull(parsed).dispatchVariant,
            )
            if (!MessageDigest.isEqual(expectedStatic, checkNotNull(parsed).staticBinding)) return false
            routeBytes = route.encode()
            expectedFinal = finalBinding(checkNotNull(parsed).staticBinding, routeBytes, callSiteProof)
            return MessageDigest.isEqual(expectedFinal, checkNotNull(parsed).finalBinding)
        } catch (_: IllegalArgumentException) {
            return false
        } finally {
            parsed?.wipe()
            expectedStatic?.let { Arrays.fill(it, 0) }
            expectedFinal?.let { Arrays.fill(it, 0) }
            routeBytes?.let { Arrays.fill(it, 0) }
        }
    }

    internal fun copyPageNonceForVerification(): ByteArray {
        val parsed = parse(opaqueValue)
        return try {
            parsed.pageNonce.copyOf()
        } finally {
            parsed.wipe()
        }
    }

    override fun equals(other: Any?): Boolean =
        other is AkenBoundDecryptorPlan && Arrays.equals(opaqueValue, other.opaqueValue)

    override fun hashCode(): Int = opaqueValue.contentHashCode()

    override fun toString(): String = "AkenBoundDecryptorPlan(page-bound, bytes=${opaqueValue.size})"

    companion object {
        private const val LANE_COUNT: Int = 8
        private const val WORD_FAMILY_COUNT: Int = 8
        internal const val PLAN_NONCE_SIZE: Int = 16
        private const val LANE_SALT_SIZE: Int = 16
        private const val LANE_TAG_SIZE: Int = 16
        private const val PLAN_TAG_SIZE: Int = 32
        private const val DIGEST_SIZE: Int = 32
        private const val MIN_TOKEN_SIZE: Int = 17
        private const val MAX_TOKEN_SIZE: Int = 48
        private const val MAX_OPAQUE_SIZE: Int = 128 * 1024
        private val STATIC_BINDING_DOMAIN = "bound-page-static".toByteArray(Charsets.US_ASCII)
        private val FINAL_BINDING_DOMAIN = "bound-page-final".toByteArray(Charsets.US_ASCII)
        private val LANE_MASK_DOMAIN = "bound-page-lane-mask".toByteArray(Charsets.US_ASCII)
        private val LANE_TAG_DOMAIN = "bound-page-lane-tag".toByteArray(Charsets.US_ASCII)
        private val PLAN_TAG_DOMAIN = "bound-page-plan-tag".toByteArray(Charsets.US_ASCII)

        internal fun fromOpaque(opaque: ByteArray): AkenBoundDecryptorPlan {
            require(opaque.isNotEmpty() && opaque.size <= MAX_OPAQUE_SIZE) {
                "AKEN bound decryptor descriptor length is invalid"
            }
            return AkenBoundDecryptorPlan(opaque)
        }

        internal fun encodeOpaque(
            dispatchVariant: Int,
            pageNonce: ByteArray,
            planNonce: ByteArray,
            staticBinding: ByteArray,
            finalBinding: ByteArray,
            lanes: List<LaneRecord>,
        ): ByteArray {
            require(lanes.size == LANE_COUNT) { "AKEN bound lane count is invalid" }
            val body = ByteArrayOutputStream().use { out ->
                out.write(dispatchVariant)
                out.write(LANE_COUNT)
                out.write(pageNonce)
                out.write(planNonce)
                out.write(staticBinding)
                out.write(finalBinding)
                lanes.forEach { lane ->
                    out.write(lane.wordIndex)
                    out.write(lane.family)
                    writeFramed(out, lane.token)
                    out.write(lane.salt)
                    writeInt(out, lane.encodedWord)
                    out.write(lane.tag)
                }
                out.toByteArray()
            }
            var tag: ByteArray? = null
            try {
                tag = digest(PLAN_TAG_DOMAIN) { update(body) }
                return body + checkNotNull(tag)
            } finally {
                Arrays.fill(body, 0)
                tag?.let { Arrays.fill(it, 0) }
            }
        }

        private fun validateStandalone(opaque: ByteArray) {
            val parsed = parse(opaque)
            try {
                // parse() verifies every lane tag and the terminal plan tag.
            } finally {
                parsed.wipe()
            }
        }

        private fun parse(opaque: ByteArray): ParsedPlan {
            require(opaque.size in minimumEncodedSize()..MAX_OPAQUE_SIZE) {
                "AKEN bound decryptor descriptor length is invalid"
            }
            val reader = BoundReader(opaque)
            var pageNonce: ByteArray? = null
            var planNonce: ByteArray? = null
            var staticBinding: ByteArray? = null
            var finalBinding: ByteArray? = null
            val lanes = ArrayList<LaneRecord>(LANE_COUNT)
            var planTag: ByteArray? = null
            var completed = false
            try {
                val dispatchVariant = reader.readU8("AKEN bound dispatcher variant")
                require(reader.readU8("AKEN bound lane count") == LANE_COUNT) {
                    "AKEN bound lane count is invalid"
                }
                pageNonce = reader.readFixed(AkenResourceCodec.NONCE_SIZE, "AKEN bound page nonce")
                planNonce = reader.readFixed(PLAN_NONCE_SIZE, "AKEN bound plan nonce")
                staticBinding = reader.readFixed(DIGEST_SIZE, "AKEN bound static binding")
                finalBinding = reader.readFixed(DIGEST_SIZE, "AKEN bound final binding")
                repeat(LANE_COUNT) {
                    val wordIndex = reader.readU8("AKEN bound lane word index")
                    val family = reader.readU8("AKEN bound lane family")
                    require(wordIndex in 0 until LANE_COUNT && family in 0 until WORD_FAMILY_COUNT) {
                        "AKEN bound lane metadata is invalid"
                    }
                    val token = reader.readFramed(MAX_TOKEN_SIZE, "AKEN bound lane token", allowEmpty = false)
                    require(token.size >= MIN_TOKEN_SIZE) { "AKEN bound lane token is invalid" }
                    val salt = reader.readFixed(LANE_SALT_SIZE, "AKEN bound lane salt")
                    val encodedWord = reader.readInt("AKEN bound encoded lane")
                    val tag = reader.readFixed(LANE_TAG_SIZE, "AKEN bound lane tag")
                    val expectedTag = laneTag(checkNotNull(staticBinding), wordIndex, family, token, salt, encodedWord)
                    try {
                        require(MessageDigest.isEqual(tag, expectedTag)) { "AKEN bound lane authentication failed" }
                    } finally {
                        Arrays.fill(expectedTag, 0)
                    }
                    lanes += LaneRecord(wordIndex, family, token, salt, encodedWord, tag)
                    Arrays.fill(token, 0)
                    Arrays.fill(salt, 0)
                    Arrays.fill(tag, 0)
                }
                require(lanes.map { it.wordIndex }.toSet() == (0 until LANE_COUNT).toSet()) {
                    "AKEN bound lanes do not cover the current page"
                }
                val tagOffset = reader.offset
                planTag = reader.readFixed(PLAN_TAG_SIZE, "AKEN bound plan tag")
                reader.requireFullyRead("AKEN bound descriptor")
                val expectedPlanTag = digest(PLAN_TAG_DOMAIN) { update(opaque, 0, tagOffset) }
                try {
                    require(MessageDigest.isEqual(checkNotNull(planTag), expectedPlanTag)) {
                        "AKEN bound descriptor authentication failed"
                    }
                } finally {
                    Arrays.fill(expectedPlanTag, 0)
                }
                completed = true
                return ParsedPlan(
                    dispatchVariant = dispatchVariant,
                    pageNonce = checkNotNull(pageNonce),
                    planNonce = checkNotNull(planNonce),
                    staticBinding = checkNotNull(staticBinding),
                    finalBinding = checkNotNull(finalBinding),
                    lanes = lanes,
                )
            } finally {
                pageNonce?.let { Arrays.fill(it, 0) }
                planNonce?.let { Arrays.fill(it, 0) }
                staticBinding?.let { Arrays.fill(it, 0) }
                finalBinding?.let { Arrays.fill(it, 0) }
                planTag?.let { Arrays.fill(it, 0) }
                if (!completed) lanes.forEach { it.wipe() }
            }
        }

        internal fun staticBinding(
            resourceKind: AkenResourceKind,
            logicalIdentity: ByteArray,
            pageIndex: Int,
            targetPageSize: Int,
            codecVariant: String,
            layoutVariant: String,
            encodedHandle: ByteArray,
            locatorToken: ByteArray,
            evaluatorFingerprint: ByteArray,
            artifactCanonicalCommitment: ByteArray,
            pageNonce: ByteArray,
            planNonce: ByteArray,
            dispatchVariant: Int,
        ): ByteArray {
            require(logicalIdentity.isNotEmpty()) { "AKEN bound logical identity must not be empty" }
            require(pageIndex >= 0) { "AKEN bound page index is invalid" }
            require(targetPageSize in AkenPageSizePolicy.DEFAULT.allowedSizes(resourceKind)) {
                "AKEN bound target page size is invalid"
            }
            require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) { "AKEN bound handle size is invalid" }
            require(locatorToken.size == AkenHandle.LOCATOR_TOKEN_SIZE) { "AKEN bound locator size is invalid" }
            require(evaluatorFingerprint.size == DIGEST_SIZE) { "AKEN bound evaluator fingerprint size is invalid" }
            require(artifactCanonicalCommitment.size == DIGEST_SIZE) { "AKEN bound artifact commitment size is invalid" }
            require(pageNonce.size == AkenResourceCodec.NONCE_SIZE) { "AKEN bound page nonce size is invalid" }
            require(planNonce.size == PLAN_NONCE_SIZE) { "AKEN bound plan nonce size is invalid" }
            require(dispatchVariant in 0..0xFF) { "AKEN bound dispatcher variant is invalid" }
            val codecBytes = AkenResourceCodec.normalizeCodecVariant(codecVariant).toByteArray(Charsets.UTF_8)
            val layout = AkenPageLayout.fromVariant(layoutVariant)
            var layoutBytes: ByteArray? = null
            try {
                require(layout.variant == layoutVariant) { "AKEN bound layout variant is not canonical" }
                layoutBytes = layout.variant.toByteArray(Charsets.UTF_8)
                return digest(STATIC_BINDING_DOMAIN) {
                    update(dispatchVariant.toByte())
                    update(resourceKind.id.toByte())
                    updateFramed(logicalIdentity)
                    updateInt(pageIndex)
                    updateInt(targetPageSize)
                    updateFramed(codecBytes)
                    updateFramed(checkNotNull(layoutBytes))
                    updateFramed(encodedHandle)
                    updateFramed(locatorToken)
                    update(evaluatorFingerprint)
                    update(artifactCanonicalCommitment)
                    update(pageNonce)
                    update(planNonce)
                }
            } finally {
                Arrays.fill(codecBytes, 0)
                layoutBytes?.let { Arrays.fill(it, 0) }
                layout.wipe()
            }
        }

        internal fun finalBinding(staticBinding: ByteArray, routeEncoding: ByteArray, callSiteProof: ByteArray): ByteArray {
            require(staticBinding.size == DIGEST_SIZE) { "AKEN bound static binding size is invalid" }
            require(routeEncoding.isNotEmpty()) { "AKEN bound route encoding is invalid" }
            require(callSiteProof.isNotEmpty()) { "AKEN bound call-site proof is invalid" }
            return digest(FINAL_BINDING_DOMAIN) {
                update(staticBinding)
                updateFramed(routeEncoding)
                updateFramed(callSiteProof)
            }
        }

        internal fun laneMask(
            staticBinding: ByteArray,
            wordIndex: Int,
            family: Int,
            token: ByteArray,
            salt: ByteArray,
        ): Int {
            val hash = digest(LANE_MASK_DOMAIN) {
                update(staticBinding)
                updateInt(wordIndex)
                updateInt(family)
                updateFramed(token)
                updateFramed(salt)
            }
            return try {
                readWord(hash, 0)
            } finally {
                Arrays.fill(hash, 0)
            }
        }

        internal fun laneTag(
            staticBinding: ByteArray,
            wordIndex: Int,
            family: Int,
            token: ByteArray,
            salt: ByteArray,
            encodedWord: Int,
        ): ByteArray {
            val full = digest(LANE_TAG_DOMAIN) {
                update(staticBinding)
                updateInt(wordIndex)
                updateInt(family)
                updateFramed(token)
                updateFramed(salt)
                updateInt(encodedWord)
            }
            return try {
                full.copyOf(LANE_TAG_SIZE)
            } finally {
                Arrays.fill(full, 0)
            }
        }

        internal fun encodeWord(value: Int, mask: Int, family: Int, wordIndex: Int): Int {
            val rotation = ((mask xor (family * 0x45D9F3B) xor wordIndex) and 31) + 1
            val tweak = Integer.rotateLeft(mask xor (0x9E3779B9.toInt() * (wordIndex + 1)), (wordIndex + family) and 31)
            return when (family) {
                0 -> value xor mask
                1 -> Integer.rotateLeft(value + mask, rotation)
                2 -> Integer.rotateRight(value xor mask, rotation) + tweak
                3 -> Integer.rotateLeft(value + tweak, rotation) xor mask
                4 -> Integer.rotateRight(value - mask, rotation) xor tweak
                5 -> (value xor Integer.rotateLeft(mask, wordIndex + 1)) + 0x7F4A7C15
                6 -> Integer.rotateLeft(value xor tweak, rotation) - mask
                7 -> Integer.rotateLeft(value + mask, rotation) xor tweak
                else -> error("AKEN bound lane family is invalid")
            }
        }

        private fun digest(domain: ByteArray, update: MessageDigest.() -> Unit): ByteArray =
            MessageDigest.getInstance("SHA-256").apply {
                update(domain)
                update()
            }.digest()

        private fun MessageDigest.updateFramed(value: ByteArray) {
            updateInt(value.size)
            update(value)
        }

        private fun MessageDigest.updateInt(value: Int) {
            update((value ushr 24).toByte())
            update((value ushr 16).toByte())
            update((value ushr 8).toByte())
            update(value.toByte())
        }

        private fun writeFramed(out: ByteArrayOutputStream, value: ByteArray) {
            writeInt(out, value.size)
            out.write(value)
        }

        private fun writeInt(out: ByteArrayOutputStream, value: Int) {
            out.write((value ushr 24) and 0xFF)
            out.write((value ushr 16) and 0xFF)
            out.write((value ushr 8) and 0xFF)
            out.write(value and 0xFF)
        }

        internal fun readWord(value: ByteArray, offset: Int): Int {
            require(offset >= 0 && offset <= value.size - Int.SIZE_BYTES) { "AKEN bound word is truncated" }
            return ((value[offset].toInt() and 0xFF) shl 24) or
                ((value[offset + 1].toInt() and 0xFF) shl 16) or
                ((value[offset + 2].toInt() and 0xFF) shl 8) or
                (value[offset + 3].toInt() and 0xFF)
        }

        private fun minimumEncodedSize(): Int =
            2 + AkenResourceCodec.NONCE_SIZE + PLAN_NONCE_SIZE + DIGEST_SIZE + DIGEST_SIZE +
                LANE_COUNT * (2 + Int.SIZE_BYTES + MIN_TOKEN_SIZE + LANE_SALT_SIZE + Int.SIZE_BYTES + LANE_TAG_SIZE) +
                PLAN_TAG_SIZE
    }
}

internal class LaneRecord(
    val wordIndex: Int,
    val family: Int,
    token: ByteArray,
    salt: ByteArray,
    val encodedWord: Int,
    tag: ByteArray,
) {
    var token = token.copyOf()
        private set
    var salt = salt.copyOf()
        private set
    var tag = tag.copyOf()
        private set

    fun copyForOwner(): LaneRecord = LaneRecord(wordIndex, family, token, salt, encodedWord, tag)

    fun wipe() {
        Arrays.fill(token, 0)
        Arrays.fill(salt, 0)
        Arrays.fill(tag, 0)
        token = ByteArray(0)
        salt = ByteArray(0)
        tag = ByteArray(0)
    }
}

private class ParsedPlan(
    val dispatchVariant: Int,
    pageNonce: ByteArray,
    planNonce: ByteArray,
    staticBinding: ByteArray,
    finalBinding: ByteArray,
    lanes: List<LaneRecord>,
) {
    var pageNonce = pageNonce.copyOf()
        private set
    var planNonce = planNonce.copyOf()
        private set
    var staticBinding = staticBinding.copyOf()
        private set
    var finalBinding = finalBinding.copyOf()
        private set
    private var lanesValue = lanes

    fun wipe() {
        Arrays.fill(pageNonce, 0)
        Arrays.fill(planNonce, 0)
        Arrays.fill(staticBinding, 0)
        Arrays.fill(finalBinding, 0)
        lanesValue.forEach { it.wipe() }
        pageNonce = ByteArray(0)
        planNonce = ByteArray(0)
        staticBinding = ByteArray(0)
        finalBinding = ByteArray(0)
        lanesValue = emptyList()
    }
}

private class BoundReader(private val bytes: ByteArray) {
    var offset: Int = 0
        private set

    fun readU8(label: String): Int {
        requireRemaining(1, label)
        return bytes[offset++].toInt() and 0xFF
    }

    fun readInt(label: String): Int {
        requireRemaining(Int.SIZE_BYTES, label)
        val result = ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)
        offset += Int.SIZE_BYTES
        return result
    }

    fun readFixed(length: Int, label: String): ByteArray {
        require(length >= 0) { "AKEN bound fixed length is invalid" }
        requireRemaining(length, label)
        return bytes.copyOfRange(offset, offset + length).also { offset += length }
    }

    fun readFramed(maximum: Int, label: String, allowEmpty: Boolean): ByteArray {
        val length = readInt("$label length")
        require(length in 0..maximum && (allowEmpty || length > 0)) { "$label length is invalid" }
        return readFixed(length, label)
    }

    fun requireFullyRead(label: String) {
        require(offset == bytes.size) { "$label contains trailing bytes" }
    }

    private fun requireRemaining(length: Int, label: String) {
        require(length >= 0 && offset <= bytes.size - length) { "$label is truncated" }
    }
}
