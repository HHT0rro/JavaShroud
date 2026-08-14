package io.github.hht0rro.javashroud.transforms.protection.aken

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

/**
 * Build-time codec for AKEN-7 evaluator state.
 *
 * A high-value page key and the public canonical artifact commitment are both
 * split across all seven fragments. Every individual fragment carries only a
 * page-bound, reversibly transformed DEK share plus one opaque commitment
 * share; no fragment is a raw DEK or a complete commitment, and there is no
 * shared cross-page state. The serialized shape is deliberately opaque to
 * callers: it is interpreted only by a purpose-built evaluator implementation
 * for the current page.
 *
 * This file belongs to the build engine rather than the injected runtime.  Its
 * recovery routine exists solely to assert generation/descriptor parity while
 * the build authority is still live; it is not a runtime resource decoder.
 */
internal object AkenEvaluatorState {
    const val STATE_WIDTH: Int = 32

    private const val FRAGMENT_COUNT = 7
    private const val TRANSFORM_FAMILY_COUNT = 16
    private const val SHAPE_VERSION: Int = 2
    private const val SALT_SIZE: Int = 16
    private const val TAG_SIZE: Int = 8
    private const val ENCODED_SHARE_OFFSET: Int = 1
    private const val COMMITMENT_SHARE_OFFSET: Int = ENCODED_SHARE_OFFSET + STATE_WIDTH
    private const val SALT_OFFSET: Int = COMMITMENT_SHARE_OFFSET + STATE_WIDTH
    private const val TAG_OFFSET: Int = SALT_OFFSET + SALT_SIZE
    private const val MIN_SHAPE_SIZE: Int = TAG_OFFSET + TAG_SIZE
    private const val MIN_CALL_TOKEN_SIZE: Int = 32

    private val MASK_DOMAIN = "AKEN-v4-evaluator-state-mask-v1".toByteArray(StandardCharsets.US_ASCII)
    private val TAG_DOMAIN = "AKEN-v4-evaluator-state-tag-v1".toByteArray(StandardCharsets.US_ASCII)

    /**
     * Split [dek] into seven independent XOR shares.  The terminal share is
     * chosen last so all seven shares are necessary to reconstruct the page
     * key.  Every returned share is owned by the caller and must be wiped.
     */
    fun splitDek(dek: ByteArray, random: SecureRandom): Array<ByteArray> =
        splitState(dek, random, "DEK")

    /**
     * Spread the public canonical artifact commitment across the same seven
     * page-local evaluator fragments. This is integrity material, not a key;
     * its purpose is to prevent a single fragment from carrying a reusable
     * complete root value and to require the full graph for root comparison.
     */
    fun splitArtifactCommitment(commitment: ByteArray, random: SecureRandom): Array<ByteArray> =
        splitState(commitment, random, "artifact commitment")

    private fun splitState(value: ByteArray, random: SecureRandom, label: String): Array<ByteArray> {
        require(value.size == STATE_WIDTH) { "AKEN evaluator $label must be 32 bytes" }
        val shares = Array(FRAGMENT_COUNT) { ByteArray(STATE_WIDTH) }
        val terminal = value.copyOf()
        var completed = false
        try {
            for (index in 0 until FRAGMENT_COUNT - 1) {
                random.nextBytes(shares[index])
                xorInto(terminal, shares[index])
            }
            shares[FRAGMENT_COUNT - 1] = terminal.copyOf()
            completed = true
            return shares
        } finally {
            Arrays.fill(terminal, 0)
            if (!completed) shares.forEach { Arrays.fill(it, 0) }
        }
    }

    /**
     * Compile one page-local key share into a polymorphic evaluator fragment.
     * The public binding inputs intentionally serve only as anti-swap/integrity
     * context; they are not treated as secret material.
     */
    fun createFragment(
        random: SecureRandom,
        ordinal: Int,
        share: ByteArray,
        artifactCommitmentShare: ByteArray,
        kind: AkenResourceKind,
        identity: ByteArray,
        pageIndex: Int,
        targetSize: Int,
        codecVariant: String,
        layoutVariant: String,
        encodedHandle: ByteArray,
        locator: ByteArray,
    ): AkenBuildPlan.EvaluatorFragment {
        require(ordinal in 0 until FRAGMENT_COUNT) { "AKEN evaluator fragment ordinal is invalid" }
        require(share.size == STATE_WIDTH) { "AKEN evaluator share must be 32 bytes" }
        require(artifactCommitmentShare.size == STATE_WIDTH) {
            "AKEN evaluator artifact commitment share must be 32 bytes"
        }
        require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) { "AKEN evaluator handle length is invalid" }
        require(locator.size == AkenHandle.LOCATOR_TOKEN_SIZE) { "AKEN evaluator locator length is invalid" }

        val family = random.nextInt(TRANSFORM_FAMILY_COUNT)
        val callToken = ByteArray(MIN_CALL_TOKEN_SIZE + random.nextInt(17)).also(random::nextBytes)
        val permutation = randomPermutation(STATE_WIDTH, random)
        val salt = ByteArray(SALT_SIZE).also(random::nextBytes)
        var mask: ByteArray? = null
        var encodedShare: ByteArray? = null
        var tag: ByteArray? = null
        var decoy: ByteArray? = null
        var shape: ByteArray? = null
        var completed = false
        try {
            mask = maskFor(
                ordinal = ordinal,
                family = family,
                kind = kind,
                identity = identity,
                pageIndex = pageIndex,
                targetSize = targetSize,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
                encodedHandle = encodedHandle,
                locator = locator,
                callToken = callToken,
                salt = salt,
            )
            encodedShare = encodeShare(share, checkNotNull(mask), family, permutation)
            tag = tagFor(
                ordinal = ordinal,
                family = family,
                kind = kind,
                identity = identity,
                pageIndex = pageIndex,
                targetSize = targetSize,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
                encodedHandle = encodedHandle,
                locator = locator,
                callToken = callToken,
                permutation = permutation,
                encodedShare = checkNotNull(encodedShare),
                artifactCommitmentShare = artifactCommitmentShare,
                salt = salt,
            )
            decoy = ByteArray(8 + random.nextInt(17)).also(random::nextBytes)
            shape = ByteArray(MIN_SHAPE_SIZE + checkNotNull(decoy).size)
            shape[0] = SHAPE_VERSION.toByte()
            System.arraycopy(checkNotNull(encodedShare), 0, shape, ENCODED_SHARE_OFFSET, STATE_WIDTH)
            System.arraycopy(artifactCommitmentShare, 0, shape, COMMITMENT_SHARE_OFFSET, STATE_WIDTH)
            System.arraycopy(salt, 0, shape, SALT_OFFSET, SALT_SIZE)
            System.arraycopy(checkNotNull(tag), 0, shape, TAG_OFFSET, TAG_SIZE)
            System.arraycopy(checkNotNull(decoy), 0, shape, MIN_SHAPE_SIZE, checkNotNull(decoy).size)
            val result = AkenBuildPlan.EvaluatorFragment(
                ordinal = ordinal,
                family = family,
                shape = checkNotNull(shape),
                callToken = callToken,
                tablePermutation = permutation,
            )
            completed = true
            return result
        } finally {
            mask?.let { Arrays.fill(it, 0) }
            encodedShare?.let { Arrays.fill(it, 0) }
            tag?.let { Arrays.fill(it, 0) }
            decoy?.let { Arrays.fill(it, 0) }
            salt.fill(0)
            callToken.fill(0)
            permutation.fill(0)
            if (!completed) shape?.let { Arrays.fill(it, 0) }
        }
    }

    /**
     * Build-side invariant check for the freshly generated evaluator graph.
     * The returned copy is caller-owned and is immediately wiped by the planner
     * after comparison with its transient page DEK.
     */
    fun recoverForBuildVerification(
        page: AkenBuildPlan.Page,
        expectedArtifactCommitment: ByteArray? = null,
    ): ByteArray {
        expectedArtifactCommitment?.let {
            require(it.size == STATE_WIDTH) { "AKEN evaluator expected artifact commitment must be 32 bytes" }
        }
        val identity = page.logicalIdentity
        val handle = page.handle
        val encodedHandle = handle.encoded
        val locator = handle.locatorToken
        val fragments = page.evaluatorPlan.allFragments
        return try {
            recover(
                fragments = fragments.map { fragment ->
                    FragmentView(fragment.ordinal, fragment.family, fragment.shape, fragment.callToken, fragment.tablePermutation)
                },
                kind = page.resourceKind,
                identity = identity,
                pageIndex = page.pageIndex,
                targetSize = page.targetSize,
                codecVariant = page.codecVariant,
                layoutVariant = page.layoutVariant,
                encodedHandle = encodedHandle,
                locator = locator,
                expectedArtifactCommitment = expectedArtifactCommitment,
            )
        } finally {
            identity.fill(0)
            encodedHandle.fill(0)
            locator.fill(0)
            fragments.forEach { fragment ->
                // The public accessors above returned defensive copies that are
                // held by FragmentView and wiped by recover() in all paths.
                @Suppress("UNUSED_VARIABLE") val ignored = fragment
            }
        }
    }

    /**
     * Descriptor parity check used only by build/sealing tests.  It verifies
     * that serializing and parsing the descriptor retains the exact page-local
     * evaluator state; it is not called by a generated artifact at runtime.
     */
    fun recoverDescriptorForBuildVerification(descriptor: AkenRuntimePageDescriptor): ByteArray {
        val identity = descriptor.logicalIdentity
        val handle = descriptor.handle
        val encodedHandle = handle.encoded
        val locator = handle.locatorToken
        val artifactCommitment = descriptor.proof.artifactCanonicalCommitment
        val evaluator = descriptor.evaluatorPlan
        val fragments = evaluator.javaFragments + evaluator.nativeFragments + evaluator.terminal
        return try {
            recover(
                fragments = fragments.map { fragment ->
                    FragmentView(fragment.ordinal, fragment.family, fragment.shape, fragment.callToken, fragment.tablePermutation)
                },
                kind = descriptor.resourceKind,
                identity = identity,
                pageIndex = descriptor.pageIndex,
                targetSize = descriptor.targetPageSize,
                codecVariant = descriptor.route.codecVariant,
                layoutVariant = descriptor.route.layoutVariant,
                encodedHandle = encodedHandle,
                locator = locator,
                expectedArtifactCommitment = artifactCommitment,
            )
        } finally {
            identity.fill(0)
            encodedHandle.fill(0)
            locator.fill(0)
            artifactCommitment.fill(0)
        }
    }

    private data class FragmentView(
        val ordinal: Int,
        val family: Int,
        val shape: ByteArray,
        val callToken: ByteArray,
        val permutation: IntArray,
    ) {
        fun wipe() {
            shape.fill(0)
            callToken.fill(0)
            permutation.fill(0)
        }
    }

    private fun recover(
        fragments: List<FragmentView>,
        kind: AkenResourceKind,
        identity: ByteArray,
        pageIndex: Int,
        targetSize: Int,
        codecVariant: String,
        layoutVariant: String,
        encodedHandle: ByteArray,
        locator: ByteArray,
        expectedArtifactCommitment: ByteArray?,
    ): ByteArray {
        require(fragments.size == FRAGMENT_COUNT) { "AKEN evaluator graph must contain seven fragments" }
        require(fragments.map { it.ordinal }.toSet() == (0 until FRAGMENT_COUNT).toSet()) {
            "AKEN evaluator graph ordinals are invalid"
        }
        val result = ByteArray(STATE_WIDTH)
        val reconstructedCommitment = ByteArray(STATE_WIDTH)
        var completed = false
        try {
            for (fragment in fragments) {
                val artifactCommitmentShare = fragment.shape.copyOfRange(COMMITMENT_SHARE_OFFSET, SALT_OFFSET)
                val share = recoverShare(
                    fragment = fragment,
                    kind = kind,
                    identity = identity,
                    pageIndex = pageIndex,
                    targetSize = targetSize,
                    codecVariant = codecVariant,
                    layoutVariant = layoutVariant,
                    encodedHandle = encodedHandle,
                    locator = locator,
                    artifactCommitmentShare = artifactCommitmentShare,
                )
                try {
                    xorInto(result, share)
                    xorInto(reconstructedCommitment, artifactCommitmentShare)
                } finally {
                    share.fill(0)
                    artifactCommitmentShare.fill(0)
                }
            }
            if (expectedArtifactCommitment != null) {
                require(MessageDigest.isEqual(reconstructedCommitment, expectedArtifactCommitment)) {
                    "AKEN evaluator graph does not reconstruct the canonical artifact commitment"
                }
            }
            completed = true
            return result
        } finally {
            fragments.forEach { it.wipe() }
            reconstructedCommitment.fill(0)
            if (!completed) result.fill(0)
        }
    }

    private fun recoverShare(
        fragment: FragmentView,
        kind: AkenResourceKind,
        identity: ByteArray,
        pageIndex: Int,
        targetSize: Int,
        codecVariant: String,
        layoutVariant: String,
        encodedHandle: ByteArray,
        locator: ByteArray,
        artifactCommitmentShare: ByteArray,
    ): ByteArray {
        require(fragment.ordinal in 0 until FRAGMENT_COUNT) { "AKEN evaluator fragment ordinal is invalid" }
        require(fragment.family in 0 until TRANSFORM_FAMILY_COUNT) { "AKEN evaluator family is invalid" }
        require(fragment.shape.size >= MIN_SHAPE_SIZE && fragment.shape[0].toInt() == SHAPE_VERSION) {
            "AKEN evaluator fragment shape is invalid"
        }
        require(fragment.callToken.size >= MIN_CALL_TOKEN_SIZE) { "AKEN evaluator call token is invalid" }
        require(isPermutation(fragment.permutation, STATE_WIDTH)) { "AKEN evaluator permutation is invalid" }
        require(artifactCommitmentShare.size == STATE_WIDTH) {
            "AKEN evaluator artifact commitment share is invalid"
        }

        val encodedShare = fragment.shape.copyOfRange(ENCODED_SHARE_OFFSET, COMMITMENT_SHARE_OFFSET)
        val salt = fragment.shape.copyOfRange(SALT_OFFSET, TAG_OFFSET)
        val expectedTag = fragment.shape.copyOfRange(TAG_OFFSET, MIN_SHAPE_SIZE)
        var actualTag: ByteArray? = null
        var mask: ByteArray? = null
        try {
            actualTag = tagFor(
                ordinal = fragment.ordinal,
                family = fragment.family,
                kind = kind,
                identity = identity,
                pageIndex = pageIndex,
                targetSize = targetSize,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
                encodedHandle = encodedHandle,
                locator = locator,
                callToken = fragment.callToken,
                permutation = fragment.permutation,
                encodedShare = encodedShare,
                artifactCommitmentShare = artifactCommitmentShare,
                salt = salt,
            )
            require(MessageDigest.isEqual(expectedTag, actualTag)) { "AKEN evaluator fragment integrity check failed" }
            mask = maskFor(
                ordinal = fragment.ordinal,
                family = fragment.family,
                kind = kind,
                identity = identity,
                pageIndex = pageIndex,
                targetSize = targetSize,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
                encodedHandle = encodedHandle,
                locator = locator,
                callToken = fragment.callToken,
                salt = salt,
            )
            return decodeShare(encodedShare, checkNotNull(mask), fragment.family, fragment.permutation)
        } finally {
            encodedShare.fill(0)
            salt.fill(0)
            expectedTag.fill(0)
            actualTag?.fill(0)
            mask?.fill(0)
        }
    }

    private fun encodeShare(share: ByteArray, mask: ByteArray, family: Int, permutation: IntArray): ByteArray {
        val transformed = ByteArray(STATE_WIDTH)
        val result = ByteArray(STATE_WIDTH)
        try {
            for (index in 0 until STATE_WIDTH) {
                transformed[index] = forward(share[index].u8(), mask[index].u8(), family, index).toByte()
            }
            for (index in 0 until STATE_WIDTH) result[index] = transformed[permutation[index]]
            return result
        } finally {
            transformed.fill(0)
        }
    }

    private fun decodeShare(encoded: ByteArray, mask: ByteArray, family: Int, permutation: IntArray): ByteArray {
        val transformed = ByteArray(STATE_WIDTH)
        val result = ByteArray(STATE_WIDTH)
        var completed = false
        try {
            for (index in 0 until STATE_WIDTH) transformed[permutation[index]] = encoded[index]
            for (index in 0 until STATE_WIDTH) {
                result[index] = inverse(transformed[index].u8(), mask[index].u8(), family, index).toByte()
            }
            completed = true
            return result
        } finally {
            transformed.fill(0)
            if (!completed) result.fill(0)
        }
    }

    private fun forward(value: Int, mask: Int, family: Int, index: Int): Int {
        val twist = ((mask ushr 3) + family + index) and 0xFF
        val rotation = ((mask xor family xor index) and 7) + 1
        return when (family) {
            0 -> value xor mask
            1 -> (value + mask) and 0xFF
            2 -> (value - mask) and 0xFF
            3 -> rol8(value xor mask, rotation)
            4 -> ror8(value xor mask, rotation)
            5 -> ((value + mask) xor 0xA5) and 0xFF
            6 -> ((value xor 0xA5) + mask) and 0xFF
            7 -> rol8((value + twist) and 0xFF, rotation) xor mask
            8 -> ror8((value - twist) and 0xFF, rotation) xor mask
            9 -> ((value xor mask) + twist) and 0xFF
            10 -> ((value + mask) xor twist) and 0xFF
            11 -> rol8(value xor twist, rotation) xor mask
            12 -> ror8(value xor twist, rotation) xor mask
            13 -> ((value - mask) xor 0x5A) and 0xFF
            14 -> ((value xor 0x5A) - mask) and 0xFF
            15 -> rol8((value xor mask xor twist) and 0xFF, rotation)
            else -> error("AKEN evaluator family is invalid")
        }
    }

    private fun inverse(value: Int, mask: Int, family: Int, index: Int): Int {
        val twist = ((mask ushr 3) + family + index) and 0xFF
        val rotation = ((mask xor family xor index) and 7) + 1
        return when (family) {
            0 -> value xor mask
            1 -> (value - mask) and 0xFF
            2 -> (value + mask) and 0xFF
            3 -> ror8(value, rotation) xor mask
            4 -> rol8(value, rotation) xor mask
            5 -> ((value xor 0xA5) - mask) and 0xFF
            6 -> ((value - mask) xor 0xA5) and 0xFF
            7 -> (ror8(value xor mask, rotation) - twist) and 0xFF
            8 -> (rol8(value xor mask, rotation) + twist) and 0xFF
            9 -> ((value - twist) xor mask) and 0xFF
            10 -> ((value xor twist) - mask) and 0xFF
            11 -> ror8(value xor mask, rotation) xor twist
            12 -> rol8(value xor mask, rotation) xor twist
            13 -> ((value xor 0x5A) + mask) and 0xFF
            14 -> ((value + mask) xor 0x5A) and 0xFF
            15 -> ror8(value, rotation) xor mask xor twist
            else -> error("AKEN evaluator family is invalid")
        }
    }

    private fun maskFor(
        ordinal: Int,
        family: Int,
        kind: AkenResourceKind,
        identity: ByteArray,
        pageIndex: Int,
        targetSize: Int,
        codecVariant: String,
        layoutVariant: String,
        encodedHandle: ByteArray,
        locator: ByteArray,
        callToken: ByteArray,
        salt: ByteArray,
    ): ByteArray = digest(MASK_DOMAIN) { message ->
        updateBinding(
            message,
            kind,
            identity,
            pageIndex,
            targetSize,
            codecVariant,
            layoutVariant,
            encodedHandle,
            locator,
        )
        updateInt(message, ordinal)
        updateInt(message, family)
        updateFramed(message, callToken)
        updateFramed(message, salt)
    }

    private fun tagFor(
        ordinal: Int,
        family: Int,
        kind: AkenResourceKind,
        identity: ByteArray,
        pageIndex: Int,
        targetSize: Int,
        codecVariant: String,
        layoutVariant: String,
        encodedHandle: ByteArray,
        locator: ByteArray,
        callToken: ByteArray,
        permutation: IntArray,
        encodedShare: ByteArray,
        artifactCommitmentShare: ByteArray,
        salt: ByteArray,
    ): ByteArray {
        val full = digest(TAG_DOMAIN) { message ->
            updateBinding(
                message,
                kind,
                identity,
                pageIndex,
                targetSize,
                codecVariant,
                layoutVariant,
                encodedHandle,
                locator,
            )
            updateInt(message, ordinal)
            updateInt(message, family)
            updateFramed(message, callToken)
            updateInt(message, permutation.size)
            permutation.forEach { updateInt(message, it) }
            updateFramed(message, encodedShare)
            updateFramed(message, artifactCommitmentShare)
            updateFramed(message, salt)
        }
        return try {
            full.copyOf(TAG_SIZE)
        } finally {
            full.fill(0)
        }
    }

    private fun digest(domain: ByteArray, update: (MessageDigest) -> Unit): ByteArray {
        val message = MessageDigest.getInstance("SHA-256")
        message.update(domain)
        update(message)
        return message.digest()
    }

    private fun updateBinding(
        message: MessageDigest,
        kind: AkenResourceKind,
        identity: ByteArray,
        pageIndex: Int,
        targetSize: Int,
        codecVariant: String,
        layoutVariant: String,
        encodedHandle: ByteArray,
        locator: ByteArray,
    ) {
        val codec = codecVariant.toByteArray(StandardCharsets.UTF_8)
        val layout = layoutVariant.toByteArray(StandardCharsets.UTF_8)
        try {
            message.update(kind.id.toByte())
            updateFramed(message, identity)
            updateInt(message, pageIndex)
            updateInt(message, targetSize)
            updateFramed(message, codec)
            updateFramed(message, layout)
            updateFramed(message, encodedHandle)
            updateFramed(message, locator)
        } finally {
            codec.fill(0)
            layout.fill(0)
        }
    }

    private fun updateInt(message: MessageDigest, value: Int) {
        message.update((value ushr 24).toByte())
        message.update((value ushr 16).toByte())
        message.update((value ushr 8).toByte())
        message.update(value.toByte())
    }

    private fun updateFramed(message: MessageDigest, bytes: ByteArray) {
        updateInt(message, bytes.size)
        message.update(bytes)
    }

    private fun randomPermutation(size: Int, random: SecureRandom): IntArray = IntArray(size) { it }.also { values ->
        for (index in values.lastIndex downTo 1) {
            val other = random.nextInt(index + 1)
            val swap = values[index]
            values[index] = values[other]
            values[other] = swap
        }
    }

    private fun isPermutation(values: IntArray, expectedSize: Int): Boolean {
        if (values.size != expectedSize) return false
        val seen = BooleanArray(expectedSize)
        for (value in values) {
            if (value !in 0 until expectedSize || seen[value]) return false
            seen[value] = true
        }
        return true
    }

    private fun xorInto(target: ByteArray, value: ByteArray) {
        for (index in target.indices) target[index] = (target[index].toInt() xor value[index].toInt()).toByte()
    }

    private fun Byte.u8(): Int = toInt() and 0xFF

    private fun rol8(value: Int, shift: Int): Int = ((value shl shift) or (value ushr (8 - shift))) and 0xFF

    private fun ror8(value: Int, shift: Int): Int = ((value ushr shift) or (value shl (8 - shift))) and 0xFF
}
