package io.github.hht0rro.javashroud.transforms.protection.aken

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

private const val EVALUATOR_DIGEST_SIZE: Int = 32
private const val EVALUATOR_PLAN_NONCE_SIZE: Int = 16
private const val EVALUATOR_FRAGMENT_SALT_SIZE: Int = 16
private const val EVALUATOR_FRAGMENT_TAG_SIZE: Int = 16
private const val EVALUATOR_DIALECT_SIZE: Int = 32
private const val EVALUATOR_MIN_FRAGMENT_COUNT: Int = 4
private const val EVALUATOR_MAX_FRAGMENT_COUNT: Int = 12
private const val EVALUATOR_MIN_TOKEN_SIZE: Int = 17
private const val EVALUATOR_MAX_TOKEN_SIZE: Int = 48
private const val EVALUATOR_MAX_OPAQUE_SIZE: Int = 128 * 1024
private val EVALUATOR_WIRE_MARKER = byteArrayOf(0x41, 0x4B, 0x45, 0x31)

/**
 * Build-only evaluator seed for one page. The serialized terminal is an
 * artifact-specific VBC4 program: its fragment count, offsets, opcodes,
 * registers, token sizes and dialect are randomized for every page.
 */
internal class AkenBoundDecryptorCore private constructor(
    pageNonce: ByteArray,
    planNonce: ByteArray,
    dialectByte: Int,
    dialectCommitment: ByteArray,
    staticBinding: ByteArray,
    fragments: List<EvaluatorFragmentRecord>,
) : AutoCloseable {
    private var dialectByteValue = dialectByte
    private var dialectCommitmentValue = dialectCommitment.copyOf()
    private var staticBindingValue = staticBinding.copyOf()
    private var pageNonceValue = pageNonce.copyOf()
    private var planNonceValue = planNonce.copyOf()
    private var fragmentsValue = fragments

    @Volatile
    private var wiped = false

    init {
        require(pageNonceValue.size == AkenResourceCodec.NONCE_SIZE) {
            "AKEN evaluator page nonce length is invalid"
        }
        require(planNonceValue.size == EVALUATOR_PLAN_NONCE_SIZE) {
            "AKEN evaluator plan nonce length is invalid"
        }
        require(dialectByteValue in 0..0xFF) { "AKEN evaluator dialect byte is invalid" }
        require(dialectCommitmentValue.size == EVALUATOR_DIALECT_SIZE) {
            "AKEN evaluator dialect commitment length is invalid"
        }
        require(staticBindingValue.size == EVALUATOR_DIGEST_SIZE) {
            "AKEN evaluator static binding length is invalid"
        }
        require(fragmentsValue.size in EVALUATOR_MIN_FRAGMENT_COUNT..EVALUATOR_MAX_FRAGMENT_COUNT) {
            "AKEN evaluator fragment count is invalid"
        }
        require(hasValidEvaluatorSchedule(fragmentsValue)) {
            "AKEN evaluator schedule is invalid"
        }
    }

    internal fun copyPageNonceForCodec(): ByteArray {
        requireLive()
        return pageNonceValue.copyOf()
    }

    internal fun copyPageMaterialForBuild(): ByteArray {
        requireLive()
        return AkenBoundDecryptorPlan.materializePageMaterial(
            dialectByte = dialectByteValue,
            planNonce = planNonceValue,
            staticBinding = staticBindingValue,
            dialectCommitment = dialectCommitmentValue,
            fragments = fragmentsValue,
        )
    }

    /** Seal the build-only evaluator into the descriptor consumed by native. */
    internal fun finalizeForRuntime(
        route: AkenRoutingMetadata,
        callSiteProof: ByteArray,
    ): AkenBoundDecryptorPlan {
        requireLive()
        require(callSiteProof.isNotEmpty()) { "AKEN evaluator call-site proof must not be empty" }
        fragmentsValue.forEach { fragment ->
            val expected = AkenBoundDecryptorPlan.fragmentTag(
                staticBinding = staticBindingValue,
                dialectCommitment = dialectCommitmentValue,
                offset = fragment.offset,
                length = fragment.encoded.size,
                family = fragment.family,
                opcode = fragment.opcode,
                register = fragment.register,
                token = fragment.token,
                salt = fragment.salt,
                encoded = fragment.encoded,
            )
            try {
                require(MessageDigest.isEqual(expected, fragment.tag)) {
                    "AKEN evaluator fragment authentication failed"
                }
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
                dialectByte = dialectByteValue,
                pageNonce = pageNonceValue,
                planNonce = planNonceValue,
                staticBinding = staticBindingValue,
                finalBinding = checkNotNull(finalBinding),
                dialectCommitment = dialectCommitmentValue,
                fragments = fragmentsValue,
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
        Arrays.fill(dialectCommitmentValue, 0)
        fragmentsValue.forEach { it.wipe() }
        pageNonceValue = ByteArray(0)
        planNonceValue = ByteArray(0)
        staticBindingValue = ByteArray(0)
        dialectCommitmentValue = ByteArray(0)
        fragmentsValue = emptyList()
        dialectByteValue = 0
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN evaluator core has been wiped" }
    }

    companion object {
        internal fun compile(
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
            require(pageNonce.size == AkenResourceCodec.NONCE_SIZE) {
                "AKEN evaluator page nonce length is invalid"
            }
            require(evaluatorFingerprint.size == EVALUATOR_DIGEST_SIZE) {
                "AKEN evaluator fingerprint length is invalid"
            }
            require(artifactCanonicalCommitment.size == EVALUATOR_DIGEST_SIZE) {
                "AKEN evaluator artifact commitment length is invalid"
            }
            val planNonce = ByteArray(EVALUATOR_PLAN_NONCE_SIZE).also(random::nextBytes)
            val dialectByte = random.nextInt(256)
            var staticBinding: ByteArray? = null
            var dialectCommitment: ByteArray? = null
            val fragments = ArrayList<EvaluatorFragmentRecord>()
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
                    dialectByte = dialectByte,
                )
                dialectCommitment = AkenBoundDecryptorPlan.dialectCommitment(
                    staticBinding = checkNotNull(staticBinding),
                    planNonce = planNonce,
                    dialectByte = dialectByte,
                )
                val count = EVALUATOR_MIN_FRAGMENT_COUNT +
                    random.nextInt(EVALUATOR_MAX_FRAGMENT_COUNT - EVALUATOR_MIN_FRAGMENT_COUNT + 1)
                val steps = (0 until count).toMutableList()
                steps.shuffle(random)
                steps.forEach { offset ->
                    val family = random.nextInt(16)
                    val opcode = random.nextInt(256)
                    val register = random.nextInt(32)
                    val token = ByteArray(
                        EVALUATOR_MIN_TOKEN_SIZE +
                            random.nextInt(EVALUATOR_MAX_TOKEN_SIZE - EVALUATOR_MIN_TOKEN_SIZE + 1),
                    ).also(random::nextBytes)
                    val salt = ByteArray(EVALUATOR_FRAGMENT_SALT_SIZE).also(random::nextBytes)
                    val encoded = ByteArray(
                        EVALUATOR_MIN_TOKEN_SIZE +
                            random.nextInt(EVALUATOR_MAX_TOKEN_SIZE - EVALUATOR_MIN_TOKEN_SIZE + 1),
                    ).also(random::nextBytes)
                    var tag: ByteArray? = null
                    try {
                        tag = AkenBoundDecryptorPlan.fragmentTag(
                            staticBinding = checkNotNull(staticBinding),
                            dialectCommitment = checkNotNull(dialectCommitment),
                            offset = offset,
                            length = encoded.size,
                            family = family,
                            opcode = opcode,
                            register = register,
                            token = token,
                            salt = salt,
                            encoded = encoded,
                        )
                        fragments += EvaluatorFragmentRecord(
                            offset = offset,
                            family = family,
                            opcode = opcode,
                            register = register,
                            token = token,
                            salt = salt,
                            encoded = encoded,
                            tag = checkNotNull(tag),
                        )
                    } finally {
                        Arrays.fill(token, 0)
                        Arrays.fill(salt, 0)
                        Arrays.fill(encoded, 0)
                        tag?.let { Arrays.fill(it, 0) }
                    }
                }
                completed = true
                return AkenBoundDecryptorCore(
                    pageNonce = pageNonce,
                    planNonce = planNonce,
                    dialectByte = dialectByte,
                    dialectCommitment = checkNotNull(dialectCommitment),
                    staticBinding = checkNotNull(staticBinding),
                    fragments = fragments,
                )
            } finally {
                Arrays.fill(planNonce, 0)
                staticBinding?.let { Arrays.fill(it, 0) }
                dialectCommitment?.let { Arrays.fill(it, 0) }
                if (!completed) fragments.forEach { it.wipe() }
            }
        }

    }
}

/** Opaque artifact-specific evaluator descriptor for one page terminal. */
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
        var parsed: ParsedEvaluator? = null
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
                dialectByte = checkNotNull(parsed).dialectByte,
            )
            if (!MessageDigest.isEqual(expectedStatic, checkNotNull(parsed).staticBinding)) return false
            val expectedDialect = dialectCommitment(
                staticBinding = checkNotNull(expectedStatic),
                planNonce = checkNotNull(parsed).planNonce,
                dialectByte = checkNotNull(parsed).dialectByte,
            )
            try {
                if (!MessageDigest.isEqual(expectedDialect, checkNotNull(parsed).dialectCommitment)) return false
            } finally {
                Arrays.fill(expectedDialect, 0)
            }
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

    override fun toString(): String = "AkenBoundDecryptorPlan(bytes=${opaqueValue.size})"

    companion object {
        private const val PLAN_TAG_SIZE: Int = EVALUATOR_DIGEST_SIZE
        private const val MAX_TOKEN_SIZE: Int = EVALUATOR_MAX_TOKEN_SIZE
        private const val MAX_FRAGMENT_SIZE: Int = EVALUATOR_MAX_TOKEN_SIZE
        private val EVALUATOR_DOMAIN_SALT = byteArrayOf(
            0xA1.toByte(), 0xE1.toByte(), 0x09, 0xC3.toByte(),
            0x77, 0x2B, 0xD4.toByte(), 0x18,
        )
        private fun evaluatorDomain(role: Byte): ByteArray = EVALUATOR_DOMAIN_SALT + byteArrayOf(role)
        private val STATIC_BINDING_DOMAIN = evaluatorDomain(1)
        private val ROUTE_BINDING_DOMAIN = evaluatorDomain(2)
        private val MASK_DOMAIN = evaluatorDomain(3)
        private val FRAGMENT_TAG_DOMAIN = evaluatorDomain(4)
        private val DIALECT_DOMAIN = evaluatorDomain(5)
        private val PLAN_TAG_DOMAIN = evaluatorDomain(6)
        private val MATERIALIZE_DOMAIN = evaluatorDomain(7)

        internal fun fromOpaque(opaque: ByteArray): AkenBoundDecryptorPlan {
            require(opaque.isNotEmpty() && opaque.size <= EVALUATOR_MAX_OPAQUE_SIZE) {
                "AKEN evaluator descriptor length is invalid"
            }
            return AkenBoundDecryptorPlan(opaque)
        }

        internal fun encodeOpaque(
            dialectByte: Int,
            pageNonce: ByteArray,
            planNonce: ByteArray,
            staticBinding: ByteArray,
            finalBinding: ByteArray,
            dialectCommitment: ByteArray,
            fragments: List<EvaluatorFragmentRecord>,
        ): ByteArray {
            require(dialectByte in 0..0xFF)
            require(pageNonce.size == AkenResourceCodec.NONCE_SIZE)
            require(planNonce.size == EVALUATOR_PLAN_NONCE_SIZE)
            require(staticBinding.size == EVALUATOR_DIGEST_SIZE)
            require(finalBinding.size == EVALUATOR_DIGEST_SIZE)
            require(dialectCommitment.size == EVALUATOR_DIALECT_SIZE)
            require(fragments.size in EVALUATOR_MIN_FRAGMENT_COUNT..EVALUATOR_MAX_FRAGMENT_COUNT)
            val body = ByteArrayOutputStream().use { out ->
                out.write(EVALUATOR_WIRE_MARKER)
                out.write(dialectByte)
                out.write(fragments.size)
                out.write(pageNonce)
                out.write(planNonce)
                out.write(staticBinding)
                out.write(finalBinding)
                out.write(dialectCommitment)
                fragments.forEach { fragment ->
                    out.write(fragment.offset)
                    out.write(fragment.encoded.size)
                    out.write(fragment.family)
                    out.write(fragment.opcode)
                    out.write(fragment.register)
                    writeFramed(out, fragment.token)
                    out.write(fragment.salt)
                    writeFramed(out, fragment.encoded)
                    out.write(fragment.tag)
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
            parsed.wipe()
        }

        private fun parse(opaque: ByteArray): ParsedEvaluator {
            require(opaque.size <= EVALUATOR_MAX_OPAQUE_SIZE) {
                "AKEN evaluator descriptor length is invalid"
            }
            val reader = EvaluatorReader(opaque)
            var pageNonce: ByteArray? = null
            var planNonce: ByteArray? = null
            var staticBinding: ByteArray? = null
            var finalBinding: ByteArray? = null
            var dialectCommitment: ByteArray? = null
            val fragments = ArrayList<EvaluatorFragmentRecord>()
            var planTag: ByteArray? = null
            var completed = false
            try {
                require(reader.readFixed(EVALUATOR_WIRE_MARKER.size, "AKEN evaluator marker")
                    .contentEquals(EVALUATOR_WIRE_MARKER)) {
                    "AKEN evaluator marker is invalid"
                }
                val dialectByte = reader.readU8("AKEN evaluator dialect")
                val fragmentCount = reader.readU8("AKEN evaluator fragment count")
                require(fragmentCount in EVALUATOR_MIN_FRAGMENT_COUNT..EVALUATOR_MAX_FRAGMENT_COUNT) {
                    "AKEN evaluator fragment count is invalid"
                }
                pageNonce = reader.readFixed(AkenResourceCodec.NONCE_SIZE, "AKEN evaluator page nonce")
                planNonce = reader.readFixed(EVALUATOR_PLAN_NONCE_SIZE, "AKEN evaluator plan nonce")
                staticBinding = reader.readFixed(EVALUATOR_DIGEST_SIZE, "AKEN evaluator static binding")
                finalBinding = reader.readFixed(EVALUATOR_DIGEST_SIZE, "AKEN evaluator final binding")
                dialectCommitment = reader.readFixed(EVALUATOR_DIALECT_SIZE, "AKEN evaluator dialect commitment")
                repeat(fragmentCount) {
                    val offset = reader.readU8("AKEN evaluator fragment offset")
                    val encodedLength = reader.readU8("AKEN evaluator fragment length")
                    val family = reader.readU8("AKEN evaluator fragment family")
                    val opcode = reader.readU8("AKEN evaluator fragment opcode")
                    val register = reader.readU8("AKEN evaluator fragment register")
                    require(encodedLength in EVALUATOR_MIN_TOKEN_SIZE..EVALUATOR_MAX_TOKEN_SIZE) {
                        "AKEN evaluator fragment operand length is invalid"
                    }
                    val token = reader.readFramed(MAX_TOKEN_SIZE, "AKEN evaluator fragment token", false)
                    require(token.size >= EVALUATOR_MIN_TOKEN_SIZE) { "AKEN evaluator token is invalid" }
                    val salt = reader.readFixed(EVALUATOR_FRAGMENT_SALT_SIZE, "AKEN evaluator fragment salt")
                    val encoded = reader.readFramed(MAX_FRAGMENT_SIZE, "AKEN evaluator fragment bytes", false)
                    require(encoded.size == encodedLength) { "AKEN evaluator fragment length mismatch" }
                    val tag = reader.readFixed(EVALUATOR_FRAGMENT_TAG_SIZE, "AKEN evaluator fragment tag")
                    val expectedTag = fragmentTag(
                        staticBinding = checkNotNull(staticBinding),
                        dialectCommitment = checkNotNull(dialectCommitment),
                        offset = offset,
                        length = encodedLength,
                        family = family,
                        opcode = opcode,
                        register = register,
                        token = token,
                        salt = salt,
                        encoded = encoded,
                    )
                    try {
                        require(MessageDigest.isEqual(tag, expectedTag)) {
                            "AKEN evaluator fragment authentication failed"
                        }
                    } finally {
                        Arrays.fill(expectedTag, 0)
                    }
                    fragments += EvaluatorFragmentRecord(
                        offset = offset,
                        family = family,
                        opcode = opcode,
                        register = register,
                        token = token,
                        salt = salt,
                        encoded = encoded,
                        tag = tag,
                    )
                    Arrays.fill(token, 0)
                    Arrays.fill(salt, 0)
                    Arrays.fill(encoded, 0)
                    Arrays.fill(tag, 0)
                }
                require(hasValidEvaluatorSchedule(fragments)) { "AKEN evaluator schedule is invalid" }
                val tagOffset = reader.offset
                planTag = reader.readFixed(PLAN_TAG_SIZE, "AKEN evaluator seal")
                reader.requireFullyRead("AKEN evaluator descriptor")
                val expectedPlanTag = digest(PLAN_TAG_DOMAIN) { update(opaque, 0, tagOffset) }
                try {
                    require(MessageDigest.isEqual(checkNotNull(planTag), expectedPlanTag)) {
                        "AKEN evaluator descriptor authentication failed"
                    }
                } finally {
                    Arrays.fill(expectedPlanTag, 0)
                }
                val expectedDialect = dialectCommitment(
                    staticBinding = checkNotNull(staticBinding),
                    planNonce = checkNotNull(planNonce),
                    dialectByte = dialectByte,
                )
                try {
                    require(MessageDigest.isEqual(expectedDialect, checkNotNull(dialectCommitment))) {
                        "AKEN evaluator dialect commitment is invalid"
                    }
                } finally {
                    Arrays.fill(expectedDialect, 0)
                }
                completed = true
                return ParsedEvaluator(
                    dialectByte = dialectByte,
                    pageNonce = checkNotNull(pageNonce),
                    planNonce = checkNotNull(planNonce),
                    staticBinding = checkNotNull(staticBinding),
                    finalBinding = checkNotNull(finalBinding),
                    dialectCommitment = checkNotNull(dialectCommitment),
                    fragments = fragments,
                )
            } finally {
                pageNonce?.let { Arrays.fill(it, 0) }
                planNonce?.let { Arrays.fill(it, 0) }
                staticBinding?.let { Arrays.fill(it, 0) }
                finalBinding?.let { Arrays.fill(it, 0) }
                dialectCommitment?.let { Arrays.fill(it, 0) }
                planTag?.let { Arrays.fill(it, 0) }
                if (!completed) fragments.forEach { it.wipe() }
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
            dialectByte: Int,
        ): ByteArray {
            require(logicalIdentity.isNotEmpty()) { "AKEN evaluator logical identity must not be empty" }
            require(pageIndex >= 0) { "AKEN evaluator page index is invalid" }
            require(targetPageSize in AkenPageSizePolicy.DEFAULT.allowedSizes(resourceKind)) {
                "AKEN evaluator target page size is invalid"
            }
            require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) { "AKEN evaluator handle size is invalid" }
            require(locatorToken.size == AkenHandle.LOCATOR_TOKEN_SIZE) { "AKEN evaluator locator size is invalid" }
            require(evaluatorFingerprint.size == EVALUATOR_DIGEST_SIZE) { "AKEN evaluator fingerprint size is invalid" }
            require(artifactCanonicalCommitment.size == EVALUATOR_DIGEST_SIZE) { "AKEN evaluator artifact commitment size is invalid" }
            require(pageNonce.size == AkenResourceCodec.NONCE_SIZE) { "AKEN evaluator page nonce size is invalid" }
            require(planNonce.size == EVALUATOR_PLAN_NONCE_SIZE) { "AKEN evaluator plan nonce size is invalid" }
            require(dialectByte in 0..0xFF) { "AKEN evaluator dialect byte is invalid" }
            val codecBytes = AkenResourceCodec.normalizeCodecVariant(codecVariant).toByteArray(Charsets.UTF_8)
            val layout = AkenPageLayout.fromVariant(layoutVariant)
            var layoutBytes: ByteArray? = null
            try {
                require(layout.variant == layoutVariant) { "AKEN evaluator layout variant is not canonical" }
                layoutBytes = layout.variant.toByteArray(Charsets.UTF_8)
                return digest(STATIC_BINDING_DOMAIN) {
                    update(dialectByte.toByte())
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

        internal fun finalBinding(staticBinding: ByteArray, routeEncoding: ByteArray, callSiteProof: ByteArray): ByteArray =
            digest(ROUTE_BINDING_DOMAIN) {
                update(staticBinding)
                updateFramed(routeEncoding)
                updateFramed(callSiteProof)
            }

        internal fun dialectCommitment(staticBinding: ByteArray, planNonce: ByteArray, dialectByte: Int): ByteArray =
            digest(DIALECT_DOMAIN) {
                update(staticBinding)
                update(planNonce)
                update(dialectByte.toByte())
            }

        internal fun materializePageMaterial(
            dialectByte: Int,
            planNonce: ByteArray,
            staticBinding: ByteArray,
            dialectCommitment: ByteArray,
            fragments: List<EvaluatorFragmentRecord>,
        ): ByteArray {
            require(hasValidEvaluatorSchedule(fragments)) { "AKEN evaluator schedule is invalid" }
            return digest(MATERIALIZE_DOMAIN) {
                update(staticBinding)
                update(dialectCommitment)
                update(planNonce)
                update(dialectByte.toByte())
                fragments.sortedWith(
                    compareBy<EvaluatorFragmentRecord> { (it.opcode + dialectByte * 13 + it.register * 7) and 0xFF }
                        .thenBy { it.offset },
                ).forEach { fragment ->
                    updateInt(fragment.offset)
                    updateInt(fragment.family)
                    updateInt(fragment.opcode)
                    updateInt(fragment.register)
                    updateFramed(fragment.token)
                    update(fragment.salt)
                    updateFramed(fragment.encoded)
                }
            }
        }

        internal fun fragmentMask(
            staticBinding: ByteArray,
            dialectCommitment: ByteArray,
            offset: Int,
            length: Int,
            family: Int,
            opcode: Int,
            register: Int,
            token: ByteArray,
            salt: ByteArray,
        ): ByteArray {
            require(offset >= 0 && length > 0 && offset + length <= AkenVbc4Material.PAGE_MATERIAL_SIZE)
            val output = ByteArray(length)
            var produced = 0
            var counter = 0
            while (produced < length) {
                val block = digest(MASK_DOMAIN) {
                    update(staticBinding)
                    update(dialectCommitment)
                    updateInt(offset)
                    updateInt(length)
                    updateInt(family)
                    updateInt(opcode)
                    updateInt(register)
                    updateFramed(token)
                    updateFramed(salt)
                    updateInt(counter++)
                }
                val copy = minOf(block.size, length - produced)
                block.copyInto(output, produced, 0, copy)
                produced += copy
                Arrays.fill(block, 0)
            }
            return output
        }

        internal fun fragmentTag(
            staticBinding: ByteArray,
            dialectCommitment: ByteArray,
            offset: Int,
            length: Int,
            family: Int,
            opcode: Int,
            register: Int,
            token: ByteArray,
            salt: ByteArray,
            encoded: ByteArray,
        ): ByteArray {
            val full = digest(FRAGMENT_TAG_DOMAIN) {
                update(staticBinding)
                update(dialectCommitment)
                updateInt(offset)
                updateInt(length)
                updateInt(family)
                updateInt(opcode)
                updateInt(register)
                updateFramed(token)
                updateFramed(salt)
                updateFramed(encoded)
            }
            return try {
                full.copyOf(EVALUATOR_FRAGMENT_TAG_SIZE)
            } finally {
                Arrays.fill(full, 0)
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
    }
}

private fun hasValidEvaluatorSchedule(fragments: List<EvaluatorFragmentRecord>): Boolean {
    if (fragments.size !in EVALUATOR_MIN_FRAGMENT_COUNT..EVALUATOR_MAX_FRAGMENT_COUNT) return false
    val offsets = hashSetOf<Int>()
    for (fragment in fragments) {
        if (fragment.encoded.size !in EVALUATOR_MIN_TOKEN_SIZE..EVALUATOR_MAX_TOKEN_SIZE) return false
        if (!offsets.add(fragment.offset)) return false
    }
    return true
}

internal class EvaluatorFragmentRecord(
    val offset: Int,
    val family: Int,
    val opcode: Int,
    val register: Int,
    token: ByteArray,
    salt: ByteArray,
    encoded: ByteArray,
    tag: ByteArray,
) {
    var token = token.copyOf()
        private set
    var salt = salt.copyOf()
        private set
    var encoded = encoded.copyOf()
        private set
    var tag = tag.copyOf()
        private set

    fun wipe() {
        Arrays.fill(token, 0)
        Arrays.fill(salt, 0)
        Arrays.fill(encoded, 0)
        Arrays.fill(tag, 0)
        token = ByteArray(0)
        salt = ByteArray(0)
        encoded = ByteArray(0)
        tag = ByteArray(0)
    }
}

private class ParsedEvaluator(
    val dialectByte: Int,
    pageNonce: ByteArray,
    planNonce: ByteArray,
    staticBinding: ByteArray,
    finalBinding: ByteArray,
    dialectCommitment: ByteArray,
    fragments: List<EvaluatorFragmentRecord>,
) {
    var pageNonce = pageNonce.copyOf()
        private set
    var planNonce = planNonce.copyOf()
        private set
    var staticBinding = staticBinding.copyOf()
        private set
    var finalBinding = finalBinding.copyOf()
        private set
    var dialectCommitment = dialectCommitment.copyOf()
        private set
    private var fragmentsValue = fragments

    fun wipe() {
        Arrays.fill(pageNonce, 0)
        Arrays.fill(planNonce, 0)
        Arrays.fill(staticBinding, 0)
        Arrays.fill(finalBinding, 0)
        Arrays.fill(dialectCommitment, 0)
        fragmentsValue.forEach { it.wipe() }
        pageNonce = ByteArray(0)
        planNonce = ByteArray(0)
        staticBinding = ByteArray(0)
        finalBinding = ByteArray(0)
        dialectCommitment = ByteArray(0)
        fragmentsValue = emptyList()
    }
}

private class EvaluatorReader(private val bytes: ByteArray) {
    var offset: Int = 0
        private set

    fun readU8(label: String): Int {
        requireRemaining(1, label)
        return bytes[offset++].toInt() and 0xFF
    }

    fun readFixed(length: Int, label: String): ByteArray {
        require(length >= 0) { "AKEN evaluator fixed length is invalid" }
        requireRemaining(length, label)
        return bytes.copyOfRange(offset, offset + length).also { offset += length }
    }

    fun readFramed(maximum: Int, label: String, allowEmpty: Boolean): ByteArray {
        val length = readU32("$label length")
        require(length in 0..maximum && (allowEmpty || length > 0)) { "$label length is invalid" }
        return readFixed(length, label)
    }

    fun requireFullyRead(label: String) {
        require(offset == bytes.size) { "$label contains trailing bytes" }
    }

    private fun readU32(label: String): Int {
        requireRemaining(4, label)
        val value = ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)
        offset += 4
        require(value >= 0) { "$label exceeds JVM bounds" }
        return value
    }

    private fun requireRemaining(length: Int, label: String) {
        require(length >= 0 && offset <= bytes.size - length) { "$label is truncated" }
    }
}
