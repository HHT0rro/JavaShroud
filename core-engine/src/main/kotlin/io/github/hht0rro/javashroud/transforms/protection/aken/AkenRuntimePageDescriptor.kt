package io.github.hht0rro.javashroud.transforms.protection.aken

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays

/**
 * Execution role of one generated fragment in a page-local AKEN-7 graph.
 *
 * The role is metadata for the current descriptor only; it does not represent
 * a runtime registry or a generic resource-decoding capability.
 */
enum class AkenRuntimeEvaluatorRole(val id: Int) {
    Java(1),
    Native(2),
    Terminal(3),
    ;

    companion object {
        fun fromId(id: Int): AkenRuntimeEvaluatorRole? = entries.firstOrNull { it.id == id }
    }
}

/**
 * Immutable, serializable metadata for one generated evaluator fragment.
 *
 * It contains one page-local, transformed evaluator share plus its reversible
 * execution metadata. No fragment carries a raw DEK; shared authority, route
 * tables, and sibling-page data are absent.
 */
class AkenRuntimeEvaluatorFragment private constructor(
    val role: AkenRuntimeEvaluatorRole,
    val ordinal: Int,
    val family: Int,
    shape: ByteArray,
    callToken: ByteArray,
    tablePermutation: IntArray,
) {
    private val shapeValue = shape.copyOf()
    private val callTokenValue = callToken.copyOf()
    private val tablePermutationValue = tablePermutation.copyOf()

    init {
        require(ordinal in 0 until AKEN_FRAGMENT_COUNT) { "AKEN runtime fragment ordinal is invalid" }
        require(family in 0 until AKEN_TRANSFORM_FAMILY_COUNT) { "AKEN runtime fragment family is invalid" }
        require(shapeValue.isNotEmpty() && shapeValue.size <= MAX_FRAGMENT_SHAPE_SIZE) {
            "AKEN runtime fragment shape length is invalid"
        }
        require(callTokenValue.isNotEmpty() && callTokenValue.size <= MAX_FRAGMENT_CALL_TOKEN_SIZE) {
            "AKEN runtime fragment call token length is invalid"
        }
        require(tablePermutationValue.isNotEmpty() && tablePermutationValue.size <= MAX_TABLE_PERMUTATION_SIZE) {
            "AKEN runtime fragment table length is invalid"
        }
        require(isPermutation(tablePermutationValue)) { "AKEN runtime fragment table is not a permutation" }
    }

    val shape: ByteArray
        get() = shapeValue.copyOf()

    val callToken: ByteArray
        get() = callTokenValue.copyOf()

    val tablePermutation: IntArray
        get() = tablePermutationValue.copyOf()

    fun encode(): ByteArray = ByteArrayOutputStream().use { out ->
        out.write(role.id)
        writeRuntimeInt(out, ordinal)
        writeRuntimeInt(out, family)
        writeRuntimeFramed(out, shapeValue)
        writeRuntimeFramed(out, callTokenValue)
        writeRuntimeInt(out, tablePermutationValue.size)
        tablePermutationValue.forEach { writeRuntimeInt(out, it) }
        out.toByteArray()
    }

    override fun equals(other: Any?): Boolean =
        other is AkenRuntimeEvaluatorFragment &&
            role == other.role &&
            ordinal == other.ordinal &&
            family == other.family &&
            Arrays.equals(shapeValue, other.shapeValue) &&
            Arrays.equals(callTokenValue, other.callTokenValue) &&
            Arrays.equals(tablePermutationValue, other.tablePermutationValue)

    override fun hashCode(): Int {
        var result = role.hashCode()
        result = 31 * result + ordinal
        result = 31 * result + family
        result = 31 * result + shapeValue.contentHashCode()
        result = 31 * result + callTokenValue.contentHashCode()
        return 31 * result + tablePermutationValue.contentHashCode()
    }

    override fun toString(): String =
        "AkenRuntimeEvaluatorFragment(role=$role, ordinal=$ordinal, family=$family)"

    companion object {
        private const val AKEN_FRAGMENT_COUNT = 7
        private const val AKEN_TRANSFORM_FAMILY_COUNT = 16
        private const val MAX_FRAGMENT_SHAPE_SIZE = 4096
        private const val MAX_FRAGMENT_CALL_TOKEN_SIZE = 4096
        private const val MAX_TABLE_PERMUTATION_SIZE = 256
        internal const val MAX_ENCODED_SIZE = 12 * 1024

        fun create(
            role: AkenRuntimeEvaluatorRole,
            ordinal: Int,
            family: Int,
            shape: ByteArray,
            callToken: ByteArray,
            tablePermutation: IntArray,
        ): AkenRuntimeEvaluatorFragment = AkenRuntimeEvaluatorFragment(
            role = role,
            ordinal = ordinal,
            family = family,
            shape = shape,
            callToken = callToken,
            tablePermutation = tablePermutation,
        )

        fun decode(encoded: ByteArray): AkenRuntimeEvaluatorFragment {
            require(encoded.isNotEmpty() && encoded.size <= MAX_ENCODED_SIZE) {
                "AKEN runtime fragment encoding length is invalid"
            }
            val reader = AkenRuntimeDescriptorReader(encoded)
            val role = AkenRuntimeEvaluatorRole.fromId(reader.readUnsignedByte("AKEN runtime fragment role"))
                ?: throw IllegalArgumentException("unknown AKEN runtime fragment role")
            val ordinal = reader.readInt("AKEN runtime fragment ordinal")
            val family = reader.readInt("AKEN runtime fragment family")
            var shape: ByteArray? = null
            var callToken: ByteArray? = null
            var tablePermutation: IntArray? = null
            return try {
                shape = reader.readFramed(MAX_FRAGMENT_SHAPE_SIZE, "AKEN runtime fragment shape", allowEmpty = false)
                callToken = reader.readFramed(
                    MAX_FRAGMENT_CALL_TOKEN_SIZE,
                    "AKEN runtime fragment call token",
                    allowEmpty = false,
                )
                val tableSize = reader.readInt("AKEN runtime fragment table length")
                require(tableSize in 1..MAX_TABLE_PERMUTATION_SIZE) {
                    "AKEN runtime fragment table length is invalid"
                }
                tablePermutation = IntArray(tableSize) {
                    reader.readInt("AKEN runtime fragment table entry")
                }
                reader.requireFullyRead("AKEN runtime fragment")
                create(role, ordinal, family, checkNotNull(shape), checkNotNull(callToken), checkNotNull(tablePermutation))
            } finally {
                shape?.let { Arrays.fill(it, 0) }
                callToken?.let { Arrays.fill(it, 0) }
                tablePermutation?.let { Arrays.fill(it, 0) }
            }
        }

        private fun isPermutation(values: IntArray): Boolean {
            val seen = BooleanArray(values.size)
            values.forEach { value ->
                if (value !in values.indices || seen[value]) return false
                seen[value] = true
            }
            return true
        }
    }
}

/**
 * AKEN-7 evaluator graph metadata for a single page. The role-specific lists
 * preserve execution order but expose no cross-page discovery operation.
 */
class AkenRuntimeEvaluatorPlan private constructor(
    javaFragments: List<AkenRuntimeEvaluatorFragment>,
    nativeFragments: List<AkenRuntimeEvaluatorFragment>,
    terminal: AkenRuntimeEvaluatorFragment?,
    boundDecryptor: AkenBoundDecryptorPlan?,
    fingerprint: ByteArray,
) {
    private val javaFragmentsValue = javaFragments.toList()
    private val nativeFragmentsValue = nativeFragments.toList()
    private val terminalValue = terminal
    private val boundDecryptorValue = boundDecryptor
    private val fingerprintValue = fingerprint.copyOf()

    init {
        require(fingerprintValue.size == AkenHandle.FINGERPRINT_SIZE) {
            "AKEN runtime evaluator fingerprint length is invalid"
        }
        if (boundDecryptorValue != null) {
            require(javaFragmentsValue.isEmpty() && nativeFragmentsValue.isEmpty() && terminalValue == null) {
                "AKEN bound evaluator plan must not carry legacy fragments"
            }
        } else {
            require(terminalValue != null) { "AKEN runtime legacy evaluator terminal is missing" }
            validateLegacyTopology(javaFragmentsValue, nativeFragmentsValue, checkNotNull(terminalValue))
        }
    }

    /** True only for the legacy AKEN-7 descriptor encoding retained for old artifacts and fixtures. */
    internal val isLegacyAken7: Boolean
        get() = boundDecryptorValue == null

    /**
     * Compatibility view for legacy descriptors. New production descriptors
     * intentionally expose no fragment topology at runtime.
     */
    val javaFragments: List<AkenRuntimeEvaluatorFragment>
        get() = javaFragmentsValue.map { copyRuntimeFragment(it) }

    /** Compatibility view for legacy descriptors only. */
    val nativeFragments: List<AkenRuntimeEvaluatorFragment>
        get() = nativeFragmentsValue.map { copyRuntimeFragment(it) }

    /** Compatibility view for legacy descriptors only. */
    val terminal: AkenRuntimeEvaluatorFragment
        get() = terminalValue?.let(::copyRuntimeFragment)
            ?: throw IllegalStateException("AKEN bound evaluator has no legacy terminal fragment")

    val fingerprint: ByteArray
        get() = fingerprintValue.copyOf()

    /** Copy only the current page's opaque native terminal descriptor. */
    internal fun copyBoundDecryptorForNative(): ByteArray? =
        boundDecryptorValue?.copyOpaqueForNative()

    fun encode(): ByteArray {
        val bound = checkNotNull(boundDecryptorValue) {
            "current evaluator plan requires a bound decryptor"
        }
        return ByteArrayOutputStream().use { out ->
            val opaque = bound.copyOpaqueForNative()
            try {
                writeRuntimeFramed(out, opaque)
                out.write(fingerprintValue)
            } finally {
                Arrays.fill(opaque, 0)
            }
            out.toByteArray().also {
                require(it.size <= MAX_PLAN_ENCODING_SIZE) {
                    "runtime evaluator plan encoding is too large"
                }
            }
        }
    }

    override fun equals(other: Any?): Boolean =
        other is AkenRuntimeEvaluatorPlan &&
            javaFragmentsValue == other.javaFragmentsValue &&
            nativeFragmentsValue == other.nativeFragmentsValue &&
            terminalValue == other.terminalValue &&
            boundDecryptorValue == other.boundDecryptorValue &&
            Arrays.equals(fingerprintValue, other.fingerprintValue)

    override fun hashCode(): Int {
        var result = javaFragmentsValue.hashCode()
        result = 31 * result + nativeFragmentsValue.hashCode()
        result = 31 * result + (terminalValue?.hashCode() ?: 0)
        result = 31 * result + (boundDecryptorValue?.hashCode() ?: 0)
        return 31 * result + fingerprintValue.contentHashCode()
    }

    override fun toString(): String =
        if (boundDecryptorValue != null) "AkenRuntimeEvaluatorPlan(bound-page)" else "AkenRuntimeEvaluatorPlan(aken7-legacy)"

    /**
     * Legacy graph check retained only for old serialized descriptors. Bound
     * descriptors require route/proof context and are checked by
     * [matchesDescriptorBinding].
     */
    internal fun matchesPageBinding(
        resourceKind: AkenResourceKind,
        logicalIdentity: ByteArray,
        pageIndex: Int,
        targetPageSize: Int,
        codecVariant: String,
        layoutVariant: String,
        handleEncoding: ByteArray,
        locatorToken: ByteArray,
    ): Boolean {
        if (boundDecryptorValue != null) return false
        val expected = computeFingerprint(
            resourceKind,
            logicalIdentity,
            pageIndex,
            targetPageSize,
            codecVariant,
            layoutVariant,
            handleEncoding,
            locatorToken,
            javaFragmentsValue,
            nativeFragmentsValue,
            checkNotNull(terminalValue),
        )
        return try {
            Arrays.equals(fingerprintValue, expected)
        } finally {
            Arrays.fill(expected, 0)
        }
    }

    /** Verify the complete page binding that a bound descriptor commits to. */
    internal fun matchesDescriptorBinding(
        resourceKind: AkenResourceKind,
        logicalIdentity: ByteArray,
        pageIndex: Int,
        targetPageSize: Int,
        route: AkenRoutingMetadata,
        proof: AkenSealingProofMetadata,
        handleEncoding: ByteArray,
        locatorToken: ByteArray,
    ): Boolean {
        val bound = boundDecryptorValue
        if (bound == null) {
            return matchesPageBinding(
                resourceKind,
                logicalIdentity,
                pageIndex,
                targetPageSize,
                route.codecVariant,
                route.layoutVariant,
                handleEncoding,
                locatorToken,
            )
        }
        var artifactCommitment: ByteArray? = null
        var callSiteProof: ByteArray? = null
        try {
            artifactCommitment = proof.artifactCanonicalCommitment
            callSiteProof = proof.callSiteProof
            return bound.matchesPageBinding(
                resourceKind = resourceKind,
                logicalIdentity = logicalIdentity,
                pageIndex = pageIndex,
                targetPageSize = targetPageSize,
                codecVariant = route.codecVariant,
                layoutVariant = route.layoutVariant,
                handleEncoding = handleEncoding,
                locatorToken = locatorToken,
                evaluatorFingerprint = fingerprintValue,
                artifactCanonicalCommitment = checkNotNull(artifactCommitment),
                route = route,
                callSiteProof = checkNotNull(callSiteProof),
            )
        } finally {
            artifactCommitment?.let { Arrays.fill(it, 0) }
            callSiteProof?.let { Arrays.fill(it, 0) }
        }
    }

    companion object {
        private const val JAVA_FRAGMENT_COUNT = 3
        private const val NATIVE_FRAGMENT_COUNT = 3
        private const val AKEN_FRAGMENT_COUNT = JAVA_FRAGMENT_COUNT + NATIVE_FRAGMENT_COUNT + 1
        private const val MAX_PLAN_ENCODING_SIZE = 128 * 1024
        private val EVALUATOR_DOMAIN = "evaluator-graph".toByteArray(StandardCharsets.US_ASCII)
        private const val FRAGMENT_ROLE_JAVA: Byte = 1
        private const val FRAGMENT_ROLE_NATIVE: Byte = 2
        private const val FRAGMENT_ROLE_TERMINAL: Byte = 3

        fun create(
            javaFragments: List<AkenRuntimeEvaluatorFragment>,
            nativeFragments: List<AkenRuntimeEvaluatorFragment>,
            terminal: AkenRuntimeEvaluatorFragment,
            fingerprint: ByteArray,
        ): AkenRuntimeEvaluatorPlan = AkenRuntimeEvaluatorPlan(
            javaFragments,
            nativeFragments,
            terminal,
            null,
            fingerprint,
        )

        /** New production representation: opaque page-bound native terminal only. */
        internal fun createBound(
            boundDecryptor: AkenBoundDecryptorPlan,
            fingerprint: ByteArray,
        ): AkenRuntimeEvaluatorPlan = AkenRuntimeEvaluatorPlan(
            emptyList(),
            emptyList(),
            null,
            boundDecryptor,
            fingerprint,
        )

        /**
         * Exact legacy graph fingerprint reconstruction used only for v1
         * compatibility descriptors and build-time fixture parity.
         */
        fun computeFingerprint(
            resourceKind: AkenResourceKind,
            logicalIdentity: ByteArray,
            pageIndex: Int,
            targetPageSize: Int,
            codecVariant: String,
            layoutVariant: String,
            handleEncoding: ByteArray,
            locatorToken: ByteArray,
            javaFragments: List<AkenRuntimeEvaluatorFragment>,
            nativeFragments: List<AkenRuntimeEvaluatorFragment>,
            terminal: AkenRuntimeEvaluatorFragment,
        ): ByteArray {
            require(logicalIdentity.isNotEmpty() && logicalIdentity.size <= MAX_LOGICAL_IDENTITY_SIZE) {
                "AKEN runtime logical identity length is invalid"
            }
            require(pageIndex >= 0) { "AKEN runtime page index must be non-negative" }
            require(targetPageSize in AkenPageSizePolicy.DEFAULT.allowedSizes(resourceKind)) {
                "AKEN runtime target page size is invalid for resource kind"
            }
            require(handleEncoding.size == AkenHandle.ENCODED_HANDLE_SIZE) {
                "AKEN runtime handle encoding length is invalid"
            }
            require(locatorToken.size == AkenHandle.LOCATOR_TOKEN_SIZE) {
                "AKEN runtime locator token length is invalid"
            }
            validateLegacyTopology(javaFragments, nativeFragments, terminal)
            val canonicalCodec = AkenResourceCodec.normalizeCodecVariant(codecVariant)
            require(canonicalCodec == codecVariant) { "AKEN runtime codec variant is not canonical" }
            val layout = AkenPageLayout.fromVariant(layoutVariant)
            var codecBytes: ByteArray? = null
            var layoutBytes: ByteArray? = null
            try {
                val canonicalLayout = layout.variant
                require(canonicalLayout == layoutVariant) { "AKEN runtime layout variant is not canonical" }
                codecBytes = canonicalCodec.toByteArray(StandardCharsets.UTF_8)
                layoutBytes = canonicalLayout.toByteArray(StandardCharsets.UTF_8)
                val digest = MessageDigest.getInstance("SHA-256")
                digest.update(EVALUATOR_DOMAIN)
                digest.update(resourceKind.id.toByte())
                updateRuntimeFramed(digest, logicalIdentity)
                updateRuntimeInt(digest, pageIndex)
                updateRuntimeInt(digest, targetPageSize)
                updateRuntimeFramed(digest, checkNotNull(codecBytes))
                updateRuntimeFramed(digest, checkNotNull(layoutBytes))
                updateRuntimeFramed(digest, handleEncoding)
                updateRuntimeFramed(digest, locatorToken)
                updateRuntimeFragments(digest, FRAGMENT_ROLE_JAVA, javaFragments)
                updateRuntimeFragments(digest, FRAGMENT_ROLE_NATIVE, nativeFragments)
                updateRuntimeFragments(digest, FRAGMENT_ROLE_TERMINAL, listOf(terminal))
                return digest.digest()
            } finally {
                codecBytes?.let { Arrays.fill(it, 0) }
                layoutBytes?.let { Arrays.fill(it, 0) }
                layout.wipe()
            }
        }

        fun decode(encoded: ByteArray): AkenRuntimeEvaluatorPlan {
            require(encoded.isNotEmpty() && encoded.size <= MAX_PLAN_ENCODING_SIZE) {
                "AKEN runtime evaluator plan encoding length is invalid"
            }
            val reader = AkenRuntimeDescriptorReader(encoded)
            return decodeBound(reader)
        }

        private fun decodeLegacy(reader: AkenRuntimeDescriptorReader): AkenRuntimeEvaluatorPlan {
            val javaFragments = ArrayList<AkenRuntimeEvaluatorFragment>(JAVA_FRAGMENT_COUNT)
            val nativeFragments = ArrayList<AkenRuntimeEvaluatorFragment>(NATIVE_FRAGMENT_COUNT)
            var terminal: AkenRuntimeEvaluatorFragment? = null
            var fingerprint: ByteArray? = null
            return try {
                repeat(JAVA_FRAGMENT_COUNT) {
                    javaFragments += readRuntimeFragment(reader, "AKEN runtime Java fragment")
                }
                repeat(NATIVE_FRAGMENT_COUNT) {
                    nativeFragments += readRuntimeFragment(reader, "AKEN runtime native fragment")
                }
                terminal = readRuntimeFragment(reader, "AKEN runtime terminal fragment")
                fingerprint = reader.readFixed(AkenHandle.FINGERPRINT_SIZE, "AKEN runtime evaluator fingerprint")
                reader.requireFullyRead("AKEN runtime evaluator plan")
                create(javaFragments, nativeFragments, checkNotNull(terminal), checkNotNull(fingerprint))
            } finally {
                fingerprint?.let { Arrays.fill(it, 0) }
            }
        }

        private fun decodeBound(reader: AkenRuntimeDescriptorReader): AkenRuntimeEvaluatorPlan {
            var opaque: ByteArray? = null
            var fingerprint: ByteArray? = null
            return try {
                opaque = reader.readFramed(MAX_PLAN_ENCODING_SIZE - AkenHandle.FINGERPRINT_SIZE - 5, "AKEN bound evaluator", allowEmpty = false)
                fingerprint = reader.readFixed(AkenHandle.FINGERPRINT_SIZE, "AKEN runtime evaluator fingerprint")
                reader.requireFullyRead("AKEN runtime bound evaluator plan")
                createBound(AkenBoundDecryptorPlan.fromOpaque(checkNotNull(opaque)), checkNotNull(fingerprint))
            } finally {
                opaque?.let { Arrays.fill(it, 0) }
                fingerprint?.let { Arrays.fill(it, 0) }
            }
        }

        private fun validateLegacyTopology(
            javaFragments: List<AkenRuntimeEvaluatorFragment>,
            nativeFragments: List<AkenRuntimeEvaluatorFragment>,
            terminal: AkenRuntimeEvaluatorFragment,
        ) {
            require(javaFragments.size == JAVA_FRAGMENT_COUNT) {
                "AKEN runtime evaluator requires three Java fragments"
            }
            require(nativeFragments.size == NATIVE_FRAGMENT_COUNT) {
                "AKEN runtime evaluator requires three native fragments"
            }
            require(javaFragments.all { it.role == AkenRuntimeEvaluatorRole.Java }) {
                "AKEN runtime Java fragment role is invalid"
            }
            require(nativeFragments.all { it.role == AkenRuntimeEvaluatorRole.Native }) {
                "AKEN runtime native fragment role is invalid"
            }
            require(terminal.role == AkenRuntimeEvaluatorRole.Terminal) {
                "AKEN runtime terminal fragment role is invalid"
            }
            val ordinals = javaFragments.map { it.ordinal } + nativeFragments.map { it.ordinal } + terminal.ordinal
            require(ordinals.sorted() == (0 until AKEN_FRAGMENT_COUNT).toList()) {
                "AKEN runtime evaluator must contain seven unique fragment ordinals"
            }
            require(javaFragments.all { it.ordinal in 0 until JAVA_FRAGMENT_COUNT }) {
                "AKEN runtime Java fragment ordinal is invalid"
            }
            require(nativeFragments.all { it.ordinal in JAVA_FRAGMENT_COUNT until JAVA_FRAGMENT_COUNT + NATIVE_FRAGMENT_COUNT }) {
                "AKEN runtime native fragment ordinal is invalid"
            }
            require(terminal.ordinal == AKEN_FRAGMENT_COUNT - 1) {
                "AKEN runtime terminal fragment ordinal is invalid"
            }
        }

        private fun writeRuntimeFragment(out: ByteArrayOutputStream, fragment: AkenRuntimeEvaluatorFragment) {
            val encoded = fragment.encode()
            try {
                writeRuntimeFramed(out, encoded)
            } finally {
                Arrays.fill(encoded, 0)
            }
        }

        private fun readRuntimeFragment(
            reader: AkenRuntimeDescriptorReader,
            label: String,
        ): AkenRuntimeEvaluatorFragment {
            val encoded = reader.readFramed(AkenRuntimeEvaluatorFragment.MAX_ENCODED_SIZE, label, allowEmpty = false)
            return try {
                AkenRuntimeEvaluatorFragment.decode(encoded)
            } finally {
                Arrays.fill(encoded, 0)
            }
        }

        private fun copyRuntimeFragment(source: AkenRuntimeEvaluatorFragment): AkenRuntimeEvaluatorFragment {
            val shape = source.shape
            val callToken = source.callToken
            val tablePermutation = source.tablePermutation
            return try {
                AkenRuntimeEvaluatorFragment.create(
                    source.role,
                    source.ordinal,
                    source.family,
                    shape,
                    callToken,
                    tablePermutation,
                )
            } finally {
                Arrays.fill(shape, 0)
                Arrays.fill(callToken, 0)
                Arrays.fill(tablePermutation, 0)
            }
        }

        private fun updateRuntimeFragments(
            digest: MessageDigest,
            role: Byte,
            fragments: List<AkenRuntimeEvaluatorFragment>,
        ) {
            updateRuntimeInt(digest, fragments.size)
            fragments.forEachIndexed { executionIndex, fragment ->
                val shape = fragment.shape
                val callToken = fragment.callToken
                val tablePermutation = fragment.tablePermutation
                try {
                    digest.update(role)
                    updateRuntimeInt(digest, executionIndex)
                    updateRuntimeInt(digest, fragment.ordinal)
                    updateRuntimeInt(digest, fragment.family)
                    updateRuntimeFramed(digest, shape)
                    updateRuntimeInt(digest, tablePermutation.size)
                    tablePermutation.forEach { updateRuntimeInt(digest, it) }
                    updateRuntimeFramed(digest, callToken)
                } finally {
                    Arrays.fill(shape, 0)
                    Arrays.fill(callToken, 0)
                    Arrays.fill(tablePermutation, 0)
                }
            }
        }
    }
}

/**
 * Runtime-neutral metadata for exactly one high-value AKEN v4 page.
 *
 * It combines one opaque handle binding, the corresponding logical identity,
 * one route, one integrity/call-site proof, and one AKEN-7 graph. It offers no
 * directory, traversal, or arbitrary-resource decoding surface.
 */
class AkenRuntimePageDescriptor private constructor(
    private val leafIdentityValue: AkenHighValueLeafIdentity,
    private val routeValue: AkenRoutingMetadata,
    private val proofValue: AkenSealingProofMetadata,
    val targetPageSize: Int,
    private val evaluatorPlanValue: AkenRuntimeEvaluatorPlan,
) {
    init {
        validateBinding(leafIdentityValue, routeValue, proofValue, targetPageSize, evaluatorPlanValue)
    }

    val resourceKind: AkenResourceKind
        get() = leafIdentityValue.resourceKind

    val pageIndex: Int
        get() = leafIdentityValue.pageIndex

    val logicalIdentity: ByteArray
        get() = leafIdentityValue.logicalIdentity

    /** A fresh opaque handle for this descriptor's only page binding. */
    val handle: AkenHandle
        get() = handleFromIdentity(leafIdentityValue)

    val route: AkenRoutingMetadata
        get() = routeValue

    val proof: AkenSealingProofMetadata
        get() = proofValue

    val evaluatorPlan: AkenRuntimeEvaluatorPlan
        get() = evaluatorPlanValue

    fun matches(candidate: AkenHandle): Boolean = leafIdentityValue.matches(candidate)

    fun encode(): ByteArray = ByteArrayOutputStream().use { out ->
        val route = routeValue.encode()
        val proof = proofValue.encode()
        val evaluator = evaluatorPlanValue.encode()
        try {
            writeRuntimeFramed(out, route)
            writeRuntimeFramed(out, proof)
            writeRuntimeInt(out, targetPageSize)
            writeRuntimeFramed(out, evaluator)
            out.toByteArray().also {
                require(it.size <= MAX_DESCRIPTOR_ENCODING_SIZE) {
                    "AKEN runtime page descriptor encoding is too large"
                }
            }
        } finally {
            Arrays.fill(route, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(evaluator, 0)
        }
    }

    override fun toString(): String =
        "AkenRuntimePageDescriptor(kind=" + resourceKind.logicalName + ", page=" + pageIndex + ")"

    companion object {
        private const val MAX_DESCRIPTOR_ENCODING_SIZE = 384 * 1024
        private const val MAX_ROUTE_ENCODING_SIZE = 128 * 1024
        private const val MAX_PROOF_ENCODING_SIZE = 160 * 1024
        private const val MAX_EVALUATOR_PLAN_ENCODING_SIZE = 128 * 1024

        fun create(
            handle: AkenHandle,
            logicalIdentity: ByteArray,
            route: AkenRoutingMetadata,
            proof: AkenSealingProofMetadata,
            targetPageSize: Int,
            evaluatorPlan: AkenRuntimeEvaluatorPlan,
        ): AkenRuntimePageDescriptor {
            val identity = AkenHighValueLeafIdentity.fromHandle(handle, logicalIdentity)
            return fromMetadata(identity, route, proof, targetPageSize, evaluatorPlan)
        }

        fun decode(encoded: ByteArray): AkenRuntimePageDescriptor {
            require(encoded.isNotEmpty() && encoded.size <= MAX_DESCRIPTOR_ENCODING_SIZE) {
                "AKEN runtime page descriptor encoding length is invalid"
            }
            val reader = AkenRuntimeDescriptorReader(encoded)
            var routeBytes: ByteArray? = null
            var proofBytes: ByteArray? = null
            var evaluatorBytes: ByteArray? = null
            return try {
                routeBytes = reader.readFramed(MAX_ROUTE_ENCODING_SIZE, "AKEN runtime page route", allowEmpty = false)
                val route = AkenRoutingMetadata.decode(checkNotNull(routeBytes))
                proofBytes = reader.readFramed(MAX_PROOF_ENCODING_SIZE, "AKEN runtime page proof", allowEmpty = false)
                val proof = AkenSealingProofMetadata.decode(checkNotNull(proofBytes))
                val targetPageSize = reader.readInt("AKEN runtime target page size")
                evaluatorBytes = reader.readFramed(
                    MAX_EVALUATOR_PLAN_ENCODING_SIZE,
                    "AKEN runtime evaluator plan",
                    allowEmpty = false,
                )
                val evaluatorPlan = AkenRuntimeEvaluatorPlan.decode(checkNotNull(evaluatorBytes))
                reader.requireFullyRead("AKEN runtime page descriptor")
                fromMetadata(route.leafIdentity, route, proof, targetPageSize, evaluatorPlan)
            } finally {
                routeBytes?.let { Arrays.fill(it, 0) }
                proofBytes?.let { Arrays.fill(it, 0) }
                evaluatorBytes?.let { Arrays.fill(it, 0) }
            }
        }

        private fun fromMetadata(
            identity: AkenHighValueLeafIdentity,
            route: AkenRoutingMetadata,
            proof: AkenSealingProofMetadata,
            targetPageSize: Int,
            evaluatorPlan: AkenRuntimeEvaluatorPlan,
        ): AkenRuntimePageDescriptor = AkenRuntimePageDescriptor(
            identity,
            route,
            proof,
            targetPageSize,
            evaluatorPlan,
        )

        private fun validateBinding(
            identity: AkenHighValueLeafIdentity,
            route: AkenRoutingMetadata,
            proof: AkenSealingProofMetadata,
            targetPageSize: Int,
            evaluatorPlan: AkenRuntimeEvaluatorPlan,
        ) {
            require(route.leafIdentity == identity) { "AKEN runtime route does not bind the current page" }
            require(proof.leafIdentity == identity) { "AKEN runtime proof does not bind the current page" }
            require(route.codecVariant == proof.codecVariant) { "AKEN runtime route/proof codec mismatch" }
            require(route.layoutVariant == proof.layoutVariant) { "AKEN runtime route/proof layout mismatch" }

            var logicalIdentity: ByteArray? = null
            var handleEncoding: ByteArray? = null
            var locatorToken: ByteArray? = null
            var expectedFingerprint: ByteArray? = null
            var graphFingerprint: ByteArray? = null
            try {
                logicalIdentity = identity.logicalIdentity
                handleEncoding = identity.handleEncoding
                locatorToken = identity.locatorToken
                expectedFingerprint = identity.evaluatorFingerprint
                graphFingerprint = evaluatorPlan.fingerprint
                require(Arrays.equals(expectedFingerprint, graphFingerprint)) {
                    "AKEN runtime evaluator fingerprint does not match the page handle"
                }
                require(
                    evaluatorPlan.matchesDescriptorBinding(
                        resourceKind = identity.resourceKind,
                        logicalIdentity = checkNotNull(logicalIdentity),
                        pageIndex = identity.pageIndex,
                        targetPageSize = targetPageSize,
                        route = route,
                        proof = proof,
                        handleEncoding = checkNotNull(handleEncoding),
                        locatorToken = checkNotNull(locatorToken),
                    ),
                ) { "AKEN runtime evaluator graph binding is invalid" }
            } finally {
                logicalIdentity?.let { Arrays.fill(it, 0) }
                handleEncoding?.let { Arrays.fill(it, 0) }
                locatorToken?.let { Arrays.fill(it, 0) }
                expectedFingerprint?.let { Arrays.fill(it, 0) }
                graphFingerprint?.let { Arrays.fill(it, 0) }
            }
        }

        private fun handleFromIdentity(identity: AkenHighValueLeafIdentity): AkenHandle {
            var encoded: ByteArray? = null
            var locator: ByteArray? = null
            var fingerprint: ByteArray? = null
            return try {
                encoded = identity.handleEncoding
                locator = identity.locatorToken
                fingerprint = identity.evaluatorFingerprint
                AkenHandle.create(
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

private const val MAX_LOGICAL_IDENTITY_SIZE = 64 * 1024

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

private fun updateRuntimeInt(digest: MessageDigest, value: Int) {
    digest.update((value ushr 24).toByte())
    digest.update((value ushr 16).toByte())
    digest.update((value ushr 8).toByte())
    digest.update(value.toByte())
}

private fun updateRuntimeFramed(digest: MessageDigest, value: ByteArray) {
    updateRuntimeInt(digest, value.size)
    digest.update(value)
}

private class AkenRuntimeDescriptorReader(private val bytes: ByteArray) {
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
        require(length >= 0) { "AKEN runtime fixed length must be non-negative" }
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
