package io.github.hht0rro.javashroud.transforms.protection.aken

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import kotlin.jvm.JvmSynthetic

/**
 * Build-only AKEN v4 planner.
 *
 * Every registered high-value page receives an independent random DEK, an
 * independent physical frame, and a randomized seven-fragment evaluator graph.
 * The graph carries transformed XOR shares rather than a raw or contiguous
 * page key, so no fragment, table entry, or page descriptor is a root-key
 * substitute. This object deliberately provides no page enumeration, raw-DEK
 * export, or Java-visible generic decoder. Materialization can only emit a
 * page-local ciphertext or perform a boolean AEAD binding check whose transient
 * plaintext is zeroed before control returns.
 */
class AkenBuildPlan private constructor(
    private val commitment: ByteArray,
    private val random: SecureRandom,
    val pageSizePolicy: AkenPageSizePolicy,
) : AutoCloseable {

    /** One generated Java/native evaluator fragment with defensive-copy views. */
    class EvaluatorFragment internal constructor(
        val ordinal: Int,
        val family: Int,
        shape: ByteArray,
        callToken: ByteArray,
        tablePermutation: IntArray,
    ) {
        private var shapeValue: ByteArray = shape.copyOf()
        private var callTokenValue: ByteArray = callToken.copyOf()
        private var tablePermutationValue: IntArray = tablePermutation.copyOf()

        @Volatile
        private var wiped: Boolean = false

        init {
            require(ordinal in 0 until AKEN_FRAGMENT_COUNT) { "AKEN fragment ordinal is invalid" }
            require(family in 0 until AKEN_TRANSFORM_FAMILY_COUNT) { "AKEN transform family is invalid" }
            require(shapeValue.isNotEmpty()) { "AKEN fragment shape must not be empty" }
            require(callTokenValue.isNotEmpty()) { "AKEN fragment call token must not be empty" }
            require(isPermutation(tablePermutationValue)) { "AKEN fragment table is not a permutation" }
        }

        val shape: ByteArray
            get() {
                requireLive()
                return shapeValue.copyOf()
            }

        val callToken: ByteArray
            get() {
                requireLive()
                return callTokenValue.copyOf()
            }

        val tablePermutation: IntArray
            get() {
                requireLive()
                return tablePermutationValue.copyOf()
            }

        internal fun wipe() {
            if (wiped) return
            Arrays.fill(shapeValue, 0)
            Arrays.fill(callTokenValue, 0)
            Arrays.fill(tablePermutationValue, 0)
            shapeValue = ByteArray(0)
            callTokenValue = ByteArray(0)
            tablePermutationValue = IntArray(0)
            wiped = true
        }

        private fun requireLive() {
            check(!wiped) { "AKEN evaluator fragment has been wiped" }
        }

        private fun isPermutation(values: IntArray): Boolean {
            if (values.isEmpty()) return false
            val seen = BooleanArray(values.size)
            for (value in values) {
                if (value !in values.indices || seen[value]) return false
                seen[value] = true
            }
            return true
        }
    }

    /** Complete AKEN-7 evaluator graph for exactly one page. */
    class EvaluatorPlan internal constructor(
        javaFragments: List<EvaluatorFragment>,
        nativeFragments: List<EvaluatorFragment>,
        terminal: EvaluatorFragment,
        fingerprint: ByteArray,
    ) {
        private var javaFragmentsValue: List<EvaluatorFragment> = javaFragments.toList()
        private var nativeFragmentsValue: List<EvaluatorFragment> = nativeFragments.toList()
        private var terminalValue: EvaluatorFragment? = terminal
        private var fingerprintValue: ByteArray = fingerprint.copyOf()

        @Volatile
        private var wiped: Boolean = false

        init {
            require(javaFragmentsValue.size == JAVA_FRAGMENT_COUNT) { "AKEN graph requires three Java fragments" }
            require(nativeFragmentsValue.size == NATIVE_FRAGMENT_COUNT) { "AKEN graph requires three native fragments" }
            require(fingerprintValue.size == AkenHandle.FINGERPRINT_SIZE) {
                "AKEN evaluator fingerprint has an invalid length"
            }
            val ordinals = (javaFragmentsValue + nativeFragmentsValue + listOfNotNull(terminalValue)).map { it.ordinal }
            require(ordinals.size == AKEN_FRAGMENT_COUNT && ordinals.toSet().size == AKEN_FRAGMENT_COUNT) {
                "AKEN graph must contain seven unique fragments"
            }
        }

        /** Execution order is represented by the order of each returned list. */
        val javaFragments: List<EvaluatorFragment>
            get() {
                requireLive()
                return javaFragmentsValue.toList()
            }

        /** Execution order is represented by the order of each returned list. */
        val nativeFragments: List<EvaluatorFragment>
            get() {
                requireLive()
                return nativeFragmentsValue.toList()
            }

        val terminal: EvaluatorFragment
            get() {
                requireLive()
                return terminalValue ?: error("AKEN evaluator terminal has been wiped")
            }

        val fingerprint: ByteArray
            get() {
                requireLive()
                return fingerprintValue.copyOf()
            }

        val allFragments: List<EvaluatorFragment>
            get() {
                requireLive()
                return ArrayList<EvaluatorFragment>(AKEN_FRAGMENT_COUNT).apply {
                    addAll(javaFragmentsValue)
                    addAll(nativeFragmentsValue)
                    add(terminalValue ?: error("AKEN evaluator terminal has been wiped"))
                }
            }

        /** Compact, non-secret execution-order metadata for code generators. */
        val executionOrder: IntArray
            get() {
                requireLive()
                return allFragments.map { it.ordinal }.toIntArray()
            }

        internal fun copyFingerprintForBuild(): ByteArray {
            requireLive()
            return fingerprintValue.copyOf()
        }

        internal fun wipe() {
            if (wiped) return
            javaFragmentsValue.forEach { it.wipe() }
            nativeFragmentsValue.forEach { it.wipe() }
            terminalValue?.wipe()
            javaFragmentsValue = emptyList()
            nativeFragmentsValue = emptyList()
            terminalValue = null
            Arrays.fill(fingerprintValue, 0)
            fingerprintValue = ByteArray(0)
            wiped = true
        }

        private fun requireLive() {
            check(!wiped) { "AKEN evaluator plan has been wiped" }
        }
    }

    /** Immutable-view metadata for one high-value page. */
    class Page internal constructor(
        handle: AkenHandle,
        resourceKind: AkenResourceKind,
        logicalIdentity: ByteArray,
        pageIndex: Int,
        targetSize: Int,
        evaluatorPlan: EvaluatorPlan,
        codecVariant: String,
        layout: AkenPageLayout,
    ) {
        private var handleValue: AkenHandle? = handle
        private val resourceKindValue: AkenResourceKind = resourceKind
        private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
        private val pageIndexValue: Int = pageIndex
        private val targetSizeValue: Int = targetSize
        private var evaluatorPlanValue: EvaluatorPlan? = evaluatorPlan
        private val codecVariantValue: String = codecVariant
        private var layoutValue: AkenPageLayout? = layout

        @Volatile
        private var wiped: Boolean = false

        val handle: AkenHandle
            get() {
                requireLive()
                return handleValue ?: error("AKEN page handle has been wiped")
            }

        val resourceKind: AkenResourceKind
            get() {
                requireLive()
                return resourceKindValue
            }

        val logicalIdentity: ByteArray
            get() {
                requireLive()
                return logicalIdentityValue.copyOf()
            }

        val pageIndex: Int
            get() {
                requireLive()
                return pageIndexValue
            }

        val targetSize: Int
            get() {
                requireLive()
                return targetSizeValue
            }

        val evaluatorPlan: EvaluatorPlan
            get() {
                requireLive()
                return evaluatorPlanValue ?: error("AKEN page evaluator has been wiped")
            }

        val codecVariant: String
            get() {
                requireLive()
                return codecVariantValue
            }

        /** Authenticated build-specific frame descriptor for sealing/runtime emitters. */
        val pageLayout: AkenPageLayout
            get() {
                requireLive()
                return (layoutValue ?: error("AKEN page layout has been wiped")).copyForBuild()
            }

        /** Canonical descriptor for [pageLayout], not a caller-provided decorative label. */
        val layoutVariant: String
            get() {
                requireLive()
                return (layoutValue ?: error("AKEN page layout has been wiped")).variant
            }

        internal fun <T> withCodecContext(block: (PageCodecContext) -> T): T {
            requireLive()
            val context = PageCodecContext(
                identity = logicalIdentityValue.copyOf(),
                fingerprint = (evaluatorPlanValue ?: error("AKEN page evaluator has been wiped")).copyFingerprintForBuild(),
                locator = (handleValue ?: error("AKEN page handle has been wiped")).copyLocatorTokenForBuild(),
                codecVariant = codecVariantValue,
                layout = (layoutValue ?: error("AKEN page layout has been wiped")).copyForBuild(),
            )
            return try {
                block(context)
            } finally {
                context.close()
            }
        }

        internal fun wipe() {
            if (wiped) return
            Arrays.fill(logicalIdentityValue, 0)
            logicalIdentityValue = ByteArray(0)
            evaluatorPlanValue?.wipe()
            evaluatorPlanValue = null
            layoutValue?.wipe()
            layoutValue = null
            handleValue?.wipe()
            handleValue = null
            wiped = true
        }

        private fun requireLive() {
            check(!wiped) { "AKEN page has been wiped" }
        }
    }

    /**
     * A short build-only DEK window. It is private to the planner so raw key
     * material cannot become a Java/runtime API. [withDek] copies the leased
     * material for a planner callback and zeroes that callback copy before it
     * returns.
     */
    private class AkenPageLease(
        dek: ByteArray,
        private var releaseCallback: ((AkenPageLease) -> Unit)?,
    ) : AutoCloseable {
        private var dekValue: ByteArray? = dek.copyOf()

        @Volatile
        private var closed: Boolean = false

        fun <T> withDek(block: (ByteArray) -> T): T = synchronized(this) {
            check(!closed) { "AKEN page lease is closed" }
            val source = dekValue ?: error("AKEN page lease has no key material")
            val callbackCopy = source.copyOf()
            try {
                block(callbackCopy)
            } finally {
                Arrays.fill(callbackCopy, 0)
            }
        }

        override fun close() {
            val callback: ((AkenPageLease) -> Unit)?
            synchronized(this) {
                if (closed) return
                closed = true
                dekValue?.let { Arrays.fill(it, 0) }
                dekValue = null
                callback = releaseCallback
                releaseCallback = null
            }
            callback?.invoke(this)
        }
    }

    internal class PageCodecContext(
        val identity: ByteArray,
        val fingerprint: ByteArray,
        val locator: ByteArray,
        val codecVariant: String,
        val layout: AkenPageLayout,
    ) : AutoCloseable {
        override fun close() {
            Arrays.fill(identity, 0)
            Arrays.fill(fingerprint, 0)
            Arrays.fill(locator, 0)
            layout.wipe()
        }
    }

    private class Record(
        val page: Page,
        private var dekValue: ByteArray,
    ) {
        fun copyDekForLease(): ByteArray = dekValue.copyOf()

        fun wipe() {
            Arrays.fill(dekValue, 0)
            dekValue = ByteArray(0)
            page.wipe()
        }
    }

    private data class AcquiredRecord(
        val record: Record,
        val lease: AkenPageLease,
    )

    @Volatile
    private var wiped: Boolean = false

    private val records = LinkedHashMap<String, Record>()
    private val registrationKeys = HashSet<String>()
    private val activeLeases: MutableSet<AkenPageLease> =
        Collections.newSetFromMap(ConcurrentHashMap<AkenPageLease, Boolean>())

    /** Defensive-copy view of the build-only artifact binding. */
    val artifactCanonicalCommitment: ByteArray
        get() {
            requireLive()
            return commitment.copyOf()
        }

    /**
     * Register exactly one page. The kind, logical identity, page index triple
     * is unique within a plan regardless of requested codec/layout names.
     */
    @JvmOverloads
    @Synchronized
    fun registerPage(
        kind: AkenResourceKind,
        identity: ByteArray,
        pageIndex: Int,
        codecVariant: String = "gcm",
        layoutVariant: String = "default",
        targetPageSize: Int? = null,
        encodedHandleOverride: ByteArray? = null,
    ): Page {
        requireLive()
        require(identity.isNotEmpty()) { "AKEN page identity must not be empty" }
        require(pageIndex >= 0) { "AKEN page index must be non-negative" }
        encodedHandleOverride?.let { encodedHandle ->
            require(
                kind == AkenResourceKind.Vbc4Method &&
                    pageIndex == 0 &&
                    encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE,
            ) {
                "AKEN preassigned handle is only valid for a VBC4 page-zero dispatch binding"
            }
        }
        val allowedTargetSizes = pageSizePolicy.allowedSizes(kind)
        targetPageSize?.let { requestedTargetSize ->
            require(requestedTargetSize in allowedTargetSizes) {
                "AKEN requested page target size is unsupported for resource kind"
            }
        }

        val identityCopy = identity.copyOf()
        val registrationKey = registrationKey(kind, identityCopy, pageIndex)
        require(registrationKey !in registrationKeys) {
            "AKEN page identity is already registered for this resource kind and index"
        }

        val canonicalCodec = AkenResourceCodec.normalizeCodecVariant(codecVariant)
        var layout: AkenPageLayout? = null
        var evaluatorPlan: EvaluatorPlan? = null
        var handle: AkenHandle? = null
        var page: Page? = null
        var dek: ByteArray? = null
        var evaluatorShares: Array<ByteArray>? = null
        var artifactCommitmentShares: Array<ByteArray>? = null
        var encodedHandle: ByteArray? = null
        var locator: ByteArray? = null
        var fingerprint: ByteArray? = null
        var success = false

        try {
            layout = AkenPageLayout.create(layoutVariant, random)
            val targetSize = targetPageSize ?: pageSizePolicy.choose(kind, random)
            require(targetSize in allowedTargetSizes) {
                "AKEN selected page target size is unsupported for resource kind"
            }
            // Handles are part of the evaluator-state binding.  Mint them
            // before the first fragment and bind them again into the final
            // graph fingerprint below.
            encodedHandle = encodedHandleOverride?.copyOf()
                ?: ByteArray(AkenHandle.ENCODED_HANDLE_SIZE).also(random::nextBytes)
            locator = ByteArray(AkenHandle.LOCATOR_TOKEN_SIZE).also(random::nextBytes)
            dek = ByteArray(AkenEvaluatorState.STATE_WIDTH).also(random::nextBytes)
            evaluatorShares = AkenEvaluatorState.splitDek(checkNotNull(dek), random)
            artifactCommitmentShares = AkenEvaluatorState.splitArtifactCommitment(artifactCanonicalCommitment, random)
            val javaFragments = randomizeExecution(
                List(JAVA_FRAGMENT_COUNT) { ordinal ->
                    createFragment(
                        ordinal = ordinal,
                        share = checkNotNull(evaluatorShares)[ordinal],
                        artifactCommitmentShare = checkNotNull(artifactCommitmentShares)[ordinal],
                        kind = kind,
                        identity = identityCopy,
                        pageIndex = pageIndex,
                        targetSize = targetSize,
                        codecVariant = canonicalCodec,
                        layoutVariant = layout.variant,
                        encodedHandle = checkNotNull(encodedHandle),
                        locator = checkNotNull(locator),
                    )
                },
            )
            val nativeFragments = randomizeExecution(
                List(NATIVE_FRAGMENT_COUNT) { index ->
                    val ordinal = JAVA_FRAGMENT_COUNT + index
                    createFragment(
                        ordinal = ordinal,
                        share = checkNotNull(evaluatorShares)[ordinal],
                        artifactCommitmentShare = checkNotNull(artifactCommitmentShares)[ordinal],
                        kind = kind,
                        identity = identityCopy,
                        pageIndex = pageIndex,
                        targetSize = targetSize,
                        codecVariant = canonicalCodec,
                        layoutVariant = layout.variant,
                        encodedHandle = checkNotNull(encodedHandle),
                        locator = checkNotNull(locator),
                    )
                },
            )
            val terminal = createFragment(
                ordinal = AKEN_FRAGMENT_COUNT - 1,
                share = checkNotNull(evaluatorShares)[AKEN_FRAGMENT_COUNT - 1],
                artifactCommitmentShare = checkNotNull(artifactCommitmentShares)[AKEN_FRAGMENT_COUNT - 1],
                kind = kind,
                identity = identityCopy,
                pageIndex = pageIndex,
                targetSize = targetSize,
                codecVariant = canonicalCodec,
                layoutVariant = layout.variant,
                encodedHandle = checkNotNull(encodedHandle),
                locator = checkNotNull(locator),
            )
            fingerprint = evaluatorFingerprint(
                kind = kind,
                identity = identityCopy,
                pageIndex = pageIndex,
                targetSize = targetSize,
                codecVariant = canonicalCodec,
                layout = layout,
                encodedHandle = encodedHandle,
                locator = locator,
                javaFragments = javaFragments,
                nativeFragments = nativeFragments,
                terminal = terminal,
            )
            evaluatorPlan = EvaluatorPlan(
                javaFragments = javaFragments,
                nativeFragments = nativeFragments,
                terminal = terminal,
                fingerprint = fingerprint,
            )
            handle = AkenHandle.create(
                resourceKind = kind,
                pageIndex = pageIndex,
                encoded = encodedHandle,
                locatorToken = locator,
                evaluatorFingerprint = fingerprint,
            )
            page = Page(
                handle = handle,
                resourceKind = kind,
                logicalIdentity = identityCopy,
                pageIndex = pageIndex,
                targetSize = targetSize,
                evaluatorPlan = evaluatorPlan,
                codecVariant = canonicalCodec,
                layout = layout,
            )
            val recovered = AkenEvaluatorState.recoverForBuildVerification(
                page = checkNotNull(page),
                expectedArtifactCommitment = artifactCanonicalCommitment,
            )
            try {
                require(MessageDigest.isEqual(recovered, checkNotNull(dek))) {
                    "AKEN evaluator graph does not reconstruct its page-local DEK"
                }
            } finally {
                Arrays.fill(recovered, 0)
            }
            val handleKey = handle.encodedKey()
            require(handleKey !in records) { "AKEN page handle encoding is already registered" }
            records[handleKey] = Record(page, dek)
            registrationKeys += registrationKey
            success = true
            return page
        } finally {
            Arrays.fill(identityCopy, 0)
            encodedHandle?.fill(0)
            locator?.fill(0)
            fingerprint?.fill(0)
            evaluatorShares?.forEach { Arrays.fill(it, 0) }
            artifactCommitmentShares?.forEach { Arrays.fill(it, 0) }
            if (!success) {
                dek?.fill(0)
                page?.wipe() ?: run {
                    evaluatorPlan?.wipe()
                    layout?.wipe()
                    handle?.wipe()
                }
            }
        }
    }

    /**
     * Emit one page-local ciphertext for the materializer. This Kotlin-module
     * bridge is hidden from Java source and never returns a DEK or plaintext.
     */
    @JvmSynthetic
    internal fun encodeForMaterialization(handle: AkenHandle, plain: ByteArray): ByteArray {
        val acquired = acquire(handle)
        return try {
            acquired.lease.withDek { dek ->
                acquired.record.page.withCodecContext { context ->
                    AkenResourceCodec.encode(
                        plain = plain,
                        dek = dek,
                        commitment = commitment,
                        identity = context.identity,
                        pageIndex = acquired.record.page.pageIndex,
                        kind = acquired.record.page.resourceKind,
                        fingerprint = context.fingerprint,
                        codec = context.codecVariant,
                        layout = context.layout,
                        locator = context.locator,
                        random = random,
                    )
                }
            }
        } finally {
            acquired.lease.close()
        }
    }

    /**
     * Build-only AEAD re-authentication for a page that was just emitted.
     *
     * The operation is intentionally boolean-only: it uses the page-local
     * handle and every AAD input held by this plan, wipes the temporary opened
     * plaintext, and exposes neither plaintext nor a generic Java decoder.
     */
    @JvmSynthetic
    internal fun verifyEncodedPayloadForMaterialization(handle: AkenHandle, encoded: ByteArray): Boolean {
        if (wiped) return false
        val acquired = try {
            acquire(handle)
        } catch (_: IllegalStateException) {
            return false
        } catch (_: IllegalArgumentException) {
            return false
        }
        return try {
            acquired.lease.withDek { dek ->
                acquired.record.page.withCodecContext { context ->
                    val opened = AkenResourceCodec.decode(
                        encoded = encoded,
                        dek = dek,
                        commitment = commitment,
                        identity = context.identity,
                        pageIndex = acquired.record.page.pageIndex,
                        kind = acquired.record.page.resourceKind,
                        fingerprint = context.fingerprint,
                        codec = context.codecVariant,
                        layout = context.layout,
                        locator = context.locator,
                    )
                    try {
                        opened != null
                    } finally {
                        opened?.let { Arrays.fill(it, 0) }
                    }
                }
            }
        } catch (_: IllegalStateException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        } finally {
            acquired.lease.close()
        }
    }

    override fun close() {
        val leases: List<AkenPageLease>
        synchronized(this) {
            if (wiped) return
            wiped = true
            leases = activeLeases.toList()
        }

        // Do not retain the plan monitor while waiting for a lease callback.
        // A build callback may query plan metadata and must see fail-closed
        // state rather than deadlock with a concurrent wipe.
        leases.forEach { it.close() }

        synchronized(this) {
            records.values.forEach { it.wipe() }
            records.clear()
            registrationKeys.clear()
            activeLeases.clear()
            Arrays.fill(commitment, 0)
        }
    }

    fun wipe() = close()

    fun isWiped(): Boolean = wiped

    private fun acquire(handle: AkenHandle): AcquiredRecord = synchronized(this) {
        requireLive()
        val record = records[handle.encodedKey()]
            ?: throw IllegalArgumentException("unknown AKEN page handle")
        val lease = AkenPageLease(record.copyDekForLease()) { released -> activeLeases.remove(released) }
        activeLeases += lease
        AcquiredRecord(record, lease)
    }

    private fun requireLive() {
        check(!wiped) { "AKEN build plan has been wiped" }
    }

    private fun createFragment(
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
    ): EvaluatorFragment = AkenEvaluatorState.createFragment(
        random = random,
        ordinal = ordinal,
        share = share,
        artifactCommitmentShare = artifactCommitmentShare,
        kind = kind,
        identity = identity,
        pageIndex = pageIndex,
        targetSize = targetSize,
        codecVariant = codecVariant,
        layoutVariant = layoutVariant,
        encodedHandle = encodedHandle,
        locator = locator,
    )

    private fun <T> randomizeExecution(values: List<T>): List<T> {
        val shuffled = values.toMutableList()
        for (index in shuffled.lastIndex downTo 1) {
            val other = random.nextInt(index + 1)
            val temporary = shuffled[index]
            shuffled[index] = shuffled[other]
            shuffled[other] = temporary
        }
        return shuffled
    }

    private fun evaluatorFingerprint(
        kind: AkenResourceKind,
        identity: ByteArray,
        pageIndex: Int,
        targetSize: Int,
        codecVariant: String,
        layout: AkenPageLayout,
        encodedHandle: ByteArray,
        locator: ByteArray,
        javaFragments: List<EvaluatorFragment>,
        nativeFragments: List<EvaluatorFragment>,
        terminal: EvaluatorFragment,
    ): ByteArray {
        var codecBytes: ByteArray? = null
        var layoutBytes: ByteArray? = null
        try {
            codecBytes = codecVariant.toByteArray(StandardCharsets.UTF_8)
            layoutBytes = layout.variant.toByteArray(StandardCharsets.UTF_8)
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(EVALUATOR_DOMAIN)
            digest.update(kind.id.toByte())
            updateFramed(digest, identity)
            updateInt(digest, pageIndex)
            updateInt(digest, targetSize)
            updateFramed(digest, codecBytes)
            updateFramed(digest, layoutBytes)
            updateFramed(digest, encodedHandle)
            updateFramed(digest, locator)
            updateFragments(digest, FRAGMENT_ROLE_JAVA, javaFragments)
            updateFragments(digest, FRAGMENT_ROLE_NATIVE, nativeFragments)
            updateFragments(digest, FRAGMENT_ROLE_TERMINAL, listOf(terminal))
            return digest.digest()
        } finally {
            codecBytes?.fill(0)
            layoutBytes?.fill(0)
        }
    }

    private fun updateFragments(
        digest: MessageDigest,
        role: Byte,
        fragments: List<EvaluatorFragment>,
    ) {
        updateInt(digest, fragments.size)
        fragments.forEachIndexed { executionIndex, fragment ->
            val shape = fragment.shape
            val callToken = fragment.callToken
            val tablePermutation = fragment.tablePermutation
            try {
                digest.update(role)
                updateInt(digest, executionIndex)
                updateInt(digest, fragment.ordinal)
                updateInt(digest, fragment.family)
                updateFramed(digest, shape)
                updateInt(digest, tablePermutation.size)
                tablePermutation.forEach { updateInt(digest, it) }
                updateFramed(digest, callToken)
            } finally {
                Arrays.fill(shape, 0)
                Arrays.fill(callToken, 0)
                Arrays.fill(tablePermutation, 0)
            }
        }
    }

    private fun registrationKey(kind: AkenResourceKind, identity: ByteArray, pageIndex: Int): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(REGISTRATION_DOMAIN)
        digest.update(kind.id.toByte())
        updateFramed(digest, identity)
        updateInt(digest, pageIndex)
        val value = digest.digest()
        return try {
            Base64.getUrlEncoder().withoutPadding().encodeToString(value)
        } finally {
            Arrays.fill(value, 0)
        }
    }

    private fun updateFramed(digest: MessageDigest, value: ByteArray) {
        updateInt(digest, value.size)
        digest.update(value)
    }

    private fun updateInt(digest: MessageDigest, value: Int) {
        digest.update((value ushr 24).toByte())
        digest.update((value ushr 16).toByte())
        digest.update((value ushr 8).toByte())
        digest.update(value.toByte())
    }

    companion object {
        private const val JAVA_FRAGMENT_COUNT = 3
        private const val NATIVE_FRAGMENT_COUNT = 3
        private const val AKEN_FRAGMENT_COUNT = JAVA_FRAGMENT_COUNT + NATIVE_FRAGMENT_COUNT + 1
        private const val AKEN_TRANSFORM_FAMILY_COUNT = 16
        private const val FRAGMENT_ROLE_JAVA: Byte = 1
        private const val FRAGMENT_ROLE_NATIVE: Byte = 2
        private const val FRAGMENT_ROLE_TERMINAL: Byte = 3
        private val EVALUATOR_DOMAIN = "AKEN-v4-evaluator-graph".toByteArray(StandardCharsets.US_ASCII)
        private val REGISTRATION_DOMAIN = "AKEN-v4-registration".toByteArray(StandardCharsets.US_ASCII)

        fun create(
            commitment: ByteArray,
            random: SecureRandom = SecureRandom(),
            pageSizePolicy: AkenPageSizePolicy = AkenPageSizePolicy.DEFAULT,
        ): AkenBuildPlan {
            require(commitment.size == 32) { "AKEN artifact commitment must be 32 bytes" }
            return AkenBuildPlan(
                commitment = commitment.copyOf(),
                random = random,
                pageSizePolicy = pageSizePolicy,
            )
        }
    }
}
