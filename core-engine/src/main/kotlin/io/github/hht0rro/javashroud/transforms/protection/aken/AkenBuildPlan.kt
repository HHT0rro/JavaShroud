package io.github.hht0rro.javashroud.transforms.protection.aken

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
 * Every registered high-value page receives independent random page material,
 * an independent physical frame, and an artifact-specific opaque VBC4
 * evaluator. The evaluator's randomized dialect, fragments, bindings, and
 * authenticated terminal schedule never expose a raw or contiguous page key.
 * This object deliberately provides no page enumeration, raw-key export, or
 * Java-visible generic decoder. Materialization can only emit a
 * page-local ciphertext or perform a boolean AEAD binding check whose transient
 * plaintext is zeroed before control returns.
 */
class AkenBuildPlan private constructor(
    private val commitment: ByteArray,
    private val random: SecureRandom,
    val pageSizePolicy: AkenPageSizePolicy,
) : AutoCloseable {

    /** Current-format VBC4 evaluator plan for exactly one page. */
    class EvaluatorPlan internal constructor(
        fingerprint: ByteArray,
        boundDecryptorCore: AkenBoundDecryptorCore,
    ) {
        private var fingerprintValue: ByteArray = fingerprint.copyOf()
        private var boundDecryptorCoreValue: AkenBoundDecryptorCore? = boundDecryptorCore

        @Volatile
        private var wiped: Boolean = false

        init {
            require(fingerprintValue.size == AkenHandle.FINGERPRINT_SIZE) {
                "AKEN evaluator fingerprint has an invalid length"
            }
        }

        val fingerprint: ByteArray
            get() {
                requireLive()
                return fingerprintValue.copyOf()
            }

        internal fun copyFingerprintForBuild(): ByteArray {
            requireLive()
            return fingerprintValue.copyOf()
        }

        /** Page-local nonce is owned by the bound VBC4 terminal seed. */
        internal fun copyPageNonceForCodec(): ByteArray {
            requireLive()
            return (boundDecryptorCoreValue
                ?: error("AKEN bound decryptor core has been wiped"))
                .copyPageNonceForCodec()
        }

        /** Finalize one typed native descriptor after route/proof materialization. */
        internal fun boundPlanForRuntime(
            route: AkenRoutingMetadata,
            callSiteProof: ByteArray,
        ): AkenBoundDecryptorPlan {
            requireLive()
            return (boundDecryptorCoreValue
                ?: error("AKEN bound decryptor core has been wiped"))
                .finalizeForRuntime(route, callSiteProof)
        }

        internal fun wipe() {
            if (wiped) return
            boundDecryptorCoreValue?.wipe()
            boundDecryptorCoreValue = null
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
            val evaluator = evaluatorPlanValue ?: error("AKEN page evaluator has been wiped")
            val context = PageCodecContext(
                identity = logicalIdentityValue.copyOf(),
                fingerprint = evaluator.copyFingerprintForBuild(),
                locator = (handleValue ?: error("AKEN page handle has been wiped")).copyLocatorTokenForBuild(),
                pageNonce = evaluator.copyPageNonceForCodec(),
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
        val pageNonce: ByteArray,
        val codecVariant: String,
        val layout: AkenPageLayout,
    ) : AutoCloseable {
        override fun close() {
            Arrays.fill(identity, 0)
            Arrays.fill(fingerprint, 0)
            Arrays.fill(locator, 0)
            Arrays.fill(pageNonce, 0)
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
            require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) {
                "AKEN preassigned handle size is invalid"
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
        var encodedHandle: ByteArray? = null
        var locator: ByteArray? = null
        var pageNonce: ByteArray? = null
        var fingerprint: ByteArray? = null
        var boundDecryptorCore: AkenBoundDecryptorCore? = null
        var success = false

        try {
            layout = AkenPageLayout.create(layoutVariant, random)
            val targetSize = targetPageSize ?: pageSizePolicy.choose(kind, random)
            require(targetSize in allowedTargetSizes) {
                "AKEN selected page target size is unsupported for resource kind"
            }

            // The handle, locator and evaluator fingerprint are page-local
            // binding inputs.  VBC4 compile creates the opaque randomized
            // fragment program and authenticates the complete page material.
            encodedHandle = encodedHandleOverride?.copyOf()
                ?: ByteArray(AkenHandle.ENCODED_HANDLE_SIZE).also(random::nextBytes)
            locator = ByteArray(AkenHandle.LOCATOR_TOKEN_SIZE).also(random::nextBytes)
            pageNonce = ByteArray(AkenResourceCodec.NONCE_SIZE).also(random::nextBytes)
            fingerprint = ByteArray(AkenHandle.FINGERPRINT_SIZE).also(random::nextBytes)

            boundDecryptorCore = AkenBoundDecryptorCore.compile(
                resourceKind = kind,
                logicalIdentity = identityCopy,
                pageIndex = pageIndex,
                targetPageSize = targetSize,
                codecVariant = canonicalCodec,
                layoutVariant = layout.variant,
                encodedHandle = checkNotNull(encodedHandle),
                locatorToken = checkNotNull(locator),
                evaluatorFingerprint = checkNotNull(fingerprint),
                artifactCanonicalCommitment = commitment,
                pageNonce = checkNotNull(pageNonce),
                random = random,
            )
            dek = checkNotNull(boundDecryptorCore).copyPageMaterialForBuild()
            evaluatorPlan = EvaluatorPlan(
                fingerprint = checkNotNull(fingerprint),
                boundDecryptorCore = checkNotNull(boundDecryptorCore),
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
            pageNonce?.fill(0)
            fingerprint?.fill(0)
            if (!success) {
                dek?.fill(0)
                page?.wipe() ?: run {
                    evaluatorPlan?.wipe() ?: boundDecryptorCore?.wipe()
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
                        nonceOverride = context.pageNonce,
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
        private val REGISTRATION_DOMAIN = "AKEN-v4-registration".toByteArray(Charsets.US_ASCII)

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
