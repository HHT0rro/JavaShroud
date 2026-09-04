package io.github.hht0rro.javashroud.transforms.protection.qp

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import kotlin.jvm.JvmSynthetic

/**
 * Build-only Qp current format planner.
 *
 * Every registered high-value page receives one native secret-pack slot, one
 * independent physical frame, and a page key derived from structured binary
 * inputs. The slot seed is owned by the build's [NativeVmSecretPackDraft]; it
 * is emitted only into the artifact-specific native specialization and never
 * serialized into a descriptor, catalog, or resource. This object deliberately
 * provides no page enumeration, raw-key export, or Java-visible generic
 * decoder. Materialization can only emit a page-local ciphertext or perform a
 * boolean AEAD binding check whose transient plaintext is zeroed before
 * control returns.
 */
class QpBuildPlan private constructor(
    private val commitment: ByteArray,
    internal val secretPack: NativeVmSecretPackDraft,
    private val random: SecureRandom,
    val pageSizePolicy: QpPageSizePolicy,
) : AutoCloseable {

    /** Immutable-view metadata for one high-value page. */
    class Page internal constructor(
        handle: QpHandle,
        resourceKind: QpResourceKind,
        logicalIdentity: ByteArray,
        pageIndex: Int,
        targetSize: Int,
        secretSlot: Int,
        keyCommitment: ByteArray,
        pageNonce: ByteArray,
        codecVariant: String,
        layout: QpPageLayout,
    ) {
        private var handleValue: QpHandle? = handle
        private val resourceKindValue: QpResourceKind = resourceKind
        private var logicalIdentityValue: ByteArray = logicalIdentity.copyOf()
        private val pageIndexValue: Int = pageIndex
        private val targetSizeValue: Int = targetSize
        private val secretSlotValue: Int = secretSlot
        private var keyCommitmentValue: ByteArray = keyCommitment.copyOf()
        private var pageNonceValue: ByteArray = pageNonce.copyOf()
        private val codecVariantValue: String = codecVariant
        private var layoutValue: QpPageLayout? = layout

        @Volatile
        private var wiped: Boolean = false

        val handle: QpHandle
            get() {
                requireLive()
                return handleValue ?: error("Qp page handle has been wiped")
            }

        val resourceKind: QpResourceKind
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

        /** Native secret-pack slot that owns this page's key derivation material. */
        val secretSlot: Int
            get() {
                requireLive()
                return secretSlotValue
            }

        val codecVariant: String
            get() {
                requireLive()
                return codecVariantValue
            }

        /** Authenticated build-specific frame descriptor for sealing/runtime emitters. */
        val pageLayout: QpPageLayout
            get() {
                requireLive()
                return (layoutValue ?: error("Qp page layout has been wiped")).copyForBuild()
            }

        /** Canonical descriptor for [pageLayout], not a caller-provided decorative label. */
        val layoutVariant: String
            get() {
                requireLive()
                return (layoutValue ?: error("Qp page layout has been wiped")).variant
            }

        internal fun <T> withCodecContext(block: (PageCodecContext) -> T): T {
            requireLive()
            val context = PageCodecContext(
                identity = logicalIdentityValue.copyOf(),
                keyCommitment = keyCommitmentValue.copyOf(),
                locator = (handleValue ?: error("Qp page handle has been wiped")).copyLocatorTokenForBuild(),
                pageNonce = pageNonceValue.copyOf(),
                codecVariant = codecVariantValue,
                layout = (layoutValue ?: error("Qp page layout has been wiped")).copyForBuild(),
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
            Arrays.fill(keyCommitmentValue, 0)
            keyCommitmentValue = ByteArray(0)
            Arrays.fill(pageNonceValue, 0)
            pageNonceValue = ByteArray(0)
            layoutValue?.wipe()
            layoutValue = null
            handleValue?.wipe()
            handleValue = null
            wiped = true
        }

        private fun requireLive() {
            check(!wiped) { "Qp page has been wiped" }
        }
    }

    /**
     * A short build-only DEK window. It is private to the planner so raw key
     * material cannot become a Java/runtime API. [withDek] copies the leased
     * material for a planner callback and zeroes that callback copy before it
     * returns.
     */
    private class QpPageLease(
        dek: ByteArray,
        private var releaseCallback: ((QpPageLease) -> Unit)?,
    ) : AutoCloseable {
        private var dekValue: ByteArray? = dek.copyOf()

        @Volatile
        private var closed: Boolean = false

        fun <T> withDek(block: (ByteArray) -> T): T = synchronized(this) {
            check(!closed) { "Qp page lease is closed" }
            val source = dekValue ?: error("Qp page lease has no key material")
            val callbackCopy = source.copyOf()
            try {
                block(callbackCopy)
            } finally {
                Arrays.fill(callbackCopy, 0)
            }
        }

        override fun close() {
            val callback: ((QpPageLease) -> Unit)?
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
        val keyCommitment: ByteArray,
        val locator: ByteArray,
        val pageNonce: ByteArray,
        val codecVariant: String,
        val layout: QpPageLayout,
    ) : AutoCloseable {
        override fun close() {
            Arrays.fill(identity, 0)
            Arrays.fill(keyCommitment, 0)
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
        val lease: QpPageLease,
    )

    @Volatile
    private var wiped: Boolean = false

    private val records = LinkedHashMap<String, Record>()
    private val registrationKeys = HashSet<String>()
    private val activeLeases: MutableSet<QpPageLease> =
        Collections.newSetFromMap(ConcurrentHashMap<QpPageLease, Boolean>())

    /** Defensive-copy view of the build-only artifact binding. */
    val artifactCanonicalCommitment: ByteArray
        get() {
            requireLive()
            return commitment.copyOf()
        }

    @JvmOverloads
    @Synchronized
    fun registerPage(
        kind: QpResourceKind,
        identity: ByteArray,
        pageIndex: Int,
        codecVariant: String = "gcm",
        layoutVariant: String = "default",
        targetPageSize: Int? = null,
        encodedHandleOverride: ByteArray? = null,
    ): Page {
        requireLive()
        require(identity.isNotEmpty()) { "Qp page identity must not be empty" }
        require(pageIndex >= 0) { "Qp page index must be non-negative" }
        encodedHandleOverride?.let { encodedHandle ->
            require(encodedHandle.size == QpHandle.ENCODED_HANDLE_SIZE) {
                "Qp preassigned handle size is invalid"
            }
        }
        val allowedTargetSizes = pageSizePolicy.allowedSizes(kind)
        targetPageSize?.let { requestedTargetSize ->
            require(requestedTargetSize in allowedTargetSizes) {
                "Qp requested page target size is unsupported for resource kind"
            }
        }

        val identityCopy = identity.copyOf()
        val registrationKey = registrationKey(kind, identityCopy, pageIndex)
        require(registrationKey !in registrationKeys) {
            "Qp page identity is already registered for this resource kind and index"
        }

        val canonicalCodec = QpPageCodec.normalizeCodecVariant(codecVariant)
        var layout: QpPageLayout? = null
        var handle: QpHandle? = null
        var page: Page? = null
        var dek: ByteArray? = null
        var encodedHandle: ByteArray? = null
        var locator: ByteArray? = null
        var pageNonce: ByteArray? = null
        var keyCommitment: ByteArray? = null
        var success = false

        try {
            layout = QpPageLayout.create(layoutVariant, random)
            val targetSize = targetPageSize ?: pageSizePolicy.choose(kind, random)
            require(targetSize in allowedTargetSizes) {
                "Qp selected page target size is unsupported for resource kind"
            }

            // The handle, locator and page nonce are page-local binding inputs
            // of the structured key derivation. The secret slot owns the only
            // derivation seed; it lives in the artifact's native specialization.
            encodedHandle = encodedHandleOverride?.copyOf()
                ?: ByteArray(QpHandle.ENCODED_HANDLE_SIZE).also(random::nextBytes)
            locator = ByteArray(QpHandle.LOCATOR_TOKEN_SIZE).also(random::nextBytes)
            pageNonce = ByteArray(QpPageCodec.NONCE_SIZE).also(random::nextBytes)
            val secretSlot = secretPack.registerSlot()
            dek = secretPack.pageKey(
                slotId = secretSlot,
                resourceKind = kind,
                pageIndex = pageIndex,
                encodedHandle = checkNotNull(encodedHandle),
                locatorToken = checkNotNull(locator),
                pageNonce = checkNotNull(pageNonce),
                preNativeCommitment = commitment,
            )
            keyCommitment = secretPack.keyCommitment(secretSlot, checkNotNull(dek))
            handle = QpHandle.create(
                resourceKind = kind,
                pageIndex = pageIndex,
                encoded = encodedHandle,
                locatorToken = locator,
                keyCommitmentFingerprint = keyCommitment,
            )
            page = Page(
                handle = handle,
                resourceKind = kind,
                logicalIdentity = identityCopy,
                pageIndex = pageIndex,
                targetSize = targetSize,
                secretSlot = secretSlot,
                keyCommitment = checkNotNull(keyCommitment),
                pageNonce = checkNotNull(pageNonce),
                codecVariant = canonicalCodec,
                layout = layout,
            )
            // The page now owns the only nonce copy.
            pageNonce = null
            val handleKey = handle.encodedKey()
            require(handleKey !in records) { "Qp page handle encoding is already registered" }
            records[handleKey] = Record(page, checkNotNull(dek))
            registrationKeys += registrationKey
            success = true
            return page
        } finally {
            Arrays.fill(identityCopy, 0)
            encodedHandle?.fill(0)
            locator?.fill(0)
            pageNonce?.fill(0)
            if (!success) {
                dek?.fill(0)
                keyCommitment?.fill(0)
                page?.wipe() ?: run {
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
    internal fun encodeForMaterialization(handle: QpHandle, plain: ByteArray): ByteArray {
        val acquired = acquire(handle)
        return try {
            acquired.lease.withDek { dek ->
                acquired.record.page.withCodecContext { context ->
                    QpPageCodec.encode(
                        plain = plain,
                        dek = dek,
                        commitment = commitment,
                        identity = context.identity,
                        pageIndex = acquired.record.page.pageIndex,
                        kind = acquired.record.page.resourceKind,
                        fingerprint = context.keyCommitment,
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
    internal fun verifyEncodedPayloadForMaterialization(handle: QpHandle, encoded: ByteArray): Boolean {
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
                    val opened = QpPageCodec.decode(
                        encoded = encoded,
                        dek = dek,
                        commitment = commitment,
                        identity = context.identity,
                        pageIndex = acquired.record.page.pageIndex,
                        kind = acquired.record.page.resourceKind,
                        fingerprint = context.keyCommitment,
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
        val leases: List<QpPageLease>
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

    private fun acquire(handle: QpHandle): AcquiredRecord = synchronized(this) {
        requireLive()
        val record = records[handle.encodedKey()]
            ?: throw IllegalArgumentException("unknown Qp page handle")
        val lease = QpPageLease(record.copyDekForLease()) { released -> activeLeases.remove(released) }
        activeLeases += lease
        AcquiredRecord(record, lease)
    }

    private fun requireLive() {
        check(!wiped) { "Qp build plan has been wiped" }
    }

    private fun registrationKey(kind: QpResourceKind, identity: ByteArray, pageIndex: Int): String {
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
        digest.update((value and 0xFF).toByte())
    }

    companion object {
        private val REGISTRATION_DOMAIN = "javashroud-qp-registration-v1".toByteArray(Charsets.US_ASCII)

        internal fun create(
            commitment: ByteArray,
            secretPack: NativeVmSecretPackDraft,
            random: SecureRandom = SecureRandom(),
            pageSizePolicy: QpPageSizePolicy = QpPageSizePolicy.DEFAULT,
        ): QpBuildPlan {
            require(commitment.size == 32) { "Qp artifact commitment must be 32 bytes" }
            return QpBuildPlan(
                commitment = commitment.copyOf(),
                secretPack = secretPack,
                random = random,
                pageSizePolicy = pageSizePolicy,
            )
        }
    }
}
