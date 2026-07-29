package io.github.hht0rro.javashroud.transforms.protection

import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.IdentityHashMap
import java.util.Locale

/**
 * Build-only authority for max-protection key material.
 *
 * Identity requests are collected before any leaf can be borrowed. Freezing
 * binds the random build secret to the complete, canonically sorted inventory.
 */
internal class MaxBuildSecurityPlan private constructor(
    private val buildIdentity: ByteArray,
    entropySource: MaxEntropySource,
) : AutoCloseable {
    internal enum class Lifecycle {
        COLLECTING,
        FROZEN,
        CLOSING,
        CLOSED,
    }

    internal data class InventoryCounts(
        val targets: Int,
        val partitions: Int,
        val methods: Int,
        val profiles: Int,
        val pages: Int,
    )

    @Suppress("PLATFORM_CLASS_MAPPED_TO_KOTLIN")
    private val lock = java.lang.Object()
    private val identities = LinkedHashMap<IdentityKey, IdentityRecord>()
    private val borrowDepths = IdentityHashMap<Thread, Int>()
    private var activeBorrows = 0

    @Volatile
    private var lifecycleState = Lifecycle.COLLECTING
    private var derivationSecret = ByteArray(LEAF_SIZE).also(entropySource::fill)
    private var frozenPlanDigest = ByteArray(0)

    internal val lifecycle: Lifecycle
        get() = lifecycleState

    internal fun requestTarget(
        targetId: String,
        operatingSystem: String,
        architecture: String,
        abi: String,
    ) {
        val id = checkedTextField(targetId, "targetId")
        registerIdentity(
            purpose = LeafPurpose.TARGET,
            slotFields = listOf(id),
            identityFields = listOf(
                id,
                checkedTextField(operatingSystem, "operatingSystem", foldCase = true),
                checkedTextField(architecture, "architecture", foldCase = true),
                checkedTextField(abi, "abi", foldCase = true),
            ),
        )
    }

    internal fun requestPartition(targetId: String, partitionId: Int, partitionDigest: ByteArray) {
        val target = checkedTextField(targetId, "targetId")
        val partition = checkedIntField(partitionId, "partitionId")
        registerIdentity(
            purpose = LeafPurpose.PARTITION,
            slotFields = listOf(target, partition),
            identityFields = listOf(target, partition, checkedDigestField(partitionDigest, "partitionDigest")),
            parentSlots = listOf(slot(LeafPurpose.TARGET, target)),
        )
    }

    internal fun requestMethod(
        targetId: String,
        partitionId: Int,
        methodId: Long,
        semanticDigest: ByteArray,
        bytecodeDigest: ByteArray,
        contextDigest: ByteArray,
    ) {
        val target = checkedTextField(targetId, "targetId")
        val partition = checkedIntField(partitionId, "partitionId")
        val method = checkedLongField(methodId, "methodId")
        registerIdentity(
            purpose = LeafPurpose.METHOD,
            slotFields = listOf(target, partition, method),
            identityFields = listOf(
                target,
                partition,
                method,
                checkedDigestField(semanticDigest, "semanticDigest"),
                checkedDigestField(bytecodeDigest, "bytecodeDigest"),
                checkedDigestField(contextDigest, "contextDigest"),
            ),
            parentSlots = listOf(slot(LeafPurpose.PARTITION, target, partition)),
        )
    }

    internal fun requestProfile(targetId: String, profileId: Int, profileDigest: ByteArray) {
        val target = checkedTextField(targetId, "targetId")
        val profile = checkedIntField(profileId, "profileId")
        registerIdentity(
            purpose = LeafPurpose.PROFILE,
            slotFields = listOf(target, profile),
            identityFields = listOf(target, profile, checkedDigestField(profileDigest, "profileDigest")),
            parentSlots = listOf(slot(LeafPurpose.TARGET, target)),
        )
    }

    internal fun requestPage(
        targetId: String,
        profileId: Int,
        sectionId: Int,
        pageOrdinal: Int,
        pageDigest: ByteArray,
    ) {
        val target = checkedTextField(targetId, "targetId")
        val profile = checkedIntField(profileId, "profileId")
        val section = checkedIntField(sectionId, "sectionId")
        val page = checkedIntField(pageOrdinal, "pageOrdinal")
        registerIdentity(
            purpose = LeafPurpose.PAGE,
            slotFields = listOf(target, profile, section, page),
            identityFields = listOf(target, profile, section, page, checkedDigestField(pageDigest, "pageDigest")),
            parentSlots = listOf(slot(LeafPurpose.PROFILE, target, profile)),
        )
    }

    internal fun freeze(expectedInventory: InventoryCounts) {
        synchronized(lock) {
            ensureLifecycle(Lifecycle.COLLECTING)
            try {
                validateInventoryLocked(expectedInventory)
                freezeLocked(identities.values.map(IdentityRecord::canonicalIdentity))
            } catch (failure: Throwable) {
                beginClosingLocked()
                throw failure
            }
        }
    }

    /**
     * Freeze the build authority before target inventory exists. This narrow
     * path is used by [Vbc4BuildContext] creation: it mints the production
     * build root without pretending that the later target/method hierarchy has
     * already been collected.
     */
    private fun freezeBuildDomain() {
        synchronized(lock) {
            ensureLifecycle(Lifecycle.COLLECTING)
            try {
                if (identities.isNotEmpty()) {
                    failClosedLocked("Max security build-domain freeze requires an empty target inventory")
                }
                freezeLocked(emptyList())
            } catch (failure: Throwable) {
                beginClosingLocked()
                throw failure
            }
        }
    }

    internal fun <T> withBuildLeaf(block: (ByteArray) -> T): T =
        withCanonicalLeaf(LeafPurpose.BUILD, buildIdentity, block)

    internal fun <T> withTargetLeaf(targetId: String, block: (ByteArray) -> T): T =
        withRegisteredLeaf(slot(LeafPurpose.TARGET, checkedTextField(targetId, "targetId")), block)

    internal fun <T> withPartitionLeaf(
        targetId: String,
        partitionId: Int,
        block: (ByteArray) -> T,
    ): T = withRegisteredLeaf(
        slot(
            LeafPurpose.PARTITION,
            checkedTextField(targetId, "targetId"),
            checkedIntField(partitionId, "partitionId"),
        ),
        block,
    )

    internal fun <T> withMethodLeaf(
        targetId: String,
        partitionId: Int,
        methodId: Long,
        block: (ByteArray) -> T,
    ): T = withRegisteredLeaf(
        slot(
            LeafPurpose.METHOD,
            checkedTextField(targetId, "targetId"),
            checkedIntField(partitionId, "partitionId"),
            checkedLongField(methodId, "methodId"),
        ),
        block,
    )

    internal fun <T> withProfileLeaf(
        targetId: String,
        profileId: Int,
        block: (ByteArray) -> T,
    ): T = withRegisteredLeaf(
        slot(
            LeafPurpose.PROFILE,
            checkedTextField(targetId, "targetId"),
            checkedIntField(profileId, "profileId"),
        ),
        block,
    )

    internal fun <T> withPageLeaf(
        targetId: String,
        profileId: Int,
        sectionId: Int,
        pageOrdinal: Int,
        block: (ByteArray) -> T,
    ): T = withRegisteredLeaf(
        slot(
            LeafPurpose.PAGE,
            checkedTextField(targetId, "targetId"),
            checkedIntField(profileId, "profileId"),
            checkedIntField(sectionId, "sectionId"),
            checkedIntField(pageOrdinal, "pageOrdinal"),
        ),
        block,
    )

    override fun close() {
        synchronized(lock) {
            check((borrowDepths[Thread.currentThread()] ?: 0) == 0) {
                "Max security plan cannot close from inside a leaf borrow"
            }
            beginClosingLocked()
            var interrupted = false
            while (activeBorrows != 0) {
                try {
                    lock.wait()
                } catch (_: InterruptedException) {
                    interrupted = true
                }
            }
            completeCloseLocked()
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    private fun registerIdentity(
        purpose: LeafPurpose,
        slotFields: List<CanonicalField>,
        identityFields: List<CanonicalField>,
        parentSlots: List<ByteArray> = emptyList(),
    ) {
        val slotBytes = canonicalIdentity(purpose, slotFields)
        val canonical = canonicalIdentity(purpose, identityFields)
        val key = IdentityKey(slotBytes)
        val parentKeys = parentSlots.map(::IdentityKey)
        var installed = false
        try {
            synchronized(lock) {
                ensureLifecycle(Lifecycle.COLLECTING)
                val existing = identities[key]
                if (existing != null) {
                    val failureKind = if (existing.canonicalIdentity.contentEquals(canonical)) "duplicate" else "conflicting"
                    failClosedLocked("Max security plan rejected a $failureKind ${purpose.description} identity")
                }
                identities[key] = IdentityRecord(
                    purpose = purpose,
                    canonicalIdentity = canonical,
                    parentSlots = parentKeys,
                )
                installed = true
            }
        } catch (failure: Throwable) {
            synchronized(lock) { beginClosingLocked() }
            throw failure
        } finally {
            slotBytes.fill(0)
            parentSlots.forEach { it.fill(0) }
            slotFields.forEach { it.bytes.fill(0) }
            identityFields.forEach { it.bytes.fill(0) }
            if (!installed) {
                canonical.fill(0)
                key.wipe()
                parentKeys.forEach(IdentityKey::wipe)
            }
        }
    }

    private fun <T> withRegisteredLeaf(slotBytes: ByteArray, block: (ByteArray) -> T): T {
        val lookupKey = IdentityKey(slotBytes)
        val canonical = try {
            synchronized(lock) {
                ensureLifecycle(Lifecycle.FROZEN)
                identities[lookupKey]?.canonicalIdentity
                    ?: failClosedLocked("Max security plan leaf was not registered")
            }
        } finally {
            lookupKey.wipe()
            slotBytes.fill(0)
        }
        return withCanonicalLeaf(canonicalPurpose(canonical), canonical, block)
    }

    private fun <T> withCanonicalLeaf(
        purpose: LeafPurpose,
        canonicalIdentity: ByteArray,
        block: (ByteArray) -> T,
    ): T {
        val borrowingThread = Thread.currentThread()
        val borrowed = synchronized(lock) {
            ensureLifecycle(Lifecycle.FROZEN)
            val message = fixedKdfMessage(LEAF_STAGE + purpose.code, frozenPlanDigest, canonicalIdentity)
            try {
                hmacSha256(derivationSecret, message).also {
                    activeBorrows++
                    borrowDepths[borrowingThread] = (borrowDepths[borrowingThread] ?: 0) + 1
                }
            } finally {
                message.fill(0)
            }
        }
        return try {
            block(borrowed)
        } finally {
            borrowed.fill(0)
            synchronized(lock) {
                activeBorrows--
                val remainingDepth = (borrowDepths[borrowingThread] ?: 1) - 1
                if (remainingDepth == 0) borrowDepths.remove(borrowingThread)
                else borrowDepths[borrowingThread] = remainingDepth
                if (activeBorrows == 0 && lifecycleState == Lifecycle.CLOSING) completeCloseLocked()
                lock.notifyAll()
            }
        }
    }

    private fun beginClosingLocked() {
        if (lifecycleState == Lifecycle.CLOSING || lifecycleState == Lifecycle.CLOSED) return
        derivationSecret.fill(0)
        frozenPlanDigest.fill(0)
        buildIdentity.fill(0)
        identities.forEach { (key, record) ->
            key.wipe()
            record.canonicalIdentity.fill(0)
            record.parentSlots.forEach(IdentityKey::wipe)
        }
        identities.clear()
        lifecycleState = if (activeBorrows == 0) Lifecycle.CLOSED else Lifecycle.CLOSING
    }

    private fun completeCloseLocked() {
        if (activeBorrows != 0 || lifecycleState == Lifecycle.CLOSED) return
        derivationSecret = ByteArray(0)
        frozenPlanDigest = ByteArray(0)
        lifecycleState = Lifecycle.CLOSED
    }

    private fun failClosedLocked(message: String): Nothing {
        beginClosingLocked()
        throw IllegalArgumentException(message)
    }

    private fun freezeLocked(canonicalIdentities: List<ByteArray>) {
        val digest = MessageDigest.getInstance(SHA_256)
        updateFramed(digest, buildIdentity)
        canonicalIdentities
            .sortedWith(UNSIGNED_BYTE_ARRAY_COMPARATOR)
            .forEach { updateFramed(digest, it) }
        val planDigest = digest.digest()
        val freezeMessage = fixedKdfMessage(FREEZE_STAGE, buildIdentity, planDigest)
        val frozenSecret = try {
            hmacSha256(derivationSecret, freezeMessage)
        } finally {
            freezeMessage.fill(0)
        }

        derivationSecret.fill(0)
        derivationSecret = frozenSecret
        frozenPlanDigest = planDigest
        lifecycleState = Lifecycle.FROZEN
    }

    private fun validateInventoryLocked(expected: InventoryCounts) {
        val expectedValues = listOf(
            expected.targets,
            expected.partitions,
            expected.methods,
            expected.profiles,
            expected.pages,
        )
        if (expectedValues.any { it <= 0 }) {
            failClosedLocked("Max security plan requires positive expected inventory counts")
        }
        val actual = InventoryCounts(
            targets = identities.values.count { it.purpose == LeafPurpose.TARGET },
            partitions = identities.values.count { it.purpose == LeafPurpose.PARTITION },
            methods = identities.values.count { it.purpose == LeafPurpose.METHOD },
            profiles = identities.values.count { it.purpose == LeafPurpose.PROFILE },
            pages = identities.values.count { it.purpose == LeafPurpose.PAGE },
        )
        if (actual != expected) {
            failClosedLocked("Max security plan inventory mismatch: expected=$expected actual=$actual")
        }
        for (record in identities.values) {
            if (record.parentSlots.any { it !in identities }) {
                failClosedLocked("Max security plan contains an identity with an unregistered parent")
            }
        }

        val childrenByParent = HashMap<IdentityKey, MutableSet<LeafPurpose>>()
        for (record in identities.values) {
            for (parent in record.parentSlots) {
                childrenByParent.getOrPut(parent, ::mutableSetOf).add(record.purpose)
            }
        }
        for ((slotKey, record) in identities) {
            val childPurposes = childrenByParent[slotKey].orEmpty()
            val complete = when (record.purpose) {
                LeafPurpose.TARGET -> LeafPurpose.PARTITION in childPurposes && LeafPurpose.PROFILE in childPurposes
                LeafPurpose.PARTITION -> LeafPurpose.METHOD in childPurposes
                LeafPurpose.PROFILE -> LeafPurpose.PAGE in childPurposes
                LeafPurpose.METHOD, LeafPurpose.PAGE -> true
                LeafPurpose.BUILD -> false
            }
            if (!complete) {
                failClosedLocked("Max security plan inventory has an incomplete ${record.purpose.description} subtree")
            }
        }
    }

    private inline fun <T> checkedIdentityInput(block: () -> T): T = try {
        block()
    } catch (failure: Throwable) {
        synchronized(lock) { beginClosingLocked() }
        throw failure
    }

    private fun checkedTextField(value: String, name: String, foldCase: Boolean = false): CanonicalField =
        checkedIdentityInput { textField(value, name, foldCase) }

    private fun checkedIntField(value: Int, name: String): CanonicalField =
        checkedIdentityInput { intField(value, name) }

    private fun checkedLongField(value: Long, name: String): CanonicalField =
        checkedIdentityInput { longField(value, name) }

    private fun checkedDigestField(value: ByteArray, name: String): CanonicalField =
        checkedIdentityInput { digestField(value, name) }

    private fun ensureLifecycle(expected: Lifecycle) {
        check(lifecycleState == expected) {
            "Max security plan must be $expected but is $lifecycleState"
        }
    }

    internal companion object {
        private const val DIGEST_SIZE = 32
        private const val LEAF_SIZE = 32
        private const val MAX_TEXT_BYTES = 1_024
        private const val SHA_256 = "SHA-256"
        private const val FREEZE_STAGE = 0x31
        private const val LEAF_STAGE = 0x50

        private val PROTOCOL_DOMAIN = "JavaShroud-MaxBuildSecurityPlan-v1".toByteArray(Charsets.US_ASCII)
        private val UNSIGNED_BYTE_ARRAY_COMPARATOR = Comparator<ByteArray> { left, right ->
            val commonLength = minOf(left.size, right.size)
            for (index in 0 until commonLength) {
                val difference = (left[index].toInt() and 0xFF) - (right[index].toInt() and 0xFF)
                if (difference != 0) return@Comparator difference
            }
            left.size - right.size
        }

        internal fun create(
            inputDigest: ByteArray,
            configurationDigest: ByteArray,
        ): MaxBuildSecurityPlan = createWithEntropy(
            inputDigest = inputDigest,
            configurationDigest = configurationDigest,
            entropySource = SecureRandomMaxEntropySource(),
        )

        /** Production bridge used while constructing one VBC4 build context. */
        internal fun <T> withProductionBuildLeaf(
            inputDigest: ByteArray,
            configurationDigest: ByteArray,
            block: (ByteArray) -> T,
        ): T = create(inputDigest, configurationDigest).use { plan ->
            plan.freezeBuildDomain()
            plan.withBuildLeaf(block)
        }

        internal fun createForTesting(
            inputDigest: ByteArray,
            configurationDigest: ByteArray,
            fixedEntropy: ByteArray,
        ): MaxBuildSecurityPlan {
            require(fixedEntropy.size == LEAF_SIZE) { "Fixed max-plan entropy must be $LEAF_SIZE bytes" }
            return createWithEntropy(
                inputDigest = inputDigest,
                configurationDigest = configurationDigest,
                entropySource = FixedMaxEntropySource(fixedEntropy),
            )
        }

        private fun createWithEntropy(
            inputDigest: ByteArray,
            configurationDigest: ByteArray,
            entropySource: MaxEntropySource,
        ): MaxBuildSecurityPlan {
            val identity = canonicalIdentity(
                LeafPurpose.BUILD,
                listOf(
                    digestField(inputDigest, "inputDigest"),
                    digestField(configurationDigest, "configurationDigest"),
                ),
            )
            return MaxBuildSecurityPlan(identity, entropySource)
        }

        private fun slot(purpose: LeafPurpose, vararg fields: CanonicalField): ByteArray =
            canonicalIdentity(purpose, fields.asList())

        private fun canonicalIdentity(purpose: LeafPurpose, fields: List<CanonicalField>): ByteArray {
            val output = ByteArrayOutputStream()
            writeFramed(output, PROTOCOL_DOMAIN)
            output.write(purpose.code)
            writeInt(output, fields.size)
            for (field in fields) {
                output.write(field.type)
                writeFramed(output, field.bytes)
            }
            return output.toByteArray()
        }

        private fun canonicalPurpose(canonicalIdentity: ByteArray): LeafPurpose {
            val purposeOffset = Int.SIZE_BYTES + PROTOCOL_DOMAIN.size
            require(canonicalIdentity.size > purposeOffset) { "Invalid canonical max-plan identity" }
            val code = canonicalIdentity[purposeOffset].toInt() and 0xFF
            return LeafPurpose.entries.firstOrNull { it.code == code }
                ?: throw IllegalArgumentException("Unknown canonical max-plan identity purpose")
        }

        private fun fixedKdfMessage(stage: Int, vararg fields: ByteArray): ByteArray {
            val output = ByteArrayOutputStream()
            writeFramed(output, PROTOCOL_DOMAIN)
            output.write(stage)
            writeInt(output, fields.size)
            fields.forEach { writeFramed(output, it) }
            return output.toByteArray()
        }

        private fun textField(value: String, name: String, foldCase: Boolean = false): CanonicalField {
            require(value.isNotEmpty()) { "$name must not be empty" }
            require(value.length <= MAX_TEXT_BYTES) { "$name is too long" }
            require(value.first().isAsciiLetterOrDigit()) { "$name must start with an ASCII letter or digit" }
            require(value.all { it.isAsciiLetterOrDigit() || it == '.' || it == '_' || it == '-' }) {
                "$name contains a character outside the max-protocol identity grammar"
            }
            val canonical = if (foldCase) value.lowercase(Locale.ROOT) else value
            val bytes = canonical.toByteArray(Charsets.UTF_8)
            return CanonicalField(CanonicalField.TEXT, bytes)
        }

        private fun Char.isAsciiLetterOrDigit(): Boolean =
            this in 'a'..'z' || this in 'A'..'Z' || this in '0'..'9'

        private fun intField(value: Int, name: String): CanonicalField {
            require(value >= 0) { "$name must not be negative" }
            return CanonicalField(CanonicalField.INT, intBytes(value))
        }

        private fun longField(value: Long, name: String): CanonicalField {
            require(value >= 0L) { "$name must not be negative" }
            return CanonicalField(
                CanonicalField.LONG,
                byteArrayOf(
                    (value ushr 56).toByte(),
                    (value ushr 48).toByte(),
                    (value ushr 40).toByte(),
                    (value ushr 32).toByte(),
                    (value ushr 24).toByte(),
                    (value ushr 16).toByte(),
                    (value ushr 8).toByte(),
                    value.toByte(),
                ),
            )
        }

        private fun digestField(value: ByteArray, name: String): CanonicalField {
            require(value.size == DIGEST_SIZE) { "$name must be $DIGEST_SIZE bytes" }
            return CanonicalField(CanonicalField.DIGEST, value.copyOf())
        }

        private fun intBytes(value: Int): ByteArray = byteArrayOf(
            (value ushr 24).toByte(),
            (value ushr 16).toByte(),
            (value ushr 8).toByte(),
            value.toByte(),
        )

        private fun writeInt(output: ByteArrayOutputStream, value: Int) {
            output.write(intBytes(value))
        }

        private fun writeFramed(output: ByteArrayOutputStream, bytes: ByteArray) {
            writeInt(output, bytes.size)
            output.write(bytes)
        }

        private fun updateFramed(digest: MessageDigest, bytes: ByteArray) {
            digest.update(intBytes(bytes.size))
            digest.update(bytes)
        }

        private fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
            require(key.size <= HMAC_BLOCK_SIZE) { "Max-plan HMAC key is too large" }
            val keyBlock = ByteArray(HMAC_BLOCK_SIZE)
            val innerPad = ByteArray(HMAC_BLOCK_SIZE)
            val outerPad = ByteArray(HMAC_BLOCK_SIZE)
            var innerDigest = ByteArray(0)
            try {
                key.copyInto(keyBlock)
                for (index in 0 until HMAC_BLOCK_SIZE) {
                    innerPad[index] = (keyBlock[index].toInt() xor 0x36).toByte()
                    outerPad[index] = (keyBlock[index].toInt() xor 0x5C).toByte()
                }
                innerDigest = MessageDigest.getInstance(SHA_256).run {
                    update(innerPad)
                    update(message)
                    digest()
                }
                return MessageDigest.getInstance(SHA_256).run {
                    update(outerPad)
                    update(innerDigest)
                    digest()
                }
            } finally {
                keyBlock.fill(0)
                innerPad.fill(0)
                outerPad.fill(0)
                innerDigest.fill(0)
            }
        }

        private const val HMAC_BLOCK_SIZE = 64
    }
}

private enum class LeafPurpose(val code: Int, val description: String) {
    BUILD(1, "build"),
    TARGET(2, "target"),
    PARTITION(3, "partition"),
    METHOD(4, "method"),
    PROFILE(5, "profile"),
    PAGE(6, "page"),
}

private data class CanonicalField(val type: Int, val bytes: ByteArray) {
    companion object {
        const val TEXT = 1
        const val INT = 2
        const val LONG = 3
        const val DIGEST = 4
    }
}

private class IdentityKey(bytes: ByteArray) {
    private val canonical = bytes.copyOf()
    private val hashCode = canonical.contentHashCode()

    override fun equals(other: Any?): Boolean =
        other is IdentityKey && canonical.contentEquals(other.canonical)

    override fun hashCode(): Int = hashCode

    fun wipe() {
        canonical.fill(0)
    }
}

private data class IdentityRecord(
    val purpose: LeafPurpose,
    val canonicalIdentity: ByteArray,
    val parentSlots: List<IdentityKey>,
)

private fun interface MaxEntropySource {
    fun fill(destination: ByteArray)
}

private class SecureRandomMaxEntropySource : MaxEntropySource {
    private val secureRandom = SecureRandom()

    override fun fill(destination: ByteArray) {
        secureRandom.nextBytes(destination)
    }
}

private class FixedMaxEntropySource(entropy: ByteArray) : MaxEntropySource {
    private val fixedEntropy = entropy.copyOf()

    override fun fill(destination: ByteArray) {
        try {
            require(destination.size == fixedEntropy.size) { "Fixed max-plan entropy size mismatch" }
            fixedEntropy.copyInto(destination)
        } finally {
            fixedEntropy.fill(0)
        }
    }
}
