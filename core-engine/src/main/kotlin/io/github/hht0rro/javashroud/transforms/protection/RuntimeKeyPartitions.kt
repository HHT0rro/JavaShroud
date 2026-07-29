package io.github.hht0rro.javashroud.transforms.protection

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Per-build divergent key domains for runtime resources.
 *
 * Replaces the single globally-applicable runtime resource key: every build
 * mints an independent random key per resource partition plus one anchor key.
 * Partition keys are never derived from a shared root, so recovering any one
 * partition key (or even the anchor key) yields nothing about the others.
 * The anchor key backs cross-cutting derivations (bootstrap index auth,
 * class-encryption HKDF) that both the build and the runtime must recompute;
 * resource partitions back JSRP envelope encryption and are selected per
 * resource from a stable identity digest so the runtime can pick the matching
 * key slot from the envelope header.
 */
internal class RuntimeKeyPartitions private constructor(
    private val resourceKeys: Array<ByteArray>,
    private val anchorKey: ByteArray,
) {
    /** Number of resource partitions; the anchor slot id is this value. */
    val resourcePartitionCount: Int
        get() = resourceKeys.size

    /** Slot id used for the anchor key inside the runtime helper. */
    val anchorSlotId: Int
        get() = resourceKeys.size

    init {
        require(resourceKeys.isNotEmpty()) { "at least one resource partition is required" }
        require(resourceKeys.size <= MAX_RESOURCE_PARTITIONS) { "too many resource partitions" }
        require(resourceKeys.all { it.size == VBC4_RUNTIME_RESOURCE_KEY_SIZE }) { "partition keys must be 32 bytes" }
        require(anchorKey.size == VBC4_RUNTIME_RESOURCE_KEY_SIZE) { "anchor key must be 32 bytes" }
    }

    fun copyResourceKey(partitionId: Int): ByteArray {
        require(partitionId in resourceKeys.indices) { "resource partition out of range: $partitionId" }
        return resourceKeys[partitionId].copyOf()
    }

    fun copyAnchorKey(): ByteArray = anchorKey.copyOf()

    fun copyKeyForSlot(slotId: Int): ByteArray =
        if (slotId == anchorSlotId) copyAnchorKey() else copyResourceKey(slotId)

    /** Total key slots mirrored into the runtime: resource partitions + anchor. */
    val totalSlots: Int
        get() = resourceKeys.size + 1

    /** Stable partition assignment: same identity always maps to the same slot. */
    fun partitionFor(identity: ByteArray): Int {
        val digest = MessageDigest.getInstance(SHA_256).apply {
            update(PARTITION_DOMAIN)
            update(identity)
        }.digest()
        val value = ((digest[0].toInt() and 0xFF) shl 8) or (digest[1].toInt() and 0xFF)
        return value % resourceKeys.size
    }

    fun deepCopy(): RuntimeKeyPartitions = RuntimeKeyPartitions(
        resourceKeys = Array(resourceKeys.size) { index -> resourceKeys[index].copyOf() },
        anchorKey = anchorKey.copyOf(),
    )

    fun wipe() {
        resourceKeys.forEach { it.fill(0) }
        anchorKey.fill(0)
    }

    companion object {
        private const val SHA_256 = "SHA-256"
        private val PARTITION_DOMAIN = "jsrp-partition-v1".toByteArray(Charsets.US_ASCII)

        internal const val MIN_RESOURCE_PARTITIONS = 6
        internal const val MAX_RESOURCE_PARTITIONS = 16

        fun generate(random: SecureRandom = SecureRandom()): RuntimeKeyPartitions {
            val count = MIN_RESOURCE_PARTITIONS + random.nextInt(MAX_RESOURCE_PARTITIONS - MIN_RESOURCE_PARTITIONS + 1)
            val keys = Array(count) { ByteArray(VBC4_RUNTIME_RESOURCE_KEY_SIZE).also(random::nextBytes) }
            val anchor = ByteArray(VBC4_RUNTIME_RESOURCE_KEY_SIZE).also(random::nextBytes)
            return RuntimeKeyPartitions(keys, anchor)
        }
    }
}
