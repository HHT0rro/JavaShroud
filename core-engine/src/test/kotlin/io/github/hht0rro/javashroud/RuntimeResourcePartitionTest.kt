package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.RuntimeKeyPartitions
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class RuntimeResourcePartitionTest {
    @Test
    fun partitioned_envelope_roundtrips_and_marks_header() = withVbc4BuildContext(partitionedContext()) {
        val plain = "partitioned-vm-payload".toByteArray(Charsets.UTF_8)
        val encoded = RuntimeResourceCodec.encode(
            bytes = plain,
            kind = RuntimeResourceKind.VmBytecode,
            seed = 0x5150,
            variantId = 3,
            layerCount = 4,
        )

        assertEquals(7, encoded[4].toInt() and 0xFF, "partitioned build must emit the partitioned envelope version")
        assertEquals(96, readLe16(encoded, 21), "partitioned header keeps encrypted metadata length")
        assertEquals(32, readLe16(encoded, 23), "partitioned header keeps MAC length")
        val partitionId = readLe16(encoded, 25)
        val partitions = io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext().runtimeKeyPartitions!!
        assertTrue(partitionId in 0 until partitions.resourcePartitionCount, "header partition id must address a real partition")
        assertContentEquals(plain, RuntimeResourceCodec.decode(encoded), "partitioned envelope must round-trip")
    }

    @Test
    fun resources_with_distinct_identities_spread_across_partitions() = withVbc4BuildContext(partitionedContext()) {
        val partitions = io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext().runtimeKeyPartitions!!
        val seen = sortedSetOf<Int>()
        for (index in 0 until 64) {
            seen += partitions.partitionFor("vm|com/example/Foo|m$index|()V".toByteArray(Charsets.UTF_8))
        }
        assertTrue(seen.size >= 2, "partition assignment must diverge across method identities, got $seen")
    }

    @Test
    fun tampering_fails_closed_for_body_tag_and_partition_fields() = withVbc4BuildContext(partitionedContext()) {
        val plain = ByteArray(301) { (it * 31 + 7).toByte() }
        val encoded = RuntimeResourceCodec.encode(
            bytes = plain,
            kind = RuntimeResourceKind.VmBytecode,
            seed = 0x777,
            variantId = 5,
            layerCount = 3,
        )
        val cases = mutableListOf<Pair<String, ByteArray>>()
        cases += "body flip" to encoded.copyOf().also { it[it.size - 40] = (it[it.size - 40].toInt() xor 0x01).toByte() }
        cases += "tag flip" to encoded.copyOf().also { it[it.size - 10] = (it[it.size - 10].toInt() xor 0x80).toByte() }
        cases += "partition bump" to encoded.copyOf().also {
            val current = readLe16(it, 25)
            val partitions = io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext().runtimeKeyPartitions!!
            val bumped = (current + 1) % partitions.resourcePartitionCount
            it[25] = (bumped and 0xFF).toByte()
            it[26] = ((bumped ushr 8) and 0xFF).toByte()
        }
        cases += "metadata flip" to encoded.copyOf().also { it[40] = (it[40].toInt() xor 0x10).toByte() }
        for ((name, mutated) in cases) {
            assertEquals(null, RuntimeResourceCodec.decode(mutated), "$name must fail closed before plaintext is produced")
        }
    }

    @Test
    fun foreign_partition_set_cannot_decode_envelope() {
        val plain = "cross-build-replay".toByteArray(Charsets.UTF_8)
        val encoded = withVbc4BuildContext(partitionedContext()) {
            RuntimeResourceCodec.encode(
                bytes = plain,
                kind = RuntimeResourceKind.VmBytecode,
                seed = 0x999,
                variantId = 2,
                layerCount = 3,
            )
        }
        withVbc4BuildContext(partitionedContext()) {
            assertEquals(null, RuntimeResourceCodec.decode(encoded), "an envelope sealed under another build's partitions must fail closed")
        }
    }

    @Test
    fun independent_builds_mint_divergent_key_domains() {
        val first = RuntimeKeyPartitions.generate()
        val second = RuntimeKeyPartitions.generate()
        try {
            var identicalSlots = 0
            val compared = minOf(first.totalSlots, second.totalSlots)
            for (slot in 0 until compared) {
                if (first.copyKeyForSlot(slot).contentEquals(second.copyKeyForSlot(slot))) identicalSlots++
            }
            assertEquals(0, identicalSlots, "independent builds must not share key material")
            assertTrue(first.resourcePartitionCount >= RuntimeKeyPartitions.MIN_RESOURCE_PARTITIONS)
            assertTrue(first.resourcePartitionCount <= RuntimeKeyPartitions.MAX_RESOURCE_PARTITIONS)
        } finally {
            first.wipe()
            second.wipe()
        }
    }

    private fun partitionedContext(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 11 + 1).toByte() },
        nativeSeed = 0x0BAD_5EEDL,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 3 + 7).toByte() },
        runtimeKeyPartitions = RuntimeKeyPartitions.generate(),
    )

    private fun readLe16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)
}
