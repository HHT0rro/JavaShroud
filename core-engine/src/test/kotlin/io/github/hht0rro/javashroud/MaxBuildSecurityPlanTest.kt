package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.MaxBuildSecurityPlan
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class MaxBuildSecurityPlanTest {
    @Test
    fun lifecycle_requires_freeze_and_close_wipes_backing_and_borrowed_secrets() {
        val plan = fixedPlan()
        assertEquals(MaxBuildSecurityPlan.Lifecycle.COLLECTING, plan.lifecycle)
        registerInventory(plan)

        assertFailsWith<IllegalStateException> {
            plan.withBuildLeaf { it.copyOf() }
        }

        freezeComplete(plan)
        assertEquals(MaxBuildSecurityPlan.Lifecycle.FROZEN, plan.lifecycle)

        val secretField = plan.javaClass.getDeclaredField("derivationSecret").apply { isAccessible = true }
        val backingSecret = secretField.get(plan) as ByteArray
        lateinit var borrowedSecret: ByteArray
        val returnedSecret = plan.withBuildLeaf { borrowed ->
            borrowedSecret = borrowed
            assertTrue(borrowed.any { it != 0.toByte() })
            borrowed
        }
        assertSame(borrowedSecret, returnedSecret)
        assertTrue(returnedSecret.all { it == 0.toByte() }, "borrowed secret must be wiped before it escapes")

        plan.close()
        assertEquals(MaxBuildSecurityPlan.Lifecycle.CLOSED, plan.lifecycle)
        assertTrue(backingSecret.all { it == 0.toByte() }, "close must wipe the frozen derivation secret")
        assertFailsWith<IllegalStateException> {
            plan.withBuildLeaf { it.copyOf() }
        }
        plan.close()
    }

    @Test
    fun callback_failure_still_wipes_the_borrowed_secret() {
        val plan = fixedPlan().also(::registerInventory)
        freezeComplete(plan)
        lateinit var borrowedSecret: ByteArray

        assertFailsWith<ExpectedBorrowFailure> {
            plan.withMethodLeaf(TARGET_ID, PARTITION_ID, METHOD_ID) { borrowed ->
                borrowedSecret = borrowed
                throw ExpectedBorrowFailure()
            }
        }

        assertTrue(borrowedSecret.all { it == 0.toByte() })
        plan.close()
    }

    @Test
    fun fixed_entropy_and_inventory_are_deterministic_independent_of_request_order() {
        val forward = fixedPlan()
        val reverse = fixedPlan()
        registerInventory(forward)
        registerInventoryReverse(reverse)
        freezeComplete(forward)
        freezeComplete(reverse)

        assertContentEquals(copyBuildLeaf(forward), copyBuildLeaf(reverse))
        assertContentEquals(copyTargetLeaf(forward), copyTargetLeaf(reverse))
        assertContentEquals(copyPartitionLeaf(forward), copyPartitionLeaf(reverse))
        assertContentEquals(copyMethodLeaf(forward), copyMethodLeaf(reverse))
        assertContentEquals(copyProfileLeaf(forward), copyProfileLeaf(reverse))
        assertContentEquals(copyPageLeaf(forward), copyPageLeaf(reverse))

        forward.close()
        reverse.close()
    }

    @Test
    fun typed_leaf_domains_do_not_alias() {
        val plan = fixedPlan().also(::registerInventory)
        freezeComplete(plan)

        val leaves = listOf(
            copyBuildLeaf(plan),
            copyTargetLeaf(plan),
            copyPartitionLeaf(plan),
            copyMethodLeaf(plan),
            copyProfileLeaf(plan),
            copyPageLeaf(plan),
        )
        assertEquals(leaves.size, leaves.map(ByteArray::toList).distinct().size)
        plan.close()
    }

    @Test
    fun canonical_length_prefixes_keep_ambiguous_text_tuples_distinct() {
        val first = fixedPlan().apply { registerCompleteInventory(this, "ab", "c") }
        val second = fixedPlan().apply { registerCompleteInventory(this, "a", "bc") }
        freezeComplete(first)
        freezeComplete(second)

        val firstLeaf = first.withTargetLeaf("ab") { it.copyOf() }
        val secondLeaf = second.withTargetLeaf("a") { it.copyOf() }
        assertNotEquals(firstLeaf.toList(), secondLeaf.toList())

        first.close()
        second.close()
    }

    @Test
    fun duplicate_and_conflicting_identities_fail_closed() {
        val duplicate = fixedPlan()
        duplicate.requestTarget(TARGET_ID, "windows", "x86_64", "msvc")
        val duplicateFailure = assertFailsWith<IllegalArgumentException> {
            duplicate.requestTarget(TARGET_ID, "windows", "x86_64", "msvc")
        }
        assertTrue(duplicateFailure.message.orEmpty().contains("duplicate"))
        assertEquals(MaxBuildSecurityPlan.Lifecycle.CLOSED, duplicate.lifecycle)

        val conflicting = fixedPlan()
        conflicting.requestTarget(TARGET_ID, "windows", "x86_64", "msvc")
        val conflictFailure = assertFailsWith<IllegalArgumentException> {
            conflicting.requestTarget(TARGET_ID, "linux", "x86_64", "gnu")
        }
        assertTrue(conflictFailure.message.orEmpty().contains("conflicting"))
        assertEquals(MaxBuildSecurityPlan.Lifecycle.CLOSED, conflicting.lifecycle)
    }

    @Test
    fun missing_parent_identity_fails_closed_during_freeze() {
        val plan = fixedPlan()
        plan.requestMethod(
            TARGET_ID,
            PARTITION_ID,
            METHOD_ID,
            METHOD_SEMANTIC_DIGEST,
            METHOD_DIGEST,
            METHOD_CONTEXT_DIGEST,
        )

        assertFailsWith<IllegalArgumentException> { freezeComplete(plan) }
        assertEquals(MaxBuildSecurityPlan.Lifecycle.CLOSED, plan.lifecycle)
        assertFailsWith<IllegalStateException> {
            plan.withMethodLeaf(TARGET_ID, PARTITION_ID, METHOD_ID) { it.copyOf() }
        }
    }

    @Test
    fun production_plans_with_the_same_inventory_diverge() {
        val first = productionPlan().also(::registerInventory)
        val second = productionPlan().also(::registerInventory)
        freezeComplete(first)
        freezeComplete(second)

        assertFalse(copyBuildLeaf(first).contentEquals(copyBuildLeaf(second)))
        assertFalse(copyMethodLeaf(first).contentEquals(copyMethodLeaf(second)))

        first.close()
        second.close()
    }

    @Test
    fun production_build_leaf_bridge_mints_and_wipes_a_real_build_authority() {
        lateinit var borrowed: ByteArray
        val first = MaxBuildSecurityPlan.withProductionBuildLeaf(INPUT_DIGEST, CONFIGURATION_DIGEST) { leaf ->
            borrowed = leaf
            leaf.copyOf()
        }
        val second = MaxBuildSecurityPlan.withProductionBuildLeaf(INPUT_DIGEST, CONFIGURATION_DIGEST) { it.copyOf() }

        assertTrue(first.any { it != 0.toByte() })
        assertTrue(borrowed.all { it == 0.toByte() }, "Production bridge must wipe the borrowed build leaf")
        assertFalse(first.contentEquals(second), "Independent production builds must mint distinct build authorities")
    }

    @Test
    fun close_waits_until_active_borrow_is_wiped() {
        val plan = fixedPlan().also(::registerInventory)
        freezeComplete(plan)
        val borrowStarted = CountDownLatch(1)
        val releaseBorrow = CountDownLatch(1)
        val closeReturned = AtomicBoolean(false)
        lateinit var borrowedSecret: ByteArray

        val borrower = Thread {
            plan.withMethodLeaf(TARGET_ID, PARTITION_ID, METHOD_ID) { borrowed ->
                borrowedSecret = borrowed
                borrowStarted.countDown()
                check(releaseBorrow.await(5, TimeUnit.SECONDS))
            }
        }.apply { start() }
        assertTrue(borrowStarted.await(5, TimeUnit.SECONDS))

        val closer = Thread {
            plan.close()
            closeReturned.set(true)
        }.apply { start() }

        try {
            assertTrue(waitUntil { plan.lifecycle == MaxBuildSecurityPlan.Lifecycle.CLOSING })
            assertFalse(closeReturned.get())
            assertTrue(borrowedSecret.any { it != 0.toByte() })
        } finally {
            releaseBorrow.countDown()
            borrower.join(5_000)
            closer.join(5_000)
        }

        assertFalse(borrower.isAlive)
        assertFalse(closer.isAlive)
        assertTrue(closeReturned.get())
        assertTrue(borrowedSecret.all { it == 0.toByte() })
        assertEquals(MaxBuildSecurityPlan.Lifecycle.CLOSED, plan.lifecycle)
    }

    @Test
    fun unregistered_leaf_access_fails_closed() {
        val plan = fixedPlan().also(::registerInventory)
        freezeComplete(plan)

        assertFailsWith<IllegalArgumentException> {
            plan.withMethodLeaf(TARGET_ID, PARTITION_ID, METHOD_ID + 1) { it.copyOf() }
        }

        assertEquals(MaxBuildSecurityPlan.Lifecycle.CLOSED, plan.lifecycle)
        assertFailsWith<IllegalStateException> { copyMethodLeaf(plan) }
    }

    @Test
    fun freeze_rejects_empty_or_incomplete_inventory() {
        val empty = fixedPlan()
        assertFailsWith<IllegalArgumentException> { freezeComplete(empty) }
        assertEquals(MaxBuildSecurityPlan.Lifecycle.CLOSED, empty.lifecycle)

        val incomplete = fixedPlan().apply {
            requestTarget(TARGET_ID, "windows", "x86_64", "msvc")
            requestPartition(TARGET_ID, PARTITION_ID, PARTITION_DIGEST)
            requestProfile(TARGET_ID, PROFILE_ID, PROFILE_DIGEST)
            requestPage(TARGET_ID, PROFILE_ID, SECTION_ID, PAGE_ORDINAL, PAGE_DIGEST)
        }
        assertFailsWith<IllegalArgumentException> {
            incomplete.freeze(COMPLETE_INVENTORY)
        }
        assertEquals(MaxBuildSecurityPlan.Lifecycle.CLOSED, incomplete.lifecycle)
    }

    @Test
    fun identity_text_rejects_native_unsafe_or_non_ascii_values() {
        for (targetId in listOf("win\u0000x64", "windows/x64", "wíndows")) {
            val plan = fixedPlan()
            assertFailsWith<IllegalArgumentException> {
                plan.requestTarget(targetId, "windows", "x86_64", "msvc")
            }
            assertEquals(MaxBuildSecurityPlan.Lifecycle.CLOSED, plan.lifecycle)
        }
    }

    @Test
    fun build_and_context_digests_perturb_method_leaf() {
        val plans = listOf(
            fixedPlan().also(::registerInventory),
            fixedPlan(inputDigest = mutated(INPUT_DIGEST)).also(::registerInventory),
            fixedPlan(configurationDigest = mutated(CONFIGURATION_DIGEST)).also(::registerInventory),
            fixedPlan().also { registerInventory(it, partitionDigest = mutated(PARTITION_DIGEST)) },
            fixedPlan().also { registerInventory(it, semanticDigest = mutated(METHOD_SEMANTIC_DIGEST)) },
            fixedPlan().also { registerInventory(it, methodDigest = mutated(METHOD_DIGEST)) },
            fixedPlan().also { registerInventory(it, contextDigest = mutated(METHOD_CONTEXT_DIGEST)) },
            fixedPlan().also { registerInventory(it, profileDigest = mutated(PROFILE_DIGEST)) },
        )
        plans.forEach(::freezeComplete)

        val leaves = plans.map(::copyMethodLeaf)
        assertEquals(leaves.size, leaves.map(ByteArray::toList).distinct().size)
        plans.forEach(MaxBuildSecurityPlan::close)
    }

    private fun fixedPlan(
        inputDigest: ByteArray = INPUT_DIGEST,
        configurationDigest: ByteArray = CONFIGURATION_DIGEST,
    ): MaxBuildSecurityPlan = MaxBuildSecurityPlan.createForTesting(
        inputDigest = inputDigest,
        configurationDigest = configurationDigest,
        fixedEntropy = FIXED_ENTROPY,
    )

    private fun productionPlan(): MaxBuildSecurityPlan = MaxBuildSecurityPlan.create(
        inputDigest = INPUT_DIGEST,
        configurationDigest = CONFIGURATION_DIGEST,
    )

    private fun registerInventory(
        plan: MaxBuildSecurityPlan,
        partitionDigest: ByteArray = PARTITION_DIGEST,
        semanticDigest: ByteArray = METHOD_SEMANTIC_DIGEST,
        methodDigest: ByteArray = METHOD_DIGEST,
        contextDigest: ByteArray = METHOD_CONTEXT_DIGEST,
        profileDigest: ByteArray = PROFILE_DIGEST,
    ) {
        plan.requestTarget(TARGET_ID, "windows", "x86_64", "msvc")
        plan.requestPartition(TARGET_ID, PARTITION_ID, partitionDigest)
        plan.requestMethod(
            TARGET_ID,
            PARTITION_ID,
            METHOD_ID,
            semanticDigest,
            methodDigest,
            contextDigest,
        )
        plan.requestProfile(TARGET_ID, PROFILE_ID, profileDigest)
        plan.requestPage(TARGET_ID, PROFILE_ID, SECTION_ID, PAGE_ORDINAL, PAGE_DIGEST)
    }

    private fun mutated(source: ByteArray): ByteArray = source.copyOf().also {
        it[0] = (it[0].toInt() xor 0x5A).toByte()
    }

    private fun registerCompleteInventory(plan: MaxBuildSecurityPlan, targetId: String, operatingSystem: String) {
        plan.requestTarget(targetId, operatingSystem, "x86_64", "gnu")
        plan.requestPartition(targetId, PARTITION_ID, PARTITION_DIGEST)
        plan.requestMethod(
            targetId,
            PARTITION_ID,
            METHOD_ID,
            METHOD_SEMANTIC_DIGEST,
            METHOD_DIGEST,
            METHOD_CONTEXT_DIGEST,
        )
        plan.requestProfile(targetId, PROFILE_ID, PROFILE_DIGEST)
        plan.requestPage(targetId, PROFILE_ID, SECTION_ID, PAGE_ORDINAL, PAGE_DIGEST)
    }

    private fun freezeComplete(plan: MaxBuildSecurityPlan) {
        plan.freeze(COMPLETE_INVENTORY)
    }

    private fun waitUntil(timeoutMillis: Long = 5_000, condition: () -> Boolean): Boolean {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        while (System.nanoTime() < deadline) {
            if (condition()) return true
            Thread.sleep(1)
        }
        return condition()
    }

    private fun registerInventoryReverse(plan: MaxBuildSecurityPlan) {
        plan.requestPage(TARGET_ID, PROFILE_ID, SECTION_ID, PAGE_ORDINAL, PAGE_DIGEST)
        plan.requestProfile(TARGET_ID, PROFILE_ID, PROFILE_DIGEST)
        plan.requestMethod(
            TARGET_ID,
            PARTITION_ID,
            METHOD_ID,
            METHOD_SEMANTIC_DIGEST,
            METHOD_DIGEST,
            METHOD_CONTEXT_DIGEST,
        )
        plan.requestPartition(TARGET_ID, PARTITION_ID, PARTITION_DIGEST)
        plan.requestTarget(TARGET_ID, "windows", "x86_64", "msvc")
    }

    private fun copyBuildLeaf(plan: MaxBuildSecurityPlan): ByteArray =
        plan.withBuildLeaf { it.copyOf() }

    private fun copyTargetLeaf(plan: MaxBuildSecurityPlan): ByteArray =
        plan.withTargetLeaf(TARGET_ID) { it.copyOf() }

    private fun copyPartitionLeaf(plan: MaxBuildSecurityPlan): ByteArray =
        plan.withPartitionLeaf(TARGET_ID, PARTITION_ID) { it.copyOf() }

    private fun copyMethodLeaf(plan: MaxBuildSecurityPlan): ByteArray =
        plan.withMethodLeaf(TARGET_ID, PARTITION_ID, METHOD_ID) { it.copyOf() }

    private fun copyProfileLeaf(plan: MaxBuildSecurityPlan): ByteArray =
        plan.withProfileLeaf(TARGET_ID, PROFILE_ID) { it.copyOf() }

    private fun copyPageLeaf(plan: MaxBuildSecurityPlan): ByteArray =
        plan.withPageLeaf(TARGET_ID, PROFILE_ID, SECTION_ID, PAGE_ORDINAL) { it.copyOf() }

    private class ExpectedBorrowFailure : RuntimeException()

    private companion object {
        const val TARGET_ID = "windows-x86_64"
        const val PARTITION_ID = 7
        const val METHOD_ID = 11L
        const val PROFILE_ID = 13
        val COMPLETE_INVENTORY = MaxBuildSecurityPlan.InventoryCounts(
            targets = 1,
            partitions = 1,
            methods = 1,
            profiles = 1,
            pages = 1,
        )
        const val SECTION_ID = 17
        const val PAGE_ORDINAL = 19

        val INPUT_DIGEST = ByteArray(32) { index -> (index * 3 + 1).toByte() }
        val CONFIGURATION_DIGEST = ByteArray(32) { index -> (index * 5 + 2).toByte() }
        val FIXED_ENTROPY = ByteArray(32) { index -> (index * 7 + 3).toByte() }
        val PARTITION_DIGEST = ByteArray(32) { index -> (index * 9 + 8).toByte() }
        val METHOD_SEMANTIC_DIGEST = ByteArray(32) { index -> (index * 10 + 6).toByte() }
        val METHOD_DIGEST = ByteArray(32) { index -> (index * 11 + 4).toByte() }
        val METHOD_CONTEXT_DIGEST = ByteArray(32) { index -> (index * 12 + 7).toByte() }
        val PROFILE_DIGEST = ByteArray(32) { index -> (index * 13 + 9).toByte() }
        val PAGE_DIGEST = ByteArray(32) { index -> (index * 13 + 5).toByte() }
    }
}
