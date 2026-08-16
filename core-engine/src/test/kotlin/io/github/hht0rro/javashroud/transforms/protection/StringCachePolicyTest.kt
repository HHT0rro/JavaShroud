package io.github.hht0rro.javashroud.transforms.protection

import java.util.concurrent.atomic.AtomicInteger
import java.util.function.Supplier
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class StringCachePolicyTest {
    private var originalPolicy: String? = null

    @BeforeTest
    fun setUp() {
        originalPolicy = System.getProperty(STRING_CACHE_PROPERTY)
        System.clearProperty(STRING_CACHE_PROPERTY)
        StringEncryptionHelper.resetCacheForTesting()
    }

    @AfterTest
    fun tearDown() {
        if (originalPolicy == null) {
            System.clearProperty(STRING_CACHE_PROPERTY)
        } else {
            System.setProperty(STRING_CACHE_PROPERTY, originalPolicy)
        }
        StringEncryptionHelper.resetCacheForTesting()
    }

    @Test
    fun default_policy_is_soft() {
        assertEquals("soft", StringEncryptionHelper.cachePolicyForTesting())
    }

    @Test
    fun off_redecodes_without_retaining_entries() {
        setPolicy("off")
        val calls = AtomicInteger()

        repeat(2) {
            StringEncryptionHelper.cacheForTesting("opaque-off", decoder(calls))
        }

        assertEquals(2, calls.get(), "off must invoke the decoder for every request")
        assertEquals(0, StringEncryptionHelper.softCacheEntryCountForTesting())
        assertEquals(0, StringEncryptionHelper.strongCacheEntryCountForTesting())
    }

    @Test
    fun soft_reuses_only_soft_reference_entries() {
        setPolicy("soft")
        val calls = AtomicInteger()

        repeat(2) {
            StringEncryptionHelper.cacheForTesting("opaque-soft", decoder(calls))
        }

        assertEquals(1, calls.get(), "an uncleared soft reference should prevent a second decode")
        assertEquals(1, StringEncryptionHelper.softCacheEntryCountForTesting())
        assertEquals(0, StringEncryptionHelper.strongCacheEntryCountForTesting())
    }

    @Test
    fun strong_reuses_strong_entries_only_when_explicitly_selected() {
        setPolicy("strong")
        val calls = AtomicInteger()

        repeat(2) {
            StringEncryptionHelper.cacheForTesting("opaque-strong", decoder(calls))
        }

        assertEquals(1, calls.get())
        assertEquals(0, StringEncryptionHelper.softCacheEntryCountForTesting())
        assertEquals(1, StringEncryptionHelper.strongCacheEntryCountForTesting())
    }

    @Test
    fun invalid_policy_fails_closed() {
        System.setProperty(STRING_CACHE_PROPERTY, "invalid-policy")

        assertFailsWith<SecurityException> {
            StringEncryptionHelper.cachePolicyForTesting()
        }
    }

    @Test
    fun aken_page_cache_key_binds_handle_page_and_raw_proof_without_aliasing() {
        val handle = ByteArray(24) { index -> (index * 11 + 7).toByte() }
        val proof = byteArrayOf(0, ':'.code.toByte(), 0, 0x7F, 0xFF.toByte(), ':'.code.toByte())
        val sameHandle = handle.copyOf()
        val sameProof = proof.copyOf()
        val changedHandle = handle.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 0x3C).toByte() }
        val changedProof = proof.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 0x55).toByte() }
        try {
            val baseline = akenStringPageCacheKey(handle, 0x0102_0304, proof)

            assertEquals(baseline, akenStringPageCacheKey(sameHandle, 0x0102_0304, sameProof))
            assertNotEquals(baseline, akenStringPageCacheKey(changedHandle, 0x0102_0304, proof))
            assertNotEquals(baseline, akenStringPageCacheKey(handle, 0x0102_0305, proof))
            assertNotEquals(baseline, akenStringPageCacheKey(handle, 0x0102_0304, changedProof))
        } finally {
            handle.fill(0)
            proof.fill(0)
            sameHandle.fill(0)
            sameProof.fill(0)
            changedHandle.fill(0)
            changedProof.fill(0)
        }
    }

    @Test
    fun malformed_aken_page_request_fails_closed_before_cache_or_native_dispatch() {
        setPolicy("strong")

        assertFailsWith<SecurityException> {
            StringEncryptionHelper.cachedDecodeAkenStringPage(ByteArray(23), 0, byteArrayOf(1))
        }
        assertFailsWith<SecurityException> {
            StringEncryptionHelper.cachedDecodeAkenStringPage(ByteArray(24), -1, byteArrayOf(1))
        }
        assertFailsWith<SecurityException> {
            StringEncryptionHelper.cachedDecodeAkenStringPage(ByteArray(24), 0, ByteArray(0))
        }

        assertEquals(0, StringEncryptionHelper.softCacheEntryCountForTesting())
        assertEquals(0, StringEncryptionHelper.strongCacheEntryCountForTesting())
    }

    private fun setPolicy(policy: String) {
        System.setProperty(STRING_CACHE_PROPERTY, policy)
        StringEncryptionHelper.resetCacheForTesting()
    }

    private fun decoder(calls: AtomicInteger): Supplier<String> = Supplier {
        calls.incrementAndGet()
        String(charArrayOf('v', 'a', 'l', 'u', 'e'))
    }

    private fun akenStringPageCacheKey(handle: ByteArray, pageIndex: Int, proof: ByteArray): String {
        val primitiveInt = requireNotNull(Int::class.javaPrimitiveType)
        val method = StringEncryptionHelper::class.java.getDeclaredMethod(
            "akenStringPageCacheKey",
            ByteArray::class.java,
            primitiveInt,
            ByteArray::class.java,
        )
        method.isAccessible = true
        return method.invoke(null, handle, pageIndex, proof) as String
    }

    private companion object {
        const val STRING_CACHE_PROPERTY = "javashroud.stringCache"
    }
}
