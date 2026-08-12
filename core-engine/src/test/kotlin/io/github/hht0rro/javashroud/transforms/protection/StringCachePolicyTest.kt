package io.github.hht0rro.javashroud.transforms.protection

import java.util.concurrent.atomic.AtomicInteger
import java.util.function.Supplier
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

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

    private fun setPolicy(policy: String) {
        System.setProperty(STRING_CACHE_PROPERTY, policy)
        StringEncryptionHelper.resetCacheForTesting()
    }

    private fun decoder(calls: AtomicInteger): Supplier<String> = Supplier {
        calls.incrementAndGet()
        String(charArrayOf('v', 'a', 'l', 'u', 'e'))
    }

    private companion object {
        const val STRING_CACHE_PROPERTY = "javashroud.stringCache"
    }
}
