package io.github.hht0rro.javashroud.transforms.protection

import java.lang.ref.Reference
import java.lang.reflect.Modifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import java.lang.invoke.MethodHandles
import java.lang.invoke.MethodType

class StringCachePolicyTest {
    @Test
    fun string_helper_retains_no_plaintext_cache_fields_or_methods() {
        val helper = StringEncryptionHelper::class.java

        helper.declaredFields.forEach { field ->
            assertFalse(field.name.contains("cache", ignoreCase = true), "String helper must not retain cache field ${field.name}")
            assertFalse(java.util.Map::class.java.isAssignableFrom(field.type), "String helper must not retain map-backed plaintext state")
            assertFalse(java.util.concurrent.ConcurrentMap::class.java.isAssignableFrom(field.type), "String helper must not retain concurrent plaintext state")
            assertFalse(Reference::class.java.isAssignableFrom(field.type), "String helper must not retain soft/weak plaintext references")
            assertFalse(
                Modifier.isStatic(field.modifiers) && field.type == String::class.java,
                "String helper must not retain static String cache or policy state",
            )
        }
        assertFalse(
            helper.declaredMethods.any { it.name.contains("cache", ignoreCase = true) },
            "String helper must not expose cache-control or cached decode methods",
        )
    }

    @Test
    fun string_helper_bytecode_contains_no_retired_cache_contract() {
        val resource = "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper.class"
        val classBytes = checkNotNull(StringEncryptionHelper::class.java.classLoader.getResourceAsStream(resource)) {
            "StringEncryptionHelper.class must be available on the test classpath"
        }.use { it.readBytes() }
        val classText = String(classBytes, Charsets.ISO_8859_1)

        listOf(
            "javashroud." + "stringCache",
            "SOFT_" + "CACHE",
            "STRONG_" + "CACHE",
            "CachePolicy",
            "cached" + "DecodeAkenStringPage",
            "decode" + "AkenStringPage",
            "cacheForTesting",
            "resetCacheForTesting",
        ).forEach { retired ->
            assertFalse(retired in classText, "String helper bytecode must not retain retired cache marker $retired")
        }
    }

    @Test
    fun string_terminal_is_not_a_public_repeatable_decoder_api() {
        val helper = StringEncryptionHelper::class.java
        val primitiveInt = requireNotNull(Int::class.javaPrimitiveType)
        val terminal = helper.getDeclaredMethod(
            "invokeAkenStringTerminal",
            ByteArray::class.java,
            primitiveInt,
            ByteArray::class.java,
        )

        assertEquals(String::class.java, terminal.returnType)
        assertFalse(Modifier.isPublic(terminal.modifiers), "Unsealed helper must not expose a public repeatable page decoder")
        assertTrue(Modifier.isStatic(terminal.modifiers))
        assertEquals(
            emptyList(),
            helper.declaredMethods
                .filter {
                    Modifier.isPublic(it.modifiers) &&
                        Modifier.isStatic(it.modifiers) &&
                        it.returnType == String::class.java
                }
                .map { it.name }
                .sorted(),
            "String helper must not expose a public String-returning page terminal",
        )
    }

    @Test
    fun malformed_aken_page_request_fails_closed_before_native_dispatch() {
        assertFailsWith<SecurityException> {
            StringEncryptionHelper.invokeAkenStringTerminal(ByteArray(23), 0, byteArrayOf(1))
        }
        assertFailsWith<SecurityException> {
            StringEncryptionHelper.invokeAkenStringTerminal(ByteArray(24), -1, byteArrayOf(1))
        }
        assertFailsWith<SecurityException> {
            StringEncryptionHelper.invokeAkenStringTerminal(ByteArray(24), 0, ByteArray(0))
        }
        assertFailsWith<SecurityException> {
            StringEncryptionHelper.invokeAkenStringTerminal(ByteArray(24), 0, ByteArray(4097))
        }
    }

    @Test
    fun string_bootstrap_rejects_foreign_same_signature_targets() {
        val type = MethodType.methodType(String::class.java, ByteArray::class.java)
        val foreign = MethodHandles.lookup().findStatic(
            StringCachePolicyTest::class.java,
            "foreignStringTarget",
            type,
        )
        listOf(
            StringEncryptionHelper::q0,
            StringEncryptionHelper::m7,
            StringEncryptionHelper::x3,
            StringEncryptionHelper::v8,
        ).forEach { bootstrap ->
            assertFailsWith<SecurityException> {
                bootstrap.invoke(
                    MethodHandles.lookup(),
                    "a0",
                    type,
                    foreign,
                )
            }
        }
    }

    @Test
    fun string_bootstrap_accepts_only_the_current_terminal_handle() {
        val type = MethodType.methodType(String::class.java, ByteArray::class.java)
        val terminal = MethodHandles.privateLookupIn(
            StringEncryptionHelper::class.java,
            MethodHandles.lookup(),
        ).findStatic(
            StringEncryptionHelper::class.java,
            "invokeAkenStringTerminal",
            type,
        )
        val callSite = StringEncryptionHelper.q0(MethodHandles.lookup(), "a0", type, terminal)
        val actualTarget = callSite.javaClass.getMethod("getTarget").invoke(callSite) as java.lang.invoke.MethodHandle
        val actualType = java.lang.invoke.MethodHandle::class.java.getMethod("type").invoke(actualTarget) as MethodType
        assertEquals(type, actualType)
    }

    private companion object {
        @JvmStatic
        private fun foreignStringTarget(token: ByteArray): String =
            "foreign-${token.size}"
    }
}
