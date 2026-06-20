package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper
import io.github.hht0rro.javashroud.transforms.protection.VBC4_DERIVE_LABEL_CLASS_ENCRYPTION
import io.github.hht0rro.javashroud.transforms.protection.hkdfSha256
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

import kotlin.test.assertFailsWith

/**
 * TASK-205 gate. The class-encryption key derivation uses ONE shared HKDF-SHA256
 * (RFC 5869) skeleton across build (Kotlin) and runtime (native). This test:
 *  (a) pins the Kotlin HKDF primitive to the official RFC 5869 Test Case 1 vector
 *      so the shared skeleton is provably standard HKDF-SHA256, and
 *  (b) asserts the Java->native bridge is fail-closed (no Java fallback) when the
 *      sealed native kernel is absent, so the root key/derivation never live in
 *      distributable Java bytecode (SEC-001/SEC-003, TASK-106/TASK-201/202).
 * Runtime byte-for-byte parity with the native C derivation is guaranteed by both
 * sides being RFC 5869 HKDF-SHA256 over the same label + keyId||salt info, and is
 * exercised end-to-end by the class-encryption round-trip in a produced artifact.
 */
class CrossLanguageDerivationTest {
    private fun hex(s: String): ByteArray {
        val clean = s.filter { !it.isWhitespace() }
        return ByteArray(clean.length / 2) { ((clean.substring(it * 2, it * 2 + 2)).toInt(16)).toByte() }
    }

    @Test
    fun shared_hkdf_skeleton_matches_rfc5869_test_case_1() {
        val ikm = hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val expectedOkm = hex(
            "3cb25f25faacd57a90434f64d0362f2a" +
                "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                "34007208d5b887185865",
        )
        val okm = hkdfSha256(ikm = ikm, salt = salt, info = info, length = 42)
        assertTrue(okm.contentEquals(expectedOkm), "Kotlin HKDF must match RFC 5869 Test Case 1 OKM")
    }

    @Test
    fun build_label_constant_is_the_native_jse_class_label() {
        assertEquals("javashroud-vbc4-jse-class-v1", VBC4_DERIVE_LABEL_CLASS_ENCRYPTION)
    }

    @Test
    fun java_class_key_derivation_is_native_only_fail_closed() {
        val keyId = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val salt = ByteArray(16) { (it * 3 + 1).toByte() }
        assertFailsWith<SecurityException>("class-key derivation must fail closed without the sealed native kernel") {
            JniMicrokernelHelper.deriveClassEncryptionKey(keyId, salt, 32)
        }
    }
}
