package io.github.hht0rro.javashroud.hardening

import io.github.hht0rro.javashroud.transforms.protection.hardening.IndyTargetTokenEnvelope
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.Opcodes

class IndyTargetTokenEnvelopeTest {
    @Test
    fun site_keys_differ_and_round_trip_without_classfile_lanes() {
        val siteA = binding()
        val siteB = binding().copy(siteIndex = 8)
        val keyA = siteA.siteKey()
        val keyB = siteB.siteKey()
        assertEquals(16, keyA.size)
        assertFalse(keyA.contentEquals(keyB))
        val sealed = IndyTargetTokenEnvelope.seal(
            IndyTargetTokenEnvelope.Target("com/example/T", "work", "(I)I", Opcodes.H_INVOKESTATIC, false),
            siteA,
        )
        val opened = IndyTargetTokenEnvelope.open(sealed, siteA)
        assertEquals("work", opened.name)
        assertFailsWith<SecurityException> { IndyTargetTokenEnvelope.open(sealed, siteB) }
        val helper = javaClass.classLoader.getResourceAsStream(
            "io/github/hht0rro/javashroud/transforms/protection/IndyTargetBootstrap.class",
        )!!.use { it.readBytes() }
        fun hasLane(sentinel: Int): Boolean {
            val needle = byteArrayOf(
                ((sentinel ushr 24) and 0xFF).toByte(),
                ((sentinel ushr 16) and 0xFF).toByte(),
                ((sentinel ushr 8) and 0xFF).toByte(),
                (sentinel and 0xFF).toByte(),
            )
            outer@ for (start in 0..helper.size - 4) {
                for (i in 0 until 4) if (helper[start + i] != needle[i]) continue@outer
                return true
            }
            return false
        }
        assertFalse(hasLane(0x4A535230) && hasLane(0x4A535231) && hasLane(0x4A535232) && hasLane(0x4A535233))
    }

    @Test
    fun round_trip_with_nonzero_binding() {
        val sealed = token()
        val opened = IndyTargetTokenEnvelope.open(sealed, binding(), key())
        assertEquals("com/example/T", opened.owner)
        assertEquals("work", opened.name)
        assertEquals("(I)I", opened.descriptor)
        assertEquals(Opcodes.H_INVOKESTATIC, opened.tag)
        assertFalse(opened.isInterface)
        assertFalse(sealed.contains("com/example/T"))
        assertFalse(sealed.contains("work"))

        val raw = Base64.getUrlDecoder().decode(sealed)
        assertEquals('I'.code.toByte(), raw[0])
        assertEquals('T'.code.toByte(), raw[1])
        assertEquals('K'.code.toByte(), raw[2])
        assertEquals('1'.code.toByte(), raw[3])
        assertEquals(3, raw[4].toInt() and 0xFF)
        assertEquals(7, readU32be(raw, 5))
        assertTrue(binding().artifactDigest.contentEquals(raw.copyOfRange(9, 41)))
        assertTrue(canonicalAad(binding()).contentEquals(binding().aad()))
    }

    @Test
    fun ciphertext_nonce_and_tag_flips_fail_closed() {
        val sealed = token()
        val raw = Base64.getUrlDecoder().decode(sealed)
        val nonceIndex = 41
        val ciphertextIndex = 53
        val tagIndex = raw.size - 16
        assertFailsWith<SecurityException> { openFlipped(sealed, ciphertextIndex) }
        assertFailsWith<SecurityException> { openFlipped(sealed, nonceIndex) }
        assertFailsWith<SecurityException> { openFlipped(sealed, tagIndex) }
        val retiredVersion = raw.copyOf().also { it[4] = 2 }
        assertFailsWith<IllegalArgumentException> {
            IndyTargetTokenEnvelope.open(
                Base64.getUrlEncoder().withoutPadding().encodeToString(retiredVersion),
                binding(),
                key(),
            )
        }
    }

    @Test
    fun site_index_mismatch_fails_closed() {
        assertFailsWith<SecurityException> {
            IndyTargetTokenEnvelope.open(token(), binding().copy(siteIndex = 8), key())
        }
    }

    @Test
    fun artifact_digest_mismatch_fails_closed() {
        assertFailsWith<SecurityException> {
            IndyTargetTokenEnvelope.open(
                token(),
                binding().copy(artifactDigest = ByteArray(32) { 1 }),
                key(),
            )
        }
    }

    @Test
    fun caller_site_mismatch_fails_closed() {
        val sealed = token()
        assertFailsWith<SecurityException> {
            IndyTargetTokenEnvelope.open(sealed, binding().copy(callerOwner = "com/other/Z"), key())
        }
        assertFailsWith<SecurityException> {
            IndyTargetTokenEnvelope.open(sealed, binding().copy(indyName = "other"), key())
        }
        assertFailsWith<SecurityException> {
            IndyTargetTokenEnvelope.open(sealed, binding().copy(indyMethodType = "()V"), key())
        }
        val siteB = IndyTargetTokenEnvelope.Binding(
            artifactDigest = ByteArray(32) { (it + 4).toByte() },
            callerOwner = "com/site/B",
            indyName = "other",
            indyMethodType = "()V",
            siteIndex = 3,
        )
        assertFailsWith<SecurityException> { IndyTargetTokenEnvelope.open(sealed, siteB, key()) }
    }

    @Test
    fun version_1_token_fails_closed_as_unsupported() {
        val raw = Base64.getUrlDecoder().decode(token())
        raw[4] = 1
        val v1Patched = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        val patchedEx = assertFailsWith<IllegalArgumentException> {
            IndyTargetTokenEnvelope.open(v1Patched, binding(), key())
        }
        assertEquals("indy target token version is unsupported", patchedEx.message)

        val compactV1 = ByteArray(4 + 1 + 12 + 8 + 16)
        byteArrayOf('I'.code.toByte(), 'T'.code.toByte(), 'K'.code.toByte(), '1'.code.toByte()).copyInto(compactV1)
        compactV1[4] = 1
        val compactToken = Base64.getUrlEncoder().withoutPadding().encodeToString(compactV1)
        val compactEx = assertFailsWith<IllegalArgumentException> {
            IndyTargetTokenEnvelope.open(compactToken, binding(), key())
        }
        assertEquals("indy target token version is unsupported", compactEx.message)
    }

    private fun openFlipped(token: String, index: Int) {
        val raw = Base64.getUrlDecoder().decode(token)
        raw[index] = (raw[index].toInt() xor 1).toByte()
        IndyTargetTokenEnvelope.open(
            Base64.getUrlEncoder().withoutPadding().encodeToString(raw),
            binding(),
            key(),
        )
    }

    private fun token(): String = IndyTargetTokenEnvelope.seal(
        IndyTargetTokenEnvelope.Target("com/example/T", "work", "(I)I", Opcodes.H_INVOKESTATIC, false),
        binding(),
        key(),
        SecureRandom(byteArrayOf(1, 2, 3, 4)),
    )

    private fun binding(): IndyTargetTokenEnvelope.Binding = IndyTargetTokenEnvelope.Binding(
        artifactDigest = ByteArray(32) { (it * 3 + 11).toByte() },
        callerOwner = "com/foo/Bar",
        indyName = "run",
        indyMethodType = "(I)V",
        siteIndex = 7,
    )

    private fun key(): ByteArray = ByteArray(16) { (it + 3).toByte() }

    private fun canonicalAad(binding: IndyTargetTokenEnvelope.Binding): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(
            byteArrayOf(
                'J'.code.toByte(),
                'S'.code.toByte(),
                'I'.code.toByte(),
                'T'.code.toByte(),
                'K'.code.toByte(),
                'A'.code.toByte(),
                'A'.code.toByte(),
                'D'.code.toByte(),
                3,
            ),
        )
        updateLenPrefixed(digest, binding.callerOwner.toByteArray(Charsets.UTF_8))
        updateLenPrefixed(digest, binding.indyName.toByteArray(Charsets.UTF_8))
        updateLenPrefixed(digest, binding.indyMethodType.toByteArray(Charsets.UTF_8))
        updateU32be(digest, binding.siteIndex)
        digest.update(binding.artifactDigest)
        updateU32be(digest, binding.protocolVersion)
        return digest.digest()
    }

    private fun updateLenPrefixed(digest: MessageDigest, utf8: ByteArray) {
        updateU32be(digest, utf8.size)
        digest.update(utf8)
    }

    private fun updateU32be(digest: MessageDigest, value: Int) {
        digest.update((value ushr 24).toByte())
        digest.update((value ushr 16).toByte())
        digest.update((value ushr 8).toByte())
        digest.update(value.toByte())
    }

    private fun readU32be(src: ByteArray, offset: Int): Int =
        ((src[offset].toInt() and 0xFF) shl 24) or
            ((src[offset + 1].toInt() and 0xFF) shl 16) or
            ((src[offset + 2].toInt() and 0xFF) shl 8) or
            (src[offset + 3].toInt() and 0xFF)
}
