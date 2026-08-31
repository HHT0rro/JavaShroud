package io.github.hht0rro.javashroud.hardening

import io.github.hht0rro.javashroud.transforms.protection.hardening.QpTargetTokenEnvelope
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue
import org.objectweb.asm.Opcodes

class QpTargetTokenEnvelopeTest {
    @Test
    fun site_keys_differ_and_round_trip_without_classfile_lanes() {
        val siteA = binding()
        val siteB = binding().copy(siteIndex = 8)
        val keyA = siteA.siteKey()
        val keyB = siteB.siteKey()
        assertEquals(16, keyA.size)
        assertFalse(keyA.contentEquals(keyB))
        val sealed = QpTargetTokenEnvelope.seal(
            QpTargetTokenEnvelope.Target("com/example/T", "work", "(I)I", Opcodes.H_INVOKESTATIC, false),
            siteA,
        )
        val opened = QpTargetTokenEnvelope.open(sealed, siteA)
        assertEquals("work", opened.name)
        assertFailsWith<SecurityException> { QpTargetTokenEnvelope.open(sealed, siteB) }
        val helper = javaClass.classLoader.getResourceAsStream(
            "io/github/hht0rro/javashroud/transforms/protection/qp/QpBootstrap.class",
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
        fun containsAscii(value: String): Boolean {
            val needle = value.toByteArray(Charsets.US_ASCII)
            outer@ for (start in 0..helper.size - needle.size) {
                for (i in needle.indices) if (helper[start + i] != needle[i]) continue@outer
                return true
            }
            return false
        }
        assertFalse(containsAscii("JSITKAAD"))
        assertFalse(containsAscii("JSITKKDF"))
        assertFalse(containsAscii("ITK1"))
    }

    @Test
    fun round_trip_with_nonzero_binding() {
        val sealed = token()
        val opened = QpTargetTokenEnvelope.open(sealed, binding(), key())
        assertEquals("com/example/T", opened.owner)
        assertEquals("work", opened.name)
        assertEquals("(I)I", opened.descriptor)
        assertEquals(Opcodes.H_INVOKESTATIC, opened.tag)
        assertFalse(opened.isInterface)
        assertFalse(sealed.contains("com/example/T"))
        assertFalse(sealed.contains("work"))

        val raw = Base64.getUrlDecoder().decode(sealed)
        assertFalse(raw.copyOf(4).contentEquals(byteArrayOf(0x49, 0x54, 0x4b, 0x31)))
        val expectedMagic = io.github.hht0rro.javashroud.transforms.protection.qp
            .qpNameSchedule(binding().artifactDigest)
            .use { schedule ->
                schedule.deriveMagic(
                    io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_TOKEN,
                )
            }
        assertContentEquals(
            expectedMagic,
            raw.copyOf(4),
        )
        assertEquals(4, raw[4].toInt() and 0xFF)
        assertEquals(7, readU32be(raw, 21))
        assertTrue(binding().artifactDigest.contentEquals(raw.copyOfRange(25, 57)))
        assertTrue(canonicalAad(binding()).contentEquals(binding().aad()))
    }

    @Test
    fun ciphertext_nonce_and_tag_flips_fail_closed() {
        val sealed = token()
        val raw = Base64.getUrlDecoder().decode(sealed)
        val nonceIndex = 57
        val ciphertextIndex = 69
        val tagIndex = raw.size - 16
        assertFailsWith<SecurityException> { openFlipped(sealed, ciphertextIndex) }
        assertFailsWith<SecurityException> { openFlipped(sealed, nonceIndex) }
        assertFailsWith<SecurityException> { openFlipped(sealed, tagIndex) }
        val retiredVersion = raw.copyOf().also { it[4] = 2 }
        assertFailsWith<IllegalArgumentException> {
            QpTargetTokenEnvelope.open(
                Base64.getUrlEncoder().withoutPadding().encodeToString(retiredVersion),
                binding(),
                key(),
            )
        }
    }

    @Test
    fun site_index_mismatch_fails_closed() {
        assertFailsWith<SecurityException> {
            QpTargetTokenEnvelope.open(token(), binding().copy(siteIndex = 8), key())
        }
    }

    @Test
    fun artifact_digest_mismatch_fails_closed() {
        assertFailsWith<SecurityException> {
            QpTargetTokenEnvelope.open(
                token(),
                binding().copy(artifactDigest = ByteArray(32) { 1 }),
                key(),
            )
        }
    }

    @Test
    fun early_token_rebinds_to_directory_commitment_and_rejects_old_or_tampered_binding() {
        val oldBinding = binding()
        val directoryCommitment = ByteArray(32) { index -> (index * 7 + 19).toByte() }
        val original = QpTargetTokenEnvelope.seal(
            QpTargetTokenEnvelope.Target(
                "com/example/T",
                "work",
                "(I)I",
                Opcodes.H_INVOKESTATIC,
                false,
            ),
            oldBinding,
        )
        val rebound = QpTargetTokenEnvelope.rebindArtifact(
            token = original,
            artifactDigest = directoryCommitment,
            callerOwner = oldBinding.callerOwner,
            indyName = oldBinding.indyName,
            indyMethodType = oldBinding.indyMethodType,
            random = SecureRandom(byteArrayOf(9, 8, 7, 6)),
        )
        val finalBinding = oldBinding.copy(artifactDigest = directoryCommitment)
        assertEquals("work", QpTargetTokenEnvelope.open(rebound, finalBinding).name)
        assertFailsWith<SecurityException> { QpTargetTokenEnvelope.open(rebound, oldBinding) }

        val raw = Base64.getUrlDecoder().decode(rebound)
        assertContentEquals(directoryCommitment, raw.copyOfRange(25, 57))
        val tamperedCommitment = raw.copyOf().also { bytes -> bytes[25] = (bytes[25].toInt() xor 1).toByte() }
        val tamperedToken = Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedCommitment)
        assertFalse(QpTargetTokenEnvelope.isToken(tamperedToken))
        assertFailsWith<SecurityException> {
            QpTargetTokenEnvelope.rebindArtifact(
                token = tamperedToken,
                artifactDigest = directoryCommitment,
                callerOwner = oldBinding.callerOwner,
                indyName = oldBinding.indyName,
                indyMethodType = oldBinding.indyMethodType,
            )
        }
    }

    @Test
    fun caller_site_mismatch_fails_closed() {
        val sealed = token()
        assertFailsWith<SecurityException> {
            QpTargetTokenEnvelope.open(sealed, binding().copy(callerOwner = "com/other/Z"), key())
        }
        assertFailsWith<SecurityException> {
            QpTargetTokenEnvelope.open(sealed, binding().copy(indyName = "other"), key())
        }
        assertFailsWith<SecurityException> {
            QpTargetTokenEnvelope.open(sealed, binding().copy(indyMethodType = "()V"), key())
        }
        val siteB = QpTargetTokenEnvelope.Binding(
            artifactDigest = ByteArray(32) { (it + 4).toByte() },
            callerOwner = "com/site/B",
            indyName = "other",
            indyMethodType = "()V",
            siteIndex = 3,
        )
        assertFailsWith<SecurityException> { QpTargetTokenEnvelope.open(sealed, siteB, key()) }
    }

    @Test
    fun protocol_version_mismatch_fails_closed_via_aad() {
        val sealed = token()
        val bindingWithDifferentProtocol = binding().copy(protocolVersion = 2)

        // The protocol version is authenticated AAD but is intentionally not part
        // of the derived site key or wire header. This proves updateAAD is effective.
        assertTrue(binding().siteKey().contentEquals(bindingWithDifferentProtocol.siteKey()))
        assertFailsWith<SecurityException> {
            QpTargetTokenEnvelope.open(sealed, bindingWithDifferentProtocol, key())
        }
    }

    @Test
    fun version_1_token_fails_closed_as_unsupported() {
        val raw = Base64.getUrlDecoder().decode(token())
        raw[4] = 1
        val v1Patched = Base64.getUrlEncoder().withoutPadding().encodeToString(raw)
        val patchedEx = assertFailsWith<IllegalArgumentException> {
            QpTargetTokenEnvelope.open(v1Patched, binding(), key())
        }
        assertEquals("indy target token version is unsupported", patchedEx.message)

        val compactV1 = ByteArray(4 + 1 + 12 + 8 + 16)
        io.github.hht0rro.javashroud.transforms.protection.qp.derivedTokenMagic().copyInto(compactV1)
        compactV1[4] = 1
        val compactToken = Base64.getUrlEncoder().withoutPadding().encodeToString(compactV1)
        val compactEx = assertFailsWith<IllegalArgumentException> {
            QpTargetTokenEnvelope.open(compactToken, binding(), key())
        }
        assertEquals("indy target token version is unsupported", compactEx.message)
    }

    private fun openFlipped(token: String, index: Int) {
        val raw = Base64.getUrlDecoder().decode(token)
        raw[index] = (raw[index].toInt() xor 1).toByte()
        QpTargetTokenEnvelope.open(
            Base64.getUrlEncoder().withoutPadding().encodeToString(raw),
            binding(),
            key(),
        )
    }

    private fun token(): String = QpTargetTokenEnvelope.seal(
        QpTargetTokenEnvelope.Target("com/example/T", "work", "(I)I", Opcodes.H_INVOKESTATIC, false),
        binding(),
        key(),
        SecureRandom(byteArrayOf(1, 2, 3, 4)),
    )

    private fun binding(): QpTargetTokenEnvelope.Binding = QpTargetTokenEnvelope.Binding(
        artifactDigest = ByteArray(32) { (it * 3 + 11).toByte() },
        callerOwner = "com/foo/Bar",
        indyName = "run",
        indyMethodType = "(I)V",
        siteIndex = 7,
    )

    private fun key(): ByteArray = ByteArray(16) { (it + 3).toByte() }

    private fun canonicalAad(binding: QpTargetTokenEnvelope.Binding): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        val domain = io.github.hht0rro.javashroud.transforms.protection.qp.qpNameSchedule(binding.artifactDigest).use {
            it.deriveDomain(
                io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_TOKEN,
                io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.LANE_TOKEN_AAD,
            )
        }
        digest.update(domain)
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
