package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.concatBytes
import io.github.hht0rro.javashroud.transforms.protection.hkdfSha256
import io.github.hht0rro.javashroud.transforms.protection.qp.NativeSecretPackLiterals
import io.github.hht0rro.javashroud.transforms.protection.qp.NativeVmSecretPackDraft
import io.github.hht0rro.javashroud.transforms.protection.qp.NativeVmSecretPack
import io.github.hht0rro.javashroud.transforms.protection.qp.QpResourceKind
import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeVmSecretPackTest {
    private fun u32be(value: Int): ByteArray = byteArrayOf(
        ((value ushr 24) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte(),
    )

    /** Mirrors the native authority derivation for parity assertions. */
    private fun deriveLikeNative(
        seed: ByteArray,
        slot: Int,
        kind: QpResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
        locatorToken: ByteArray,
        pageNonce: ByteArray,
        preNativeCommitment: ByteArray,
        nativeIdentity: ByteArray,
    ): ByteArray = hkdfSha256(
        ikm = seed,
        salt = "javashroud-qp-page-key-v6".encodeToByteArray(),
        info = concatBytes(
            arrayOf(
                preNativeCommitment,
                u32be(slot),
                byteArrayOf(kind.id.toByte()),
                u32be(pageIndex),
                encodedHandle,
                locatorToken,
                pageNonce,
                nativeIdentity,
            ),
        ),
        length = 32,
    )

    private fun commitmentLikeNative(seed: ByteArray, pageKey: ByteArray): ByteArray {
        val commitmentKey = hkdfSha256(
            ikm = seed,
            salt = "javashroud-qp-secret-commitment-v6".encodeToByteArray(),
            info = ByteArray(0),
            length = 32,
        )
        try {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(commitmentKey, "HmacSHA256"))
            return mac.doFinal(pageKey)
        } finally {
            Arrays.fill(commitmentKey, 0)
        }
    }

    @Test
    fun every_page_receives_a_unique_slot_seed_and_unique_key_commitment() {
        val draft = testSecretPackDraft()
        try {
            val slots = IntArray(8) { draft.registerSlot() }
            assertEquals((0..7).toList(), slots.toList())

            val commitments = LinkedHashSet<String>()
            val digests = LinkedHashSet<String>()
            slots.forEachIndexed { index, slot ->
                val handle = ByteArray(24) { (it + index).toByte() }
                val locator = ByteArray(16) { (it * 3 + index).toByte() }
                val nonce = ByteArray(12) { (it * 7 + index).toByte() }
                val key = draft.pageKey(
                    slotId = slot,
                    resourceKind = QpResourceKind.QpMethod,
                    pageIndex = index,
                    encodedHandle = handle,
                    locatorToken = locator,
                    pageNonce = nonce,
                    preNativeCommitment = ByteArray(32) { 0x40 },
                )
                try {
                    val commitment = draft.keyCommitment(slot, key)
                    assertTrue(commitment.any { it != 0.toByte() })
                    assertEquals(32, commitment.size)
                    digests += MessageDigest.getInstance("SHA-256").digest(key).joinToString(",")
                    commitments += commitment.joinToString(",")
                    Arrays.fill(key, 0)
                } finally {
                    Arrays.fill(handle, 0)
                    Arrays.fill(locator, 0)
                    Arrays.fill(nonce, 0)
                }
            }
            assertEquals(slots.size, digests.size, "derived page keys must be unique per slot")
            assertEquals(slots.size, commitments.size, "key commitments must be unique per slot")
        } finally {
            draft.wipe()
        }
    }

    @Test
    fun native_derivation_parity_holds_and_wrong_binding_inputs_fail_the_commitment() {
        val draft = testSecretPackDraft()
        try {
            val slot = draft.registerSlot()
            val handle = ByteArray(24) { (it + 1).toByte() }
            val locator = ByteArray(16) { (it + 2).toByte() }
            val nonce = ByteArray(12) { (it + 3).toByte() }
            val preNativeCommitment = ByteArray(32) { (it + 4).toByte() }
            val key = draft.pageKey(
                slotId = slot,
                resourceKind = QpResourceKind.StringPage,
                pageIndex = 5,
                encodedHandle = handle,
                locatorToken = locator,
                pageNonce = nonce,
                preNativeCommitment = preNativeCommitment,
            )
            try {
                val commitment = draft.keyCommitment(slot, key)
                val nativeIdentity = draft.copyNativeIdentity()
                try {
                    // Parity: the native-side structured derivation over the
                    // same slot seed must reproduce the exact page key.
                    val parityKey = deriveLikeNative(
                        seed = seedOf(draft, slot),
                        slot = slot,
                        kind = QpResourceKind.StringPage,
                        pageIndex = 5,
                        encodedHandle = handle,
                        locatorToken = locator,
                        pageNonce = nonce,
                        preNativeCommitment = preNativeCommitment,
                        nativeIdentity = nativeIdentity,
                    )
                    try {
                        assertContentEquals(key, parityKey)
                        assertContentEquals(commitment, commitmentLikeNative(seedOf(draft, slot), parityKey))
                    } finally {
                        Arrays.fill(parityKey, 0)
                    }
                } finally {
                    Arrays.fill(nativeIdentity, 0)
                }

                // Wrong slot: a different seed yields a different key, so the
                // descriptor-bound commitment cannot authenticate.
                val otherSlot = draft.registerSlot()
                val wrongSlotKey = draft.pageKey(
                    slotId = otherSlot,
                    resourceKind = QpResourceKind.StringPage,
                    pageIndex = 5,
                    encodedHandle = handle,
                    locatorToken = locator,
                    pageNonce = nonce,
                    preNativeCommitment = preNativeCommitment,
                )
                try {
                    assertFalse(key.contentEquals(wrongSlotKey))
                    assertFalse(commitment.contentEquals(draft.keyCommitment(otherSlot, wrongSlotKey)))
                } finally {
                    Arrays.fill(wrongSlotKey, 0)
                }

                // Wrong page identity or nonce: commitment mismatch.
                val wrongHandle = handle.copyOf().also { it[0] = (it[0].toInt() xor 0x5A).toByte() }
                try {
                    val shifted = draft.pageKey(
                        slotId = slot,
                        resourceKind = QpResourceKind.StringPage,
                        pageIndex = 5,
                        encodedHandle = wrongHandle,
                        locatorToken = locator,
                        pageNonce = nonce,
                        preNativeCommitment = preNativeCommitment,
                    )
                    try {
                        assertFalse(key.contentEquals(shifted))
                    } finally {
                        Arrays.fill(shifted, 0)
                    }
                } finally {
                    Arrays.fill(wrongHandle, 0)
                }
            } finally {
                Arrays.fill(key, 0)
                Arrays.fill(handle, 0)
                Arrays.fill(locator, 0)
                Arrays.fill(nonce, 0)
                Arrays.fill(preNativeCommitment, 0)
            }
        } finally {
            draft.wipe()
        }
    }

    @Test
    fun loader_only_sealed_copy_has_zero_slots_and_still_carries_native_identity() {
        val draft = testSecretPackDraft()
        try {
            val sealed = draft.sealedCopyForSpecialization()
            try {
                assertEquals(0, sealed.slotCount)
                assertEquals(32, sealed.nativeIdentity.size)
                assertTrue(sealed.nativeIdentity.any { it != 0.toByte() })
                assertTrue(sealed.slotsForSpecialization().isEmpty())
            } finally {
                sealed.wipe()
            }
        } finally {
            draft.wipe()
        }
    }

    @Test
    fun sealed_specialization_copies_are_consistent_and_wipe_is_final() {
        val draft = testSecretPackDraft()
        try {
            repeat(3) { draft.registerSlot() }
            val first = draft.sealedCopyForSpecialization()
            val second = draft.sealedCopyForSpecialization()
            try {
                assertEquals(first.slotCount, second.slotCount)
                assertContentEquals(first.nativeIdentity, second.nativeIdentity)
                assertEquals(3, first.slotCount)
                assertTrue(first.slotsForSpecialization().all { !it.isWiped })
            } finally {
                first.wipe()
                second.wipe()
            }
            // A wiped sealed copy must hand out no material.
            val sealed = draft.sealedCopyForSpecialization()
            sealed.wipe()
            assertTrue(sealed.isWiped)
            assertFailsWith<IllegalStateException> {
                sealed.slotsForSpecialization()
            }
        } finally {
            draft.wipe()
        }
    }

    @Test
    fun image_digest_ignores_commitment_slot_and_binds_the_rest() {
        val bytes = samplePeWithMeasurement()
        val first = io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement.digest(bytes)
        bytes[0x208] = 0x5A
        val second = io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement.digest(bytes)
        assertContentEquals(first, second)
        bytes[0x230] = (bytes[0x230].toInt() xor 0x01).toByte()
        val third = io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement.digest(bytes)
        assertFalse(first.contentEquals(third))
    }

    @Test
    fun aead_wrap_shards_open_only_under_the_image_commitment() {
        val draft = testSecretPackDraft()
        try {
            val slot = draft.registerSlot()
            val handle = ByteArray(24) { it.toByte() }
            val locator = ByteArray(16) { it.toByte() }
            val pageNonce = ByteArray(12) { it.toByte() }
            draft.pageKey(
                slotId = slot,
                resourceKind = QpResourceKind.QpMethod,
                pageIndex = 0,
                encodedHandle = handle,
                locatorToken = locator,
                pageNonce = pageNonce,
                preNativeCommitment = ByteArray(32) { 0x40 },
            )
            val sealed = draft.sealedCopyForSpecialization()
            val literals = NativeSecretPackLiterals.prepare(
                pack = sealed,
                random = java.util.Random(7),
                cryptoDomain = ByteArray(32) { 0x11 },
                layoutDigest = ByteArray(32) { 0x22 },
            )
            try {
                assertEquals(8, literals.mbaWords.size)
                // The MBA immediates must reconstruct the static half exactly.
                val cm = ByteArray(32)
                literals.mbaWords.forEachIndexed { index, word ->
                    val value = word.multiplier * word.factor + word.addend
                    cm[index * 4] = (value ushr 24).toByte()
                    cm[index * 4 + 1] = (value ushr 16).toByte()
                    cm[index * 4 + 2] = (value ushr 8).toByte()
                    cm[index * 4 + 3] = value.toByte()
                }
                assertContentEquals(literals.measurementKey, cm)

                val imageCommitment = ByteArray(32) { (it * 5 + 1).toByte() }
                val blob = literals.sealForPlatform("windows-x64", imageCommitment)
                assertContentEquals(blob, literals.blobByPlatform().getValue("windows-x64"))
                assertFalse(blob.decodeToString().contains("QP_SP_S"))

                // Walk the shard container: magic 0x6A,0 || u16 count || shards.
                val buf = java.nio.ByteBuffer.wrap(blob)
                assertEquals(0x6A, buf.get().toInt() and 0xFF)
                assertEquals(0, buf.get().toInt())
                assertEquals(5, buf.short.toInt())
                var methodWrapped: ByteArray? = null
                var methodNonce: ByteArray? = null
                repeat(5) {
                    val kind = buf.get().toInt()
                    buf.get()
                    val nonceLength = buf.short.toInt()
                    assertEquals(12, nonceLength)
                    val length = buf.int
                    val shardNonce = ByteArray(nonceLength).also { buf.get(it) }
                    val wrappedShard = ByteArray(length).also { buf.get(it) }
                    if (kind == 1) {
                        methodWrapped = wrappedShard
                        methodNonce = shardNonce
                    }
                }
                assertTrue(buf.remaining() == 0)

                // The method shard opens under HMAC(cm, image commitment).
                val mac = Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(cm, "HmacSHA256"))
                val shardKey = mac.doFinal(imageCommitment)
                val aad = "javashroud-qp-secret-wrap-v6".encodeToByteArray()
                val openCipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                openCipher.init(
                    javax.crypto.Cipher.DECRYPT_MODE,
                    SecretKeySpec(shardKey, "AES"),
                    javax.crypto.spec.GCMParameterSpec(128, methodNonce),
                )
                openCipher.updateAAD(aad)
                val plaintext = openCipher.doFinal(methodWrapped)
                assertEquals(1, plaintext[0].toInt(), "method shard must echo its kind")
                assertTrue(plaintext.size > 5, "method shard must carry its slot record")

                // A different image commitment must fail the tag check.
                val wrongKey = mac.doFinal(ByteArray(32) { 0x5A })
                val badCipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
                badCipher.init(
                    javax.crypto.Cipher.DECRYPT_MODE,
                    SecretKeySpec(wrongKey, "AES"),
                    javax.crypto.spec.GCMParameterSpec(128, methodNonce),
                )
                badCipher.updateAAD(aad)
                assertFailsWith<Exception> { badCipher.doFinal(methodWrapped) }
            } finally {
                literals.wipe()
                sealed.wipe()
            }
        } finally {
            draft.wipe()
        }
    }

    private fun samplePeWithMeasurement(): ByteArray {
        val bytes = ByteArray(0x400)
        bytes[0] = 'M'.code.toByte()
        bytes[1] = 'Z'.code.toByte()
        bytes[0x3C] = 0x80.toByte()
        bytes[0x80] = 'P'.code.toByte()
        bytes[0x81] = 'E'.code.toByte()
        bytes[0x84] = 0x64
        bytes[0x85] = 0x86.toByte()
        bytes[0x86] = 1
        bytes[0x94] = 0xF0.toByte()
        bytes[0x98] = 0x0B
        bytes[0x99] = 0x02
        bytes[0x80 + 24 + 108] = 16
        val relocDir = 0x80 + 24 + 112 + 5 * 8
        bytes[relocDir] = 0x80.toByte()
        bytes[relocDir + 1] = 0x02
        bytes[relocDir + 4] = 8
        val iatDir = 0x80 + 24 + 112 + 12 * 8
        bytes[iatDir] = 0x88.toByte()
        bytes[iatDir + 1] = 0x02
        bytes[iatDir + 4] = 8
        val section = 0x80 + 24 + 0xF0
        bytes[section + 8] = 0x80.toByte()
        bytes[section + 9] = 0x02
        bytes[section + 12] = 0x00
        bytes[section + 13] = 0x02
        bytes[section + 16] = 0x80.toByte()
        bytes[section + 17] = 0x02
        bytes[section + 20] = 0x00
        bytes[section + 21] = 0x02
        val magic = io.github.hht0rro.javashroud.transforms.protection.qp.IMAGE_MEASUREMENT_MAGIC
        magic.copyInto(bytes, 0x200)
        bytes[0x280] = 0x11
        bytes[0x288] = 0x22
        return bytes
    }

    /** Re-derives one slot seed the way the draft does, for parity assertions. */
    private fun seedOf(draft: NativeVmSecretPackDraft, slot: Int): ByteArray {
        val sealed = draft.sealedCopyForSpecialization()
        return try {
            sealed.slotsForSpecialization().single { it.slotId == slot }.copySeedForSpecialization()
        } finally {
            sealed.wipe()
        }
    }
}
