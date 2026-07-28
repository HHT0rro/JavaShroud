package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.Vbc4EntryMetadata
import io.github.hht0rro.javashroud.transforms.protection.Vbc4ZstdCodec
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import io.github.hht0rro.javashroud.transforms.protection.deriveVbc4Identity
import io.github.hht0rro.javashroud.transforms.protection.deriveVbc4OwnerIdentity
import io.github.hht0rro.javashroud.transforms.protection.vbc4ArgumentTagVector
import io.github.hht0rro.javashroud.transforms.protection.vbc4ReturnTag
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class Vbc4IdentityConfidentialityTest {
    @Test
    fun metadata_v2_contains_only_keyed_identity_and_call_shape() {
        val context = fixedContext(0x31)
        val owner = "example/SecretLicenseService"
        val name = "verifySubscription"
        val descriptor = "(Ljava/lang/String;[BJD)Ljava/lang/Boolean;"
        val encoded = Vbc4EntryMetadata(
            entryToken = 0x1234_5678L,
            returnDescriptor = vbc4ReturnTag(descriptor),
            methodLocalProfile = 0x5151,
            methodIdentity = context.deriveVbc4Identity(owner, name, descriptor),
            ownerIdentity = context.deriveVbc4OwnerIdentity(owner),
            argumentTags = vbc4ArgumentTagVector(descriptor),
            resourcePath = "r/a.bin",
            isStatic = true,
        ).encode()

        assertTrue(encoded.startsWith("vbc4-meta-v2|"))
        assertFalse(encoded.contains(owner))
        assertFalse(encoded.contains(name))
        assertFalse(encoded.contains(descriptor))
        assertTrue(encoded.contains("|L[JD|"))
        assertEquals(11, encoded.split('|').size)
    }

    @Test
    fun identities_are_256_bit_keyed_and_build_local() {
        val owner = "example/SecretLicenseService"
        val name = "verifySubscription"
        val descriptor = "(I)Z"
        val first = fixedContext(0x41).deriveVbc4Identity(owner, name, descriptor)
        val second = fixedContext(0x42).deriveVbc4Identity(owner, name, descriptor)

        assertEquals(64, first.length)
        assertTrue(first.all { it in '0'..'9' || it in 'a'..'f' })
        assertNotEquals(first, second)
    }

    @Test
    fun real_serializer_seals_identity_strings_and_rejects_wrong_keys_and_tag_tampering() {
        val context = fixedContext(0x51)
        val wrongContext = fixedContext(0x52)
        val owner = "example/SecretIdentityFixture"
        val name = "recursiveSecret"
        val descriptor = "(I)Ljava/lang/Class;"
        val selfType = "L$owner;"
        val selfReference = "$owner.$name:$descriptor"
        val modifiedUtf8 = "modified:\u0000\u007f\u0080\u07ff\u0800\ud83d\ude03"
        val stateBinding = "identity-confidentiality-fixture"
        val metadata = Vbc4EntryMetadata(
            entryToken = 0x0102_0304_0506_0708L,
            returnDescriptor = vbc4ReturnTag(descriptor),
            methodLocalProfile = 0x1357,
            methodIdentity = context.deriveVbc4Identity(owner, name, descriptor),
            ownerIdentity = context.deriveVbc4OwnerIdentity(owner),
            argumentTags = vbc4ArgumentTagVector(descriptor),
            resourcePath = "r/identity-fixture.bin",
            isStatic = true,
        )
        val serializer = VmBytecodeSerializer(
            buildSeed = 0x2468_1357,
            stateBinding = stateBinding,
            entryMetadata = metadata,
            buildContext = context,
            structureEntropy = ByteArray(32) { index -> (index * 17 + 9).toByte() },
        )
        serializer.visitCode()
        serializer.visitLdcInsn(modifiedUtf8)
        serializer.visitInsn(Opcodes.POP)
        serializer.visitLdcInsn(0x1357_9BDF)
        serializer.visitInsn(Opcodes.POP)
        serializer.visitLdcInsn(0x1020_3040_5060_7080L)
        serializer.visitInsn(Opcodes.POP2)
        serializer.visitLdcInsn(123.25f)
        serializer.visitInsn(Opcodes.POP)
        serializer.visitLdcInsn(-9876.5)
        serializer.visitInsn(Opcodes.POP2)
        serializer.visitLdcInsn(Type.getObjectType(owner))
        serializer.visitInsn(Opcodes.POP)
        serializer.visitInsn(Opcodes.ICONST_1)
        serializer.visitMethodInsn(Opcodes.INVOKESTATIC, owner, name, descriptor, false)
        serializer.visitInsn(Opcodes.POP)
        serializer.visitInsn(Opcodes.RETURN)
        serializer.visitMaxs(4, 1)
        serializer.visitEnd()

        val payload = serializer.serialize()
        val forbiddenIdentityStrings = listOf(owner, name, descriptor, selfType, selfReference)
        forbiddenIdentityStrings.forEach { value ->
            assertFalse(payload.containsBytes(value.toByteArray(Charsets.UTF_8)), "VBC4 payload exposed $value")
        }
        assertFails("A different build context must not unwrap the VBC4 seed token") {
            parseConstantPool(payload, wrongContext, stateBinding)
        }

        val parsed = parseConstantPool(payload, context, stateBinding)
        forbiddenIdentityStrings.forEach { value ->
            assertFalse(parsed.outerPlain.containsBytes(value.toByteArray(Charsets.UTF_8)), "Outer CP exposed $value")
            parsed.entries.forEach { entry ->
                assertFalse(entry.containsBytes(value.toByteArray(Charsets.UTF_8)), "Sealed CP entry exposed $value")
            }
        }

        val strings = mutableListOf<String>()
        val integers = mutableListOf<Int>()
        val longs = mutableListOf<Long>()
        val floats = mutableListOf<Float>()
        val doubles = mutableListOf<Double>()
        val sealedStrings = mutableListOf<ByteArray>()
        val buildKey = context.deriveVmBuildKey()
        try {
            parsed.entries.forEach { entry ->
                when (entry.u1(0)) {
                    CP_SEALED_STRING -> {
                        assertEquals(CP_SEALED_STRING_VERSION, entry.u1(1), "String CP entries must use the authenticated v1 envelope")
                        sealedStrings += entry
                        strings += requireNotNull(decodeSealedString(entry, buildKey)) { "Correct build key must authenticate the string CP entry" }
                    }
                    CP_INT -> integers += entry.i4(1)
                    CP_LONG -> longs += entry.i8(1)
                    CP_FLOAT -> floats += Float.fromBits(entry.i4(1))
                    CP_DOUBLE -> doubles += Double.fromBits(entry.i8(1))
                    else -> error("Unexpected VBC4 constant-pool type ${entry.u1(0)}")
                }
            }
        } finally {
            Arrays.fill(buildKey, 0)
        }

        val encodedMetadata = strings.single { it.startsWith("vbc4-meta-v2|") }
        assertFalse(encodedMetadata.contains(owner))
        assertFalse(encodedMetadata.contains(name))
        assertFalse(encodedMetadata.contains(descriptor))
        assertTrue(selfType in strings, "Real serializer fixture must include the self Type constant")
        assertTrue(selfReference in strings, "Real serializer fixture must include the recursive self-call reference")
        assertTrue(modifiedUtf8 in strings, "Modified UTF-8 must round-trip through the sealed string CP")
        assertTrue(0x1357_9BDF in integers)
        assertTrue(0x1020_3040_5060_7080L in longs)
        assertTrue(123.25f in floats)
        assertTrue(-9876.5 in doubles)

        val sealed = sealedStrings.first()
        val wrongBuildKey = wrongContext.deriveVmBuildKey()
        try {
            assertEquals(null, decodeSealedString(sealed, wrongBuildKey), "A different build key must fail string CP authentication")
        } finally {
            Arrays.fill(wrongBuildKey, 0)
        }
        val tampered = sealed.copyOf().also { bytes ->
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
        }
        val verificationKey = context.deriveVmBuildKey()
        try {
            assertEquals(null, decodeSealedString(tampered, verificationKey), "String CP tag tampering must fail closed")
        } finally {
            Arrays.fill(verificationKey, 0)
        }
    }

    private fun parseConstantPool(payload: ByteArray, context: Vbc4BuildContext, stateBinding: String): ParsedConstantPool {
        require(payload.size >= VBC4_HEADER_SIZE + VBC4_MAC_SIZE + 1)
        require(payload.copyOfRange(0, 4).contentEquals("VBC4".toByteArray(Charsets.US_ASCII)))
        require(payload.u2(4) == VBC4_VERSION)
        val nonce = payload.copyOfRange(6, 22)
        val declaredKeyId = payload.i4(22)
        val wrappedSeed = payload.copyOfRange(26, 42)
        val binding = stateBinding.toByteArray(Charsets.UTF_8)
        val seedMask = vbc4Hmac(context, "vbc4-seed-wrap", 0, nonce, binding)
        val seed = try {
            payloadInt(wrappedSeed, seedMask)
        } finally {
            Arrays.fill(seedMask, 0)
        }
        val expectedSeedToken = vbc4Hmac(context, "vbc4-seed-token", seed, nonce, binding)
        try {
            require(MessageDigest.isEqual(expectedSeedToken.copyOfRange(0, 12), wrappedSeed.copyOfRange(4, 16))) {
                "VBC4 wrapped seed token authentication failed"
            }
        } finally {
            Arrays.fill(expectedSeedToken, 0)
        }
        val expectedKeyId = vbc4Hmac(context, "vbc4-key-id", seed, nonce)
        try {
            require(expectedKeyId.i4(0) == declaredKeyId) { "VBC4 key id mismatch" }
        } finally {
            Arrays.fill(expectedKeyId, 0)
        }
        val macOffset = payload.size - VBC4_MAC_SIZE - 1
        require(payload.u1(payload.lastIndex) == VBC4_MAC_SIZE)
        val authenticatedPayload = payload.copyOfRange(0, macOffset)
        val expectedMac = vbc4Hmac(context, authenticatedPayload, seed, nonce)
        try {
            require(MessageDigest.isEqual(expectedMac, payload.copyOfRange(macOffset, macOffset + VBC4_MAC_SIZE))) {
                "VBC4 payload MAC mismatch"
            }
        } finally {
            Arrays.fill(expectedMac, 0)
            Arrays.fill(authenticatedPayload, 0)
        }

        val flags = payload.u2(42)
        require(flags and (FLAG_ENCRYPTED_CP or FLAG_PER_ENTRY_CP) == (FLAG_ENCRYPTED_CP or FLAG_PER_ENTRY_CP))
        val declaredPlainSize = payload.i4(46)
        val outerLength = payload.i4(50)
        require(declaredPlainSize >= 2 && outerLength >= 4 && VBC4_HEADER_SIZE + outerLength <= macOffset)
        val outerCiphertext = payload.copyOfRange(VBC4_HEADER_SIZE, VBC4_HEADER_SIZE + outerLength)
        val outerPlain = cryptVbc4(context, outerCiphertext, seed, nonce, SECTION_CP, 0)
        val cursor = Cursor(outerPlain)
        require(cursor.u2() == CP_SECTION_VERSION)
        val count = cursor.u2()
        val entries = ArrayList<ByteArray>(count)
        repeat(count) { index ->
            val plainLength = cursor.i4()
            val encodedStoredLength = cursor.i4()
            val encryptedLength = cursor.i4()
            require(plainLength > 0 && encryptedLength >= 0)
            val compressed = encodedStoredLength and STORED_ZSTD_FLAG != 0
            val storedLength = encodedStoredLength and STORED_LENGTH_MASK
            require(storedLength == encryptedLength)
            val encrypted = cursor.bytes(encryptedLength)
            val stored = cryptVbc4(context, encrypted, seed, nonce, SECTION_CP_ENTRY, index)
            val plain = if (compressed) {
                Vbc4ZstdCodec.decompress(stored, plainLength)
                    ?: error("Invalid compressed VBC4 CP entry")
            } else {
                require(stored.size == plainLength)
                stored
            }
            entries += plain
        }
        require(cursor.exhausted())
        require(2 + entries.sumOf { it.size } == declaredPlainSize)
        return ParsedConstantPool(outerPlain, entries)
    }

    private fun decodeSealedString(entry: ByteArray, buildKey: ByteArray): String? {
        if (entry.size < 1 + 1 + 16 + 2 + 32 || entry.u1(0) != CP_SEALED_STRING || entry.u1(1) != CP_SEALED_STRING_VERSION) return null
        val nonce = entry.copyOfRange(2, 18)
        val ciphertextLength = entry.u2(18)
        val ciphertextOffset = 20
        val tagOffset = ciphertextOffset + ciphertextLength
        if (tagOffset + 32 != entry.size) return null
        val ciphertext = entry.copyOfRange(ciphertextOffset, tagOffset)
        val actualTag = entry.copyOfRange(tagOffset, entry.size)
        val expectedTag = hmac(buildKey, CP_STRING_TAG_DOMAIN, nonce, ciphertext)
        if (!MessageDigest.isEqual(expectedTag, actualTag)) {
            Arrays.fill(expectedTag, 0)
            Arrays.fill(ciphertext, 0)
            Arrays.fill(nonce, 0)
            return null
        }
        val keyMaterial = hmac(buildKey, CP_STRING_KEY_DOMAIN, nonce)
        val ivMaterial = hmac(buildKey, CP_STRING_IV_DOMAIN, nonce)
        val key = keyMaterial.copyOfRange(0, 16)
        val iv = ivMaterial.copyOfRange(0, 16)
        return try {
            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            decodeModifiedUtf8(cipher.doFinal(ciphertext))
        } finally {
            Arrays.fill(expectedTag, 0)
            Arrays.fill(keyMaterial, 0)
            Arrays.fill(ivMaterial, 0)
            Arrays.fill(key, 0)
            Arrays.fill(iv, 0)
            Arrays.fill(ciphertext, 0)
            Arrays.fill(nonce, 0)
        }
    }

    private fun decodeModifiedUtf8(bytes: ByteArray): String {
        require(bytes.size <= 0xFFFF)
        val framed = ByteArray(bytes.size + 2)
        framed[0] = (bytes.size ushr 8).toByte()
        framed[1] = bytes.size.toByte()
        bytes.copyInto(framed, 2)
        return try {
            DataInputStream(ByteArrayInputStream(framed)).use { it.readUTF() }
        } finally {
            Arrays.fill(framed, 0)
            Arrays.fill(bytes, 0)
        }
    }

    private fun cryptVbc4(
        context: Vbc4BuildContext,
        data: ByteArray,
        seed: Int,
        nonce: ByteArray,
        section: Int,
        blockId: Int,
    ): ByteArray {
        val keyMaterial = vbc4Hmac(context, "vbc4-aes-key", seed, nonce, intBytes(section), intBytes(blockId))
        val ivMaterial = vbc4Hmac(context, "vbc4-aes-iv", seed, nonce, intBytes(section), intBytes(blockId))
        val key = keyMaterial.copyOfRange(0, 16)
        val iv = ivMaterial.copyOfRange(0, 16)
        return try {
            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            cipher.doFinal(data)
        } finally {
            Arrays.fill(keyMaterial, 0)
            Arrays.fill(ivMaterial, 0)
            Arrays.fill(key, 0)
            Arrays.fill(iv, 0)
        }
    }

    private fun vbc4Hmac(context: Vbc4BuildContext, label: String, seed: Int, vararg parts: ByteArray): ByteArray =
        vbc4Hmac(context, label.toByteArray(Charsets.US_ASCII), seed, *parts)

    private fun vbc4Hmac(context: Vbc4BuildContext, label: ByteArray, seed: Int, vararg parts: ByteArray): ByteArray {
        val masterKey = context.copyMasterKey()
        val sessionMaterial = try {
            MessageDigest.getInstance("SHA-256").apply {
                update("vbc4-session-integrity".toByteArray(Charsets.US_ASCII))
                update(masterKey)
                update(context.jarLayoutDigest)
                update(byteArrayOf(0x10, 0x42, 0x9F.toByte(), 0x6C))
            }.digest()
        } finally {
            Arrays.fill(masterKey, 0)
        }
        val scopedParts = arrayOf(intBytes(seed), *parts, label)
        val scopedKey = try {
            hmac(sessionMaterial, *scopedParts)
        } finally {
            Arrays.fill(sessionMaterial, 0)
        }
        return try {
            hmac(scopedKey, *scopedParts)
        } finally {
            Arrays.fill(scopedKey, 0)
        }
    }

    private fun hmac(key: ByteArray, vararg parts: ByteArray): ByteArray = Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach(::update)
        doFinal()
    }

    private fun payloadInt(wrappedSeed: ByteArray, mask: ByteArray): Int =
        (((wrappedSeed[0].toInt() xor mask[0].toInt()) and 0xFF) shl 24) or
            (((wrappedSeed[1].toInt() xor mask[1].toInt()) and 0xFF) shl 16) or
            (((wrappedSeed[2].toInt() xor mask[2].toInt()) and 0xFF) shl 8) or
            ((wrappedSeed[3].toInt() xor mask[3].toInt()) and 0xFF)

    private fun intBytes(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

    private fun ByteArray.containsBytes(needle: ByteArray): Boolean =
        needle.isNotEmpty() && indices.any { start ->
            start <= size - needle.size && needle.indices.all { offset -> this[start + offset] == needle[offset] }
        }

    private fun ByteArray.u1(offset: Int): Int {
        require(offset in indices)
        return this[offset].toInt() and 0xFF
    }

    private fun ByteArray.u2(offset: Int): Int {
        require(offset >= 0 && offset + 2 <= size)
        return (u1(offset) shl 8) or u1(offset + 1)
    }

    private fun ByteArray.i4(offset: Int): Int {
        require(offset >= 0 && offset + 4 <= size)
        return (u1(offset) shl 24) or (u1(offset + 1) shl 16) or (u1(offset + 2) shl 8) or u1(offset + 3)
    }

    private fun ByteArray.i8(offset: Int): Long {
        require(offset >= 0 && offset + 8 <= size)
        var value = 0L
        repeat(8) { index -> value = (value shl 8) or u1(offset + index).toLong() }
        return value
    }

    private data class ParsedConstantPool(val outerPlain: ByteArray, val entries: List<ByteArray>)

    private class Cursor(private val bytes: ByteArray) {
        private var offset = 0

        fun u2(): Int = take(2).u2(0)
        fun i4(): Int = take(4).i4(0)
        fun bytes(length: Int): ByteArray = take(length)
        fun exhausted(): Boolean = offset == bytes.size

        private fun take(length: Int): ByteArray {
            require(length >= 0 && offset <= bytes.size - length)
            return bytes.copyOfRange(offset, offset + length).also { offset += length }
        }
    }

    private fun fixedContext(seed: Int): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (seed + index * 5).toByte() },
        nativeSeed = seed.toLong(),
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (seed xor index * 11).toByte() },
    )

    private companion object {
        const val VBC4_VERSION = 4
        const val VBC4_HEADER_SIZE = 54
        const val VBC4_MAC_SIZE = 32
        const val FLAG_ENCRYPTED_CP = 0x0001
        const val FLAG_PER_ENTRY_CP = 0x0040
        const val SECTION_CP = 1
        const val SECTION_CP_ENTRY = 9
        const val CP_SECTION_VERSION = 1
        const val STORED_ZSTD_FLAG = Int.MIN_VALUE
        const val STORED_LENGTH_MASK = Int.MAX_VALUE
        const val CP_INT = 0x02
        const val CP_LONG = 0x03
        const val CP_FLOAT = 0x04
        const val CP_DOUBLE = 0x05
        const val CP_SEALED_STRING = 0x06
        const val CP_SEALED_STRING_VERSION = 1
        val CP_STRING_KEY_DOMAIN = "javashroud-vbc4-cp-string-key-v1".toByteArray(Charsets.US_ASCII)
        val CP_STRING_IV_DOMAIN = "javashroud-vbc4-cp-string-iv-v1".toByteArray(Charsets.US_ASCII)
        val CP_STRING_TAG_DOMAIN = "javashroud-vbc4-cp-string-tag-v1".toByteArray(Charsets.US_ASCII)
    }
}
