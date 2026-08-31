package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.transforms.protection.hkdfSha256
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes

/**
 * Opaque invokedynamic target token. Classfiles store only this envelope;
 * owner/name/descriptor are recovered for a short lifetime and wiped.
 */
internal object QpTargetTokenEnvelope {
    const val KEY_SIZE = 16
    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16
    private const val VERSION: Int = ProtectionFormat.CURRENT
    private const val SITE_INDEX_SIZE = 4
    private const val ARTIFACT_DIGEST_SIZE = 32
    private val RETIRED_MAGIC = byteArrayOf(0x49, 0x54, 0x4b, 0x31)
    private const val MAGIC_SIZE = 4
    private const val NAME_SEED_SIZE = 16
    private const val NAME_SEED_OFFSET = MAGIC_SIZE + 1
    private const val SITE_OFFSET = NAME_SEED_OFFSET + NAME_SEED_SIZE
    private val HEADER_SIZE = SITE_OFFSET + SITE_INDEX_SIZE + ARTIFACT_DIGEST_SIZE

    data class Target(
        val owner: String,
        val name: String,
        val descriptor: String,
        val tag: Int,
        val isInterface: Boolean,
    ) {
        fun toHandle(): Handle = Handle(tag, owner, name, descriptor, isInterface)
    }

    data class Binding(
        val artifactDigest: ByteArray,
        val callerOwner: String,
        val indyName: String,
        val indyMethodType: String,
        val siteIndex: Int,
        val protocolVersion: Int = ProtectionFormat.CURRENT,
    ) {
        fun aad(nameSeed: ByteArray = io.github.hht0rro.javashroud.transforms.protection.qp.currentNameSeed()): ByteArray {
            require(artifactDigest.size == ARTIFACT_DIGEST_SIZE) { "indy token artifact digest must be 32 bytes" }
            val callerOwnerUtf8 = callerOwner.toByteArray(Charsets.UTF_8)
            val indyNameUtf8 = indyName.toByteArray(Charsets.UTF_8)
            val methodTypeUtf8 = indyMethodType.toByteArray(Charsets.UTF_8)
            val digest = MessageDigest.getInstance("SHA-256")
            val domain = tokenDomain(nameSeed, artifactDigest, aad = true)
            try {
                digest.update(domain)
            } finally {
                Arrays.fill(domain, 0)
            }
            updateLenPrefixed(digest, callerOwnerUtf8)
            updateLenPrefixed(digest, indyNameUtf8)
            updateLenPrefixed(digest, methodTypeUtf8)
            updateU32be(digest, siteIndex)
            digest.update(artifactDigest)
            updateU32be(digest, protocolVersion)
            return digest.digest()
        }

        fun siteKey(nameSeed: ByteArray = io.github.hht0rro.javashroud.transforms.protection.qp.currentNameSeed()): ByteArray {
            require(artifactDigest.size == ARTIFACT_DIGEST_SIZE) { "indy token artifact digest must be 32 bytes" }
            val callerOwnerUtf8 = callerOwner.toByteArray(Charsets.UTF_8)
            val indyNameUtf8 = indyName.toByteArray(Charsets.UTF_8)
            val methodTypeUtf8 = indyMethodType.toByteArray(Charsets.UTF_8)
            val info = ByteArray(16 + callerOwnerUtf8.size + indyNameUtf8.size + methodTypeUtf8.size)
            var offset = 0
            fun writeLenPrefixed(utf8: ByteArray) {
                info[offset] = (utf8.size ushr 24).toByte()
                info[offset + 1] = (utf8.size ushr 16).toByte()
                info[offset + 2] = (utf8.size ushr 8).toByte()
                info[offset + 3] = utf8.size.toByte()
                utf8.copyInto(info, offset + 4)
                offset += 4 + utf8.size
            }
            writeLenPrefixed(callerOwnerUtf8)
            writeLenPrefixed(indyNameUtf8)
            writeLenPrefixed(methodTypeUtf8)
            info[offset] = (siteIndex ushr 24).toByte()
            info[offset + 1] = (siteIndex ushr 16).toByte()
            info[offset + 2] = (siteIndex ushr 8).toByte()
            info[offset + 3] = siteIndex.toByte()
            val domain = tokenDomain(nameSeed, artifactDigest, aad = false)
            return try {
                hkdfSha256(artifactDigest, domain, info, KEY_SIZE)
            } finally {
                Arrays.fill(info, 0)
                Arrays.fill(domain, 0)
            }
        }
    }

    fun seal(target: Target, binding: Binding, random: SecureRandom = SecureRandom()): String {
        val key = binding.siteKey()
        try {
            return seal(target, binding, key, random)
        } finally {
            Arrays.fill(key, 0)
        }
    }

    fun open(token: String, binding: Binding): Target {
        val key = binding.siteKey()
        try {
            return open(token, binding, key)
        } finally {
            Arrays.fill(key, 0)
        }
    }

    fun seal(target: Target, binding: Binding, key: ByteArray, random: SecureRandom = SecureRandom()): String {
        val nameSeed = io.github.hht0rro.javashroud.transforms.protection.qp.currentNameSeed()
        return try {
            seal(target, binding, key, random, nameSeed)
        } finally {
            Arrays.fill(nameSeed, 0)
        }
    }

    private fun seal(
        target: Target,
        binding: Binding,
        key: ByteArray,
        random: SecureRandom,
        nameSeed: ByteArray,
    ): String {
        require(key.size == KEY_SIZE) { "indy token key must be 16 bytes" }
        require(binding.artifactDigest.size == ARTIFACT_DIGEST_SIZE) { "indy token artifact digest must be 32 bytes" }
        require(nameSeed.size == NAME_SEED_SIZE) { "indy token name seed must be 16 bytes" }
        val plaintext = encodeTarget(target)
        val nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
        var aad: ByteArray? = null
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
            aad = binding.aad(nameSeed)
            cipher.updateAAD(aad)
            val sealed = cipher.doFinal(plaintext)
            val ciphertext = sealed.copyOfRange(0, sealed.size - TAG_SIZE)
            val tag = sealed.copyOfRange(sealed.size - TAG_SIZE, sealed.size)
            val out = ByteArray(HEADER_SIZE + NONCE_SIZE + ciphertext.size + TAG_SIZE)
            val magic = tokenMagic(nameSeed, binding.artifactDigest)
            try {
                magic.copyInto(out)
            } finally {
                Arrays.fill(magic, 0)
            }
            out[MAGIC_SIZE] = VERSION.toByte()
            nameSeed.copyInto(out, NAME_SEED_OFFSET)
            writeU32be(out, SITE_OFFSET, binding.siteIndex)
            binding.artifactDigest.copyInto(out, SITE_OFFSET + SITE_INDEX_SIZE)
            nonce.copyInto(out, HEADER_SIZE)
            ciphertext.copyInto(out, HEADER_SIZE + NONCE_SIZE)
            tag.copyInto(out, HEADER_SIZE + NONCE_SIZE + ciphertext.size)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(out)
        } finally {
            Arrays.fill(plaintext, 0)
            Arrays.fill(nonce, 0)
            if (aad != null) Arrays.fill(aad, 0)
        }
    }

    fun open(token: String, binding: Binding, key: ByteArray): Target {
        require(key.size == KEY_SIZE) { "indy token key must be 16 bytes" }
        require(binding.artifactDigest.size == ARTIFACT_DIGEST_SIZE) { "indy token artifact digest must be 32 bytes" }
        val raw = try {
            Base64.getUrlDecoder().decode(token)
        } catch (_: RuntimeException) {
            throw SecurityException("indy target token is invalid")
        }
        require(raw.size > MAGIC_SIZE) { "indy target token is truncated" }
        require((raw[MAGIC_SIZE].toInt() and 0xFF) == VERSION) { "indy target token version is unsupported" }
        val suppliedMagic = raw.copyOf(MAGIC_SIZE)
        require(raw.size > HEADER_SIZE + NONCE_SIZE + TAG_SIZE) { "indy target token is truncated" }
        val nameSeed = raw.copyOfRange(NAME_SEED_OFFSET, NAME_SEED_OFFSET + NAME_SEED_SIZE)
        val headerDigest = raw.copyOfRange(SITE_OFFSET + SITE_INDEX_SIZE, HEADER_SIZE)
        val expectedMagic = tokenMagic(nameSeed, headerDigest)
        try {
            require(!suppliedMagic.contentEquals(RETIRED_MAGIC)) { "retired indy target token magic is rejected" }
            require(suppliedMagic.contentEquals(expectedMagic)) { "indy target token is invalid" }
        } finally {
            Arrays.fill(suppliedMagic, 0)
            Arrays.fill(expectedMagic, 0)
        }
        val headerSiteBytes = raw.copyOfRange(SITE_OFFSET, SITE_OFFSET + SITE_INDEX_SIZE)
        val expectedSiteBytes = u32be(binding.siteIndex)
        val nonce = raw.copyOfRange(HEADER_SIZE, HEADER_SIZE + NONCE_SIZE)
        val ciphertext = raw.copyOfRange(HEADER_SIZE + NONCE_SIZE, raw.size - TAG_SIZE)
        val tag = raw.copyOfRange(raw.size - TAG_SIZE, raw.size)
        val sealed = ciphertext + tag
        var aad: ByteArray? = null
        try {
            val siteOk = MessageDigest.isEqual(headerSiteBytes, expectedSiteBytes)
            val digestOk = MessageDigest.isEqual(headerDigest, binding.artifactDigest)
            if (!siteOk || !digestOk) {
                throw SecurityException("indy target token authentication failed")
            }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
            aad = binding.aad(nameSeed)
            cipher.updateAAD(aad)
            val plaintext = cipher.doFinal(sealed)
            try {
                val target = decodeTarget(plaintext)
                require(
                    target.tag == Opcodes.H_INVOKEVIRTUAL ||
                        target.tag == Opcodes.H_INVOKESTATIC ||
                        target.tag == Opcodes.H_INVOKESPECIAL ||
                        target.tag == Opcodes.H_INVOKEINTERFACE,
                ) { "indy target handle tag is unsupported" }
                return target
            } finally {
                Arrays.fill(plaintext, 0)
            }
        } catch (ex: SecurityException) {
            throw ex
        } catch (ex: Exception) {
            throw SecurityException("indy target token authentication failed")
        } finally {
            Arrays.fill(raw, 0)
            Arrays.fill(nameSeed, 0)
            Arrays.fill(headerSiteBytes, 0)
            Arrays.fill(expectedSiteBytes, 0)
            Arrays.fill(headerDigest, 0)
            Arrays.fill(nonce, 0)
            Arrays.fill(ciphertext, 0)
            Arrays.fill(tag, 0)
            Arrays.fill(sealed, 0)
            if (aad != null) Arrays.fill(aad, 0)
        }
    }

    fun isToken(value: String): Boolean {
        if (value.length < 24) return false
        return try {
            val raw = Base64.getUrlDecoder().decode(value)
            try {
                if (raw.size <= HEADER_SIZE + NONCE_SIZE + TAG_SIZE ||
                    (raw[MAGIC_SIZE].toInt() and 0xFF) != VERSION
                ) {
                    false
                } else {
                    val suppliedMagic = raw.copyOf(MAGIC_SIZE)
                    val nameSeed = raw.copyOfRange(NAME_SEED_OFFSET, NAME_SEED_OFFSET + NAME_SEED_SIZE)
                    val artifactDigest = raw.copyOfRange(SITE_OFFSET + SITE_INDEX_SIZE, HEADER_SIZE)
                    val expectedMagic = tokenMagic(nameSeed, artifactDigest)
                    try {
                        !suppliedMagic.contentEquals(RETIRED_MAGIC) &&
                            MessageDigest.isEqual(suppliedMagic, expectedMagic)
                    } finally {
                        Arrays.fill(suppliedMagic, 0)
                        Arrays.fill(nameSeed, 0)
                        Arrays.fill(artifactDigest, 0)
                        Arrays.fill(expectedMagic, 0)
                    }
                }
            } finally {
                Arrays.fill(raw, 0)
            }
        } catch (_: RuntimeException) {
            false
        }
    }

    /**
     * Re-authenticate a build-time token and bind it to the commitment that is
     * serialized into the runtime directory. This is used for tokens emitted
     * before page finalization; it does not accept unauthenticated plaintext.
     */
    fun rebindArtifact(
        token: String,
        artifactDigest: ByteArray,
        callerOwner: String,
        indyName: String,
        indyMethodType: String,
        random: SecureRandom = SecureRandom(),
    ): String {
        require(artifactDigest.size == ARTIFACT_DIGEST_SIZE) { "indy token artifact digest must be 32 bytes" }
        val raw = try {
            Base64.getUrlDecoder().decode(token)
        } catch (_: RuntimeException) {
            throw SecurityException("indy target token is invalid")
        }
        require(raw.size > HEADER_SIZE + NONCE_SIZE + TAG_SIZE) { "indy target token is truncated" }
        val nameSeed = raw.copyOfRange(NAME_SEED_OFFSET, NAME_SEED_OFFSET + NAME_SEED_SIZE)
        val oldDigest = raw.copyOfRange(SITE_OFFSET + SITE_INDEX_SIZE, HEADER_SIZE)
        val currentSeed = io.github.hht0rro.javashroud.transforms.protection.qp.currentNameSeed()
        val siteIndex = readU32be(raw, SITE_OFFSET)
        var oldKey: ByteArray? = null
        var newKey: ByteArray? = null
        try {
            if (!MessageDigest.isEqual(nameSeed, currentSeed)) {
                throw SecurityException("indy target token name binding mismatch")
            }
            val oldBinding = Binding(
                artifactDigest = oldDigest,
                callerOwner = callerOwner,
                indyName = indyName,
                indyMethodType = indyMethodType,
                siteIndex = siteIndex,
                protocolVersion = VERSION,
            )
            oldKey = oldBinding.siteKey(nameSeed)
            val target = try {
                open(token, oldBinding, checkNotNull(oldKey))
            } catch (error: SecurityException) {
                throw error
            } catch (error: RuntimeException) {
                throw SecurityException("indy target token authentication failed", error)
            }
            if (MessageDigest.isEqual(oldDigest, artifactDigest)) return token

            val newBinding = oldBinding.copy(artifactDigest = artifactDigest)
            newKey = newBinding.siteKey(currentSeed)
            return seal(target, newBinding, checkNotNull(newKey), random, currentSeed)
        } finally {
            Arrays.fill(raw, 0)
            Arrays.fill(nameSeed, 0)
            Arrays.fill(oldDigest, 0)
            Arrays.fill(currentSeed, 0)
            oldKey?.let { Arrays.fill(it, 0) }
            newKey?.let { Arrays.fill(it, 0) }
        }
    }

    fun fromHandle(handle: Handle): Target = Target(
        owner = handle.owner,
        name = handle.name,
        descriptor = handle.desc,
        tag = handle.tag,
        isInterface = handle.isInterface,
    )

    fun isBusinessTargetHandle(handle: Handle): Boolean {
        if (handle.tag == Opcodes.H_INVOKESTATIC && isJdkBootstrapOwner(handle.owner)) return false
        if (isJdkBootstrapOwner(handle.owner)) return false
        if (handle.owner.startsWith("io/github/hht0rro/javashroud/transforms/protection/")) return false
        if (handle.name.startsWith("a_bsm") || handle.name.startsWith("\$_j")) return false
        return true
    }

    fun isJdkBootstrapOwner(owner: String): Boolean =
        owner.startsWith("java/") || owner.startsWith("javax/") || owner.startsWith("jdk/")

    private fun tokenDomain(nameSeed: ByteArray, artifactDigest: ByteArray, aad: Boolean): ByteArray {
        val schedule = io.github.hht0rro.javashroud.transforms.protection.qp.qpNameSchedule(artifactDigest, nameSeed)
        return try {
            if (aad) {
                schedule.deriveDomain(
                    io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_TOKEN,
                    io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.LANE_TOKEN_AAD,
                )
            } else {
                schedule.deriveDomain(
                    io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_TOKEN,
                    io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.LANE_TOKEN_KEY,
                )
            }
        } finally {
            schedule.close()
        }
    }

    private fun tokenMagic(nameSeed: ByteArray, artifactDigest: ByteArray): ByteArray {
        val schedule = io.github.hht0rro.javashroud.transforms.protection.qp.qpNameSchedule(artifactDigest, nameSeed)
        return try {
            schedule.deriveMagic(io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule.ROLE_TOKEN)
        } finally {
            schedule.close()
        }
    }

    private fun encodeTarget(target: Target): ByteArray {
        val text = target.owner + "\u0000" + target.name + "\u0000" + target.descriptor + "\u0000" +
            target.tag.toString() + "\u0000" + if (target.isInterface) "1" else "0"
        return text.toByteArray(Charsets.UTF_8)
    }

    private fun decodeTarget(plaintext: ByteArray): Target {
        val parts = String(plaintext, Charsets.UTF_8).split('\u0000')
        require(parts.size == 5) { "indy target token payload is invalid" }
        return Target(
            owner = parts[0],
            name = parts[1],
            descriptor = parts[2],
            tag = parts[3].toInt(),
            isInterface = parts[4] == "1",
        )
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

    private fun writeU32be(out: ByteArray, offset: Int, value: Int) {
        out[offset] = (value ushr 24).toByte()
        out[offset + 1] = (value ushr 16).toByte()
        out[offset + 2] = (value ushr 8).toByte()
        out[offset + 3] = value.toByte()
    }

    private fun readU32be(input: ByteArray, offset: Int): Int =
        ((input[offset].toInt() and 0xFF) shl 24) or
            ((input[offset + 1].toInt() and 0xFF) shl 16) or
            ((input[offset + 2].toInt() and 0xFF) shl 8) or
            (input[offset + 3].toInt() and 0xFF)

    private fun u32be(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )
}
