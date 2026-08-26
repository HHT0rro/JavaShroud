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
internal object IndyTargetTokenEnvelope {
    const val KEY_SIZE = 16
    const val NONCE_SIZE = 12
    const val TAG_SIZE = 16
    private const val VERSION: Int = 3
    private const val SITE_INDEX_SIZE = 4
    private const val ARTIFACT_DIGEST_SIZE = 32
    private val MAGIC = ProtectionFormat.INDY_TOKEN_MAGIC.toByteArray(Charsets.US_ASCII)
    private val AAD_DOMAIN = byteArrayOf(
        'J'.code.toByte(),
        'S'.code.toByte(),
        'I'.code.toByte(),
        'T'.code.toByte(),
        'K'.code.toByte(),
        'A'.code.toByte(),
        'A'.code.toByte(),
        'D'.code.toByte(),
        VERSION.toByte(),
    )
    private val KEY_DOMAIN = byteArrayOf(
        'J'.code.toByte(),
        'S'.code.toByte(),
        'I'.code.toByte(),
        'T'.code.toByte(),
        'K'.code.toByte(),
        'K'.code.toByte(),
        'D'.code.toByte(),
        'F'.code.toByte(),
        VERSION.toByte(),
    )
    private val HEADER_SIZE = MAGIC.size + 1 + SITE_INDEX_SIZE + ARTIFACT_DIGEST_SIZE

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
        val protocolVersion: Int = 3,
    ) {
        fun aad(): ByteArray {
            require(artifactDigest.size == ARTIFACT_DIGEST_SIZE) { "indy token artifact digest must be 32 bytes" }
            val callerOwnerUtf8 = callerOwner.toByteArray(Charsets.UTF_8)
            val indyNameUtf8 = indyName.toByteArray(Charsets.UTF_8)
            val methodTypeUtf8 = indyMethodType.toByteArray(Charsets.UTF_8)
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(AAD_DOMAIN)
            updateLenPrefixed(digest, callerOwnerUtf8)
            updateLenPrefixed(digest, indyNameUtf8)
            updateLenPrefixed(digest, methodTypeUtf8)
            updateU32be(digest, siteIndex)
            digest.update(artifactDigest)
            updateU32be(digest, protocolVersion)
            return digest.digest()
        }

        fun siteKey(): ByteArray {
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
            return try {
                hkdfSha256(artifactDigest, KEY_DOMAIN, info, KEY_SIZE)
            } finally {
                Arrays.fill(info, 0)
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
        require(key.size == KEY_SIZE) { "indy token key must be 16 bytes" }
        require(binding.artifactDigest.size == ARTIFACT_DIGEST_SIZE) { "indy token artifact digest must be 32 bytes" }
        val plaintext = encodeTarget(target)
        val nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
        var aad: ByteArray? = null
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
            aad = binding.aad()
            cipher.updateAAD(aad)
            val sealed = cipher.doFinal(plaintext)
            val ciphertext = sealed.copyOfRange(0, sealed.size - TAG_SIZE)
            val tag = sealed.copyOfRange(sealed.size - TAG_SIZE, sealed.size)
            val out = ByteArray(HEADER_SIZE + NONCE_SIZE + ciphertext.size + TAG_SIZE)
            MAGIC.copyInto(out)
            out[MAGIC.size] = VERSION.toByte()
            writeU32be(out, MAGIC.size + 1, binding.siteIndex)
            binding.artifactDigest.copyInto(out, MAGIC.size + 1 + SITE_INDEX_SIZE)
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
        require(raw.size > MAGIC.size) { "indy target token is truncated" }
        require(raw.copyOf(MAGIC.size).contentEquals(MAGIC)) { "indy target token is invalid" }
        require((raw[MAGIC.size].toInt() and 0xFF) == VERSION) { "indy target token version is unsupported" }
        require(raw.size > HEADER_SIZE + NONCE_SIZE + TAG_SIZE) { "indy target token is truncated" }
        val headerSiteBytes = raw.copyOfRange(MAGIC.size + 1, MAGIC.size + 1 + SITE_INDEX_SIZE)
        val expectedSiteBytes = u32be(binding.siteIndex)
        val headerDigest = raw.copyOfRange(MAGIC.size + 1 + SITE_INDEX_SIZE, HEADER_SIZE)
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
            aad = binding.aad()
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
            raw.size > MAGIC.size && raw.copyOf(MAGIC.size).contentEquals(MAGIC)
        } catch (_: RuntimeException) {
            false
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

    private fun u32be(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )
}
