package io.github.hht0rro.javashroud.transforms.protection.hardening

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
    private const val VERSION: Int = 1
    private val MAGIC = ProtectionFormat.INDY_TOKEN_MAGIC.toByteArray(Charsets.US_ASCII)

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
        val classIdentityDigest: ByteArray,
        val descriptorDigest: ByteArray,
        val callSiteIdentity: ByteArray,
        val routeId: ByteArray,
    ) {
        fun aad(): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update("javashroud-aken-r1-indy-token-aad-v1".toByteArray(Charsets.US_ASCII))
            digest.update(artifactDigest)
            digest.update(classIdentityDigest)
            digest.update(descriptorDigest)
            digest.update(callSiteIdentity)
            digest.update(routeId)
            return digest.digest()
        }
    }

    fun seal(target: Target, binding: Binding, key: ByteArray, random: SecureRandom = SecureRandom()): String {
        require(key.size == KEY_SIZE) { "indy token key must be 16 bytes" }
        val plaintext = encodeTarget(target)
        val nonce = ByteArray(NONCE_SIZE).also(random::nextBytes)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
            val sealed = cipher.doFinal(plaintext)
            val ciphertext = sealed.copyOfRange(0, sealed.size - TAG_SIZE)
            val tag = sealed.copyOfRange(sealed.size - TAG_SIZE, sealed.size)
            val out = ByteArray(MAGIC.size + 1 + NONCE_SIZE + ciphertext.size + TAG_SIZE)
            MAGIC.copyInto(out)
            out[MAGIC.size] = VERSION.toByte()
            nonce.copyInto(out, MAGIC.size + 1)
            ciphertext.copyInto(out, MAGIC.size + 1 + NONCE_SIZE)
            tag.copyInto(out, MAGIC.size + 1 + NONCE_SIZE + ciphertext.size)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(out)
        } finally {
            Arrays.fill(plaintext, 0)
            Arrays.fill(nonce, 0)
        }
    }

    fun open(token: String, binding: Binding, key: ByteArray): Target {
        require(key.size == KEY_SIZE) { "indy token key must be 16 bytes" }
        val raw = try {
            Base64.getUrlDecoder().decode(token)
        } catch (_: RuntimeException) {
            throw SecurityException("indy target token is invalid")
        }
        require(raw.size > MAGIC.size + 1 + NONCE_SIZE + TAG_SIZE) { "indy target token is truncated" }
        require(raw.copyOf(MAGIC.size).contentEquals(MAGIC) && raw[MAGIC.size].toInt() == VERSION) {
            "indy target token version is unsupported"
        }
        val nonce = raw.copyOfRange(MAGIC.size + 1, MAGIC.size + 1 + NONCE_SIZE)
        val ciphertext = raw.copyOfRange(MAGIC.size + 1 + NONCE_SIZE, raw.size - TAG_SIZE)
        val tag = raw.copyOfRange(raw.size - TAG_SIZE, raw.size)
        val sealed = ciphertext + tag
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
            val plaintext = cipher.doFinal(sealed)
            try {
                return decodeTarget(plaintext)
            } finally {
                Arrays.fill(plaintext, 0)
            }
        } catch (ex: Exception) {
            throw SecurityException("indy target token authentication failed")
        } finally {
            Arrays.fill(raw, 0)
            Arrays.fill(nonce, 0)
            Arrays.fill(ciphertext, 0)
            Arrays.fill(tag, 0)
            Arrays.fill(sealed, 0)
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
}
