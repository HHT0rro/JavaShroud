package io.github.hht0rro.javashroud.transforms.protection

import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.nio.file.Files
import java.nio.file.Path
import java.util.Arrays
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Versioned, artifact-bound envelope for a max-hardening Boot KEK sidecar.
 *
 * The caller supplies a unique 32-byte binding for the output artifact. It is
 * domain-separated before it becomes the AEAD key, so a sidecar from another
 * build cannot be replayed against this artifact.
 */
object BootKekSidecar {
    const val KEK_SIZE: Int = 32
    const val TEXT_PREFIX: String = "JSBK1."
    const val EMBEDDED_RESOURCE_PATH: String = "META-INF/.r/kek.dat"
    const val DELIVERY_EXTERNAL_FILE: String = "external-file"
    const val DELIVERY_EMBEDDED: String = "embedded"

    enum class Format {
        BinaryV1,
        TextV1,
    }

    private const val VERSION = 1
    private const val FLAGS = 0
    private const val BINDING_SIZE = 32
    private const val SALT_SIZE = 16
    private const val NONCE_SIZE = 12
    private const val TAG_SIZE = 16
    private const val SEALED_KEK_SIZE = KEK_SIZE + TAG_SIZE
    private const val HEADER_SIZE = 10
    private val MAGIC = byteArrayOf(0x4A, 0x53, 0x42, 0x4B) // JSBK
    private val KEY_DERIVATION_DOMAIN = "JavaShroud/BootKekSidecar/v1/key".toByteArray(Charsets.US_ASCII)
    private val secureRandom = SecureRandom()
    @Volatile internal var buildArtifactBindingProvider: (() -> ByteArray?)? = null

    internal fun requireArtifactBindingForBuild(): ByteArray {
        buildArtifactBindingProvider?.let { provider ->
            val provided = provider() ?: throw IllegalStateException("Boot KEK sidecar binding provider returned null")
            return try {
                requireBinding(provided)
                provided.copyOf()
            } finally {
                wipe(provided)
            }
        }
        val fileName = System.getenv(NativeKernelShellPacker.BOOT_SECRET_FILE_ENV)?.takeIf(String::isNotBlank)
            ?: return ByteArray(BINDING_SIZE)
        val bytes = runCatching { Files.readAllBytes(Path.of(fileName)) }.getOrNull() ?: return ByteArray(BINDING_SIZE)
        return try {
            embeddedBinding(bytes)
                ?: runCatching { embeddedBindingText(String(bytes, Charsets.US_ASCII)) }.getOrNull()
                ?: ByteArray(BINDING_SIZE)
        } finally {
            wipe(bytes)
        }
    }

    /**
     * Returns the binary sidecar format. The returned bytes contain no plaintext KEK.
     */
    @JvmStatic
    fun encode(kek: ByteArray, artifactBinding: ByteArray): ByteArray {
        requireKek(kek)
        requireBinding(artifactBinding)

        val salt = ByteArray(SALT_SIZE)
        val nonce = ByteArray(NONCE_SIZE)
        var header = ByteArray(0)
        var aad = ByteArray(0)
        var wrappingKey = ByteArray(0)
        var sealed = ByteArray(0)
        try {
            secureRandom.nextBytes(salt)
            secureRandom.nextBytes(nonce)
            header = header()
            aad = authenticatedData(header, artifactBinding, salt, nonce)
            wrappingKey = deriveWrappingKey(artifactBinding, salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(wrappingKey, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(aad)
            sealed = cipher.doFinal(kek)
            check(sealed.size == SEALED_KEK_SIZE) { "unexpected sealed Boot KEK length" }
            return ByteArray(HEADER_SIZE + BINDING_SIZE + SALT_SIZE + NONCE_SIZE + SEALED_KEK_SIZE).also { result ->
                header.copyInto(result, destinationOffset = 0)
                artifactBinding.copyInto(result, destinationOffset = HEADER_SIZE)
                salt.copyInto(result, destinationOffset = HEADER_SIZE + BINDING_SIZE)
                nonce.copyInto(result, destinationOffset = HEADER_SIZE + BINDING_SIZE + SALT_SIZE)
                sealed.copyInto(result, destinationOffset = HEADER_SIZE + BINDING_SIZE + SALT_SIZE + NONCE_SIZE)
            }
        } finally {
            wipe(salt)
            wipe(nonce)
            wipe(header)
            wipe(aad)
            wipe(wrappingKey)
            wipe(sealed)
        }
    }

    /**
     * Returns the URL-safe text representation for sidecar formats that must pass through text-only transport.
     */
    @JvmStatic
    fun encodeText(kek: ByteArray, artifactBinding: ByteArray): String {
        val binary = encode(kek, artifactBinding)
        return try {
            TEXT_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(binary)
        } finally {
            wipe(binary)
        }
    }

    /**
     * Recovers a 32-byte KEK only when the sidecar and caller-supplied artifact binding authenticate together.
     */
    @JvmStatic
    fun decode(sidecar: ByteArray, artifactBinding: ByteArray): ByteArray {
        requireBinding(artifactBinding)
        val parsed = parse(sidecar)
        var aad = ByteArray(0)
        var wrappingKey = ByteArray(0)
        var plaintext = ByteArray(0)
        var accepted = false
        try {
            require(MessageDigest.isEqual(parsed.binding, artifactBinding)) {
                "Boot KEK sidecar artifact binding mismatch"
            }
            aad = authenticatedData(parsed.header, parsed.binding, parsed.salt, parsed.nonce)
            wrappingKey = deriveWrappingKey(artifactBinding, parsed.salt)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(wrappingKey, "AES"), GCMParameterSpec(128, parsed.nonce))
            cipher.updateAAD(aad)
            plaintext = cipher.doFinal(sidecar, parsed.sealedOffset, SEALED_KEK_SIZE)
            if (plaintext.size != KEK_SIZE) {
                throw IllegalArgumentException("Boot KEK sidecar plaintext length is invalid")
            }
            accepted = true
            return plaintext
        } catch (error: GeneralSecurityException) {
            throw IllegalArgumentException("Boot KEK sidecar authentication failed", error)
        } finally {
            wipe(parsed.header)
            wipe(parsed.binding)
            wipe(parsed.salt)
            wipe(parsed.nonce)
            wipe(aad)
            wipe(wrappingKey)
            if (!accepted) wipe(plaintext)
        }
    }

    /**
     * Decodes the URL-safe text representation.
     */
    @JvmStatic
    fun decodeText(sidecar: CharSequence, artifactBinding: ByteArray): ByteArray {
        require(sidecar.startsWith(TEXT_PREFIX)) { "Boot KEK sidecar text prefix is invalid" }
        val encoded = sidecar.subSequence(TEXT_PREFIX.length, sidecar.length).toString()
        require(encoded.isNotEmpty()) { "Boot KEK sidecar text payload is empty" }
        val binary = try {
            Base64.getUrlDecoder().decode(encoded)
        } catch (error: IllegalArgumentException) {
            throw IllegalArgumentException("Boot KEK sidecar text encoding is invalid", error)
        }
        return try {
            decode(binary, artifactBinding)
        } finally {
            wipe(binary)
        }
    }

    @JvmStatic
    fun identify(sidecar: ByteArray): Format? = if (hasValidHeader(sidecar)) Format.BinaryV1 else null

    @JvmStatic
    fun embeddedBinding(sidecar: ByteArray): ByteArray? =
        if (hasValidHeader(sidecar)) sidecar.copyOfRange(HEADER_SIZE, HEADER_SIZE + BINDING_SIZE) else null

    @JvmStatic
    fun embeddedBindingText(sidecar: CharSequence): ByteArray? {
        if (!sidecar.startsWith(TEXT_PREFIX)) return null
        val binary = try {
            Base64.getUrlDecoder().decode(sidecar.subSequence(TEXT_PREFIX.length, sidecar.length).toString())
        } catch (_: IllegalArgumentException) {
            return null
        }
        return try {
            embeddedBinding(binary)
        } finally {
            wipe(binary)
        }
    }

    @JvmStatic
    fun identifyText(sidecar: CharSequence): Format? {
        if (!sidecar.startsWith(TEXT_PREFIX)) return null
        val encoded = sidecar.subSequence(TEXT_PREFIX.length, sidecar.length).toString()
        if (encoded.isEmpty()) return null
        val binary = try {
            Base64.getUrlDecoder().decode(encoded)
        } catch (_: IllegalArgumentException) {
            return null
        }
        return try {
            if (hasValidHeader(binary)) Format.TextV1 else null
        } finally {
            wipe(binary)
        }
    }

    private fun parse(sidecar: ByteArray): ParsedSidecar {
        require(hasValidHeader(sidecar)) { "Boot KEK sidecar format is invalid" }
        val header = sidecar.copyOfRange(0, HEADER_SIZE)
        val bindingOffset = HEADER_SIZE
        val saltOffset = bindingOffset + BINDING_SIZE
        val nonceOffset = saltOffset + SALT_SIZE
        val sealedOffset = nonceOffset + NONCE_SIZE
        return ParsedSidecar(
            header = header,
            binding = sidecar.copyOfRange(bindingOffset, saltOffset),
            salt = sidecar.copyOfRange(saltOffset, nonceOffset),
            nonce = sidecar.copyOfRange(nonceOffset, sealedOffset),
            sealedOffset = sealedOffset,
        )
    }

    private fun hasValidHeader(sidecar: ByteArray): Boolean {
        if (sidecar.size != HEADER_SIZE + BINDING_SIZE + SALT_SIZE + NONCE_SIZE + SEALED_KEK_SIZE) return false
        if (!sidecar.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) return false
        return (sidecar[4].toInt() and 0xFF) == VERSION &&
            (sidecar[5].toInt() and 0xFF) == FLAGS &&
            (sidecar[6].toInt() and 0xFF) == SALT_SIZE &&
            (sidecar[7].toInt() and 0xFF) == NONCE_SIZE &&
            le16(sidecar, 8) == SEALED_KEK_SIZE
    }

    private fun header(): ByteArray = ByteArray(HEADER_SIZE).also {
        MAGIC.copyInto(it, destinationOffset = 0)
        it[4] = VERSION.toByte()
        it[5] = FLAGS.toByte()
        it[6] = SALT_SIZE.toByte()
        it[7] = NONCE_SIZE.toByte()
        it[8] = SEALED_KEK_SIZE.toByte()
        it[9] = (SEALED_KEK_SIZE ushr 8).toByte()
    }

    private fun le16(value: ByteArray, offset: Int): Int =
        (value[offset].toInt() and 0xFF) or ((value[offset + 1].toInt() and 0xFF) shl 8)

    private fun authenticatedData(header: ByteArray, binding: ByteArray, salt: ByteArray, nonce: ByteArray): ByteArray =
        ByteArray(header.size + binding.size + salt.size + nonce.size).also { result ->
            header.copyInto(result, destinationOffset = 0)
            binding.copyInto(result, destinationOffset = header.size)
            salt.copyInto(result, destinationOffset = header.size + binding.size)
            nonce.copyInto(result, destinationOffset = header.size + binding.size + salt.size)
        }

    private fun deriveWrappingKey(artifactBinding: ByteArray, salt: ByteArray): ByteArray {
        val material = ByteArray(KEY_DERIVATION_DOMAIN.size + salt.size)
        return try {
            KEY_DERIVATION_DOMAIN.copyInto(material, destinationOffset = 0)
            salt.copyInto(material, destinationOffset = KEY_DERIVATION_DOMAIN.size)
            Mac.getInstance("HmacSHA256").run {
                init(SecretKeySpec(artifactBinding, "HmacSHA256"))
                doFinal(material)
            }
        } finally {
            wipe(material)
        }
    }

    private fun requireKek(kek: ByteArray) {
        require(kek.size == KEK_SIZE) { "Boot KEK must be exactly $KEK_SIZE bytes" }
    }

    private fun requireBinding(artifactBinding: ByteArray) {
        require(artifactBinding.size == KEK_SIZE) { "artifact binding must be exactly $KEK_SIZE bytes" }
    }

    private fun wipe(value: ByteArray) {
        Arrays.fill(value, 0)
    }

    private data class ParsedSidecar(
        val header: ByteArray,
        val binding: ByteArray,
        val salt: ByteArray,
        val nonce: ByteArray,
        val sealedOffset: Int,
    )
}
