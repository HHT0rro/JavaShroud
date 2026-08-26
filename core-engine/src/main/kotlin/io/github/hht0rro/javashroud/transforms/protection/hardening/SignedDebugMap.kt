package io.github.hht0rro.javashroud.transforms.protection.hardening

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.NamedParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Versioned, Ed25519-signed rename/debug mapping.
 * Production JARs never contain this file and do not need it to start.
 */
internal class SignedDebugMap private constructor(
    val formatVersion: String,
    val artifactSha256: ByteArray,
    val methodMappings: List<MemberMapping>,
    val fieldMappings: List<MemberMapping>,
    val transformVersion: String,
    val buildId: String,
    val issuerKeyId: String,
    val passConfigDigest: ByteArray,
    val nativeSha256: ByteArray,
    val abiDigest: ByteArray,
    val specializationDigest: ByteArray,
    val targetTriple: String,
    val publicKey: ByteArray,
    val signature: ByteArray,
    val encoded: ByteArray,
) {
    data class MemberMapping(
        val owner: String,
        val originalName: String,
        val descriptor: String,
        val renamedName: String,
    )

    data class Draft(
        val methodMappings: List<MemberMapping>,
        val fieldMappings: List<MemberMapping>,
        val transformVersion: String,
        val buildId: String,
        val issuerKeyId: String = "",
        val passConfigDigest: ByteArray = ByteArray(32),
        val nativeSha256: ByteArray = ByteArray(32),
        val abiDigest: ByteArray = ByteArray(32),
        val specializationDigest: ByteArray = ByteArray(32),
        val targetTriple: String = "",
    )

    data class Issuer(
        val keyId: String,
        val privateKey: PrivateKey,
        val publicKey: PublicKey,
    ) {
        companion object {
            fun generate(keyId: String): Issuer {
                val generator = KeyPairGenerator.getInstance("Ed25519")
                generator.initialize(NamedParameterSpec("Ed25519"))
                val pair = generator.generateKeyPair()
                return Issuer(keyId, pair.private, pair.public)
            }

            fun fromEnvironment(): Issuer {
                val keyId = System.getenv("JAVASHROUD_DEBUGMAP_ISSUER_ID")
                    ?: error("JAVASHROUD_DEBUGMAP_ISSUER_ID is required to sign a debug map")
                val pkcs8 = decodeEnv("JAVASHROUD_DEBUGMAP_ISSUER_PKCS8")
                val spki = decodeEnv("JAVASHROUD_DEBUGMAP_ISSUER_SPKI")
                val factory = KeyFactory.getInstance("Ed25519")
                return Issuer(
                    keyId = keyId,
                    privateKey = factory.generatePrivate(PKCS8EncodedKeySpec(pkcs8)),
                    publicKey = factory.generatePublic(X509EncodedKeySpec(spki)),
                )
            }

            fun fromEnvironmentOrEphemeral(): Issuer =
                try {
                    fromEnvironment()
                } catch (_: IllegalStateException) {
                    generate("ephemeral")
                }

            private fun decodeEnv(name: String): ByteArray {
                val value = System.getenv(name) ?: error("$name is required to sign a debug map")
                return Base64.getDecoder().decode(value)
            }
        }
    }

    fun verify(expectedArtifactSha256: ByteArray) {
        require(artifactSha256.contentEquals(expectedArtifactSha256)) {
            "signed debug map artifact digest does not match the production JAR"
        }
        val payload = encoded.copyOfRange(HEADER_BYTES, encoded.size - publicKey.size - SIGNATURE_BYTES)
        val verifier = Signature.getInstance("Ed25519")
        val keyFactory = KeyFactory.getInstance("Ed25519")
        val pub = keyFactory.generatePublic(X509EncodedKeySpec(x509Ed25519(publicKey)))
        verifier.initVerify(pub)
        verifier.update(payload)
        require(verifier.verify(signature)) { "signed debug map signature is invalid" }
    }

    companion object {
        private const val HEADER_BYTES = 4 + 2 + 4
        private const val RAW_PUBLIC_KEY_BYTES = 32
        private const val SIGNATURE_BYTES = 64

        fun create(
            artifactSha256: ByteArray,
            draft: Draft,
            issuer: Issuer = Issuer.generate("ephemeral"),
        ): SignedDebugMap {
            require(artifactSha256.size == 32) { "artifact digest must be 32 bytes" }
            val signedDraft = if (draft.issuerKeyId.isEmpty()) draft.copy(issuerKeyId = issuer.keyId) else draft
            val payload = encodePayload(ProtectionFormat.CURRENT, artifactSha256, signedDraft)
            val signer = Signature.getInstance("Ed25519")
            signer.initSign(issuer.privateKey)
            signer.update(payload)
            val signatureBytes = signer.sign()
            val rawPublic = rawEd25519PublicKey(issuer.publicKey.encoded)
            val encoded = encodeFile(payload, rawPublic, signatureBytes)
            return SignedDebugMap(
                formatVersion = ProtectionFormat.CURRENT,
                artifactSha256 = artifactSha256.copyOf(),
                methodMappings = signedDraft.methodMappings,
                fieldMappings = signedDraft.fieldMappings,
                transformVersion = signedDraft.transformVersion,
                buildId = signedDraft.buildId,
                issuerKeyId = signedDraft.issuerKeyId,
                passConfigDigest = signedDraft.passConfigDigest.copyOf(),
                nativeSha256 = signedDraft.nativeSha256.copyOf(),
                abiDigest = signedDraft.abiDigest.copyOf(),
                specializationDigest = signedDraft.specializationDigest.copyOf(),
                targetTriple = signedDraft.targetTriple,
                publicKey = rawPublic,
                signature = signatureBytes,
                encoded = encoded,
            )
        }

        fun parse(bytes: ByteArray): SignedDebugMap {
            require(bytes.size >= HEADER_BYTES + RAW_PUBLIC_KEY_BYTES + SIGNATURE_BYTES) {
                "signed debug map is truncated"
            }
            require(bytes.copyOfRange(0, 4).toString(Charsets.US_ASCII) == ProtectionFormat.DEBUG_MAP_MAGIC) {
                "signed debug map magic is invalid"
            }
            val version = ((bytes[4].toInt() and 0xFF) shl 8) or (bytes[5].toInt() and 0xFF)
            require(version == ProtectionFormat.DEBUG_MAP_VERSION) { "signed debug map version is unsupported" }
            val payloadLength = ByteBuffer.wrap(bytes, 6, 4).order(ByteOrder.BIG_ENDIAN).int
            require(payloadLength > 0 && HEADER_BYTES + payloadLength + RAW_PUBLIC_KEY_BYTES + SIGNATURE_BYTES == bytes.size) {
                "signed debug map length is invalid"
            }
            val payload = bytes.copyOfRange(HEADER_BYTES, HEADER_BYTES + payloadLength)
            val publicKey = bytes.copyOfRange(bytes.size - RAW_PUBLIC_KEY_BYTES - SIGNATURE_BYTES, bytes.size - SIGNATURE_BYTES)
            val signatureBytes = bytes.copyOfRange(bytes.size - SIGNATURE_BYTES, bytes.size)
            val parsed = decodePayload(payload)
            val map = SignedDebugMap(
                formatVersion = parsed.formatVersion,
                artifactSha256 = parsed.artifactSha256,
                methodMappings = parsed.methodMappings,
                fieldMappings = parsed.fieldMappings,
                transformVersion = parsed.transformVersion,
                buildId = parsed.buildId,
                issuerKeyId = parsed.issuerKeyId,
                passConfigDigest = parsed.passConfigDigest,
                nativeSha256 = parsed.nativeSha256,
                abiDigest = parsed.abiDigest,
                specializationDigest = parsed.specializationDigest,
                targetTriple = parsed.targetTriple,
                publicKey = publicKey,
                signature = signatureBytes,
                encoded = bytes.copyOf(),
            )
            map.verify(parsed.artifactSha256)
            return map
        }

        fun sidecarPath(outputJarPath: Path): Path =
            outputJarPath.resolveSibling(outputJarPath.fileName.toString().removeSuffix(".jar") + ".debugmap")

        fun write(
            outputJarPath: Path,
            draft: Draft,
            artifactSha256: ByteArray,
            issuer: Issuer = Issuer.fromEnvironmentOrEphemeral(),
        ): Path {
            val map = create(artifactSha256, draft, issuer)
            val path = sidecarPath(outputJarPath)
            Files.createDirectories(requireNotNull(path.parent) { "debug map path has no parent" })
            val temporary = Files.createTempFile(path.parent, ".debugmap.", ".tmp")
            try {
                Files.write(temporary, map.encoded)
                Files.move(temporary, path, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } finally {
                Files.deleteIfExists(temporary)
            }
            return path
        }

        internal fun sha256(path: Path): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            Files.newInputStream(path).use { input ->
                val buffer = ByteArray(32 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            }
            return digest.digest()
        }

        private data class ParsedPayload(
            val formatVersion: String,
            val artifactSha256: ByteArray,
            val methodMappings: List<MemberMapping>,
            val fieldMappings: List<MemberMapping>,
            val transformVersion: String,
            val buildId: String,
            val issuerKeyId: String,
            val passConfigDigest: ByteArray,
            val nativeSha256: ByteArray,
            val abiDigest: ByteArray,
            val specializationDigest: ByteArray,
            val targetTriple: String,
        )

        private fun encodeFile(payload: ByteArray, publicKey: ByteArray, signatureBytes: ByteArray): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(ProtectionFormat.DEBUG_MAP_MAGIC.toByteArray(Charsets.US_ASCII))
            out.write(byteArrayOf(((ProtectionFormat.DEBUG_MAP_VERSION ushr 8) and 0xFF).toByte(), (ProtectionFormat.DEBUG_MAP_VERSION and 0xFF).toByte()))
            out.write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(payload.size).array())
            out.write(payload)
            out.write(publicKey)
            out.write(signatureBytes)
            return out.toByteArray()
        }

        private fun encodePayload(formatVersion: String, artifactSha256: ByteArray, draft: Draft): ByteArray {
            val out = ByteArrayOutputStream()
            writeUtf8(out, formatVersion)
            out.write(artifactSha256)
            writeMappings(out, draft.methodMappings)
            writeMappings(out, draft.fieldMappings)
            writeUtf8(out, draft.transformVersion)
            writeUtf8(out, draft.buildId)
            writeUtf8(out, draft.issuerKeyId)
            writeDigest(out, draft.passConfigDigest)
            writeDigest(out, draft.nativeSha256)
            writeDigest(out, draft.abiDigest)
            writeDigest(out, draft.specializationDigest)
            writeUtf8(out, draft.targetTriple)
            return out.toByteArray()
        }

        private fun decodePayload(payload: ByteArray): ParsedPayload {
            val buffer = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)
            val formatVersion = readUtf8(buffer)
            require(formatVersion == ProtectionFormat.CURRENT) { "signed debug map format version is unsupported" }
            val digest = ByteArray(32)
            buffer.get(digest)
            val methods = readMappings(buffer)
            val fields = readMappings(buffer)
            val transformVersion = readUtf8(buffer)
            val buildId = readUtf8(buffer)
            val issuerKeyId = readUtf8(buffer)
            val passConfigDigest = readDigest(buffer)
            val nativeSha256 = readDigest(buffer)
            val abiDigest = readDigest(buffer)
            val specializationDigest = readDigest(buffer)
            val targetTriple = readUtf8(buffer)
            require(!buffer.hasRemaining()) { "signed debug map payload has trailing bytes" }
            return ParsedPayload(
                formatVersion,
                digest,
                methods,
                fields,
                transformVersion,
                buildId,
                issuerKeyId,
                passConfigDigest,
                nativeSha256,
                abiDigest,
                specializationDigest,
                targetTriple,
            )
        }

        private fun writeDigest(out: ByteArrayOutputStream, digest: ByteArray) {
            require(digest.size == 32) { "signed debug map digest must be 32 bytes" }
            out.write(digest)
        }

        private fun readDigest(buffer: ByteBuffer): ByteArray {
            require(buffer.remaining() >= 32) { "signed debug map digest is truncated" }
            val digest = ByteArray(32)
            buffer.get(digest)
            return digest
        }

        private fun writeMappings(out: ByteArrayOutputStream, mappings: List<MemberMapping>) {
            out.write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(mappings.size).array())
            mappings.forEach { mapping ->
                writeUtf8(out, mapping.owner)
                writeUtf8(out, mapping.originalName)
                writeUtf8(out, mapping.descriptor)
                writeUtf8(out, mapping.renamedName)
            }
        }

        private fun readMappings(buffer: ByteBuffer): List<MemberMapping> {
            val count = buffer.int
            require(count >= 0 && count <= 1_000_000) { "signed debug map mapping count is invalid" }
            return List(count) {
                MemberMapping(readUtf8(buffer), readUtf8(buffer), readUtf8(buffer), readUtf8(buffer))
            }
        }

        private fun writeUtf8(out: ByteArrayOutputStream, value: String) {
            val bytes = value.toByteArray(Charsets.UTF_8)
            require(bytes.size <= 0xFFFF) { "signed debug map string is too long" }
            out.write(byteArrayOf(((bytes.size ushr 8) and 0xFF).toByte(), (bytes.size and 0xFF).toByte()))
            out.write(bytes)
        }

        private fun readUtf8(buffer: ByteBuffer): String {
            val length = buffer.short.toInt() and 0xFFFF
            require(buffer.remaining() >= length) { "signed debug map string is truncated" }
            val bytes = ByteArray(length)
            buffer.get(bytes)
            return String(bytes, Charsets.UTF_8)
        }

        private fun rawEd25519PublicKey(x509: ByteArray): ByteArray {
            require(x509.size >= RAW_PUBLIC_KEY_BYTES) { "Ed25519 public key is truncated" }
            return x509.copyOfRange(x509.size - RAW_PUBLIC_KEY_BYTES, x509.size)
        }

        private fun x509Ed25519(raw: ByteArray): ByteArray {
            require(raw.size == RAW_PUBLIC_KEY_BYTES) { "Ed25519 public key must be 32 bytes" }
            val prefix = byteArrayOf(0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00)
            return prefix + raw
        }
    }
}
