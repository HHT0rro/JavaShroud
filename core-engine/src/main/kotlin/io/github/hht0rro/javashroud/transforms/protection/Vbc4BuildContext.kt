package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Shared VBC4 build context for one obfuscation run.
 *
 * Method resources are serialized before the native microkernel is recompiled,
 * so both phases must derive the same build-local root key from the same run
 * context. The key is never kept as a repository source constant; it is only
 * materialized in memory and in the per-output generated native include.
 */
internal data class Vbc4BuildContext(
    val masterKey: ByteArray,
    val nativeSeed: Long,
    val jarLayoutDigest: ByteArray,
    val runtimeResourceKey: ByteArray = generateRuntimeResourceKey(masterKey, jarLayoutDigest, nativeSeed),
) {
    init {
        require(masterKey.size == VBC4_MASTER_KEY_SIZE) { "VBC4 master key must be 32 bytes" }
        require(jarLayoutDigest.size == VBC4_LAYOUT_DIGEST_SIZE) { "VBC4 layout digest must be 32 bytes" }
        require(runtimeResourceKey.size == VBC4_RUNTIME_RESOURCE_KEY_SIZE) { "VBC4 runtime resource key must be 32 bytes" }
    }

    fun copyMasterKey(): ByteArray = masterKey.copyOf()
    fun copyRuntimeResourceKey(): ByteArray = runtimeResourceKey.copyOf()

    /**
     * Derive a build-local sub key from the per-build runtime resource root key
     * using HKDF-SHA256 (RFC 5869). The runtime resource key is the IKM, [label]
     * is the extract salt, and [info] entries are concatenated into the expand
     * info. This is the single shared derivation skeleton reused by every pass
     * that needs build-local key material, so Kotlin (build) and the Java/native
     * runtime recompute byte-for-byte identical keys from the same root.
     */
    fun deriveSubKey(label: String, length: Int, vararg info: ByteArray): ByteArray =
        hkdfSha256(
            ikm = runtimeResourceKey,
            salt = label.toByteArray(Charsets.US_ASCII),
            info = concatBytes(info),
            length = length,
        )

    fun scopedCopy(): Vbc4BuildContext = copy(
        masterKey = masterKey.copyOf(),
        jarLayoutDigest = jarLayoutDigest.copyOf(),
        runtimeResourceKey = runtimeResourceKey.copyOf(),
    )

    fun wipe() {
        java.util.Arrays.fill(masterKey, 0)
        java.util.Arrays.fill(jarLayoutDigest, 0)
        java.util.Arrays.fill(runtimeResourceKey, 0)
    }
}

internal const val VBC4_MASTER_KEY_SIZE = 32
internal const val VBC4_LAYOUT_DIGEST_SIZE = 32
internal const val VBC4_RUNTIME_RESOURCE_KEY_SIZE = 32

private val explicitRunContext = ThreadLocal<Vbc4BuildContext?>()

internal fun <T> withVbc4BuildContext(context: Vbc4BuildContext, block: () -> T): T {
    val previous = explicitRunContext.get()
    val scoped = context.scopedCopy()
    explicitRunContext.set(scoped)
    return try {
        block()
    } finally {
        scoped.wipe()
        if (previous == null) explicitRunContext.remove() else explicitRunContext.set(previous)
    }
}

internal fun currentVbc4BuildContextOrNull(): Vbc4BuildContext? = explicitRunContext.get()

internal fun requireVbc4BuildContext(): Vbc4BuildContext = currentVbc4BuildContextOrNull()
    ?: error("VBC4 build context is not initialized")

internal fun defaultVbc4BuildContext(): Vbc4BuildContext = generateStandaloneVbc4BuildContext()

internal fun buildVbc4BuildContext(config: ObfuscationConfig, artifact: BytecodeArtifact): Vbc4BuildContext {
    val layoutDigest = jarLayoutDigest(artifact)
    val seedDigest = MessageDigest.getInstance("SHA-256")
    seedDigest.update(config.inputJarPath.toByteArray(Charsets.UTF_8))
    seedDigest.update(0)
    seedDigest.update(config.outputJarPath.toByteArray(Charsets.UTF_8))
    seedDigest.update(0)
    seedDigest.update(layoutDigest)
    for (pass in config.passes.sortedBy { it.id }) {
        seedDigest.update(pass.id.toByteArray(Charsets.UTF_8))
        seedDigest.update(if (pass.enabled) 1 else 0)
        val seedNode = pass.params["seed"]
        if (seedNode != null) seedDigest.update(seedNode.toString().toByteArray(Charsets.UTF_8))
    }
    val seedBytes = seedDigest.digest()
    val randomSeedBytes = ByteArray(Long.SIZE_BYTES)
    SecureRandom().nextBytes(randomSeedBytes)
    val nativeSeed = readLong(seedBytes, 0) xor readLong(seedBytes, 8) xor readLong(randomSeedBytes, 0)
    val masterKey = generateMasterKey(layoutDigest, nativeSeed)
    return Vbc4BuildContext(
        masterKey = masterKey,
        nativeSeed = nativeSeed,
        jarLayoutDigest = layoutDigest,
        runtimeResourceKey = generateRuntimeResourceKey(masterKey, layoutDigest, nativeSeed),
    )
}

private fun generateStandaloneVbc4BuildContext(): Vbc4BuildContext {
    val random = SecureRandom()
    val layoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE)
    random.nextBytes(layoutDigest)
    val seedBytes = ByteArray(Long.SIZE_BYTES)
    random.nextBytes(seedBytes)
    val nativeSeed = readLong(seedBytes, 0)
    val masterKey = generateMasterKey(layoutDigest, nativeSeed)
    return Vbc4BuildContext(
        masterKey = masterKey,
        nativeSeed = nativeSeed,
        jarLayoutDigest = layoutDigest,
        runtimeResourceKey = generateRuntimeResourceKey(masterKey, layoutDigest, nativeSeed),
    )
}

private fun generateMasterKey(layoutDigest: ByteArray, nativeSeed: Long): ByteArray {
    val random = SecureRandom()
    val entropy = ByteArray(64)
    random.nextBytes(entropy)
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("javashroud-vbc4-build-root".toByteArray(Charsets.US_ASCII))
    digest.update(longBytes(nativeSeed))
    digest.update(layoutDigest)
    digest.update(entropy)
    return digest.digest()
}

internal fun generateRuntimeResourceKey(masterKey: ByteArray, layoutDigest: ByteArray, nativeSeed: Long): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("javashroud-vbc4-runtime-resource".toByteArray(Charsets.US_ASCII))
    digest.update(longBytes(nativeSeed))
    digest.update(layoutDigest)
    digest.update(masterKey)
    return digest.digest()
}

private fun jarLayoutDigest(artifact: BytecodeArtifact): ByteArray {
    val digest = MessageDigest.getInstance("SHA-256")
    for (classArtifact in artifact.classArtifacts.sortedBy { it.entryName }) {
        digest.update(1)
        digest.update(classArtifact.entryName.toByteArray(Charsets.UTF_8))
        digest.update(0)
        digest.update(intBytes(classArtifact.bytes.size))
        digest.update(MessageDigest.getInstance("SHA-256").digest(classArtifact.bytes))
    }
    for (entry in artifact.jarEntries.sortedBy { it.name }) {
        digest.update(2)
        digest.update(entry.name.toByteArray(Charsets.UTF_8))
        digest.update(0)
        digest.update(intBytes(entry.bytes.size))
        digest.update(MessageDigest.getInstance("SHA-256").digest(entry.bytes))
    }
    return digest.digest()
}

private fun readLong(bytes: ByteArray, offset: Int): Long {
    var value = 0L
    for (index in 0 until Long.SIZE_BYTES) {
        value = (value shl 8) or (bytes[offset + index].toLong() and 0xFFL)
    }
    return value
}

private fun longBytes(value: Long): ByteArray = ByteArray(Long.SIZE_BYTES) { index ->
    ((value ushr ((Long.SIZE_BYTES - 1 - index) * 8)) and 0xFF).toByte()
}

internal const val VBC4_DERIVE_LABEL_CLASS_ENCRYPTION = "javashroud-vbc4-jse-class-v1"

/**
 * HKDF-SHA256 (RFC 5869): extract-then-expand. Shared by every build-local key
 * derivation so the engine never invents its own enumerable KDF.
 */
internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    require(length in 1..(255 * 32)) { "HKDF-SHA256 output length out of range: $length" }
    val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
    val output = ByteArray(length)
    var produced = 0
    var counter = 1
    var previous = ByteArray(0)
    while (produced < length) {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(prk, "HmacSHA256"))
        mac.update(previous)
        mac.update(info)
        mac.update(counter.toByte())
        previous = mac.doFinal()
        val take = minOf(previous.size, length - produced)
        System.arraycopy(previous, 0, output, produced, take)
        produced += take
        counter++
    }
    java.util.Arrays.fill(prk, 0)
    java.util.Arrays.fill(previous, 0)
    return output
}

private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
    mac.init(javax.crypto.spec.SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
    return mac.doFinal(data)
}

internal fun concatBytes(parts: Array<out ByteArray>): ByteArray {
    val total = parts.sumOf { it.size }
    val out = ByteArray(total)
    var offset = 0
    for (part in parts) {
        System.arraycopy(part, 0, out, offset, part.size)
        offset += part.size
    }
    return out
}

private fun intBytes(value: Int): ByteArray = byteArrayOf(
    ((value ushr 24) and 0xFF).toByte(),
    ((value ushr 16) and 0xFF).toByte(),
    ((value ushr 8) and 0xFF).toByte(),
    (value and 0xFF).toByte(),
)