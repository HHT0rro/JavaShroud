package io.github.hht0rro.javashroud.transforms.protection.qp

import io.github.hht0rro.javashroud.transforms.protection.hkdfSha256
import java.security.SecureRandom
import java.util.Arrays

/**
 * Build-local derived names for the current protected-artifact format.
 *
 * The schedule stores only an authenticated 16-byte [nameSeed] and a numeric
 * version. It does not store human-readable protocol names and is not a
 * cryptographic secrecy boundary: it removes fixed static anchors across
 * builds.
 */
internal class QpNameSchedule private constructor(
    private val nameSeed: ByteArray,
    private val artifactCommitment: ByteArray,
    val scheduleVersion: Int,
) : AutoCloseable {
    @Volatile
    private var closed = false

    fun copyNameSeed(): ByteArray {
        requireLive()
        return nameSeed.copyOf()
    }

    fun derive(roleId: Int, laneId: Int, ordinal: Int, length: Int): ByteArray {
        requireLive()
        require(roleId in 0..0xFF) { "roleId out of range" }
        require(laneId in 0..0xFF) { "laneId out of range" }
        require(length in 1..(255 * 32)) { "derived length out of range: $length" }
        val info = byteArrayOf(
            INFO_PREFIX,
            scheduleVersion.toByte(),
            roleId.toByte(),
            laneId.toByte(),
            ((ordinal ushr 24) and 0xFF).toByte(),
            ((ordinal ushr 16) and 0xFF).toByte(),
            ((ordinal ushr 8) and 0xFF).toByte(),
            (ordinal and 0xFF).toByte(),
        )
        return try {
            hkdfSha256(nameSeed, artifactCommitment, info, length)
        } finally {
            Arrays.fill(info, 0)
        }
    }

    fun deriveMagic(roleId: Int, laneId: Int = 0, ordinal: Int = 0): ByteArray =
        derive(roleId, laneId, ordinal, 32).copyOf(4)

    fun deriveDomain(roleId: Int, laneId: Int = 0, ordinal: Int = 0): ByteArray =
        derive(roleId, laneId, ordinal, 32).copyOf(16)

    fun deriveResourceRoot(laneId: Int = 0, ordinal: Int = 0): String {
        val raw = derive(ROLE_ROOT, laneId, ordinal, 32)
        return try {
            encodeUrlSafe(raw, RESOURCE_ROOT_BYTES)
        } finally {
            Arrays.fill(raw, 0)
        }
    }

    fun derivePagePathToken(roleId: Int, pageIndex: Int, ordinal: Int = 0): String {
        val raw = derive(roleId, pageIndex and 0xFF, ordinal, 32)
        return try {
            encodeUrlSafe(raw, PAGE_TOKEN_BYTES)
        } finally {
            Arrays.fill(raw, 0)
        }
    }

    fun deriveJniName(laneId: Int = 0, ordinal: Int = 0): String {
        val raw = derive(ROLE_JNI, laneId, ordinal, 32)
        return try {
            val n = JNI_NAME_MIN + (raw[0].toInt() and 0xFF) % (JNI_NAME_MAX - JNI_NAME_MIN + 1)
            val chars = CharArray(n) { index ->
                ('a'.code + ((raw[index + 1].toInt() and 0xFF) % 26)).toChar()
            }
            "q" + String(chars)
        } finally {
            Arrays.fill(raw, 0)
        }
    }

    override fun close() = wipe()

    fun wipe() {
        if (closed) return
        Arrays.fill(nameSeed, 0)
        Arrays.fill(artifactCommitment, 0)
        closed = true
    }

    private fun requireLive() {
        check(!closed) { "QpNameSchedule has been wiped" }
    }

    companion object {
        const val CURRENT_VERSION: Int = 2
        const val NAME_SEED_SIZE: Int = 16
        const val COMMITMENT_SIZE: Int = 32
        private const val INFO_PREFIX: Byte = 0x51
        private const val RESOURCE_ROOT_BYTES: Int = 9
        private const val PAGE_TOKEN_BYTES: Int = 9
        private const val JNI_NAME_MIN: Int = 8
        private const val JNI_NAME_MAX: Int = 12

        const val ROLE_FRAME: Int = 0x11
        const val ROLE_DIRECTORY: Int = 0x12
        const val ROLE_RESOURCE: Int = 0x13
        const val ROLE_TOKEN: Int = 0x14
        const val ROLE_NATIVE: Int = 0x15
        const val ROLE_TEXT: Int = 0x16
        const val ROLE_CLASS: Int = 0x17
        const val ROLE_VM: Int = 0x18
        const val ROLE_DEBUG: Int = 0x19
        const val ROLE_ROOT: Int = 0x1A
        const val ROLE_JNI: Int = 0x1B
        const val ROLE_CRYPTO: Int = 0x1C

        const val LANE_RUNTIME_BINDING: Int = 0
        const val LANE_FRAME_AUTH: Int = 1
        const val LANE_DIR_RUNTIME: Int = 2
        const val LANE_DIR_RECORD: Int = 3
        const val LANE_DIR_ROOT: Int = 4
        const val LANE_RESOURCE_DIR: Int = 5
        const val LANE_RESOURCE_FRAME: Int = 6
        const val LANE_DEFENSE: Int = 7
        const val LANE_SPECIALIZATION: Int = 8
        const val LANE_TOKEN_AAD: Int = 9
        const val LANE_TOKEN_KEY: Int = 10
        const val LANE_RESOURCE_AUTH: Int = 11

        /** Deterministic seed used by isolated unit tests without a live build context. */
        internal val TEST_NAME_SEED: ByteArray = ByteArray(NAME_SEED_SIZE) { it.toByte() }
        internal val TEST_ARTIFACT_COMMITMENT: ByteArray = ByteArray(COMMITMENT_SIZE) { it.toByte() }

        private val URL_SAFE = (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            ).toCharArray()

        fun create(
            nameSeed: ByteArray,
            artifactCommitment: ByteArray,
            scheduleVersion: Int = CURRENT_VERSION,
        ): QpNameSchedule {
            require(nameSeed.size == NAME_SEED_SIZE) { "nameSeed must be $NAME_SEED_SIZE bytes" }
            require(artifactCommitment.size == COMMITMENT_SIZE) { "artifactCommitment must be $COMMITMENT_SIZE bytes" }
            require(scheduleVersion in 0..0xFF) { "scheduleVersion out of range" }
            return QpNameSchedule(nameSeed.copyOf(), artifactCommitment.copyOf(), scheduleVersion)
        }

        fun generate(
            artifactCommitment: ByteArray,
            random: SecureRandom = SecureRandom(),
            scheduleVersion: Int = CURRENT_VERSION,
        ): QpNameSchedule {
            val seed = ByteArray(NAME_SEED_SIZE)
            random.nextBytes(seed)
            return try {
                create(seed, artifactCommitment, scheduleVersion)
            } finally {
                Arrays.fill(seed, 0)
            }
        }

        internal fun encodeUrlSafe(raw: ByteArray, byteCount: Int): String {
            require(byteCount > 0 && byteCount <= raw.size)
            val bitCount = byteCount * 8
            val charCount = (bitCount + 5) / 6
            val chars = CharArray(charCount)
            var bitBuffer = 0
            var bits = 0
            var out = 0
            for (index in 0 until byteCount) {
                bitBuffer = (bitBuffer shl 8) or (raw[index].toInt() and 0xFF)
                bits += 8
                while (bits >= 6) {
                    bits -= 6
                    chars[out++] = URL_SAFE[(bitBuffer ushr bits) and 0x3F]
                }
            }
            if (bits > 0) {
                chars[out] = URL_SAFE[(bitBuffer shl (6 - bits)) and 0x3F]
            }
            return String(chars)
        }
    }
}

internal fun currentNameSeed(): ByteArray =
    io.github.hht0rro.javashroud.transforms.protection.currentQpBuildContextOrNull()?.copyNameSeed()
        ?: QpNameSchedule.TEST_NAME_SEED.copyOf()

internal fun qpNameSchedule(
    commitment: ByteArray,
    nameSeed: ByteArray = currentNameSeed(),
): QpNameSchedule = QpNameSchedule.create(nameSeed, commitment)

internal fun currentArtifactCommitment(): ByteArray =
    io.github.hht0rro.javashroud.transforms.protection.currentQpBuildContextOrNull()
        ?.qpBuildPlanOrNull()
        ?.artifactCanonicalCommitment
        ?.copyOf()
        ?: QpNameSchedule.TEST_ARTIFACT_COMMITMENT.copyOf()

internal fun activeQpNameSchedule(): QpNameSchedule =
    qpNameSchedule(currentArtifactCommitment())

internal fun derivedFrameMagic(): ByteArray =
    activeQpNameSchedule().use { it.deriveMagic(QpNameSchedule.ROLE_FRAME) }

internal fun derivedVmMagic(): ByteArray =
    vmNameSchedule().use { it.deriveMagic(QpNameSchedule.ROLE_VM) }

/**
 * VM program magic is bound to [currentNameSeed] only. Method virtualization
 * serializes Qp VM before the canonical artifact commitment exists; page AEAD
 * still uses the later commitment. Runtime must therefore derive VM magic
 * without that commitment or nested/high-value pages fail closed on parse.
 */
internal fun vmNameSchedule(): QpNameSchedule {
    val seed = currentNameSeed()
    val salt = ByteArray(QpNameSchedule.COMMITMENT_SIZE)
    seed.copyInto(salt, destinationOffset = 0)
    seed.copyInto(salt, destinationOffset = seed.size)
    return QpNameSchedule.create(seed, salt)
}

internal fun derivedTokenMagic(): ByteArray =
    activeQpNameSchedule().use { it.deriveMagic(QpNameSchedule.ROLE_TOKEN) }

internal fun derivedRuntimeBindingDomain(): ByteArray =
    activeQpNameSchedule().use { it.deriveDomain(QpNameSchedule.ROLE_CRYPTO, QpNameSchedule.LANE_RUNTIME_BINDING) }

internal fun derivedFrameAuthDomain(): ByteArray =
    activeQpNameSchedule().use { it.deriveDomain(QpNameSchedule.ROLE_CRYPTO, QpNameSchedule.LANE_FRAME_AUTH) }

internal fun derivedTokenAadDomain(): ByteArray =
    activeQpNameSchedule().use { it.deriveDomain(QpNameSchedule.ROLE_TOKEN, QpNameSchedule.LANE_TOKEN_AAD) }

internal fun derivedTokenKeyDomain(): ByteArray =
    activeQpNameSchedule().use { it.deriveDomain(QpNameSchedule.ROLE_TOKEN, QpNameSchedule.LANE_TOKEN_KEY) }

internal const val RETIRED_RESOURCE_DIR = "META-INF/jsrt"
internal const val RETIRED_CATALOG_INDEX = "META-INF/jsrt/catalog.index"
internal const val RETIRED_CATALOG_PREFIX = "META-INF/jsrt/catalog/"
internal const val RETIRED_DIRECTORY_FILE = "directory.jsr1"

internal fun qpResourceDir(): String =
    "META-INF/" + activeQpNameSchedule().use { it.deriveResourceRoot() }

internal fun qpCatalogIndexPath(): String = qpResourceDir() + "/catalog.index"

internal fun qpCatalogPrefix(): String = qpResourceDir() + "/catalog/"

internal fun qpDirectoryFileName(): String =
    activeQpNameSchedule().use { it.derivePagePathToken(QpNameSchedule.ROLE_DIRECTORY, 0) }

internal fun qpDirectoryResourcePath(): String = qpCatalogPrefix() + qpDirectoryFileName()

internal fun qpPageBundleFileName(): String =
    activeQpNameSchedule().use { it.derivePagePathToken(QpNameSchedule.ROLE_RESOURCE, 0) }

internal fun qpPageBundlePath(): String = qpCatalogPrefix() + qpPageBundleFileName()
