package io.github.hht0rro.javashroud.transforms.protection

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays

/**
 * Raw, non-secret locator for the AKEN v4 native evaluator artifact.
 *
 * The locator is deliberately separate from legacy JSBI/JSRP resources: it
 * identifies exactly one native artifact per supported platform and binds it
 * to its final resource path, byte length, and SHA-256 digest.  It does not
 * contain a DEK, boot material, key slot, or a general resource directory.
 */
internal const val AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE = "META-INF/aken/native.locator"
internal const val AKEN_NATIVE_BINDINGS_LOCATOR_LOGICAL_RESOURCE = "META-INF/aken/native.bindings.locator"
internal const val AKEN_NATIVE_RESOURCE_ROOT = "META-INF/"
internal const val AKEN_NATIVE_LOCATOR_VERSION = 2
internal val AKEN_NATIVE_LOCATOR_MAGIC_BYTES = byteArrayOf(0xD7.toByte(), 0xA4.toByte(), 0x91.toByte(), 0xE3.toByte())

internal data class AkenNativeLocatorEntry(
    val platform: String,
    val resourcePath: String,
    val fileSuffix: String,
    val storedLength: Int,
    val sha256: ByteArray,
) {
    init {
        require(platform in AKEN_NATIVE_PLATFORM_SUFFIXES) { "unsupported AKEN native platform: $platform" }
        require(fileSuffix == AKEN_NATIVE_PLATFORM_SUFFIXES.getValue(platform)) {
            "invalid AKEN native suffix for $platform"
        }
        require(isAkenNativeLocatorResourcePath(resourcePath)) { "invalid AKEN native resource path" }
        require(storedLength > 0) { "AKEN native resource length must be positive" }
        require(sha256.size == AKEN_NATIVE_SHA256_SIZE) { "AKEN native resource SHA-256 must be 32 bytes" }
    }

    fun copyDigest(): ByteArray = sha256.copyOf()
}

internal data class AkenNativeBindingsLocatorEntry(
    val resourcePath: String,
    val storedLength: Int,
    val sha256: ByteArray,
) {
    init {
        require(isAkenNativeLocatorResourcePath(resourcePath)) { "invalid AKEN native bindings resource path" }
        require(storedLength > 0) { "AKEN native bindings resource length must be positive" }
        require(sha256.size == AKEN_NATIVE_SHA256_SIZE) { "AKEN native bindings SHA-256 must be 32 bytes" }
    }

    fun copyDigest(): ByteArray = sha256.copyOf()
}

/**
 * Build-only serializer.  The runtime owns an independent strict parser in
 * [JniMicrokernelHelper], keeping the runtime dependency surface Java-only.
 */
internal object AkenNativeLocator {
    fun entry(
        platform: String,
        resourcePath: String,
        fileSuffix: String,
        storedBytes: ByteArray,
    ): AkenNativeLocatorEntry = AkenNativeLocatorEntry(
        platform = platform,
        resourcePath = resourcePath,
        fileSuffix = fileSuffix,
        storedLength = storedBytes.size,
        sha256 = sha256(storedBytes),
    )

    fun bindingsEntry(
        resourcePath: String,
        storedBytes: ByteArray,
    ): AkenNativeBindingsLocatorEntry = AkenNativeBindingsLocatorEntry(
        resourcePath = resourcePath,
        storedLength = storedBytes.size,
        sha256 = sha256(storedBytes),
    )

    fun encode(
        entries: Iterable<AkenNativeLocatorEntry>,
        bindingsEntry: AkenNativeBindingsLocatorEntry? = null,
    ): ByteArray {
        val ordered = entries.toList().sortedBy { AKEN_NATIVE_PLATFORM_IDS.getValue(it.platform) }
        require(ordered.isNotEmpty()) { "AKEN native locator requires at least one platform entry" }
        require(ordered.map { it.platform }.distinct().size == ordered.size) { "AKEN native locator contains duplicate platforms" }
        val routes = buildSet {
            ordered.forEach { require(add(it.resourcePath)) { "AKEN native locator contains duplicate routes" } }
            bindingsEntry?.let { require(add(it.resourcePath)) { "AKEN native locator contains duplicate routes" } }
        }
        require(routes.size == ordered.size + if (bindingsEntry == null) 0 else 1) {
            "AKEN native locator contains duplicate routes"
        }
        val recordCount = ordered.size + if (bindingsEntry == null) 0 else 1
        require(recordCount in 1..AKEN_NATIVE_LOCATOR_MAX_RECORDS) { "AKEN native locator record count is invalid" }

        val body = ByteArrayOutputStream()
        body.write(AKEN_NATIVE_LOCATOR_MAGIC_BYTES)
        body.write(AKEN_NATIVE_LOCATOR_VERSION)
        body.write(0) // flags: the current format has no optional parsing lanes.
        writeU16(body, recordCount)
        ordered.forEach { entry ->
            writeRecord(
                out = body,
                kind = AKEN_NATIVE_LOCATOR_KIND_LIBRARY,
                platformId = AKEN_NATIVE_PLATFORM_IDS.getValue(entry.platform),
                resourcePath = entry.resourcePath,
                storedLength = entry.storedLength,
                digest = entry.sha256,
            )
        }
        bindingsEntry?.let { entry ->
            writeRecord(
                out = body,
                kind = AKEN_NATIVE_LOCATOR_KIND_BINDINGS,
                platformId = 0,
                resourcePath = entry.resourcePath,
                storedLength = entry.storedLength,
                digest = entry.sha256,
            )
        }

        val payload = body.toByteArray()
        val commitment = locatorCommitment(payload)
        return try {
            ByteArray(payload.size + commitment.size).also { encoded ->
                payload.copyInto(encoded)
                commitment.copyInto(encoded, payload.size)
            }
        } finally {
            Arrays.fill(payload, 0)
            Arrays.fill(commitment, 0)
        }
    }

    private fun writeRecord(
        out: ByteArrayOutputStream,
        kind: Int,
        platformId: Int,
        resourcePath: String,
        storedLength: Int,
        digest: ByteArray,
    ) {
        val route = resourcePath.toByteArray(StandardCharsets.US_ASCII)
        var maskedRoute = ByteArray(0)
        try {
            require(route.size in 1..AKEN_NATIVE_LOCATOR_MAX_ROUTE_BYTES) {
                "AKEN native locator route length is invalid"
            }
            maskedRoute = maskRoute(route, kind, platformId, storedLength, digest)
            out.write(kind)
            out.write(platformId)
            writeU16(out, route.size)
            writeU32(out, storedLength)
            out.write(digest)
            out.write(maskedRoute)
        } finally {
            Arrays.fill(route, 0)
            Arrays.fill(maskedRoute, 0)
        }
    }
}

private const val AKEN_NATIVE_SHA256_SIZE = 32
private const val AKEN_NATIVE_LOCATOR_KIND_LIBRARY = 1
private const val AKEN_NATIVE_LOCATOR_KIND_BINDINGS = 2
private const val AKEN_NATIVE_LOCATOR_MAX_RECORDS = 5
private const val AKEN_NATIVE_LOCATOR_MAX_ROUTE_BYTES = 2048

private val AKEN_NATIVE_LOCATOR_COMMITMENT_DOMAIN =
    "javashroud-aken-native-locator-commitment-v2".toByteArray(StandardCharsets.US_ASCII)
private val AKEN_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN =
    "javashroud-aken-native-locator-route-mask-v2".toByteArray(StandardCharsets.US_ASCII)

private val AKEN_NATIVE_PLATFORM_SUFFIXES = mapOf(
    "windows-x64" to ".dll",
    "linux-x64" to ".so",
    "macos-x64" to ".dylib",
    "macos-arm64" to ".dylib",
)

private val AKEN_NATIVE_PLATFORM_IDS = mapOf(
    "windows-x64" to 1,
    "linux-x64" to 2,
    "macos-x64" to 3,
    "macos-arm64" to 4,
)

internal fun isAkenNativeLocatorResourcePath(path: String): Boolean {
    if (!path.startsWith(AKEN_NATIVE_RESOURCE_ROOT) || path.length == AKEN_NATIVE_RESOURCE_ROOT.length) return false
    if (path.any { it == '\u0000' || it == '\\' || it == '|' || it == '\r' || it == '\n' }) return false
    val tail = path.removePrefix(AKEN_NATIVE_RESOURCE_ROOT)
    return tail.split('/').all { segment ->
        segment.isNotEmpty() && segment != "." && segment != ".." &&
            segment.all { character ->
                character in 'a'..'z' ||
                    character in 'A'..'Z' ||
                    character in '0'..'9' ||
                    character == '.' || character == '_' || character == '-'
            }
    }
}

private fun writeU16(out: ByteArrayOutputStream, value: Int) {
    require(value in 0..0xFFFF) { "AKEN native locator u16 value is invalid" }
    out.write(value ushr 8)
    out.write(value)
}

private fun writeU32(out: ByteArrayOutputStream, value: Int) {
    require(value > 0) { "AKEN native locator u32 value is invalid" }
    out.write(value ushr 24)
    out.write(value ushr 16)
    out.write(value ushr 8)
    out.write(value)
}

private fun maskRoute(
    route: ByteArray,
    kind: Int,
    platformId: Int,
    storedLength: Int,
    digest: ByteArray,
): ByteArray {
    val masked = route.copyOf()
    var offset = 0
    var blockIndex = 0
    while (offset < masked.size) {
        val block = MessageDigest.getInstance("SHA-256").apply {
            update(AKEN_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN)
            update(kind.toByte())
            update(platformId.toByte())
            updateInt(storedLength)
            update(digest)
            updateInt(blockIndex++)
        }.digest()
        try {
            val count = minOf(block.size, masked.size - offset)
            repeat(count) { index ->
                masked[offset + index] = (masked[offset + index].toInt() xor block[index].toInt()).toByte()
            }
            offset += count
        } finally {
            Arrays.fill(block, 0)
        }
    }
    return masked
}

private fun locatorCommitment(payload: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").apply {
    update(AKEN_NATIVE_LOCATOR_COMMITMENT_DOMAIN)
    update(payload)
}.digest()

private fun MessageDigest.updateInt(value: Int) {
    update((value ushr 24).toByte())
    update((value ushr 16).toByte())
    update((value ushr 8).toByte())
    update(value.toByte())
}

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
