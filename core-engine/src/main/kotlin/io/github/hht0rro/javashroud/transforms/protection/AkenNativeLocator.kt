package io.github.hht0rro.javashroud.transforms.protection

import java.security.MessageDigest

/**
 * Raw, non-secret locator for the AKEN v4 native evaluator artifact.
 *
 * The locator is deliberately separate from legacy JSBI/JSRP resources: it
 * identifies exactly one native artifact per supported platform and binds it
 * to its final resource path, byte length, and SHA-256 digest.  It does not
 * contain a DEK, boot material, key slot, or a general resource directory.
 */
internal const val AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE = "META-INF/aken/native.locator"
internal const val AKEN_NATIVE_RESOURCE_ROOT = "META-INF/"
internal const val AKEN_NATIVE_LOCATOR_RECORD = "AKEN_NATIVE_LOCATOR_V1"

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

    fun encode(entries: Iterable<AkenNativeLocatorEntry>): ByteArray {
        val ordered = entries.toList().sortedBy { it.platform }
        require(ordered.isNotEmpty()) { "AKEN native locator requires at least one platform entry" }
        require(ordered.map { it.platform }.distinct().size == ordered.size) { "AKEN native locator contains duplicate platforms" }
        return buildString {
            for ((index, entry) in ordered.withIndex()) {
                if (index > 0) append('\n')
                append(AKEN_NATIVE_LOCATOR_RECORD)
                append('|')
                append(entry.platform)
                append('|')
                append(entry.resourcePath)
                append('|')
                append(entry.fileSuffix)
                append('|')
                append(entry.storedLength)
                append('|')
                append(entry.sha256.toHexLower())
            }
        }.toByteArray(Charsets.US_ASCII)
    }
}

private const val AKEN_NATIVE_SHA256_SIZE = 32

private val AKEN_NATIVE_PLATFORM_SUFFIXES = mapOf(
    "windows-x64" to ".dll",
    "linux-x64" to ".so",
    "macos-x64" to ".dylib",
    "macos-arm64" to ".dylib",
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

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
