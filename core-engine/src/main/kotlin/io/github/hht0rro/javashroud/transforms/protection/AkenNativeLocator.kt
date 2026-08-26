package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenR1FrameWriter
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenR1WireFormat
import io.github.hht0rro.javashroud.transforms.protection.aken.RuntimeBindingDigest
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays

/**
 * Raw, non-secret locator for the current AKEN-R1 Rust runtime artifact.
 *
 * The locator is deliberately separate from retired JSBI/JSRP resources: it
 * identifies exactly one Rust artifact per supported platform and binds it to
 * its final resource path, target triple, specialization, ABI surface, byte
 * length, and SHA-256 digest. It does not contain a DEK, boot material, key
 * slot, or a general resource directory.
 */
internal const val AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE = "META-INF/jsrt/native.locator"
internal const val AKEN_NATIVE_BINDINGS_LOCATOR_LOGICAL_RESOURCE = "META-INF/jsrt/native.bindings.locator"
internal const val AKEN_NATIVE_RESOURCE_ROOT = "META-INF/"
internal const val AKEN_R1_NATIVE_RESOURCE_ROOT = "META-INF/jsrt/"
internal const val AKEN_NATIVE_LOCATOR_VERSION = 2
internal const val AKEN_R1_PAYLOAD_PROFILE = "aken-r1-rust-ffi-v1"
internal val AKEN_NATIVE_LOCATOR_MAGIC_BYTES = byteArrayOf(0xD7.toByte(), 0xA4.toByte(), 0x91.toByte(), 0xE3.toByte())

internal class AkenNativeLocatorEntry(
    val platform: String,
    val resourcePath: String,
    val fileSuffix: String,
    val storedLength: Int,
    sha256: ByteArray,
) {
    private val digestValue = sha256.copyOf()

    init {
        require(platform in AKEN_NATIVE_PLATFORM_SUFFIXES) { "unsupported AKEN native platform: $platform" }
        require(fileSuffix == AKEN_NATIVE_PLATFORM_SUFFIXES.getValue(platform)) {
            "invalid AKEN native suffix for $platform"
        }
        require(isAkenNativeLocatorResourcePath(resourcePath)) { "invalid AKEN native resource path" }
        require(resourcePath.length <= AKEN_NATIVE_FINAL_BINDING_ROUTE_CHARS) {
            "AKEN native resource route is too long for the R1 binding"
        }
        require(resourcePath.endsWith(fileSuffix)) {
            "AKEN native resource route does not match its locked suffix"
        }
        require(storedLength in 1..AKEN_NATIVE_MAX_LIBRARY_BYTES) {
            "AKEN native resource length is outside the R1 bound"
        }
        require(digestValue.size == AKEN_NATIVE_SHA256_SIZE) { "AKEN native resource SHA-256 must be 32 bytes" }
    }

    fun copyDigest(): ByteArray = digestValue.copyOf()

    internal fun <T> withDigest(block: (ByteArray) -> T): T = block(digestValue)

    /** Clears only the owned digest copy used by a short-lived verification row. */
    internal fun wipeDigest() = Arrays.fill(digestValue, 0)
}

internal class AkenNativeBindingsLocatorEntry(
    val resourcePath: String,
    val storedLength: Int,
    sha256: ByteArray,
) {
    private val digestValue = sha256.copyOf()

    init {
        require(isAkenNativeLocatorResourcePath(resourcePath)) { "invalid AKEN native bindings resource path" }
        require(resourcePath.length <= AKEN_NATIVE_FINAL_BINDING_ROUTE_CHARS) {
            "AKEN native bindings route is too long for the R1 binding"
        }
        require(storedLength in 1..AKEN_NATIVE_BINDINGS_MAX_BYTES) {
            "AKEN native bindings resource length is outside the R1 bound"
        }
        require(digestValue.size == AKEN_NATIVE_SHA256_SIZE) { "AKEN native bindings SHA-256 must be 32 bytes" }
    }

    fun copyDigest(): ByteArray = digestValue.copyOf()

    internal fun <T> withDigest(block: (ByteArray) -> T): T = block(digestValue)

    /** Clears only the owned digest copy used by a short-lived verification row. */
    internal fun wipeDigest() = Arrays.fill(digestValue, 0)
}

internal data class CatalogNativeBindingInputs(
    val nativeSha256: ByteArray,
    val abiDigest: ByteArray,
    val targetTriple: String,
    val payloadProfile: String,
    val platform: String,
) : AutoCloseable {
    init {
        require(nativeSha256.size == AKEN_NATIVE_SHA256_SIZE && nativeSha256.any { it != 0.toByte() }) {
            "AKEN catalog native SHA-256 is empty or all-zero"
        }
        require(abiDigest.size == AKEN_NATIVE_SHA256_SIZE && abiDigest.any { it != 0.toByte() }) {
            "AKEN catalog ABI digest is empty or all-zero"
        }
    }

    fun wipe() {
        Arrays.fill(nativeSha256, 0)
        Arrays.fill(abiDigest, 0)
    }

    override fun close() = wipe()
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

    fun catalogBindingInputs(entries: Iterable<AkenNativeLocatorEntry>): CatalogNativeBindingInputs {
        val primary = orderedEntries(entries).first()
        val nativeSha256 = primary.copyDigest()
        val targetTriple = targetTripleForPlatform(primary.platform)
        val targetBytes = targetTriple.toByteArray(StandardCharsets.US_ASCII)
        try {
            val abiDigest = nativeAbiDigest(targetBytes, nativeSha256)
            try {
                return CatalogNativeBindingInputs(
                    nativeSha256 = nativeSha256.copyOf(),
                    abiDigest = abiDigest.copyOf(),
                    targetTriple = targetTriple,
                    payloadProfile = AKEN_R1_PAYLOAD_PROFILE,
                    platform = primary.platform,
                )
            } finally {
                Arrays.fill(abiDigest, 0)
            }
        } finally {
            Arrays.fill(nativeSha256, 0)
            Arrays.fill(targetBytes, 0)
        }
    }

    fun encode(
        entries: Iterable<AkenNativeLocatorEntry>,
        bindingsEntry: AkenNativeBindingsLocatorEntry? = null,
        expectedFinalBindingDigest: RuntimeBindingDigest? = null,
    ): ByteArray {
        val ordered = orderedEntries(entries)
        validateRecordSet(ordered, bindingsEntry)
        val actualFinalBindingDigest = finalNativeBindingDigest(ordered, bindingsEntry)
        val actualDigestBytes = actualFinalBindingDigest.asBytes()
        try {
            expectedFinalBindingDigest?.let { expected ->
                val expectedDigestBytes = expected.asBytes()
                try {
                    require(MessageDigest.isEqual(actualDigestBytes, expectedDigestBytes)) {
                        "AKEN-R1 final native binding digest changed before locator encoding"
                    }
                } finally {
                    Arrays.fill(expectedDigestBytes, 0)
                }
            }
        } finally {
            Arrays.fill(actualDigestBytes, 0)
        }

        val recordCount = ordered.size + if (bindingsEntry == null) 0 else 1
        val body = WipableByteArrayOutputStream()
        var payload: ByteArray? = null
        var commitment: ByteArray? = null
        try {
            body.write(AKEN_NATIVE_LOCATOR_MAGIC_BYTES)
            body.write(AKEN_NATIVE_LOCATOR_VERSION)
            body.write(0) // flags: the current format has no optional parsing lanes.
            writeU16(body, recordCount)
            ordered.forEach { entry ->
                entry.withDigest { digest ->
                    writeRecord(
                        out = body,
                        kind = AKEN_NATIVE_LOCATOR_KIND_LIBRARY,
                        platformId = AKEN_NATIVE_PLATFORM_IDS.getValue(entry.platform),
                        resourcePath = entry.resourcePath,
                        storedLength = entry.storedLength,
                        digest = digest,
                    )
                }
            }
            bindingsEntry?.let { entry ->
                entry.withDigest { digest ->
                    writeRecord(
                        out = body,
                        kind = AKEN_NATIVE_LOCATOR_KIND_BINDINGS,
                        platformId = 0,
                        resourcePath = entry.resourcePath,
                        storedLength = entry.storedLength,
                        digest = digest,
                    )
                }
            }
            payload = body.toByteArray()
            commitment = locatorCommitment(checkNotNull(payload))
            return ByteArray(payload!!.size + commitment!!.size).also { encoded ->
                payload!!.copyInto(encoded)
                commitment!!.copyInto(encoded, payload!!.size)
            }
        } finally {
            payload?.let { Arrays.fill(it, 0) }
            commitment?.let { Arrays.fill(it, 0) }
            body.wipe()
        }
    }

    /**
     * Computes the R1 binding over the exact final native rows.  This is
     * build-only integrity material: the current v2 locator keeps its existing
     * Java-compatible wire shape, while sealing still proves that all paths,
     * lengths, suffixes, and final SHA-256 values were fixed together.
     */
    internal fun finalNativeBindingDigest(
        entries: Iterable<AkenNativeLocatorEntry>,
        bindingsEntry: AkenNativeBindingsLocatorEntry? = null,
    ): RuntimeBindingDigest {
        val ordered = orderedEntries(entries)
        validateRecordSet(ordered, bindingsEntry)
        val recordCount = ordered.size + if (bindingsEntry == null) 0 else 1
        val writer = AkenR1FrameWriter(AkenR1WireFormat.MAX_BINDING_SIZE)
        var binding: ByteArray? = null
        try {
            writer.writeBytes(FINAL_NATIVE_BINDING_MAGIC)
            writer.writeU8(AkenR1WireFormat.VERSION)
            writer.writeU16Be(recordCount)
            ordered.forEach { entry ->
                entry.withDigest { digest ->
                    writeFinalBindingRecord(
                        writer = writer,
                        kind = AKEN_NATIVE_LOCATOR_KIND_LIBRARY,
                        platformId = AKEN_NATIVE_PLATFORM_IDS.getValue(entry.platform),
                        resourcePath = entry.resourcePath,
                        fileSuffix = entry.fileSuffix,
                        storedLength = entry.storedLength,
                        digest = digest,
                    )
                }
            }
            bindingsEntry?.let { entry ->
                entry.withDigest { digest ->
                    writeFinalBindingRecord(
                        writer = writer,
                        kind = AKEN_NATIVE_LOCATOR_KIND_BINDINGS,
                        platformId = 0,
                        resourcePath = entry.resourcePath,
                        fileSuffix = "",
                        storedLength = entry.storedLength,
                        digest = digest,
                    )
                }
            }
            binding = writer.finish()
            return AkenR1WireFormat.runtimeBindingDigest(binding)
        } finally {
            binding?.let { Arrays.fill(it, 0) }
            writer.close()
        }
    }

    /**
     * Re-reads the final artifact entries and recomputes the same binding used
     * before locator encoding. This closes the sealing boundary: a route,
     * length, or native byte mutation after row creation cannot survive.
     */
    internal fun finalNativeBindingDigestFromArtifact(
        artifactEntries: Iterable<JarEntryData>,
        locatorEntries: Iterable<AkenNativeLocatorEntry>,
        bindingsEntry: AkenNativeBindingsLocatorEntry? = null,
    ): RuntimeBindingDigest {
        val expectedLibraries = orderedEntries(locatorEntries)
        validateRecordSet(expectedLibraries, bindingsEntry)
        val expectedPaths = buildSet {
            expectedLibraries.forEach { add(it.resourcePath) }
            bindingsEntry?.let { add(it.resourcePath) }
        }
        val finalByPath = HashMap<String, JarEntryData>(expectedPaths.size)
        artifactEntries.forEach { entry ->
            if (entry.name !in expectedPaths) return@forEach
            require(finalByPath.put(entry.name, entry) == null) {
                "AKEN-R1 final native route is emitted more than once: ${entry.name}"
            }
        }
        val reboundLibraries = ArrayList<AkenNativeLocatorEntry>(expectedLibraries.size)
        var reboundBindings: AkenNativeBindingsLocatorEntry? = null
        try {
            expectedLibraries.forEach { expected ->
                val actual = checkNotNull(finalByPath[expected.resourcePath]) {
                    "AKEN-R1 final native route is missing: ${expected.resourcePath}"
                }
                require(actual.bytes.size == expected.storedLength) {
                    "AKEN-R1 final native length changed: ${expected.resourcePath}"
                }
                val rebound = entry(
                    platform = expected.platform,
                    resourcePath = expected.resourcePath,
                    fileSuffix = expected.fileSuffix,
                    storedBytes = actual.bytes,
                )
                val digestMatches = rebound.withDigest { reboundDigest ->
                    expected.withDigest { expectedDigest ->
                        MessageDigest.isEqual(reboundDigest, expectedDigest)
                    }
                }
                require(digestMatches) {
                    "AKEN-R1 final native bytes changed: ${expected.resourcePath}"
                }
                reboundLibraries += rebound
            }
            bindingsEntry?.let { expected ->
                val actual = checkNotNull(finalByPath[expected.resourcePath]) {
                    "AKEN-R1 final bindings route is missing: ${expected.resourcePath}"
                }
                require(actual.bytes.size == expected.storedLength) {
                    "AKEN-R1 final bindings length changed: ${expected.resourcePath}"
                }
                val rebound = bindingsEntry(
                    resourcePath = expected.resourcePath,
                    storedBytes = actual.bytes,
                )
                val digestMatches = rebound.withDigest { reboundDigest ->
                    expected.withDigest { expectedDigest ->
                        MessageDigest.isEqual(reboundDigest, expectedDigest)
                    }
                }
                require(digestMatches) {
                    "AKEN-R1 final bindings bytes changed: ${expected.resourcePath}"
                }
                reboundBindings = rebound
            }
            return finalNativeBindingDigest(reboundLibraries, reboundBindings)
        } finally {
            reboundLibraries.forEach { it.wipeDigest() }
            reboundBindings?.wipeDigest()
        }
    }

    private fun orderedEntries(entries: Iterable<AkenNativeLocatorEntry>): List<AkenNativeLocatorEntry> {
        val collected = ArrayList<AkenNativeLocatorEntry>(AKEN_NATIVE_LOCATOR_MAX_RECORDS)
        entries.forEach { entry ->
            require(collected.size < AKEN_NATIVE_LOCATOR_MAX_RECORDS) {
                "AKEN native locator has too many platform entries"
            }
            collected += entry
        }
        val ordered = collected.sortedBy { AKEN_NATIVE_PLATFORM_IDS[it.platform] ?: Int.MAX_VALUE }
        require(ordered.isNotEmpty()) { "AKEN native locator requires at least one platform entry" }
        require(ordered.map { it.platform }.distinct().size == ordered.size) {
            "AKEN native locator contains duplicate platforms"
        }
        return ordered
    }

    private fun validateRecordSet(
        ordered: List<AkenNativeLocatorEntry>,
        bindingsEntry: AkenNativeBindingsLocatorEntry?,
    ) {
        val routes = buildSet {
            ordered.forEach { require(add(it.resourcePath)) { "AKEN native locator contains duplicate routes" } }
            bindingsEntry?.let { require(add(it.resourcePath)) { "AKEN native locator contains duplicate routes" } }
        }
        require(routes.size == ordered.size + if (bindingsEntry == null) 0 else 1) {
            "AKEN native locator contains duplicate routes"
        }
        val recordCount = ordered.size + if (bindingsEntry == null) 0 else 1
        require(recordCount in 1..AKEN_NATIVE_LOCATOR_MAX_RECORDS) {
            "AKEN native locator record count is invalid"
        }
    }

    private fun writeFinalBindingRecord(
        writer: AkenR1FrameWriter,
        kind: Int,
        platformId: Int,
        resourcePath: String,
        fileSuffix: String,
        storedLength: Int,
        digest: ByteArray,
    ) {
        val route = resourcePath.toByteArray(StandardCharsets.US_ASCII)
        val suffix = fileSuffix.toByteArray(StandardCharsets.US_ASCII)
        var target = ByteArray(0)
        var specialization = ByteArray(0)
        var abi = ByteArray(0)
        try {
            writer.writeU8(kind)
            writer.writeU8(platformId)
            writer.writeFrame(route)
            writer.writeFrame(suffix)
            writer.writeU32Be(storedLength.toLong())
            writer.writeBytes(digest)
            if (kind == AKEN_NATIVE_LOCATOR_KIND_LIBRARY) {
                val platform = platformForId(platformId)
                target = targetTripleForPlatform(platform).toByteArray(StandardCharsets.US_ASCII)
                specialization = nativeSpecializationDigest(
                    target = target,
                    route = route,
                    suffix = suffix,
                    storedLength = storedLength,
                    finalBytesDigest = digest,
                )
                abi = nativeAbiDigest(target, digest)
                writer.writeU8(FINAL_NATIVE_METADATA_VERSION)
                writer.writeFrame(target)
                writer.writeBytes(specialization)
                writer.writeBytes(abi)
            } else {
                writer.writeU8(FINAL_NATIVE_BINDINGS_METADATA_VERSION)
            }
        } finally {
            Arrays.fill(route, 0)
            Arrays.fill(suffix, 0)
            Arrays.fill(target, 0)
            Arrays.fill(specialization, 0)
            Arrays.fill(abi, 0)
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
private const val AKEN_NATIVE_MAX_LIBRARY_BYTES = 256 * 1024 * 1024
private const val AKEN_NATIVE_BINDINGS_MAX_BYTES = 4 * 1024 * 1024
private const val AKEN_NATIVE_LOCATOR_KIND_LIBRARY = 1
private const val AKEN_NATIVE_LOCATOR_KIND_BINDINGS = 2
private const val AKEN_NATIVE_LOCATOR_MAX_RECORDS = 3
private const val AKEN_NATIVE_LOCATOR_MAX_ROUTE_BYTES = 2048
private const val AKEN_NATIVE_FINAL_BINDING_ROUTE_CHARS = 256
private const val FINAL_NATIVE_METADATA_VERSION = 1
private const val FINAL_NATIVE_BINDINGS_METADATA_VERSION = 0

private val AKEN_NATIVE_LOCATOR_COMMITMENT_DOMAIN =
    "javashroud-aken-native-locator-commitment-v2".toByteArray(StandardCharsets.US_ASCII)
private val AKEN_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN =
    "javashroud-aken-native-locator-route-mask-v2".toByteArray(StandardCharsets.US_ASCII)
private val FINAL_NATIVE_BINDING_MAGIC =
    "AKEN-R1-FINAL-NATIVE".toByteArray(StandardCharsets.US_ASCII)
private val FINAL_NATIVE_SPECIALIZATION_DOMAIN =
    "AKEN-R1-final-native-specialization-v1".toByteArray(StandardCharsets.US_ASCII)
private val FINAL_NATIVE_ABI_DOMAIN =
    "AKEN-R1-final-native-abi-v1".toByteArray(StandardCharsets.US_ASCII)
private val R1_NATIVE_ABI_EXPORTS = listOf(
    "JNI_OnLoad",
    "JNI_OnUnload",
    "jsrt_r1_runtime_binding_digest",
    "jsrt_r1_open_frame",
)

private val AKEN_NATIVE_PLATFORM_SUFFIXES = mapOf(
    "windows-x64" to ".dll",
    "linux-x64" to ".so",
)

private val AKEN_NATIVE_PLATFORM_IDS = mapOf(
    "windows-x64" to 1,
    "linux-x64" to 2,
)

internal fun isAkenNativeLocatorResourcePath(path: String): Boolean {
    if (!path.startsWith(AKEN_NATIVE_RESOURCE_ROOT) || path.length == AKEN_NATIVE_RESOURCE_ROOT.length) return false
    if (path.any { it == '\u0000' || it == '\\' || it == '|' || it == '\r' || it == '\n' }) return false
    val lowerPath = path.lowercase()
    if (lowerPath.contains("macos") || lowerPath.contains("darwin") || lowerPath.contains("macho") ||
        lowerPath.contains("mach-o") || lowerPath.endsWith(".dylib") ||
        lowerPath.startsWith("meta-inf/aken/") || lowerPath.startsWith("meta-inf/.aken/") ||
        lowerPath.startsWith("meta-inf/.r/") || lowerPath.startsWith("meta-inf/js-native/") ||
        lowerPath.startsWith("meta-inf/native-src/") ||
        (lowerPath.startsWith("meta-inf/jsrt/") &&
            !lowerPath.startsWith("meta-inf/jsrt/windows-x64/") &&
            !lowerPath.startsWith("meta-inf/jsrt/linux-x64/")) ||
        lowerPath.contains("/js_kernel_") || lowerPath.contains("/zig") ||
        !hasCurrentR1ResourceSuffix(lowerPath)
    ) return false
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

private fun hasCurrentR1ResourceSuffix(lowerPath: String): Boolean =
    lowerPath.endsWith(".dll") || lowerPath.endsWith(".so") ||
        lowerPath.endsWith(".properties") || lowerPath.endsWith(".xml") ||
        lowerPath.endsWith(".json") || lowerPath.endsWith(".yml") ||
        lowerPath.endsWith(".cfg") || lowerPath.endsWith(".conf") ||
        lowerPath.endsWith(".ini") || lowerPath.endsWith(".txt")

private fun platformForId(platformId: Int): String = when (platformId) {
    1 -> "windows-x64"
    2 -> "linux-x64"
    else -> error("AKEN-R1 native platform id is invalid: $platformId")
}

private fun targetTripleForPlatform(platform: String): String =
    NativeRecompilationRoute.forPlatform(platform).rustTarget

private fun nativeSpecializationDigest(
    target: ByteArray,
    route: ByteArray,
    suffix: ByteArray,
    storedLength: Int,
    finalBytesDigest: ByteArray,
): ByteArray = MessageDigest.getInstance("SHA-256").apply {
    update(FINAL_NATIVE_SPECIALIZATION_DOMAIN)
    updateFramed(target)
    updateFramed(route)
    updateFramed(suffix)
    updateInt(storedLength)
    update(finalBytesDigest)
}.digest()

private fun nativeAbiDigest(target: ByteArray, finalBytesDigest: ByteArray): ByteArray =
    MessageDigest.getInstance("SHA-256").apply {
        update(FINAL_NATIVE_ABI_DOMAIN)
        updateFramed(target)
        R1_NATIVE_ABI_EXPORTS.forEach { export ->
            val bytes = export.toByteArray(StandardCharsets.US_ASCII)
            try {
                updateFramed(bytes)
            } finally {
                Arrays.fill(bytes, 0)
            }
        }
        update(finalBytesDigest)
    }.digest()

private class WipableByteArrayOutputStream : ByteArrayOutputStream() {
    fun wipe() {
        Arrays.fill(buf, 0)
        count = 0
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

private fun MessageDigest.updateFramed(value: ByteArray) {
    require(value.size.toLong() <= 0xFFFF_FFFFL) { "AKEN-R1 native binding field is too large" }
    updateInt(value.size)
    update(value)
}

private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
