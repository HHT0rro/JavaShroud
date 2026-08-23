package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenNativeLocatorTest {
    @Test
    fun sealing_emits_raw_locator_for_final_native_paths_and_rewrites_the_helper() {
        val sealed = sealFixture(
            windowsBytes = byteArrayOf(0x4d, 0x5a, 0x01, 0x02, 0x03),
            linuxBytes = byteArrayOf(0x7f, 0x45, 0x4c, 0x46, 0x04),
        )

        val locatorEntry = sealed.jarEntries.single { entry ->
            entry.bytes.isBinaryLocator()
        }
        assertFalse(locatorEntry.bytes.containsAscii("AKEN_NATIVE_LOCATOR_V1"))
        assertFalse(locatorEntry.bytes.containsAscii("AKEN_NATIVE_BINDINGS_V1"))
        assertFalse(locatorEntry.bytes.containsAscii("META-INF/"), "binary locator routes must not remain plain ASCII")
        assertFalse(locatorEntry.bytes.containsAscii("windows-x64"), "binary locator must not expose platform text")
        assertFalse(locatorEntry.name == AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE)
        assertFalse(locatorEntry.name.startsWith("META-INF/js-native/"))

        val parsed = parseLocator(locatorEntry.bytes)
        assertEquals(setOf("windows-x64", "linux-x64"), parsed.libraries.keys)
        assertFalse(sealed.jarEntries.any { it.name.startsWith("META-INF/js-native/") })

        for ((platform, row) in parsed.libraries) {
            val suffix = checkNotNull(row.fileSuffix)
            assertEquals(expectedSuffix(platform), suffix)
            assertTrue(row.resourcePath.startsWith("META-INF/"))
            assertFalse(row.resourcePath.startsWith("META-INF/js-native/"))
            assertTrue(row.resourcePath.endsWith(suffix))

            val nativeEntry = sealed.jarEntries.single { it.name == row.resourcePath }
            assertEquals(nativeEntry.bytes.size, row.storedLength)
            assertTrue(
                MessageDigest.getInstance("SHA-256").digest(nativeEntry.bytes).contentEquals(row.sha256),
                "AKEN locator digest must match the final native bytes",
            )
        }

        val binding = checkNotNull(parsed.binding)
        val bindingEntry = sealed.jarEntries.single { it.name == binding.resourcePath }
        assertEquals(bindingEntry.bytes.size, binding.storedLength)
        assertTrue(
            MessageDigest.getInstance("SHA-256").digest(bindingEntry.bytes).contentEquals(binding.sha256),
            "AKEN bindings locator digest must match the final bindings bytes",
        )

        assertTrue(
            sealed.classArtifacts.any { artifact -> artifact.bytes.containsAscii(locatorEntry.name) },
            "The rewritten helper must retain only the final randomized locator route",
        )
        assertFalse(
            sealed.classArtifacts.any { artifact -> artifact.bytes.containsAscii(AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE) },
            "The logical locator path must not survive helper sealing",
        )
    }

    @Test
    fun changing_a_final_native_payload_changes_its_locator_digest_without_reusing_its_bytes() {
        val baseline = sealFixture(
            windowsBytes = byteArrayOf(0x4d, 0x5a, 0x11, 0x22, 0x33),
            linuxBytes = byteArrayOf(0x7f, 0x45, 0x4c, 0x46, 0x44),
        )
        val changed = sealFixture(
            windowsBytes = byteArrayOf(0x4d, 0x5a, 0x11, 0x22, 0x34),
            linuxBytes = byteArrayOf(0x7f, 0x45, 0x4c, 0x46, 0x44),
        )

        val baselineLocator = rawLocatorEntry(baseline).bytes
        val changedLocator = rawLocatorEntry(changed).bytes
        val baselineRows = parseLocator(baselineLocator)
        val changedRows = parseLocator(changedLocator)
        assertEquals(
            baselineRows.libraries.getValue("windows-x64").resourcePath,
            changedRows.libraries.getValue("windows-x64").resourcePath,
        )
        assertFalse(
            baselineRows.libraries.getValue("windows-x64").sha256.contentEquals(
                changedRows.libraries.getValue("windows-x64").sha256,
            ),
        )
        assertTrue(
            baselineRows.libraries.getValue("linux-x64").sha256.contentEquals(
                changedRows.libraries.getValue("linux-x64").sha256,
            ),
        )
        assertFalse(baselineLocator.contentEquals(changedLocator))
    }

    private fun sealFixture(windowsBytes: ByteArray, linuxBytes: ByteArray) = withVbc4BuildContext(
        Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { (it * 29 + 7).toByte() },
            nativeSeed = 0x5A17C0DEL,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { (it * 17 + 3).toByte() },
        ),
    ) {
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        val helperBytes = checkNotNull(javaClass.classLoader.getResourceAsStream("$helperName.class")).use { it.readBytes() }
        val helperArtifact = ClassArtifact(
            entryName = "$helperName.class",
            summary = analyzeClassBytes(helperBytes),
            bytes = helperBytes,
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(helperArtifact),
            jarEntries = listOf(
                JarEntryData(helperArtifact.entryName, helperArtifact.bytes),
                JarEntryData("META-INF/js-native/js_kernel_windows-x64.dll", windowsBytes),
                JarEntryData("META-INF/js-native/js_kernel_linux-x64.so", linuxBytes),
            ),
        )
        RuntimeArtifactSealing.seal(artifact, seed = 0x5A17C0DEL, rewritesVmRuntime = false)
    }

    private fun rawLocatorEntry(sealed: io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact): JarEntryData =
        sealed.jarEntries.single { entry -> entry.bytes.isBinaryLocator() }

    private fun parseLocator(bytes: ByteArray): ParsedLocator {
        require(bytes.size >= HEADER_BYTES + COMMITMENT_BYTES) { "binary AKEN locator is truncated" }
        assertTrue(bytes.copyOfRange(0, MAGIC.size).contentEquals(MAGIC), "AKEN locator magic must be D7 A4 91 E3")
        assertEquals(VERSION, bytes[4].toInt() and 0xFF, "AKEN locator version must be v2")
        assertEquals(0, bytes[5].toInt() and 0xFF, "AKEN locator flags must be zero")

        val payloadLength = bytes.size - COMMITMENT_BYTES
        val expectedCommitment = MessageDigest.getInstance("SHA-256").apply {
            update(COMMITMENT_DOMAIN)
            update(bytes, 0, payloadLength)
        }.digest()
        try {
            assertTrue(
                expectedCommitment.contentEquals(bytes.copyOfRange(payloadLength, bytes.size)),
                "AKEN locator commitment must cover the exact binary payload",
            )
        } finally {
            Arrays.fill(expectedCommitment, 0)
        }

        val recordCount = readU16(bytes, 6)
        assertTrue(recordCount in 1..MAX_RECORDS, "AKEN locator record count must be bounded")
        var offset = HEADER_BYTES
        val libraries = linkedMapOf<String, LocatorRow>()
        var binding: LocatorRow? = null
        val seenRoutes = mutableSetOf<String>()
        repeat(recordCount) { recordIndex ->
            assertTrue(offset <= payloadLength - RECORD_FIXED_BYTES, "AKEN locator record must be complete")
            val kind = bytes[offset++].toInt() and 0xFF
            val platformId = bytes[offset++].toInt() and 0xFF
            val routeLength = readU16(bytes, offset)
            offset += 2
            val storedLength = readU32(bytes, offset)
            offset += 4
            assertTrue(routeLength in 1..MAX_ROUTE_BYTES, "AKEN locator route length must be bounded")
            assertTrue(offset + SHA256_BYTES + routeLength <= payloadLength, "AKEN locator route must fit payload")
            val digest = bytes.copyOfRange(offset, offset + SHA256_BYTES)
            offset += SHA256_BYTES
            val maskedRoute = bytes.copyOfRange(offset, offset + routeLength)
            offset += routeLength

            val routeBytes = unmaskRoute(maskedRoute, kind, platformId, storedLength, digest)
            try {
                val resourcePath = routeBytes.toString(StandardCharsets.US_ASCII)
                assertTrue(resourcePath.startsWith("META-INF/"), "AKEN locator route must stay under META-INF/")
                assertTrue(seenRoutes.add(resourcePath), "AKEN locator routes must be unique")
                when (kind) {
                    KIND_LIBRARY -> {
                        val platform = platformForId(platformId)
                        assertTrue(platform !in libraries, "AKEN locator platforms must be unique")
                        val suffix = expectedSuffix(platform)
                        assertTrue(resourcePath.endsWith(suffix), "AKEN locator route suffix must match platform")
                        libraries[platform] = LocatorRow(
                            kind = kind,
                            platformId = platformId,
                            resourcePath = resourcePath,
                            fileSuffix = suffix,
                            storedLength = storedLength,
                            sha256 = digest.copyOf(),
                        )
                    }
                    KIND_BINDINGS -> {
                        assertEquals(0, platformId, "AKEN bindings record must have platform id zero")
                        assertEquals(recordCount - 1, recordIndex, "AKEN bindings record must be terminal")
                        assertTrue(binding == null, "AKEN bindings record must be unique")
                        binding = LocatorRow(
                            kind = kind,
                            platformId = platformId,
                            resourcePath = resourcePath,
                            fileSuffix = null,
                            storedLength = storedLength,
                            sha256 = digest.copyOf(),
                        )
                    }
                    else -> error("unexpected AKEN locator record kind: $kind")
                }
            } finally {
                Arrays.fill(routeBytes, 0)
                Arrays.fill(maskedRoute, 0)
                Arrays.fill(digest, 0)
            }
        }
        assertEquals(payloadLength, offset, "AKEN locator must not contain trailing payload bytes")
        return ParsedLocator(libraries, binding)
    }

    private fun expectedSuffix(platform: String): String = when (platform) {
        "windows-x64" -> ".dll"
        "linux-x64" -> ".so"
        "macos-x64", "macos-arm64" -> ".dylib"
        else -> error("unexpected locator platform: $platform")
    }

    private fun unmaskRoute(
        maskedRoute: ByteArray,
        kind: Int,
        platformId: Int,
        storedLength: Int,
        digest: ByteArray,
    ): ByteArray {
        val route = maskedRoute.copyOf()
        var offset = 0
        var blockIndex = 0
        while (offset < route.size) {
            val block = MessageDigest.getInstance("SHA-256").apply {
                update(ROUTE_MASK_DOMAIN)
                update(kind.toByte())
                update(platformId.toByte())
                updateInt(storedLength)
                update(digest)
                updateInt(blockIndex++)
            }.digest()
            try {
                val count = minOf(block.size, route.size - offset)
                repeat(count) { index ->
                    route[offset + index] = (route[offset + index].toInt() xor block[index].toInt()).toByte()
                }
                offset += count
            } finally {
                Arrays.fill(block, 0)
            }
        }
        return route
    }

    private fun readU16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun readU32(bytes: ByteArray, offset: Int): Int {
        val value = ((bytes[offset].toLong() and 0xFF) shl 24) or
            ((bytes[offset + 1].toLong() and 0xFF) shl 16) or
            ((bytes[offset + 2].toLong() and 0xFF) shl 8) or
            (bytes[offset + 3].toLong() and 0xFF)
        require(value in 1..Int.MAX_VALUE) { "AKEN locator stored length must be positive" }
        return value.toInt()
    }

    private fun MessageDigest.updateInt(value: Int) {
        update((value ushr 24).toByte())
        update((value ushr 16).toByte())
        update((value ushr 8).toByte())
        update(value.toByte())
    }

    private fun ByteArray.isBinaryLocator(): Boolean =
        size >= MAGIC.size && MAGIC.indices.all { index -> this[index] == MAGIC[index] }

    private fun ByteArray.containsAscii(value: String): Boolean {
        val needle = value.toByteArray(Charsets.US_ASCII)
        return needle.isNotEmpty() && size >= needle.size &&
            (0..size - needle.size).any { offset -> needle.indices.all { index -> this[offset + index] == needle[index] } }
    }

    private data class LocatorRow(
        val kind: Int,
        val platformId: Int,
        val resourcePath: String,
        val fileSuffix: String?,
        val storedLength: Int,
        val sha256: ByteArray,
    )

    private data class ParsedLocator(
        val libraries: Map<String, LocatorRow>,
        val binding: LocatorRow?,
    )

    private fun platformForId(platformId: Int): String = when (platformId) {
        1 -> "windows-x64"
        2 -> "linux-x64"
        3 -> "macos-x64"
        4 -> "macos-arm64"
        else -> error("unexpected AKEN locator platform id: $platformId")
    }

    private companion object {
        val MAGIC = byteArrayOf(0xD7.toByte(), 0xA4.toByte(), 0x91.toByte(), 0xE3.toByte())
        val COMMITMENT_DOMAIN = "javashroud-aken-native-locator-commitment-v2".toByteArray(StandardCharsets.US_ASCII)
        val ROUTE_MASK_DOMAIN = "javashroud-aken-native-locator-route-mask-v2".toByteArray(StandardCharsets.US_ASCII)
        const val VERSION = 2
        const val HEADER_BYTES = 8
        const val COMMITMENT_BYTES = 32
        const val RECORD_FIXED_BYTES = 40
        const val SHA256_BYTES = 32
        const val MAX_RECORDS = 5
        const val MAX_ROUTE_BYTES = 2048
        const val KIND_LIBRARY = 1
        const val KIND_BINDINGS = 2
    }
}
