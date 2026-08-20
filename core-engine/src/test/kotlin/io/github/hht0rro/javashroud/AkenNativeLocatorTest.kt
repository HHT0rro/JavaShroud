package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.AKEN_NATIVE_LOCATOR_RECORD
import io.github.hht0rro.javashroud.transforms.protection.AKEN_NATIVE_BINDINGS_LOCATOR_RECORD
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.security.MessageDigest
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
            entry.bytes.startsWithAscii("$AKEN_NATIVE_LOCATOR_RECORD|")
        }
        assertFalse(locatorEntry.name == AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE)
        assertFalse(locatorEntry.name.startsWith("META-INF/js-native/"))

        val rows = parseLocatorRows(locatorEntry.bytes)
        assertEquals(setOf("windows-x64", "linux-x64"), rows.keys)
        assertFalse(sealed.jarEntries.any { it.name.startsWith("META-INF/js-native/") })

        for ((platform, row) in rows) {
            assertEquals(AKEN_NATIVE_LOCATOR_RECORD, row.record)
            assertEquals(expectedSuffix(platform), row.fileSuffix)
            assertTrue(row.resourcePath.startsWith("META-INF/"))
            assertFalse(row.resourcePath.startsWith("META-INF/js-native/"))
            assertTrue(row.resourcePath.endsWith(row.fileSuffix))

            val nativeEntry = sealed.jarEntries.single { it.name == row.resourcePath }
            assertEquals(nativeEntry.bytes.size, row.storedLength)
            assertEquals(sha256Hex(nativeEntry.bytes), row.sha256)
        }

        val bindingRow = locatorEntry.bytes.decodeToString().lineSequence()
            .single { it.startsWith("$AKEN_NATIVE_BINDINGS_LOCATOR_RECORD|") }
            .split('|')
        assertEquals(4, bindingRow.size)
        val bindingEntry = sealed.jarEntries.single { it.name == bindingRow[1] }
        assertEquals(bindingEntry.bytes.size, bindingRow[2].toInt())
        assertEquals(sha256Hex(bindingEntry.bytes), bindingRow[3])

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

        val baselineRows = parseLocatorRows(rawLocatorEntry(baseline).bytes)
        val changedRows = parseLocatorRows(rawLocatorEntry(changed).bytes)
        assertEquals(baselineRows.getValue("windows-x64").resourcePath, changedRows.getValue("windows-x64").resourcePath)
        assertFalse(baselineRows.getValue("windows-x64").sha256 == changedRows.getValue("windows-x64").sha256)
        assertEquals(baselineRows.getValue("linux-x64").sha256, changedRows.getValue("linux-x64").sha256)
        assertFalse(rawLocatorEntry(baseline).bytes.decodeToString() == rawLocatorEntry(changed).bytes.decodeToString())
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
        sealed.jarEntries.single { entry -> entry.bytes.startsWithAscii("$AKEN_NATIVE_LOCATOR_RECORD|") }

    private fun parseLocatorRows(bytes: ByteArray): Map<String, LocatorRow> {
        val rows = bytes.decodeToString().lineSequence()
            .filter { line -> line.startsWith("$AKEN_NATIVE_LOCATOR_RECORD|") }
            .map { line ->
            val fields = line.split('|')
            assertEquals(6, fields.size, "AKEN native locator records must contain six fields")
            LocatorRow(
                record = fields[0],
                platform = fields[1],
                resourcePath = fields[2],
                fileSuffix = fields[3],
                storedLength = fields[4].toInt(),
                sha256 = fields[5],
            )
        }.toList()
        assertEquals(rows.size, rows.map { it.platform }.distinct().size, "AKEN native locator platforms must be unique")
        return rows.associateBy { it.platform }
    }

    private fun expectedSuffix(platform: String): String = when (platform) {
        "windows-x64" -> ".dll"
        "linux-x64" -> ".so"
        "macos-x64", "macos-arm64" -> ".dylib"
        else -> error("unexpected locator platform: $platform")
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(separator = "") { byte -> "%02x".format(byte) }

    private fun ByteArray.startsWithAscii(value: String): Boolean =
        size >= value.length && value.indices.all { index -> this[index] == value[index].code.toByte() }

    private fun ByteArray.containsAscii(value: String): Boolean {
        val needle = value.toByteArray(Charsets.US_ASCII)
        return needle.isNotEmpty() && size >= needle.size &&
            (0..size - needle.size).any { offset -> needle.indices.all { index -> this[offset + index] == needle[index] } }
    }

    private data class LocatorRow(
        val record: String,
        val platform: String,
        val resourcePath: String,
        val fileSuffix: String,
        val storedLength: Int,
        val sha256: String,
    )
}
