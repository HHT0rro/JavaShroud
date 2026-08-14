package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64
import java.util.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenNativePageLocatorIncludeTest {
    @Test
    fun emits_empty_native_private_locator_when_no_finalized_pages_exist() {
        val context = defaultVbc4BuildContext()
        try {
            val include = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(context, Random(7L))
            assertTrue(include.contains("#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_COUNT 0u"))
            assertTrue(include.contains("#define JS_AKEN_NATIVE_PAGE_LOCATOR_BLOB_SIZE 0u"))
            assertTrue(include.contains("js_aken_native_page_locator_blob[1]"))
            assertFalse(include.contains("BootMaterialEnvelope"))
            assertFalse(include.contains("RuntimeKeyPartitions"))
            assertFalse(include.contains("nativeDecodeRuntimeResource"))
        } finally {
            context.wipe()
        }
    }

    @Test
    fun serializes_only_exact_current_page_records_from_published_finalization_layout() {
        val identity0 = "fixture:aken-native-include:first".encodeToByteArray()
        val identity1 = "fixture:aken-native-include:second".encodeToByteArray()
        val plaintext0 = "first VBC4 plaintext must not enter native locator include".encodeToByteArray()
        val plaintext1 = "second VBC4 plaintext must not enter native locator include".encodeToByteArray()
        val proof0 = ByteArray(29) { index -> (index * 7 + 5).toByte() }
        val proof1 = ByteArray(31) { index -> (index * 11 + 9).toByte() }
        val page0 = AkenVbc4PendingPage.create(
            entryToken = 0x414B_454E_0000_0101L,
            logicalIdentity = identity0,
            plaintext = plaintext0,
            resourcePath = "META-INF/.aken/vbc4/native-include.bin",
            pageIndex = 0,
            callSiteProof = proof0,
            random = SecureRandom(),
        )
        val page1 = AkenVbc4PendingPage.create(
            entryToken = 0x414B_454E_0000_0202L,
            logicalIdentity = identity1,
            plaintext = plaintext1,
            resourcePath = "META-INF/.aken/vbc4/native-include.bin",
            resourceOffset = page0.expectedStoredLength + 13,
            pageIndex = 0,
            callSiteProof = proof1,
            random = SecureRandom(),
        )
        var context: Vbc4BuildContext? = null
        var layout: AkenVbc4FinalizationLayout? = null
        var expectedRecords: List<ByteArray> = emptyList()
        try {
            val commitment = AkenVbc4FinalizationLayout.reserve(
                pendingPages = listOf(page0, page1),
                fixedEntries = emptyList(),
            )
            context = defaultVbc4BuildContext()
            val plan = context.initializeAkenBuildPlan(commitment.copyBytes())
            layout = AkenVbc4FinalizationLayout.materializeAndWipe(
                plan = plan,
                commitment = commitment,
                pendingPages = listOf(page0, page1),
                fixedEntries = emptyList(),
            )
            context.publishAkenVbc4FinalizationLayout(layout)
            expectedRecords = context.withAkenNativeLocatorRecordsForBuild { records ->
                records.map { record -> record.copyOf() }
            }

            val include = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(context, Random(0xA4EEL))
            val blob = parseUnsignedByteArray(include, "js_aken_native_page_locator_blob")
            val offsets = parseUnsignedIntArray(include, "js_aken_native_page_locator_record_offsets")
            val lengths = parseUnsignedIntArray(include, "js_aken_native_page_locator_record_lengths")
            val recordCount = parseMacro(include, "JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_COUNT")
            val blobSize = parseMacro(include, "JS_AKEN_NATIVE_PAGE_LOCATOR_BLOB_SIZE")
            try {
                assertEquals(2, recordCount)
                assertEquals(blob.size, blobSize)
                assertEquals(recordCount, offsets.size)
                assertEquals(recordCount, lengths.size)

                val actualRecords = offsets.indices.map { index ->
                    val offset = offsets[index]
                    val length = lengths[index]
                    assertTrue(offset >= 0 && length > 0 && offset + length <= blob.size)
                    blob.copyOfRange(offset, offset + length)
                }
                try {
                    val expectedEncodings = expectedRecords.map { Base64.getEncoder().encodeToString(it) }.toSet()
                    val actualEncodings = actualRecords.map { Base64.getEncoder().encodeToString(it) }.toSet()
                    assertEquals(expectedEncodings, actualEncodings)
                    actualRecords.forEach { record -> assertEquals(1, record[0].toInt() and 0xFF) }
                } finally {
                    actualRecords.forEach { Arrays.fill(it, 0) }
                }

                assertFalse(include.contains(plaintext0.decodeToString()))
                assertFalse(include.contains(plaintext1.decodeToString()))
                assertFalse(include.contains("BootMaterialEnvelope"))
                assertFalse(include.contains("RuntimeKeyPartitions"))
                assertFalse(include.contains("nativeDecodeRuntimeResource"))
            } finally {
                Arrays.fill(blob, 0)
                offsets.fill(0)
                lengths.fill(0)
            }

            context.wipe()
            assertTrue(layout.isWiped)
        } finally {
            expectedRecords.forEach { Arrays.fill(it, 0) }
            layout?.wipe()
            context?.wipe()
            Arrays.fill(identity0, 0)
            Arrays.fill(identity1, 0)
            Arrays.fill(plaintext0, 0)
            Arrays.fill(plaintext1, 0)
            Arrays.fill(proof0, 0)
            Arrays.fill(proof1, 0)
            page0.wipe()
            page1.wipe()
        }
    }

    private fun parseMacro(include: String, name: String): Int {
        val match = Regex("#define\\s+$name\\s+(\\d+)u").find(include)
            ?: error("missing generated macro $name")
        return match.groupValues[1].toInt()
    }

    private fun parseUnsignedByteArray(include: String, name: String): ByteArray {
        val initializer = arrayInitializer(include, name)
        val values = Regex("0x([0-9A-F]{2})u").findAll(initializer)
            .map { match -> match.groupValues[1].toInt(16).toByte() }
            .toList()
        return values.toByteArray()
    }

    private fun parseUnsignedIntArray(include: String, name: String): IntArray {
        val initializer = arrayInitializer(include, name)
        return Regex("(\\d+)u").findAll(initializer)
            .map { match -> match.groupValues[1].toInt() }
            .toList()
            .toIntArray()
    }

    private fun arrayInitializer(include: String, name: String): String {
        val start = include.indexOf("$name[")
        require(start >= 0) { "missing generated array $name" }
        val open = include.indexOf('{', start)
        val close = include.indexOf("};", open)
        require(open >= 0 && close > open) { "malformed generated array $name" }
        return include.substring(open + 1, close)
    }
}
