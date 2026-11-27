package io.github.hht0rro.javashroud.apk

import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.apache.commons.compress.archivers.zip.ZipFile

class ApkOutputPackerTest {

    private fun tempDir(): Path = Files.createTempDirectory("packer-test-")

    @Test
    fun preservesRawBytesMethodAndStripsOldSignatures() {
        val dir = tempDir()
        val inputApk = dir.resolve("in.apk")
        Files.write(
            inputApk,
            ApkTestFixtures.syntheticApk(
                extraEntries = listOf(
                    ApkTestFixtures.ApkTemplateEntry("res/layout/main.xml", "resource-bytes".toByteArray()),
                    ApkTestFixtures.ApkTemplateEntry("resources.arsc", ByteArray(97) { (it * 3).toByte() }, method = ZipEntry.STORED),
                ),
                oldSignature = true,
                comment = "keep-me",
            ),
        )
        val unpacked = ApkInputUnpacker.read(inputApk)
        val newDex = "classes.dex" to ByteArray(48) { 7 }
        val output = dir.resolve("nested/dir/out.apk")
        val result = ApkOutputPacker.pack(unpacked, listOf(newDex), output, soPageSize = 4096)

        assertEquals(listOf("classes.dex"), result.dexEntryNames)
        assertTrue(Files.isRegularFile(output), "packer must create missing output directories")

        ZipFile.builder().setFile(output.toFile()).get().use { zip ->
            val names = java.util.Collections.list(zip.getEntries()).map { it.name }
            assertTrue("AndroidManifest.xml" in names)
            assertTrue("META-INF/MANIFEST.MF" !in names, "old v1 manifest must be stripped")
            assertTrue(names.none { it.startsWith("META-INF/") && (it.endsWith(".SF") || it.endsWith(".RSA")) })
            assertTrue(names.none { ApkOutputPacker.isDexEntry(it) && it != "classes.dex" })

            val preserved = zip.getEntry("res/layout/main.xml")
            val preservedBytes = zip.getInputStream(preserved).use { it.readBytes() }
            val template = unpacked.preservedEntries.first { it.name == "res/layout/main.xml" }
            assertTrue(preservedBytes.contentEquals(template.data))
            assertEquals(template.method, preserved.method)
            // DEFLATED raw copy: compressed payload bytes identical to input.
            assertTrue(zip.getRawInputStream(preserved).use { it.readBytes() }.contentEquals(template.rawCompressedBytes))
        }
        assertEquals("keep-me", ApkInputUnpacker.readZipComment(output))
    }

    @Test
    fun alignsStoredEntriesAndReplacesDexBlock() {
        val dir = tempDir()
        val inputApk = dir.resolve("align-in.apk")
        val soBytes = ByteArray(300) { it.toByte() }
        Files.write(
            inputApk,
            ApkTestFixtures.syntheticApk(
                dexBytes = listOf(ByteArray(64) { 1 }, ByteArray(64) { 2 }),
                extraEntries = listOf(
                    ApkTestFixtures.ApkTemplateEntry("resources.arsc", ByteArray(96), method = ZipEntry.STORED),
                    ApkTestFixtures.ApkTemplateEntry("lib/arm64-v8a/libpage.so", soBytes, method = ZipEntry.STORED),
                ),
            ),
        )
        val unpacked = ApkInputUnpacker.read(inputApk)
        // Two input dex entries collapse to one new dex entry.
        val newDex = "classes.dex" to ByteArray(80) { 9 }
        val output = dir.resolve("align-out.apk")
        val pageSize = 16 * 1024
        ApkOutputPacker.pack(unpacked, listOf(newDex), output, soPageSize = pageSize)
        ApkValidation.validateOutputArchive(unpacked, output, listOf(newDex.first), pageSize)

        ZipFile.builder().setFile(output.toFile()).get().use { zip ->
            val entryNames = java.util.Collections.list(zip.getEntries()).map { it.name }
            assertTrue("classes.dex" in entryNames)
            assertTrue("classes2.dex" !in entryNames, "superseded dex entries must be dropped")

            val arsc = zip.getEntry("resources.arsc")
            assertEquals(ZipEntry.STORED, arsc.method)
            assertEquals(0L, storedDataOffset(arsc) % 4, "resources.arsc must be 4-aligned")

            val so = zip.getEntry("lib/arm64-v8a/libpage.so")
            assertEquals(ZipEntry.STORED, so.method)
            assertEquals(0L, so.dataOffset % pageSize, "stored .so must be page-aligned")
            val alignmentExtra = so.localFileDataExtra
            assertTrue(alignmentExtra.size > 255, "fixture must exercise a 16-bit extra-field length")
            val length = (alignmentExtra[2].toInt() and 0xFF) or ((alignmentExtra[3].toInt() and 0xFF) shl 8)
            assertEquals(alignmentExtra.size - 4, length)
            assertTrue(zip.getInputStream(so).use { it.readBytes() }.contentEquals(soBytes))

            val dex = zip.getEntry("classes.dex")
            assertEquals(ZipEntry.DEFLATED, dex.method)
            assertTrue(zip.getInputStream(dex).use { it.readBytes() }.contentEquals(newDex.second))
        }
    }

    @Test
    fun preservesDeflatedResourceTableAtUnalignedOffset() {
        val dir = tempDir()
        val input = dir.resolve("compressed-in.apk")
        val table = byteArrayOf(10, 40, 3, 2)
        Files.write(input, ApkTestFixtures.syntheticApk(extraEntries = listOf(
            ApkTestFixtures.ApkTemplateEntry("resources.arsc", table, method = ZipEntry.DEFLATED),
        )))
        val unpacked = ApkInputUnpacker.read(input)
        val output = dir.resolve("compressed-out.apk")
        ApkOutputPacker.pack(unpacked, listOf("classes.dex" to ByteArray(48)), output, soPageSize = 4096)
        ApkValidation.validateOutputArchive(unpacked, output, listOf("classes.dex"), 4096)
        ZipFile.builder().setFile(output.toFile()).get().use { zip ->
            val entry = zip.getEntry("resources.arsc")
            assertEquals(ZipEntry.DEFLATED, entry.method)
            assertTrue(zip.getInputStream(entry).use { it.readBytes() }.contentEquals(table))
        }
    }

    private fun storedDataOffset(entry: org.apache.commons.compress.archivers.zip.ZipArchiveEntry): Long =
        entry.localHeaderOffset + 30L + entry.name.toByteArray(Charsets.UTF_8).size + (entry.extra?.size ?: 0)
}
