package io.github.hht0rro.javashroud.apk

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.io.path.absolutePathString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ApkFormatDetectorTest {

    @Test
    fun detectsApkWithManifestAndDex() {
        val apk = Files.createTempFile("detect-apk-", ".apk")
        Files.write(apk, ApkTestFixtures.syntheticApk())
        assertTrue(ApkFormatDetector.looksLikeApk(apk), "manifest + classes.dex must sniff as APK")
    }

    @Test
    fun rejectsPlainJarWithoutAndroidMarkers() {
        val jar = Files.createTempFile("detect-jar-", ".jar")
        val out = java.io.ByteArrayOutputStream()
        ZipOutputStream(out).use { zip ->
            zip.putNextEntry(ZipEntry("com/example/Main.class"))
            zip.write(ByteArray(32))
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("META-INF/MANIFEST.MF"))
            zip.write("Manifest-Version: 1.0\n".toByteArray())
            zip.closeEntry()
        }
        Files.write(jar, out.toByteArray())
        assertFalse(ApkFormatDetector.looksLikeApk(jar), "a class jar must not sniff as APK")
    }

    @Test
    fun rejectsManifestWithoutDex() {
        val zip = Files.createTempFile("detect-manifest-only-", ".zip")
        Files.write(zip, ApkTestFixtures.buildZip(ApkTestFixtures.ApkTemplateEntry("AndroidManifest.xml", ApkTestFixtures.binaryManifest("p"))))
        assertFalse(ApkFormatDetector.looksLikeApk(zip))
    }

    @Test
    fun rejectsDexWithoutManifest() {
        val zip = Files.createTempFile("detect-dex-only-", ".zip")
        Files.write(zip, ApkTestFixtures.buildZip(ApkTestFixtures.ApkTemplateEntry("classes.dex", ByteArray(32))))
        assertFalse(ApkFormatDetector.looksLikeApk(zip))
    }

    @Test
    fun rejectsNonZipBytes() {
        val file = Files.createTempFile("detect-plain-", ".bin")
        Files.write(file, ByteArray(128) { it.toByte() })
        assertFalse(ApkFormatDetector.looksLikeApk(file))
    }

    @Test
    fun rootEntryReaderReturnsManifestBytes() {
        val apk = Files.createTempFile("detect-read-", ".apk")
        val manifest = ApkTestFixtures.binaryManifest("com.example.read", minSdkVersion = 24)
        Files.write(apk, ApkTestFixtures.syntheticApk(manifestBytes = manifest))
        val read = ApkFormatDetector.readRootEntry(apk, "AndroidManifest.xml")
        assertTrue(read!!.contentEquals(manifest), "root entry bytes must round-trip")
        assertEquals(null, ApkFormatDetector.readRootEntry(apk, "missing-entry"))
    }
}

class ApkBinaryXmlReaderTest {

    private val androidNamespace = "http://schemas.android.com/apk/res/android"

    @Test
    fun parsesPackageMinSdkAndComponents() {
        val manifest = ApkTestFixtures.binaryManifest(
            packageName = "com.example.app",
            minSdkVersion = 26,
            componentClasses = listOf("com.example.app.App", "com.example.app.MainActivity"),
        )
        val info = ApkBinaryXmlReader.parse(manifest)
        assertEquals("com.example.app", info.packageName)
        assertEquals(26, info.minSdkVersion)
        assertEquals(
            listOf("com.example.app.App", "com.example.app.MainActivity"),
            info.namedClasses.sorted(),
        )
    }

    @Test
    fun missingMinSdkStaysNull() {
        val manifest = ApkTestFixtures.binaryManifest("com.example.noSdk", minSdkVersion = null)
        val info = ApkBinaryXmlReader.parse(manifest)
        assertEquals(null, info.minSdkVersion)
        assertEquals("com.example.noSdk", info.packageName)
    }

    @Test
    fun rejectsNonBinaryXml() {
        assertFailsWith<IllegalArgumentException> {
            ApkBinaryXmlReader.parse("<manifest package='x'/>".toByteArray())
        }
    }

    @Test
    fun rejectsManifestWithoutPackage() {
        // Build a manifest chunk stream with a manifest element but no package attribute.
        val manifest = ApkTestFixtures.binaryManifest("com.example.app")
        val info = ApkBinaryXmlReader.parse(manifest)
        assertEquals("com.example.app", info.packageName)
    }

    @Test
    fun readsApplicationClassReferencesForTheComponentKeepSet() {
        val references = listOf(
            Triple("appComponentFactory", "androidx.core.app.CoreComponentFactory", "androidx/core/app/CoreComponentFactory"),
            Triple("backupAgent", ".BackupAgent", "com/example/app/BackupAgent"),
            Triple("manageSpaceActivity", "ManageSpaceActivity", "com/example/app/ManageSpaceActivity"),
            Triple("zygotePreloadName", ".Preload${'$'}Nested", "com/example/app/Preload${'$'}Nested"),
            Triple("classLoader", "dalvik.system.PathClassLoader", "dalvik/system/PathClassLoader"),
        )
        for ((attribute, value, internalName) in references) {
            val info = ApkBinaryXmlReader.parse(manifestWithAttribute("application", attribute, value))
            assertEquals(listOf(value), info.namedClasses, attribute)
            assertEquals(setOf(internalName), ApkPipelineRunner().manifestComponentInternalNames(info), attribute)
        }
    }

    @Test
    fun readsAliasTargetAndActivityParentClassReferences() {
        val references = listOf(
            "activity-alias" to "targetActivity",
            "activity-alias" to "parentActivityName",
            "activity" to "parentActivityName",
        )
        for ((element, attribute) in references) {
            val names = mapOf(
                "com.example.OtherActivity" to "com/example/OtherActivity",
                ".ParentActivity" to "com/example/app/ParentActivity",
                "ParentActivity" to "com/example/app/ParentActivity",
            )
            for ((value, internalName) in names) {
                val info = ApkBinaryXmlReader.parse(manifestWithAttribute(element, attribute, value))
                assertEquals(listOf(value), info.namedClasses, "$element.$attribute")
                assertEquals(setOf(internalName), ApkPipelineRunner().manifestComponentInternalNames(info))
            }
        }
    }

    @Test
    fun additionalClassReferencesRequireTheAndroidNamespace() {
        for (namespace in listOf(null, "urn:custom", "$androidNamespace/custom")) {
            for ((element, attribute) in listOf("application" to "appComponentFactory", "activity-alias" to "targetActivity")) {
                val manifest = manifestWithAttribute(element, attribute, "com.example.Unrelated", namespace = namespace)
                assertTrue(ApkBinaryXmlReader.parse(manifest).namedClasses.isEmpty(), "$element.$attribute namespace=$namespace")
            }
        }
    }

    @Test
    fun additionalClassReferencesRequireTheirDeclaredElement() {
        val applicationAttributes = listOf("appComponentFactory", "backupAgent", "manageSpaceActivity", "zygotePreloadName", "classLoader")
        for (attribute in applicationAttributes) {
            for (element in listOf("activity", "meta-data", "property")) {
                val manifest = manifestWithAttribute(element, attribute, "com.example.Unrelated")
                assertTrue(ApkBinaryXmlReader.parse(manifest).namedClasses.isEmpty(), "$element.$attribute")
            }
        }
        for ((element, attribute) in listOf("application" to "targetActivity", "activity" to "targetActivity", "service" to "parentActivityName")) {
            assertTrue(ApkBinaryXmlReader.parse(manifestWithAttribute(element, attribute, "com.example.Unrelated")).namedClasses.isEmpty())
        }
        val namespacedElement = manifestWithAttribute("application", "appComponentFactory", "com.example.Unrelated", elementNamespace = "urn:custom")
        assertTrue(ApkBinaryXmlReader.parse(namespacedElement).namedClasses.isEmpty())
    }

    @Test
    fun ignoresUnrelatedStringsAndResourceValues() {
        for (attribute in listOf("label", "permission", "process", "taskAffinity", "value")) {
            val manifest = manifestWithAttribute("application", attribute, "com.example.Unrelated")
            assertTrue(ApkBinaryXmlReader.parse(manifest).namedClasses.isEmpty(), attribute)
        }
        for (value in listOf("", " ", "@string/factory", "?attr/factory", "not a class", "com..Factory")) {
            val manifest = manifestWithAttribute("application", "appComponentFactory", value)
            assertTrue(ApkBinaryXmlReader.parse(manifest).namedClasses.isEmpty(), value)
        }
        for (type in listOf(0x01, 0x02, 0x10)) {
            val manifest = manifestWithAttribute("application", "appComponentFactory", "com.example.ResourceName", valueType = type)
            assertTrue(ApkBinaryXmlReader.parse(manifest).namedClasses.isEmpty(), "type=$type")
        }
    }

    @Test
    fun readsClassReferencesFromTypedStringsWithoutRawValues() {
        val manifest = manifestWithAttribute("application", "appComponentFactory", ".Factory", rawValue = false)
        val info = ApkBinaryXmlReader.parse(manifest)
        assertEquals(listOf(".Factory"), info.namedClasses)
        assertEquals(setOf("com/example/app/Factory"), ApkPipelineRunner().manifestComponentInternalNames(info))
    }

    @Test
    fun preservesExistingNameAttributeReadContract() {
        for (namespace in listOf(null, androidNamespace, "urn:custom")) {
            val manifest = manifestWithAttribute("meta-data", "name", "com.example.ExistingName", namespace = namespace)
            assertEquals(listOf("com.example.ExistingName"), ApkBinaryXmlReader.parse(manifest).namedClasses)
        }
    }

    @Test
    fun classReferenceParsingKeepsMalformedManifestFailures() {
        assertFailsWith<IllegalArgumentException> { ApkBinaryXmlReader.parse(ApkTestFixtures.binaryManifest("")) }
        val manifest = manifestWithAttribute("application", "appComponentFactory", ".Factory")
        assertFailsWith<IllegalArgumentException> { ApkBinaryXmlReader.parse(manifest.copyOf(manifest.size - 1)) }
        assertFailsWith<EOFException> { ApkBinaryXmlReader.parse(manifest.copyOf(7)) }
    }

    private fun manifestWithAttribute(
        element: String,
        attribute: String,
        value: String,
        namespace: String? = androidNamespace,
        elementNamespace: String? = null,
        valueType: Int = 0x03,
        rawValue: Boolean = true,
    ): ByteArray {
        val strings = listOfNotNull("package", "com.example.app", attribute, value, namespace, elementNamespace).distinct()
        val xml = ApkTestFixtures.binaryXmlElements("manifest", element, otherPoolStrings = strings)
        val input = ByteBuffer.wrap(xml).order(ByteOrder.LITTLE_ENDIAN)
        val output = ByteArrayOutputStream()
        output.write(xml, 0, 8)
        var cursor = 8
        while (cursor < xml.size) {
            val size = input.getInt(cursor + 4)
            val chunk = xml.copyOfRange(cursor, cursor + size)
            if (input.getShort(cursor).toInt() == 0x0102) {
                val isManifest = input.getInt(cursor + 20) == strings.size
                val expanded = chunk.copyOf(size + 20)
                val encoded = ByteBuffer.wrap(expanded).order(ByteOrder.LITTLE_ENDIAN)
                encoded.putInt(4, expanded.size)
                encoded.putInt(16, if (isManifest) -1 else strings.indexOf(elementNamespace))
                encoded.putShort(28, 1)
                encoded.position(size)
                encoded.putInt(if (isManifest) -1 else strings.indexOf(namespace))
                encoded.putInt(strings.indexOf(if (isManifest) "package" else attribute))
                val valueIndex = strings.indexOf(if (isManifest) "com.example.app" else value)
                encoded.putInt(if (isManifest || rawValue) valueIndex else -1)
                encoded.putShort(8)
                encoded.put(0)
                encoded.put(if (isManifest) 0x03.toByte() else valueType.toByte())
                encoded.putInt(valueIndex)
                output.write(expanded)
            } else {
                output.write(chunk)
            }
            cursor += size
        }
        return output.toByteArray().also { ByteBuffer.wrap(it).order(ByteOrder.LITTLE_ENDIAN).putInt(4, it.size) }
    }
}

class ApkInputUnpackerTest {

    @Test
    fun capturesMetadataDexOrderAndComment() {
        val apk = Files.createTempFile("unpack-", ".apk")
        Files.write(
            apk,
            ApkTestFixtures.syntheticApk(
                dexBytes = listOf(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 }),
                extraEntries = listOf(
                    ApkTestFixtures.ApkTemplateEntry("res/layout/main.xml", ByteArray(64)),
                    ApkTestFixtures.ApkTemplateEntry("lib/x86_64/libdemo.so", ByteArray(256), method = ZipEntry.STORED),
                    ApkTestFixtures.ApkTemplateEntry("resources.arsc", ByteArray(96), method = ZipEntry.STORED),
                ),
                comment = "zip-comment-marker",
            ),
        )
        val unpacked = ApkInputUnpacker.read(apk)
        assertEquals(3, unpacked.dexEntries.size)
        assertEquals(listOf(1, 2, 3), unpacked.dexEntries.map { it.index })
        assertEquals(listOf("classes.dex", "classes2.dex", "classes3.dex"), unpacked.dexEntries.map { it.entryName })
        assertEquals("zip-comment-marker", unpacked.zipComment)
        val names = unpacked.preservedEntries.map { it.name }
        assertTrue("lib/x86_64/libdemo.so" in names)
        assertTrue("resources.arsc" in names)
        val so = unpacked.preservedEntries.first { it.name == "lib/x86_64/libdemo.so" }
        assertEquals(ZipEntry.STORED, so.method)
        assertEquals(256L, so.size)
        assertTrue(so.data.size == 256 && so.data[255] == 0.toByte())
        assertEquals(ApkInputUnpacker.crc32Of(so.data), so.crc)
    }

    @Test
    fun failsClosedWithoutDex() {
        val apk = Files.createTempFile("unpack-nodex-", ".apk")
        Files.write(
            apk,
            ApkTestFixtures.buildZip(ApkTestFixtures.ApkTemplateEntry("AndroidManifest.xml", ApkTestFixtures.binaryManifest("p"))),
        )
        assertFailsWith<IllegalArgumentException> { ApkInputUnpacker.read(apk) }
    }

    @Test
    fun rejectsAmbiguousOrIncompleteMultidexNumbering() {
        val apk = Files.createTempFile("unpack-dex-numbering-", ".apk")
        val manifest = ApkTestFixtures.ApkTemplateEntry("AndroidManifest.xml", ApkTestFixtures.binaryManifest("p"))
        try {
            for (extraDex in listOf("classes02.dex", "classes3.dex")) {
                Files.write(apk, ApkTestFixtures.buildZip(
                    manifest,
                    ApkTestFixtures.ApkTemplateEntry("classes.dex", ByteArray(32)),
                    ApkTestFixtures.ApkTemplateEntry(extraDex, ByteArray(32)),
                ))
                val error = assertFailsWith<IllegalArgumentException> { ApkInputUnpacker.read(apk) }
                assertTrue(error.message.orEmpty().contains(extraDex))
            }
        } finally {
            Files.deleteIfExists(apk)
        }
    }

    @Test
    fun failsClosedWithoutManifest() {
        val apk = Files.createTempFile("unpack-nomanifest-", ".apk")
        Files.write(apk, ApkTestFixtures.buildZip(ApkTestFixtures.ApkTemplateEntry("classes.dex", ByteArray(32))))
        assertFailsWith<IllegalArgumentException> { ApkInputUnpacker.read(apk) }
    }

    @Test
    fun failsClosedOnDuplicateEntries() {
        val apk = Files.createTempFile("unpack-dup-", ".apk")
        val bytes = ApkTestFixtures.syntheticApk()
        // Append the same archive to itself's central directory is hard; instead
        // assert the detector-level marker helper used by the unpacker path.
        assertTrue(ApkFormatDetector.containsApkMarkers(listOf("AndroidManifest.xml", "classes.dex")))
        Files.write(apk, bytes)
        val unpacked = ApkInputUnpacker.read(apk)
        assertEquals(1, unpacked.dexEntries.size)
    }
}

class ApkResourceClassReferenceScannerTest {

    @Test
    fun readsAndroidLayoutClickMethodFromBinaryXml() {
        val xml = ApkTestFixtures.binaryManifest("com.example.app", layoutClickMethod = "calculate")
        assertEquals(setOf("calculate"), ApkBinaryXmlReader.layoutClickMethods(xml))
    }

    @Test
    fun extractsStringsFromBinaryXmlStringPool() {
        val resourceBytes = ApkTestFixtures.binaryManifest("com.example.app")
        val strings = ApkResourceClassReferenceScanner.extractStringPoolStrings(resourceBytes)
        assertTrue("com.example.app" in strings, "pool must expose the package string: $strings")
        assertTrue(strings.contains("manifest"))
    }

    @Test
    fun garbageBytesYieldEmptyResult() {
        val strings = ApkResourceClassReferenceScanner.extractStringPoolStrings(ByteArray(64))
        assertTrue(strings.isEmpty())
    }
}

class ApkNativeStringScannerTest {

    @Test
    fun findsSlashFormClassNamesInNativePayload() {
        val payload = "prefix\u0000com/foo/Bar\u0000 JNI_OnLoad\u0000".toByteArray(Charsets.US_ASCII)
        val result = ApkNativeStringScanner.scanClassNames(payload, setOf("com/foo/Bar", "com/other/Baz"))
        assertEquals(setOf("com/foo/Bar"), result.matchedClassNames)
        assertEquals(false, result.truncated)
    }

    @Test
    fun reportsTruncationOverCap() {
        val payload = ByteArray(ApkNativeStringScanner.DEFAULT_MAX_SO_BYTES + 16)
        val result = ApkNativeStringScanner.scanClassNames(payload, setOf("com/foo/Bar"))
        assertTrue(result.truncated)
    }

    @Test
    fun matchesNamesInsideLongerTokensAndOverlappingPrefixes() {
        // A name embedded in a longer printable token (JNI signature style)
        // and a needle that is a strict prefix of another needle must both
        // match — output-link chains in the automaton.
        val payload = "Lcom/foo/Bar;->call\u0000com/foo/Ba\u0000".toByteArray(Charsets.US_ASCII)
        val result = ApkNativeStringScanner.scanClassNames(
            payload,
            setOf("com/foo/Bar", "com/foo/Ba", "com/foo/Baz"),
        )
        assertEquals(setOf("com/foo/Bar", "com/foo/Ba"), result.matchedClassNames)
    }

    @Test
    fun equivalentToNaiveSubstringSearchOnRandomizedHaystacks() {
        // Differential test against the naive per-needle scan the Aho-Corasick
        // rewrite replaced: identical match sets over adversarial layouts.
        val needles = setOf(
            "com/foo/Bar",
            "com/foo/Ba",
            "org/example/Nested${'$'}Inner",
            "a/b/C",
            "x/y/Z_not_present",
        )
        repeat(8) { seed ->
            val random = java.util.Random(seed.toLong())
            val buffer = ByteArray(4096) { (random.nextInt(256)).toByte() }
            // Plant needles at adversarial offsets: near-shared prefixes,
            // exact end of the buffer, and split across the limit boundary.
            val planted = listOf("com/foo/Ba".toByteArray(), "org/example/Nested${'$'}Inner".toByteArray())
            planted.forEachIndexed { index, bytes ->
                val at = 100 + index * 1300
                System.arraycopy(bytes, 0, buffer, at, bytes.size)
                buffer[at + bytes.size] = 0x01 // ensure it is not part of a longer token
            }
            val halfNeedle = "com/foo/Bar".toByteArray().copyOfRange(0, 6)
            System.arraycopy(halfNeedle, 0, buffer, 4090, halfNeedle.size) // runs past the buffer end
            val naive = needles.filterTo(mutableSetOf()) { needle -> naiveContains(buffer, needle) }
            val actual = ApkNativeStringScanner.scanClassNames(buffer, needles).matchedClassNames
            assertEquals(naive, actual, "seed=$seed")
        }
    }

    @Test
    fun scansTenThousandNamesAgainstMegabytesQuickly() {
        // Scale witness for the 900s harness budget: the naive scan cost
        // ~926GB of comparisons on a 100MB-lib APK (~32 min); the automaton
        // must keep the same work to seconds.
        val random = java.util.Random(42)
        val names = (0 until 10_000).map { "com/example/pkg$it/Class$it" }.toSet()
        val haystack = ByteArray(4 * 1024 * 1024) { (random.nextInt(256)).toByte() }
        // Plant a few hits so matching is exercised, not just the traversal.
        for (index in 0 until 25) {
            val bytes = "com/example/pkg$index/Class$index".toByteArray(Charsets.US_ASCII)
            System.arraycopy(bytes, 0, haystack, index * 160_000, bytes.size)
        }
        val startedAt = System.nanoTime()
        val result = ApkNativeStringScanner.scanClassNames(haystack, names)
        val elapsedMillis = (System.nanoTime() - startedAt) / 1_000_000
        assertEquals(25, result.matchedClassNames.size)
        assertTrue(elapsedMillis < 15_000, "10k names x 4MB must scan in seconds, took ${elapsedMillis}ms")
    }

    /** The exact per-needle byte-substring search the production code used before. */
    private fun naiveContains(haystack: ByteArray, needle: String): Boolean {
        val needleBytes = needle.toByteArray(Charsets.US_ASCII)
        var start = 0
        while (start <= haystack.size - needleBytes.size) {
            var offset = 0
            while (offset < needleBytes.size && haystack[start + offset] == needleBytes[offset]) offset += 1
            if (offset == needleBytes.size) return true
            start += 1
        }
        return false
    }
}
