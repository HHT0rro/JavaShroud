package io.github.hht0rro.javashroud.apk

import java.nio.file.Path
import java.util.jar.JarInputStream
import java.util.zip.ZipEntry
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry
import org.apache.commons.compress.archivers.zip.ZipFile

/**
 * Fail-closed validation gates for the APK pipeline:
 *  - dex header integrity (magic, version, header size, file size, adler32),
 *  - class-def counts vs the keep plan,
 *  - post-engine retention of every synthesized keep (class names survive,
 *    CREATOR/serialVersionUID/hook method identities survive),
 *  - preserved-entry byte fidelity and STORED-alignment of the final archive.
 */
object ApkValidation {

    private val DEX_MAGIC = byteArrayOf(0x64, 0x65, 0x78, 0x0A) // "dex\n"
    private val DEX_VERSIONS = setOf("035", "036", "037", "038", "039")
    private const val DEX_HEADER_SIZE = 0x70

    fun validateDexHeader(name: String, bytes: ByteArray) {
        require(bytes.size >= DEX_HEADER_SIZE) { "dex entry '$name' is smaller than its fixed header (${bytes.size}B)" }
        require(bytes.copyOfRange(0, 4).contentEquals(DEX_MAGIC)) { "dex entry '$name' has a wrong magic" }
        val version = String(bytes, 4, 3, Charsets.US_ASCII)
        require(version in DEX_VERSIONS) { "dex entry '$name' has unsupported version $version" }
        require(bytes[7] == 0.toByte()) { "dex entry '$name' version terminator is not NUL" }
        val headerSize = readUInt(bytes, 36).toInt()
        require(headerSize == DEX_HEADER_SIZE) { "dex entry '$name' header_size=$headerSize != $DEX_HEADER_SIZE" }
        val fileSize = readUInt(bytes, 32).toInt()
        require(fileSize == bytes.size) { "dex entry '$name' header file_size=$fileSize != actual ${bytes.size}" }
        val digest = java.security.MessageDigest.getInstance("SHA-1").apply {
            update(bytes, 32, bytes.size - 32)
        }.digest()
        require(java.security.MessageDigest.isEqual(bytes.copyOfRange(12, 32), digest)) {
            "dex entry '$name' SHA-1 signature mismatch"
        }
        val adler = readUInt(bytes, 8).toInt()
        val computed = adler32(bytes, offset = 12)
        require(adler == computed) { "dex entry '$name' adler32 mismatch: header=$adler computed=$computed" }
    }

    fun dexClassCount(bytes: ByteArray): Int {
        val mapOffset = readUInt(bytes, 52).toInt()
        require(mapOffset in 12 until bytes.size - 8) { "dex map_list offset is out of bounds: $mapOffset" }
        val mapSize = readUInt(bytes, mapOffset).toInt()
        var classDefs = 0
        var cursor = mapOffset + 4
        repeat(mapSize) {
            require(cursor + 12 <= bytes.size) { "dex map_list is truncated" }
            val type = readUShort(bytes, cursor)
            // map item layout: type(2) unused(2) size(4) offset(4) — the
            // class-def count lives in the size field at +4, NOT the table
            // offset at +8.
            if (type == 0x0006) classDefs += readUInt(bytes, cursor + 4).toInt()
            cursor += 12
        }
        return classDefs
    }

    internal fun validateDisjointDexClasses(dexes: List<Pair<String, ByteArray>>) {
        val seen = HashMap<String, String>()
        for ((name, bytes) in dexes) {
            validateDexHeader(name, bytes)
            fun table(countField: Int, width: Int): Pair<Int, Int> {
                val count = readUInt(bytes, countField).toInt()
                val offset = readUInt(bytes, countField + 4).toInt()
                require(count >= 0 && offset >= 0 && offset.toLong() + count.toLong() * width <= bytes.size) {
                    "dex entry '$name' has an out-of-bounds class identity table"
                }
                return count to offset
            }
            val (strings, stringsAt) = table(0x38, 4)
            val (types, typesAt) = table(0x40, 4)
            val (classes, classesAt) = table(0x60, 32)
            for (index in 0 until classes) {
                val type = readUInt(bytes, classesAt + index * 32).toInt()
                require(type in 0 until types) { "dex entry '$name' has an invalid class type index" }
                val string = readUInt(bytes, typesAt + type * 4).toInt()
                require(string in 0 until strings) { "dex entry '$name' has an invalid descriptor string index" }
                var cursor = readUInt(bytes, stringsAt + string * 4).toInt()
                require(cursor in DEX_HEADER_SIZE until bytes.size) { "dex entry '$name' has an invalid descriptor location" }
                var lengthBytes = 0
                while (cursor < bytes.size && bytes[cursor].toInt() and 0x80 != 0 && lengthBytes < 4) {
                    cursor++
                    lengthBytes++
                }
                require(cursor < bytes.size && bytes[cursor].toInt() and 0x80 == 0) { "dex entry '$name' has an invalid descriptor length" }
                val start = cursor + 1
                cursor = start
                while (cursor < bytes.size && bytes[cursor] != 0.toByte()) cursor++
                require(cursor < bytes.size && cursor > start) { "dex entry '$name' has an unterminated class descriptor" }
                // Preserve DEX modified UTF-8 bytes exactly, including supplementary identifier characters.
                val descriptor = String(bytes, start, cursor - start, Charsets.ISO_8859_1)
                val previous = seen.putIfAbsent(descriptor, name)
                require(previous == null) { "dex class '$descriptor' is defined more than once ($previous and $name)" }
            }
        }
    }

    data class WorkJarScan(
        val classNames: Set<String>,
        val membersByOwner: Map<String, Set<Pair<String, String>>>,
        val fieldNames: Map<String, Int>,
        val methods: Map<String, Int>,
        val methodNames: Map<String, Int>,
    )

    /**
     * Post-engine retention: excluded classes must still exist under their
     * original names; kept members must survive under their original NAME.
     *
     * Name-only matching is the correct invariant for members whose
     * descriptors reference application classes: when rename-classes relocates
     * such a class, every referencing descriptor is legitimately remapped.
     * Serialization hooks keep exact name+descriptor matching because their
     * descriptors reference only java.io types, which never rename.
     */
    fun validateKeepRetention(workJar: Path, keepPlan: ApkKeepRuleSynthesis.ApkKeepPlan) {
        val scan = scanWorkJar(workJar)
        val missingClasses = keepPlan.excludedClassNames.filterNot { it in scan.classNames }
        require(missingClasses.isEmpty()) {
            "APK keep retention failed: excluded classes were renamed or removed: ${missingClasses.sorted()}"
        }
        val missingMembers = keepPlan.memberKeeps.filter { keep ->
            val exactDescriptor = keep.reason == "serialization-hook" || keep.reason == "layout-on-click"
            if (keep.owner in keepPlan.excludedClassNames) {
                val members = scan.membersByOwner[keep.owner].orEmpty()
                return@filter members.none { (name, descriptor) ->
                    name == keep.name && (if (exactDescriptor) descriptor == keep.descriptor else (descriptor.startsWith('(') == (keep.kind == "method")))
                }
            }
            when (keep.reason) {
                "serialization-hook", "layout-on-click" -> (scan.methods["${keep.name}:${keep.descriptor}"] ?: 0) <= 0
                "parcelable-creator", "serial-version-uid", "javascript-interface", "android-framework-interface-callback" -> {
                    val count = if (keep.kind == "field") scan.fieldNames[keep.name] else scan.methodNames[keep.name]
                    (count ?: 0) <= 0
                }
                else -> true
            }
        }
        require(missingMembers.isEmpty()) {
            "APK keep retention failed: kept members were renamed or removed: " +
                missingMembers.joinToString(", ") { it.selector }
        }
    }

    internal fun scanWorkJar(workJar: Path): WorkJarScan {
        val classNames = mutableSetOf<String>()
        val membersByOwner = mutableMapOf<String, Set<Pair<String, String>>>()
        val fieldNameCounts = mutableMapOf<String, Int>()
        val methodCounts = mutableMapOf<String, Int>()
        val methodNameCounts = mutableMapOf<String, Int>()
        JarInputStream(java.nio.file.Files.newInputStream(workJar).buffered()).use { jar ->
            while (true) {
                val entry: ZipEntry = jar.nextEntry ?: break
                if (entry.isDirectory || !entry.name.endsWith(".class")) continue
                val internalName = entry.name.removeSuffix(".class")
                classNames += internalName
                ApkKeepRuleSynthesis.readClassInfo(jar.readBytes()).let { info ->
                    membersByOwner[internalName] = (info.fields + info.methods).toSet()
                    info.fields.forEach { (name, _) ->
                        fieldNameCounts.merge(name, 1, Int::plus)
                    }
                    info.methods.forEach { (name, descriptor) ->
                        methodCounts.merge("$name:$descriptor", 1, Int::plus)
                        methodNameCounts.merge(name, 1, Int::plus)
                    }
                }
            }
        }
        return WorkJarScan(
            classNames = classNames,
            membersByOwner = membersByOwner,
            fieldNames = fieldNameCounts,
            methods = methodCounts,
            methodNames = methodNameCounts,
        )
    }

    /** Final-archive fidelity: preserved entries byte-identical, method unchanged, alignment intact. */
    fun validateOutputArchive(
        inputUnpacked: ApkInputUnpacker.ApkUnpacked,
        outputApk: Path,
        expectedDexEntryNames: Collection<String>,
        soPageSize: Int,
        v1SigningEnabled: Boolean = true,
    ) {
        ZipFile.builder().setFile(outputApk.toFile()).get().use { zip: ZipFile ->
            val entryNames = java.util.Collections.list(zip.getEntries()).map { it.name }
            val duplicates = entryNames.groupingBy { it }.eachCount().filterValues { it > 1 }.keys
            require(duplicates.isEmpty()) { "output APK contains duplicate entries: $duplicates" }
            for (entry in inputUnpacked.preservedEntries) {
                if (ApkOutputPacker.isDexEntry(entry.name)) continue // D8 can repartition the DEX set.
                if (ApkOutputPacker.isStrippedSignatureEntry(entry.name) || entry.name == "META-INF/MANIFEST.MF") {
                    // With v1 signing the signer legitimately (re)introduces
                    // META-INF/MANIFEST.MF plus .SF/.RSA material; without it,
                    // every old signature name must be gone.
                    if (!v1SigningEnabled) {
                        require(entry.name !in entryNames) { "old signature entry survived: ${entry.name}" }
                    }
                    continue
                }
                val outputEntry = zip.getEntry(entry.name)
                requireNotNull(outputEntry) { "preserved entry disappeared from output APK: ${entry.name}" }
                val outputData = zip.getInputStream(outputEntry).use { it.readBytes() }
                require(outputData.contentEquals(entry.data)) {
                    "preserved entry data changed in output APK: ${entry.name}"
                }
                require(outputEntry.method == entry.method) {
                    "preserved entry compression method changed: ${entry.name}"
                }
                if (entry.name == "resources.arsc" && entry.method == java.util.zip.ZipEntry.STORED) {
                    requireStoredAligned(outputEntry, 4)
                }
                if (ApkOutputPacker.isNativeLib(entry.name) && entry.method == java.util.zip.ZipEntry.STORED) {
                    requireStoredAligned(outputEntry, soPageSize)
                }
            }
            val outputDexEntries = entryNames.filter(ApkOutputPacker::isDexEntry).toSet()
            val expectedDexEntries = expectedDexEntryNames.toSet()
            require(outputDexEntries == expectedDexEntries) {
                "output APK DEX entries differ from D8 output: missing=${expectedDexEntries - outputDexEntries}, " +
                    "unexpected=${outputDexEntries - expectedDexEntries}"
            }
        }
    }

    private fun requireStoredAligned(entry: ZipArchiveEntry, alignment: Int) {
        val dataOffset = entry.dataOffset
        require(dataOffset % alignment == 0L) {
            "STORED entry ${entry.name} data offset $dataOffset is not $alignment-byte aligned"
        }
    }

    private fun adler32(bytes: ByteArray, offset: Int): Int {
        var a = 1
        var b = 0
        for (index in offset until bytes.size) {
            a = (a + (bytes[index].toInt() and 0xFF)) % 65521
            b = (b + a) % 65521
        }
        return (b shl 16) or a
    }

    private fun readUShort(buffer: ByteArray, offset: Int): Int =
        (buffer[offset].toInt() and 0xFF) or ((buffer[offset + 1].toInt() and 0xFF) shl 8)

    private fun readUInt(buffer: ByteArray, offset: Int): Long =
        (buffer[offset].toLong() and 0xFF) or
            ((buffer[offset + 1].toLong() and 0xFF) shl 8) or
            ((buffer[offset + 2].toLong() and 0xFF) shl 16) or
            ((buffer[offset + 3].toLong() and 0xFF) shl 24)
}
