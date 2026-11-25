package io.github.hht0rro.javashroud.apk

/**
 * Scanners for the conservative keep supersets drawn out of APK payload bytes:
 * binary-XML and resource-table string pools (covers view classes, fragment
 * android:name and resource-backed behavior names) and printable strings inside native
 * libraries under lib/ (covers JNIEnv FindClass/GetMethodID callbacks into
 * renamed classes).
 */
object ApkResourceClassReferenceScanner {

    private const val CHUNK_STRING_POOL = 0x0001
    private const val CHUNK_TABLE = 0x0002
    private const val CHUNK_XML = 0x0003
    private const val CHUNK_XML_START_ELEMENT = 0x0102
    private const val STRING_POOL_UTF8_FLAG = 1 shl 8
    private const val PREFERENCE_PACKAGE = "androidx/preference/"
    private const val PREFERENCE_INFLATER = PREFERENCE_PACKAGE + "PreferenceInflater"
    private val preferencePackageAnchors = listOf(PREFERENCE_PACKAGE + "Preference", PREFERENCE_PACKAGE + "SwitchPreference")

    /** Extracts top-level pool strings from one binary XML resource or resource table. */
    fun extractStringPoolStrings(bytes: ByteArray): List<String> = buildList {
        visitResourceChunks(bytes) { type, cursor, headerSize, end ->
            if (type == CHUNK_STRING_POOL) parsePool(bytes, cursor, headerSize, end).filterNotNullTo(this)
        }
    }

    internal fun preferenceClassReferences(bytes: ByteArray, loadedClassNames: Set<String>): Set<String> {
        if (PREFERENCE_INFLATER !in loadedClassNames || bytes.size < 8 || readUShort(bytes, 0) != CHUNK_XML) return emptySet()
        val hits = mutableSetOf<String>()
        var pool: List<String?> = emptyList()
        visitResourceChunks(bytes) { type, start, headerSize, end ->
            when (type) {
                CHUNK_STRING_POOL -> pool = parsePool(bytes, start, headerSize, end)
                CHUNK_XML_START_ELEMENT -> if (headerSize >= 16 && end - start - headerSize >= 20) {
                    val index = readUInt(bytes, start + headerSize + 4)
                    val tag = if (index < pool.size) pool[index.toInt()] else null
                    if (tag != null && tag.isNotEmpty() && tag.none { it == '.' || it == '/' }) {
                        val candidate = PREFERENCE_PACKAGE + tag
                        if (candidate in loadedClassNames) hits += candidate
                    }
                }
            }
        }
        // PreferenceInflater computes its search package from these class literals at runtime.
        if (hits.isNotEmpty()) preferencePackageAnchors.filterTo(hits) { it in loadedClassNames }
        return hits
    }

    private inline fun visitResourceChunks(bytes: ByteArray, visit: (Int, Int, Int, Int) -> Unit) {
        if (bytes.size < 8) return
        val rootType = readUShort(bytes, 0)
        val rootHeaderSize = readUShort(bytes, 2)
        val rootSize = readUInt(bytes, 4)
        val minimumHeader = when (rootType) {
            CHUNK_XML -> 8
            CHUNK_TABLE -> 12
            else -> return
        }
        if (rootHeaderSize < minimumHeader || rootSize < rootHeaderSize || rootSize > bytes.size) return
        var cursor = rootHeaderSize
        while (rootSize - cursor >= 8) {
            val chunkType = readUShort(bytes, cursor)
            val headerSize = readUShort(bytes, cursor + 2)
            val chunkSize = readUInt(bytes, cursor + 4)
            if (headerSize < 8 || chunkSize < headerSize || chunkSize > rootSize - cursor) break
            val end = cursor + chunkSize.toInt()
            if (chunkType == CHUNK_STRING_POOL && headerSize < 28) break
            visit(chunkType, cursor, headerSize, end)
            cursor = end
        }
    }

    private fun parsePool(bytes: ByteArray, start: Int, headerSize: Int, end: Int): List<String?> {
        // body layout: stringCount(4) styleCount(4) flags(4) stringsStart(4) stylesStart(4)
        val stringCount = readUInt(bytes, start + 8)
        val styleCount = readUInt(bytes, start + 12)
        val flags = readUInt(bytes, start + 16).toInt()
        val stringsStart = readUInt(bytes, start + 20)
        val stylesStart = readUInt(bytes, start + 24)
        val chunkSize = end - start
        if (stringsStart < headerSize + 4 * (stringCount + styleCount) || stringsStart > chunkSize) return emptyList()
        if (stylesStart != 0L && (stylesStart < stringsStart || stylesStart > chunkSize)) return emptyList()
        val stringsEnd = if (stylesStart == 0L) end else start + stylesStart.toInt()
        val isUtf8 = flags and STRING_POOL_UTF8_FLAG != 0
        val count = stringCount.coerceAtMost(65_536L).toInt()
        val out = ArrayList<String?>(count)
        for (index in 0 until count) {
            val offsetIndex = start + headerSize + index * 4
            val absolute = start + stringsStart + readUInt(bytes, offsetIndex)
            out += when {
                absolute >= stringsEnd -> null
                isUtf8 -> decodeUtf8(bytes, absolute.toInt(), stringsEnd)
                else -> decodeUtf16(bytes, absolute.toInt(), stringsEnd)
            }
        }
        return out
    }

    private fun decodeUtf16(body: ByteArray, start: Int, end: Int): String? {
        if (end - start < 2) return null
        var cursor = start
        var unit = readUShort(body, cursor)
        cursor += 2
        if (unit and 0x8000 != 0) {
            if (end - cursor < 2) return null
            unit = ((unit and 0x7fff) shl 16) or readUShort(body, cursor)
            cursor += 2
        }
        if (unit > 65_536) return null
        val byteLength = unit * 2
        if (end - cursor - byteLength < 2 || readUShort(body, cursor + byteLength) != 0) return null
        return String(body, cursor, byteLength, Charsets.UTF_16LE)
    }

    private fun decodeUtf8(body: ByteArray, start: Int, end: Int): String? {
        var cursor = start
        var unit = body[cursor].toInt() and 0xFF
        cursor += 1
        if (unit and 0x80 != 0) cursor += 1
        if (cursor >= end) return null
        unit = body[cursor].toInt() and 0xFF
        cursor += 1
        var byteLength = unit
        if (unit and 0x80 != 0) {
            if (cursor >= end) return null
            val high = unit and 0x7F
            val low = body[cursor].toInt() and 0xFF
            cursor += 1
            byteLength = (high shl 8) or low
        }
        if (byteLength >= end - cursor || body[cursor + byteLength] != 0.toByte()) return null
        return String(body, cursor, byteLength, Charsets.UTF_8)
    }

    private fun readUShort(buffer: ByteArray, offset: Int): Int =
        (buffer[offset].toInt() and 0xFF) or ((buffer[offset + 1].toInt() and 0xFF) shl 8)

    private fun readUInt(buffer: ByteArray, offset: Int): Long =
        (buffer[offset].toLong() and 0xFF) or
            ((buffer[offset + 1].toLong() and 0xFF) shl 8) or
            ((buffer[offset + 2].toLong() and 0xFF) shl 16) or
            ((buffer[offset + 3].toLong() and 0xFF) shl 24)
}

internal object ApkServiceReferenceScanner {
    private const val PREFIX = "META-INF/services/"

    fun referencedClassNames(entries: List<ApkInputUnpacker.ApkPreservedEntry>, loadedClassNames: Set<String>): Set<String> {
        val byBinaryName = loadedClassNames.associateBy { it.replace('/', '.') }
        return buildSet {
            for (entry in entries) {
                if (entry.isDirectory || !entry.name.startsWith(PREFIX)) continue
                val service = entry.name.removePrefix(PREFIX)
                if (service.isEmpty() || '/' in service) continue
                byBinaryName[service]?.let(::add)
                // The archive bytes stay untouched; only interface and provider names feed the keep plan.
                entry.data.inputStream().bufferedReader(Charsets.UTF_8).useLines { lines ->
                    lines.forEach { line -> byBinaryName[line.substringBefore('#').trim()]?.let(::add) }
                }
            }
        }
    }
}

object ApkNativeStringScanner {

    /** Default per-.so scan cap; oversized payloads degrade to conservative mode. */
    const val DEFAULT_MAX_SO_BYTES: Int = 64 * 1024 * 1024

    data class NativeScanResult(
        /** Slash-form class names found as printable strings inside the .so. */
        val matchedClassNames: Set<String>,
        /** True when the payload exceeded the scan cap and strings were only partially collected. */
        val truncated: Boolean,
    )

    fun scanClassNames(
        soBytes: ByteArray,
        loadedSlashClassNames: Set<String>,
        maxBytes: Int = DEFAULT_MAX_SO_BYTES,
    ): NativeScanResult {
        if (loadedSlashClassNames.isEmpty()) return NativeScanResult(emptySet(), truncated = false)
        val limit = if (soBytes.size > maxBytes) maxBytes else soBytes.size
        val matched = scanMany(soBytes, limit, loadedSlashClassNames)
        return NativeScanResult(matchedClassNames = matched, truncated = soBytes.size > maxBytes)
    }

    /**
     * Multi-needle substring search over one haystack slice. Aho-Corasick
     * keeps this O(haystack + needles): a real APK carries tens of thousands
     * of class names against ~100MB of native libraries, and the naive
     * per-needle scan costs hundreds of gigabytes of byte comparisons (the
     * 30+ minute wall-clock bottleneck this replaced). Match semantics are
     * identical to a per-needle byte-substring search: a name matches when
     * its exact ASCII bytes occur anywhere within [0, limit), printable
     * context not required (conservative superset).
     */
    internal fun scanMany(haystack: ByteArray, limit: Int, needles: Set<String>): Set<String> {
        if (needles.isEmpty() || limit <= 0) return emptySet()
        val automaton = SparseByteAhoCorasick(needles)
        return automaton.scan(haystack, limit)
    }

    /**
     * Sparse-transition Aho-Corasick over raw bytes. Class names share long
     * package prefixes, so the trie stays far smaller than a full 256-way
     * goto table; missing transitions follow failure links to the root.
     */
    private class SparseByteAhoCorasick(needles: Set<String>) {

        private val children = ArrayList<MutableMap<Int, Int>>()
        private val fail = IntArrayList()
        private val terminal = IntArrayList() // needle index at state, or -1
        private val outputLink = IntArrayList() // nearest fail-ancestor with a terminal, or -1
        private val needleList = needles.toList()

        private fun newState(): Int {
            children.add(HashMap())
            fail.add(0)
            terminal.add(-1)
            outputLink.add(-1)
            return children.size - 1
        }

        init {
            newState() // root = 0
            needleList.forEachIndexed { index, needle ->
                var state = 0
                for (byte in needle.toByteArray(Charsets.US_ASCII)) {
                    val value = byte.toInt() and 0xFF
                    val next = children[state][value]
                    state = if (next != null) next else {
                        val created = newState()
                        children[state][value] = created
                        created
                    }
                }
                terminal[state] = index
            }
            // Breadth-first failure links + output links.
            val queue = ArrayDeque<Int>()
            for ((value, child) in children[0]) {
                fail[child] = 0
                outputLink[child] = -1
                queue.add(child)
            }
            while (queue.isNotEmpty()) {
                val state = queue.removeFirst()
                for ((value, child) in children[state]) {
                    val failure = transition(fail[state], value)
                    fail[child] = if (failure != child) failure else 0
                    val failState = fail[child]
                    outputLink[child] = if (terminal[failState] >= 0) failState else outputLink[failState]
                    queue.add(child)
                }
            }
        }

        /** Follows sparse children with failure-link fallback; never returns -1. */
        private fun transition(state: Int, value: Int): Int {
            var current = state
            while (true) {
                val next = children[current][value]
                if (next != null) return next
                if (current == 0) return 0
                current = fail[current]
            }
        }

        fun scan(haystack: ByteArray, limit: Int): Set<String> {
            val hit = BooleanArray(needleList.size)
            var state = 0
            var index = 0
            while (index < limit) {
                state = transition(state, haystack[index].toInt() and 0xFF)
                var terminalNeedle = terminal[state]
                if (terminalNeedle >= 0) hit[terminalNeedle] = true
                var link = outputLink[state]
                while (link >= 0) {
                    terminalNeedle = terminal[link]
                    if (terminalNeedle >= 0) hit[terminalNeedle] = true
                    link = outputLink[link]
                }
                index += 1
            }
            val matched = LinkedHashSet<String>()
            hit.forEachIndexed { needleIndex, isHit -> if (isHit) matched += needleList[needleIndex] }
            return matched
        }
    }

    /** Tiny growable int list; avoids boxing an ArrayList<Int> for the automaton arrays. */
    private class IntArrayList {
        private var data = IntArray(64)
        var size = 0
            private set

        fun add(value: Int) {
            if (size == data.size) data = data.copyOf(data.size * 2)
            data[size] = value
            size += 1
        }

        operator fun get(index: Int): Int = data[index]

        operator fun set(index: Int, value: Int) {
            data[index] = value
        }
    }
}
