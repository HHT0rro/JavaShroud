package io.github.hht0rro.javashroud.apk

import java.nio.charset.StandardCharsets

/**
 * Minimal read-only DEX site indexer that recovers the true allocated class of
 * every `new-instance H` + `invoke-direct S.<init>` pair from the INPUT dex.
 *
 * dex2jar types the corresponding classfile `new` to the CONSTRUCTOR owner S,
 * destroying H; every downstream repair (verification and semantics) needs H
 * back. The dex is authoritative for it, and the pairing protocol is stable:
 * an uninitialized-instance register produced by `new-instance vAA, H` is
 * consumed by `invoke-direct vR, S.<init>` (dalvik verifies exactly that), so
 * tracking the most recent `new-instance` per register recovers (H, S) pairs
 * with the method's instruction order preserved — the same order dex2jar's IR
 * walk emits, which makes ordinal matching against classfile sites sound.
 *
 * Only the pieces of the DEX format needed for this lookup are read (string /
 * type / proto / method ids, class defs, class data, code items). Any parse
 * problem fails closed by skipping that entry; callers treat a miss as
 * "unknown" and fall back to other recovery strategies.
 */
internal object ApkDexNewInstanceIndex {

    data class Site(val allocatedType: String, val constructorOwner: String)

    /** class → (methodName + methodDescriptor → ordered sites). */
    fun build(dexFiles: List<ByteArray>): Map<String, Map<String, List<Site>>> {
        val index = mutableMapOf<String, MutableMap<String, MutableList<Site>>>()
        for (dex in dexFiles) {
            runCatching { indexDex(dex, index) }
        }
        return index
    }

    private const val DEX_HEADER_SIZE = 0x70
    private const val OP_NOP = 0x00
    private const val OP_NEW_INSTANCE = 0x22
    private const val OP_MOVE_OBJECT = 0x07
    private const val OP_MOVE_OBJECT_FROM16 = 0x08
    private const val OP_MOVE_OBJECT_16 = 0x09
    private const val OP_MOVE_RESULT_OBJECT = 0x0c
    private const val OP_INVOKE_DIRECT = 0x70
    private const val OP_INVOKE_DIRECT_RANGE = 0x76
    private const val OP_PACKED_SWITCH_PAYLOAD = 0x0100
    private const val OP_SPARSE_SWITCH_PAYLOAD = 0x0200
    private const val OP_FILL_ARRAY_DATA_PAYLOAD = 0x0300
    private const val DEX_ACC_NATIVE = 0x100
    private const val DEX_ACC_ABSTRACT = 0x400

    /** Instruction size in 16-bit code units per opcode; 0 = unknown (abort walk). */
    private val OPCODE_SIZE_UNITS: IntArray = buildSizeTable()

    private fun buildSizeTable(): IntArray {
        val sizes = IntArray(256)
        val oneUnit = intArrayOf(
            0x00, 0x01, 0x04, 0x07, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
            0x1d, 0x1e, 0x21, 0x27, 0x28,
        )
        val twoUnits = intArrayOf(0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f, 0x20, 0x22, 0x23, 0x29, 0xfe, 0xff)
        val threeUnits = intArrayOf(
            0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x26, 0x2a, 0x2b, 0x2c,
            0x6e, 0x6f, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78, 0xfc, 0xfd,
        )
        for (op in oneUnit) sizes[op] = 1
        for (op in 0x7b..0x8f) sizes[op] = 1 // unary operators
        for (op in 0xb0..0xcf) sizes[op] = 1 // binop/2addr
        for (op in twoUnits) sizes[op] = 2
        for (range in listOf(0x2d..0x3d, 0x44..0x6d, 0x90..0xaf, 0xd0..0xe2)) {
            for (op in range) sizes[op] = 2
        }
        for (op in threeUnits) sizes[op] = 3
        sizes[0xfa] = 4
        sizes[0xfb] = 4
        sizes[0x18] = 5
        return sizes
    }

    /** Per-dex resolved id tables. */
    private class DexTables(val dex: ByteArray, val typeNames: Array<String>) {
        val methodIdsSize = readUInt(dex, 0x58).toInt()
        val methodIdsOff = readUInt(dex, 0x5C).toInt()
        val protoDescriptors: Array<String>
        val methodOwnersAndNames: Array<Pair<String, String>>

        init {
            val protoIdsSize = readUInt(dex, 0x48).toInt()
            val protoIdsOff = readUInt(dex, 0x4C).toInt()
            val stringIdsOff = readUInt(dex, 0x3C).toInt()
            protoDescriptors = Array(protoIdsSize) { i ->
                val base = protoIdsOff + i * 12
                val returnTypeIdx = readUInt(dex, base + 4).toInt()
                val parametersOff = readUInt(dex, base + 8).toInt()
                val params = StringBuilder()
                if (parametersOff > 0 && parametersOff + 4 <= dex.size) {
                    val size = readUInt(dex, parametersOff).toInt()
                    var cursor = parametersOff + 4
                    var remaining = size
                    while (remaining > 0 && cursor + 2 <= dex.size) {
                        params.append(typeNames.getOrNull(readUShort(dex, cursor)) ?: "")
                        cursor += 2
                        remaining -= 1
                    }
                }
                val ret = typeNames.getOrNull(returnTypeIdx) ?: ""
                "($params)$ret"
            }
            val strings = Array(readUInt(dex, 0x38).toInt()) { i ->
                val dataOff = readUInt(dex, stringIdsOff + i * 4).toInt()
                readMutf8String(dex, dataOff)
            }
            methodOwnersAndNames = Array(methodIdsSize) { i ->
                val base = methodIdsOff + i * 8
                val classIdx = readUShort(dex, base)
                val nameIdx = readUInt(dex, base + 4).toInt()
                (typeNames.getOrNull(classIdx) ?: "") to (strings.getOrNull(nameIdx) ?: "")
            }
        }

        fun methodInfo(methodId: Int): Triple<String, String, String>? {
            if (methodId < 0 || methodId >= methodIdsSize) return null
            val base = methodIdsOff + methodId * 8
            val protoIdx = readUShort(dex, base + 2)
            val (owner, name) = methodOwnersAndNames[methodId]
            val descriptor = protoDescriptors.getOrNull(protoIdx) ?: return null
            if (owner.isEmpty() || name.isEmpty()) return null
            return Triple(owner, name, descriptor)
        }
    }

    private fun indexDex(dex: ByteArray, index: MutableMap<String, MutableMap<String, MutableList<Site>>>) {
        if (dex.size < DEX_HEADER_SIZE) return
        if (!(dex[0] == 'd'.code.toByte() && dex[1] == 'e'.code.toByte() && dex[2] == 'x'.code.toByte())) return
        val typeIdsSize = readUInt(dex, 0x40).toInt()
        val typeIdsOff = readUInt(dex, 0x44).toInt()
        if (typeIdsOff <= 0 || typeIdsOff + 4L * typeIdsSize > dex.size) return
        val stringIdsOff = readUInt(dex, 0x3C).toInt()
        val strings = Array(readUInt(dex, 0x38).toInt()) { i ->
            val dataOff = readUInt(dex, stringIdsOff + i * 4).toInt()
            readMutf8String(dex, dataOff)
        }
        val typeNames = Array(typeIdsSize) { i ->
            val descriptorIdx = readUInt(dex, typeIdsOff + i * 4).toInt()
            strings.getOrNull(descriptorIdx) ?: ""
        }
        val tables = DexTables(dex, typeNames)
        val classDefsSize = readUInt(dex, 0x60).toInt()
        val classDefsOff = readUInt(dex, 0x64).toInt()
        if (classDefsOff <= 0 || classDefsOff + 32L * classDefsSize > dex.size) return
        for (c in 0 until classDefsSize) {
            val classDef = classDefsOff + c * 32
            val classIdx = readUInt(dex, classDef).toInt()
            val className = typeNames.getOrNull(classIdx) ?: continue
            val classDataOff = readUInt(dex, classDef + 24).toInt()
            if (classDataOff <= 0 || classDataOff >= dex.size) continue
            val classKey = className.removePrefix("L").removeSuffix(";")
            indexClassData(dex, classDataOff, tables) { methodName, descriptor, sites ->
                if (sites.isNotEmpty()) {
                    index.getOrPut(classKey) { mutableMapOf() }
                        .getOrPut(methodName + descriptor) { mutableListOf() } += sites
                }
            }
        }
    }

    /** Walks class_data items and reports (methodName, descriptor, ordered sites) per method. */
    private fun indexClassData(
        dex: ByteArray,
        classDataOff: Int,
        tables: DexTables,
        emit: (String, String, List<Site>) -> Unit,
    ) {
        var cursor = classDataOff
        fun uleb(): Int {
            var result = 0
            var shift = 0
            var b: Int
            do {
                if (cursor >= dex.size) return -1
                b = dex[cursor].toInt() and 0xFF
                cursor += 1
                result = result or ((b and 0x7F) shl shift)
                shift += 7
            } while (b and 0x80 != 0)
            return result
        }
        fun skipFields(count: Int) {
            repeat(count) {
                if (uleb() < 0 || uleb() < 0) throw IllegalArgumentException("truncated class_data")
            }
        }
        try {
            val staticFieldCount = uleb(); if (staticFieldCount < 0) return
            val instanceFieldCount = uleb(); if (instanceFieldCount < 0) return
            val directMethodCount = uleb(); if (directMethodCount < 0) return
            val virtualMethodCount = uleb(); if (virtualMethodCount < 0) return
            skipFields(staticFieldCount)
            skipFields(instanceFieldCount)
            for (kind in 0 until 2) {
                val count = if (kind == 0) directMethodCount else virtualMethodCount
                var methodIdx = 0
                repeat(count) {
                    val idxDelta = uleb(); if (idxDelta < 0) return
                    val access = uleb(); if (access < 0) return
                    val codeOff = uleb(); if (codeOff < 0) return
                    methodIdx += idxDelta
                    if (access and (DEX_ACC_NATIVE or DEX_ACC_ABSTRACT) != 0) return@repeat
                    val info = tables.methodInfo(methodIdx) ?: return@repeat
                    if (codeOff != 0 && codeOff < dex.size) {
                        val sites = sitesInCode(dex, codeOff, tables)
                        if (sites.isNotEmpty()) emit(info.second, info.third, sites)
                    }
                }
            }
        } catch (_: IllegalArgumentException) {
            // fail closed for this class only
        }
    }

    /** Ordered (H, S) pairs for one code item. */
    private fun sitesInCode(dex: ByteArray, codeOff: Int, tables: DexTables): List<Site> {
        if (codeOff + 16 > dex.size) return emptyList()
        val insnsSize = readUInt(dex, codeOff + 12).toInt()
        val insnsOff = codeOff + 16
        if (insnsSize <= 0 || insnsSize > (dex.size - insnsOff) / 2) return emptyList()
        val sites = mutableListOf<Site>()
        val pendingByRegister = HashMap<Int, String>()
        var pc = 0
        while (pc < insnsSize) {
            val unit = readUShort(dex, insnsOff + pc * 2)
            val opcode = unit and 0xFF
            if (opcode == OP_NOP) {
                val remaining = insnsSize - pc
                val payloadUnits = when (unit) {
                    OP_PACKED_SWITCH_PAYLOAD -> {
                        if (remaining < 4) return emptyList()
                        val size = readUShort(dex, insnsOff + (pc + 1) * 2)
                        4 + size * 2
                    }
                    OP_SPARSE_SWITCH_PAYLOAD -> {
                        if (remaining < 2) return emptyList()
                        val size = readUShort(dex, insnsOff + (pc + 1) * 2)
                        2 + size * 4
                    }
                    OP_FILL_ARRAY_DATA_PAYLOAD -> {
                        if (remaining < 4) return emptyList()
                        val elementWidth = readUShort(dex, insnsOff + (pc + 1) * 2)
                        if (elementWidth == 0) return emptyList()
                        val size = readUInt(dex, insnsOff + (pc + 2) * 2).toLong() and 0xffff_ffffL
                        val units = 4 + (size * elementWidth + 1) / 2
                        if (units > remaining) return emptyList()
                        units.toInt()
                    }
                    0 -> 1
                    else -> return emptyList()
                }
                if (payloadUnits > remaining) return emptyList()
                pc += payloadUnits
                continue
            }
            val sizeUnits = OPCODE_SIZE_UNITS[opcode]
            if (sizeUnits <= 0 || sizeUnits > insnsSize - pc) return emptyList()
            when (opcode) {
                OP_NEW_INSTANCE -> {
                    val register = unit ushr 8
                    val typeIdx = readUShort(dex, insnsOff + (pc + 1) * 2)
                    val type = tables.typeNames.getOrNull(typeIdx) ?: ""
                    if (type.isNotEmpty()) pendingByRegister[register] = type
                }
                OP_MOVE_OBJECT -> {
                    val dst = (unit ushr 8) and 0xF
                    val src = unit ushr 12
                    copyPendingRegister(pendingByRegister, src, dst)
                }
                OP_MOVE_OBJECT_FROM16 -> {
                    val dst = (unit ushr 8) and 0xFF
                    val src = readUShort(dex, insnsOff + (pc + 1) * 2)
                    copyPendingRegister(pendingByRegister, src, dst)
                }
                OP_MOVE_OBJECT_16 -> {
                    val dst = readUShort(dex, insnsOff + (pc + 1) * 2)
                    val src = readUShort(dex, insnsOff + (pc + 2) * 2)
                    copyPendingRegister(pendingByRegister, src, dst)
                }
                OP_MOVE_RESULT_OBJECT -> pendingByRegister.remove(unit ushr 8)
                OP_INVOKE_DIRECT, OP_INVOKE_DIRECT_RANGE -> {
                    val methodIdx = readUShort(dex, insnsOff + (pc + 1) * 2)
                    val info = tables.methodInfo(methodIdx)
                    if (info != null && info.second == "<init>") {
                        val receiver = if (opcode == OP_INVOKE_DIRECT) {
                            readUShort(dex, insnsOff + (pc + 2) * 2) and 0xF
                        } else {
                            readUShort(dex, insnsOff + (pc + 2) * 2)
                        }
                        val allocated = pendingByRegister.remove(receiver)
                        if (allocated != null) {
                            sites += Site(
                                allocatedType = allocated.removePrefix("L").removeSuffix(";"),
                                constructorOwner = info.first.removePrefix("L").removeSuffix(";"),
                            )
                        }
                    }
                }
            }
            pc += sizeUnits
        }
        return sites
    }

    private fun copyPendingRegister(pending: MutableMap<Int, String>, source: Int, target: Int) {
        val allocated = pending[source]
        if (allocated == null) pending.remove(target) else pending[target] = allocated
    }

    private fun readMutf8String(dex: ByteArray, dataOff: Int): String {
        if (dataOff <= 0 || dataOff >= dex.size) return ""
        var cursor = dataOff
        do {
            if (cursor >= dex.size) return ""
            cursor += 1
        } while (dex[cursor - 1].toInt() and 0x80 != 0)
        val start = cursor
        var end = cursor
        while (end < dex.size && dex[end] != 0.toByte()) end += 1
        return String(dex.copyOfRange(start, end), StandardCharsets.UTF_8)
    }

    private fun readUShort(dex: ByteArray, offset: Int): Int =
        (dex[offset].toInt() and 0xFF) or ((dex[offset + 1].toInt() and 0xFF) shl 8)

    private fun readUInt(dex: ByteArray, offset: Int): Int =
        (dex[offset].toInt() and 0xFF) or
            ((dex[offset + 1].toInt() and 0xFF) shl 8) or
            ((dex[offset + 2].toInt() and 0xFF) shl 16) or
            ((dex[offset + 3].toInt() and 0xFF) shl 24)
}
