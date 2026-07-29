package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.NativeVmBuildProfile
import io.github.hht0rro.javashroud.transforms.protection.RuntimeKeyPartitions
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NativeCompiledStructureDivergenceTest {

    @Test
    fun pre_shell_inner_native_target_cfgs_diverge_across_build_profiles() {
        val objdump = findObjdump() ?: return
        val parserProfiles = listOf(
            NativeVmBuildProfile(0, 0),
            NativeVmBuildProfile(1, 1),
            NativeVmBuildProfile(2, 2),
        )
        val sharedPartitions = RuntimeKeyPartitions.generate()
        val artifacts = parserProfiles.map { profile ->
            val context = fixedContext(profile, sharedPartitions)
            withVbc4BuildContext(context) {
                NativeRecompilationTransforms.compileInnerForCfgEvidence(
                    seed = 0x4455_6600L,
                    classLoader = NativeRecompilationTransforms::class.java.classLoader,
                    evidenceRandom = Random(0x1020_3040L),
                )
            } ?: error("profile $profile did not produce an inner native")
        }

        val parserCfgs = artifacts.map { artifact -> targetCfg(objdump, artifact.bytes, "js_vm_parse_program") }
        val operandCfgs = artifacts.map { artifact -> targetCfg(objdump, artifact.bytes, "js_vm_profile_fetch_operand") }
        assertEquals(3, parserCfgs.map { it.normalizedDigest }.toSet().size, "All three inner-native parser profiles must have unique normalized target CFGs")
        assertEquals(3, operandCfgs.map { it.normalizedDigest }.toSet().size, "All three inner-native operand profiles must have unique normalized target CFGs")
        assertTrue(parserCfgs.all { it.branchKinds.isNotEmpty() && it.basicBlockOutDegrees.isNotEmpty() })
        assertTrue(operandCfgs.all { it.instructionKinds.isNotEmpty() })
        writeEvidenceReport(parserProfiles, artifacts, parserCfgs, operandCfgs)
    }

    private fun targetCfg(objdump: Path, bytes: ByteArray, symbol: String): NormalizedCfg {
        val dll = Files.createTempFile("javashroud-inner-cfg-", ".dll")
        return try {
            Files.write(dll, bytes)
            val exportText = ProcessBuilder(objdump.toString(), "-p", dll.toString()).redirectErrorStream(true).start().let { process ->
                val text = process.inputStream.bufferedReader().readText()
                assertEquals(0, process.waitFor(), "objdump failed for $symbol: ${text.take(600)}")
                text
            }
            val rva = exportRva(exportText, symbol)
            val start = imageBase(exportText) + rva
            val output = ProcessBuilder(
                objdump.toString(), "-D", "-j", ".jsx", "--insn-width=16",
                dll.toString(),
            ).redirectErrorStream(true).start().let { process ->
                val text = process.inputStream.bufferedReader().readText()
                assertEquals(0, process.waitFor(), "objdump disassembly failed for $symbol: ${text.take(600)}")
                text
            }
            normalizeFunction(output, symbol, start)
        } finally {
            Files.deleteIfExists(dll)
        }
    }

    private fun exportRva(exportText: String, symbol: String): Long {
        val nameLine = exportText.lines().firstOrNull { it.trimEnd().endsWith(" $symbol") }
            ?: error("missing exported target function $symbol")
        val tableIndex = Regex("^\\s*\\[\\s*(\\d+)]").find(nameLine)?.groupValues?.get(1)?.toInt()
            ?: error("missing export table index for $symbol")
        val tableStart = exportText.indexOf("Export Address Table --")
        val tableEnd = exportText.indexOf("[Ordinal/Name Pointer] Table", tableStart)
        val table = exportText.substring(tableStart, tableEnd)
        val row = table.lines().firstOrNull { Regex("^\\s*\\[\\s*$tableIndex]\\s+\\+base").containsMatchIn(it) }
            ?: error("missing export RVA row for $symbol")
        return Regex("\\+base\\[\\s*\\d+]\\s+([0-9a-fA-F]+)").find(row)!!.groupValues[1].toLong(16)
    }

    private fun imageBase(peHeaders: String): Long {
        val value = Regex("(?m)^ImageBase\\s+([0-9a-fA-F]+)\\s*$").find(peHeaders)?.groupValues?.get(1)
            ?: error("missing PE ImageBase")
        return value.toLong(16)
    }

    private fun normalizeFunction(disassembly: String, symbol: String, startAddress: Long): NormalizedCfg {
        val instructionRegex = Regex("^\\s*([0-9a-fA-F]+):\\s+((?:[0-9a-fA-F]{2}\\s+)+)([a-zA-Z][a-zA-Z0-9.]*)(?:\\s+(.*?))?\\s*$")
        val instructions = disassembly.lineSequence().mapNotNull { line ->
            val match = instructionRegex.find(line) ?: return@mapNotNull null
            val bytes = match.groupValues[2].trim().split(Regex("\\s+")).map { it.toInt(16).toByte() }
            DisassembledInstruction(
                address = match.groupValues[1].toLong(16),
                bytes = bytes,
                mnemonic = match.groupValues[3].lowercase(),
                operands = match.groupValues.getOrElse(4) { "" }.trim(),
            )
        }.associateBy { it.address }
        require(instructions.containsKey(startAddress)) { "missing disassembly start for $symbol at 0x${startAddress.toString(16)}" }

        fun directTarget(instruction: DisassembledInstruction): Long? =
            Regex("^(?:0x)?([0-9a-fA-F]+)(?:\\s|$)").find(instruction.operands.removePrefix("*"))?.groupValues?.get(1)?.toLong(16)
        fun successors(instruction: DisassembledInstruction): List<Pair<Long, String>> {
            val fallthrough = instruction.address + instruction.bytes.size
            return when {
                instruction.mnemonic.startsWith("ret") || instruction.mnemonic in setOf("ud2", "int3", "hlt") -> emptyList()
                instruction.mnemonic == "jmp" -> directTarget(instruction)?.let { listOf(it to "jmp") } ?: emptyList()
                instruction.mnemonic.startsWith("j") -> buildList {
                    directTarget(instruction)?.let { add(it to "jcc-target") }
                    add(fallthrough to "jcc-fallthrough")
                }
                else -> listOf(fallthrough to "fallthrough")
            }.filter { (address, _) -> instructions.containsKey(address) }
        }

        val reachable = linkedSetOf<Long>()
        val work = ArrayDeque<Long>().apply { add(startAddress) }
        while (work.isNotEmpty()) {
            val address = work.removeFirst()
            if (!reachable.add(address)) continue
            successors(instructions.getValue(address)).forEach { (successor, _) -> if (successor !in reachable) work.add(successor) }
        }
        val ordered = reachable.map(instructions::getValue).sortedBy { it.address }
        val instructionKinds = mutableListOf<String>()
        val branchKinds = mutableListOf<String>()
        val instructionBytes = mutableListOf<Byte>()
        for (instruction in ordered) {
            instructionBytes += instruction.bytes
            val mnemonic = instruction.mnemonic
            val kind = when {
                mnemonic.startsWith("j") && mnemonic != "jmp" -> "jcc"
                mnemonic == "jmp" -> "jmp"
                mnemonic.startsWith("call") -> "call"
                mnemonic.startsWith("ret") -> "ret"
                else -> mnemonic
            }
            instructionKinds += kind
            if (kind == "jcc" || kind == "jmp" || kind == "ret") branchKinds += kind
        }
        val leaders = linkedSetOf(startAddress)
        ordered.forEach { instruction ->
            val edges = successors(instruction)
            if (instruction.mnemonic.startsWith("j")) edges.forEach { (target, _) -> leaders += target }
            if (instruction.mnemonic.startsWith("j") || instruction.mnemonic.startsWith("ret")) {
                val fallthrough = instruction.address + instruction.bytes.size
                if (fallthrough in reachable) leaders += fallthrough
            }
        }
        val leaderSet = leaders.filterTo(hashSetOf()) { it in reachable }
        val blocks = mutableListOf<List<DisassembledInstruction>>()
        var current = mutableListOf<DisassembledInstruction>()
        ordered.forEach { instruction ->
            if (instruction.address in leaderSet && current.isNotEmpty()) {
                blocks += current
                current = mutableListOf()
            }
            current += instruction
            if (instruction.mnemonic.startsWith("j") || instruction.mnemonic.startsWith("ret") || instruction.mnemonic in setOf("ud2", "int3", "hlt")) {
                blocks += current
                current = mutableListOf()
            }
        }
        if (current.isNotEmpty()) blocks += current
        val outDegrees = blocks.map { block -> successors(block.last()).map { it.first }.distinct().size }
        return NormalizedCfg(
            instructionKinds = instructionKinds,
            branchKinds = branchKinds,
            basicBlockOutDegrees = outDegrees,
            normalizedDigest = sha256((instructionKinds + "|" + branchKinds + "|" + outDegrees).joinToString(",")),
            rawInstructionBytesDigest = sha256(instructionBytes.toByteArray()),
        )
    }

    private fun fixedContext(profile: NativeVmBuildProfile, partitions: RuntimeKeyPartitions): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { (it * 11 + 5).toByte() },
        nativeSeed = 0x1122_3344_5566_7788L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { (it * 13 + 7).toByte() },
        runtimeKeyPartitions = partitions.deepCopy(),
        nativeVmProfile = profile,
    )

    private fun findObjdump(): Path? = sequenceOf(
        System.getenv("JAVASHROUD_OBJDUMP")?.let(Path::of),
        Path.of("C:/msys64/mingw64/bin/objdump.exe"),
        Path.of("C:/msys64/ucrt64/bin/objdump.exe"),
    ).filterNotNull().firstOrNull(Files::isExecutable)

    private fun sha256(value: String): String = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray())
        .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun sha256(value: ByteArray): String = MessageDigest.getInstance("SHA-256")
        .digest(value)
        .joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun writeEvidenceReport(
        profiles: List<NativeVmBuildProfile>,
        artifacts: List<NativeRecompilationTransforms.RecompiledNative>,
        parserCfgs: List<NormalizedCfg>,
        operandCfgs: List<NormalizedCfg>,
    ) {
        val cwd = Path.of("").toAbsolutePath().normalize()
        val root = if (cwd.fileName?.toString() == "core-engine") cwd.parent else cwd
        val reportPath = root.resolve("build/core-engine/reports/native-max/native-vm-profile-cfg-evidence.json")
        Files.createDirectories(reportPath.parent)
        fun jsonString(value: String): String = buildString {
            append('"')
            value.forEach { ch ->
                when (ch) {
                    '"' -> append("\\\"")
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    '\t' -> append("\\t")
                    else -> append(ch)
                }
            }
            append('"')
        }
        fun stringArray(values: List<String>): String =
            values.joinToString(prefix = "[", postfix = "]", separator = ",") { jsonString(it) }
        fun intArray(values: List<Int>): String = values.joinToString(prefix = "[", postfix = "]", separator = ",")
        fun cfgJson(cfg: NormalizedCfg): String =
            """{"raw_instruction_bytes_sha256":${jsonString(cfg.rawInstructionBytesDigest)},"normalized_instruction_kind_digest":${jsonString(sha256(cfg.instructionKinds.joinToString(",")))},"normalized_cfg_digest":${jsonString(cfg.normalizedDigest)},"instruction_kinds":${stringArray(cfg.instructionKinds)},"branch_kind_sequence":${stringArray(cfg.branchKinds)},"basic_block_out_degree_signature":${intArray(cfg.basicBlockOutDegrees)}}"""

        val profilesJson = profiles.indices.joinToString(separator = ",", prefix = "[", postfix = "]") { index ->
            val profile = profiles[index]
            val artifact = artifacts[index]
            """{"parser_row_profile":${profile.parserRowProfile},"operand_access_profile":${profile.operandAccessProfile},"authenticated_id":${profile.authenticatedId},"inner_size":${artifact.bytes.size},"inner_sha256":${jsonString(sha256(artifact.bytes))},"pre_seal":true,"outer_shell":false,"symbols":{"js_vm_parse_program":${cfgJson(parserCfgs[index])},"js_vm_profile_fetch_operand":${cfgJson(operandCfgs[index])}}}"""
        }
        val report = """{"schema_version":1,"scope":"pre-seal-inner","platform":"windows-x64","controls":{"compile_seed":"0x44556600","native_seed":"0x1122334455667788","shared_master_key":true,"shared_jar_layout":true,"shared_runtime_resource_key":true,"shared_runtime_key_partitions":true,"shared_evidence_rng":true,"only_profile_varied":true},"profiles":$profilesJson,"gates":{"parser_unique_normalized_cfg_count":${parserCfgs.map { it.normalizedDigest }.toSet().size},"operand_unique_normalized_cfg_count":${operandCfgs.map { it.normalizedDigest }.toSet().size},"expected":3,"passed":true},"behavior_equivalence":{"status":"see-native-vm-profile-behavior-evidence"}}"""
        Files.writeString(reportPath, report, Charsets.UTF_8)
        assertTrue(Files.size(reportPath) > 0, "CFG evidence report must be written: $reportPath")
    }

    private class NormalizedCfg(
        val instructionKinds: List<String>,
        val branchKinds: List<String>,
        val basicBlockOutDegrees: List<Int>,
        val normalizedDigest: String,
        val rawInstructionBytesDigest: String,
    )

    private data class DisassembledInstruction(
        val address: Long,
        val bytes: List<Byte>,
        val mnemonic: String,
        val operands: String,
    )
}
