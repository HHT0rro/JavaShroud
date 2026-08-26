package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarFile
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.Type
import org.objectweb.asm.tree.IincInsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.JumpInsnNode
import org.objectweb.asm.tree.LabelNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.LookupSwitchInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.TableSwitchInsnNode
import org.objectweb.asm.tree.VarInsnNode

internal data class ReleaseArtifactScanReport(
    val profile: HardenedProtectionProfile,
    val artifactDigestHex: String,
    val protocolVersion: String,
    val enabledPasses: List<String>,
    val findings: List<Finding>,
    val passed: Boolean,
) {
    data class Finding(val check: String, val passed: Boolean, val detail: String)

    fun requirePass() {
        if (passed) return
        val failed = findings.filter { !it.passed }.joinToString("; ") { it.check + ": " + it.detail }
        throw SecurityException("RELEASE artifact scan failed: " + failed)
    }

    fun toReportText(): String {
        val builder = StringBuilder()
        builder.append("profile=").append(profile.wireValue).append('\n')
        builder.append("protocol=").append(protocolVersion).append('\n')
        builder.append("artifactSha256=").append(artifactDigestHex).append('\n')
        builder.append("enabledPasses=").append(enabledPasses.joinToString(",")).append('\n')
        if (profile.isLowProtection) builder.append("risk=LOW_PROTECTION_EXPLICIT_MINIMAL\n")
        findings.forEach { finding ->
            builder.append(if (finding.passed) "PASS " else "FAIL ")
            builder.append(finding.check).append(' ').append(finding.detail).append('\n')
        }
        builder.append(if (passed) "RESULT=PASS\n" else "RESULT=FAIL\n")
        return builder.toString()
    }
}

internal object ReleaseArtifactScan {
    fun scan(
        outputJarPath: Path,
        artifact: BytecodeArtifact,
        profile: HardenedProtectionProfile,
        enabledPasses: List<String>,
        nativeBytes: List<ByteArray> = emptyList(),
        inputJarBytes: Long = -1L,
    ): ReleaseArtifactScanReport {
        val digest = SignedDebugMap.sha256(outputJarPath)
        val findings = mutableListOf<ReleaseArtifactScanReport.Finding>()
        findings += scanRenameMaps(artifact)
        findings += FixedGeneratedNameArtifactScan.scanArtifact(artifact)
        findings += scanFixedGeneratedNamesInOutputJar(outputJarPath)
        findings += scanLegacyPaths(artifact)
        findings += scanLegacyMagics(artifact)
        findings += scanIndyTargets(artifact)
        findings += scanStringKeyTriples(artifact)
        findings += scanStringStaticTriple(artifact)
        findings += scanItkKeyLanes(artifact)
        findings += scanItkAadUsed(artifact)
        findings += scanRuntimeBinding(artifact)
        findings += scanRotationStrategyDiversity(artifact)
        findings += scanCfgFixedTemplate(artifact, enabledPasses)
        findings += scanExceptionBodyClone(artifact)
        findings += scanAkenEvaluatorDirectRecovery(artifact)
        findings += scanVbc4FixedMaterial(artifact, nativeBytes)
        findings += scanDebugMapProvenance(outputJarPath, artifact)
        findings += scanBlockingJdk(profile)
        findings += scanFreshCwdReproducibility(artifact)
        findings += scanPerfBudget(outputJarPath, inputJarBytes, profile)
        findings += scanDiagnostics(artifact, nativeBytes, profile)
        findings += scanNativeSecrets(nativeBytes, profile)
        val failed = findings.any { !it.passed }
        val passed = when (profile) {
            HardenedProtectionProfile.RELEASE_HARDENED -> !failed
            HardenedProtectionProfile.ANALYSIS_ONLY -> findings.filter { it.check != "diagnostics" && it.check != "perf-budget" }.all { it.passed }
            HardenedProtectionProfile.MINIMAL -> findings
                .filter { it.check == FixedGeneratedNameArtifactScan.CHECK }
                .all { it.passed }
        }
        return ReleaseArtifactScanReport(
            profile = profile,
            artifactDigestHex = digest.joinToString("") { b -> "%02x".format(b) },
            protocolVersion = ProtectionFormat.CURRENT,
            enabledPasses = enabledPasses,
            findings = findings,
            passed = passed,
        )
    }

    fun writeReport(outputJarPath: Path, report: ReleaseArtifactScanReport): Path {
        val path = outputJarPath.resolveSibling(outputJarPath.fileName.toString().removeSuffix(".jar") + ".release-scan.txt")
        Files.write(path, report.toReportText().toByteArray(StandardCharsets.UTF_8))
        return path
    }

    fun scanJarFile(outputJarPath: Path, profile: HardenedProtectionProfile, enabledPasses: List<String>): ReleaseArtifactScanReport {
        JarFile(outputJarPath.toFile()).use { jar ->
            val names = jar.entries().toList().map { it.name }
            val findings = mutableListOf<ReleaseArtifactScanReport.Finding>()
            val idxHit = names.any(ProtectionFormat::isForbiddenReleaseRenameIndexPath)
            findings += ReleaseArtifactScanReport.Finding("rename-map", !idxHit, if (idxHit) "production JAR contains rename idx" else "absent")
            findings += FixedGeneratedNameArtifactScan.scanJarFile(jar)
            val forbiddenPath = names.firstOrNull(ProtectionFormat::isForbiddenReleaseResourcePath)
            findings += ReleaseArtifactScanReport.Finding(
                "legacy-path",
                forbiddenPath == null,
                forbiddenPath ?: "absent",
            )
            val passed = if (profile == HardenedProtectionProfile.MINIMAL) {
                findings.filter { it.check == FixedGeneratedNameArtifactScan.CHECK }.all { it.passed }
            } else {
                findings.all { it.passed }
            }
            val digest = SignedDebugMap.sha256(outputJarPath)
            return ReleaseArtifactScanReport(
                profile = profile,
                artifactDigestHex = digest.joinToString("") { b -> "%02x".format(b) },
                protocolVersion = ProtectionFormat.CURRENT,
                enabledPasses = enabledPasses,
                findings = findings,
                passed = passed,
            )
        }
    }

    private fun scanFixedGeneratedNamesInOutputJar(outputJarPath: Path): ReleaseArtifactScanReport.Finding =
        try {
            JarFile(outputJarPath.toFile()).use(FixedGeneratedNameArtifactScan::scanJarFile)
        } catch (error: Throwable) {
            ReleaseArtifactScanReport.Finding(
                FixedGeneratedNameArtifactScan.CHECK,
                false,
                "entry=$outputJarPath; class=<unreadable>; stage=release-scan; origin=output-jar; " +
                    "reason=jar-read-failed:${error.javaClass.simpleName}",
            )
        }

    private fun scanRenameMaps(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val hit = artifact.jarEntries.any { entry ->
            ProtectionFormat.isForbiddenReleaseRenameIndexPath(entry.name)
        }
        return ReleaseArtifactScanReport.Finding("rename-map", !hit, if (hit) "idx present" else "absent")
    }

    private fun scanLegacyPaths(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val hit = artifact.jarEntries.map { it.name }.firstOrNull(ProtectionFormat::isForbiddenReleaseResourcePath)
        return ReleaseArtifactScanReport.Finding("legacy-path", hit == null, hit ?: "absent")
    }

    private fun scanLegacyMagics(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val headerBytes = maxOf(16, ProtectionFormat.FORBIDDEN_RELEASE_MAGICS.maxOf(String::length))
        val hit = artifact.jarEntries.firstOrNull { entry ->
            val prefix = entry.bytes.copyOfRange(0, minOf(entry.bytes.size, headerBytes)).toString(Charsets.US_ASCII)
            ProtectionFormat.FORBIDDEN_RELEASE_MAGICS.any { magic -> prefix.startsWith(magic) }
        }
        return ReleaseArtifactScanReport.Finding("legacy-magic", hit == null, hit?.name ?: "absent")
    }

    private fun scanItkKeyLanes(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val lanes = (0 until 4).map { lane ->
            val sentinel = 0x4A535230 + lane
            byteArrayOf(
                ((sentinel ushr 24) and 0xFF).toByte(),
                ((sentinel ushr 16) and 0xFF).toByte(),
                ((sentinel ushr 8) and 0xFF).toByte(),
                (sentinel and 0xFF).toByte(),
            )
        }
        val hit = artifact.classArtifacts.any { classArtifact ->
            lanes.all { needle -> containsBytes(classArtifact.bytes, needle) }
        }
        return ReleaseArtifactScanReport.Finding(
            "itk-key-lane-absent",
            !hit,
            if (hit) "concatenated AES key lanes present" else "absent",
        )
    }

    private fun scanItkAadUsed(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val magic = byteArrayOf('I'.code.toByte(), 'T'.code.toByte(), 'K'.code.toByte(), '1'.code.toByte())
        val aad = byteArrayOf(
            'J'.code.toByte(), 'S'.code.toByte(), 'I'.code.toByte(), 'T'.code.toByte(),
            'K'.code.toByte(), 'A'.code.toByte(), 'A'.code.toByte(), 'D'.code.toByte(), 3,
        )
        val hasMagic = artifact.classArtifacts.any { containsBytes(it.bytes, magic) } ||
            artifact.jarEntries.any { containsBytes(it.bytes, magic) }
        if (!hasMagic) {
            return ReleaseArtifactScanReport.Finding("itk-aad-used", true, "no-itk")
        }
        val hasAad = artifact.classArtifacts.any { containsBytes(it.bytes, aad) } ||
            artifact.jarEntries.any { containsBytes(it.bytes, aad) }
        return ReleaseArtifactScanReport.Finding(
            "itk-aad-used",
            hasAad,
            if (hasAad) "aad-domain-present" else "ITK1 present without AAD domain",
        )
    }

    private fun scanRuntimeBinding(artifact: BytecodeArtifact): List<ReleaseArtifactScanReport.Finding> {
        val catalog = artifact.jarEntries.firstOrNull { it.name == "META-INF/jsrt/catalog/directory.jsr1" }
            ?: return listOf(
                ReleaseArtifactScanReport.Finding("runtime-binding-nonzero", true, "no-catalog"),
                ReleaseArtifactScanReport.Finding("runtime-binding-match", true, "no-catalog"),
            )
        return try {
            val directory = io.github.hht0rro.javashroud.transforms.protection.aken.r1.R1ArtifactDirectory.decode(catalog.bytes)
            try {
                val native = directory.runtimeBindingDigest.nativeSha256
                val abi = directory.runtimeBindingDigest.abiDigest
                val spec = directory.runtimeBindingDigest.specializationDigest
                val nonzero = isNonZeroDigest(native) && isNonZeroDigest(abi) && isNonZeroDigest(spec)
                val nativeMatch = artifact.jarEntries.any { entry ->
                    (entry.name.endsWith(".dll") || entry.name.endsWith(".so")) &&
                        java.security.MessageDigest.getInstance("SHA-256").digest(entry.bytes).contentEquals(native)
                }
                listOf(
                    ReleaseArtifactScanReport.Finding(
                        "runtime-binding-nonzero",
                        nonzero,
                        if (nonzero) "native/abi/specialization nonzero" else "zero digest in catalog",
                    ),
                    ReleaseArtifactScanReport.Finding(
                        "runtime-binding-match",
                        nativeMatch,
                        if (nativeMatch) "catalog native SHA-256 matches a library entry" else "catalog native SHA-256 does not match DLL/SO",
                    ),
                )
            } finally {
                directory.wipe()
            }
        } catch (error: Throwable) {
            listOf(
                ReleaseArtifactScanReport.Finding(
                    "runtime-binding-nonzero",
                    false,
                    "catalog-decode-failed:${error.javaClass.simpleName}",
                ),
                ReleaseArtifactScanReport.Finding(
                    "runtime-binding-match",
                    false,
                    "catalog-decode-failed:${error.javaClass.simpleName}",
                ),
            )
        }
    }

    private fun isNonZeroDigest(value: ByteArray): Boolean =
        value.size == 32 && value.any { it != 0.toByte() }

    private fun containsBytes(bytes: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || bytes.size < needle.size) return false
        outer@ for (i in 0..(bytes.size - needle.size)) {
            for (j in needle.indices) {
                if (bytes[i + j] != needle[j]) continue@outer
            }
            return true
        }
        return false
    }

    private fun scanPerfBudget(
        outputJarPath: Path,
        inputJarBytes: Long,
        profile: HardenedProtectionProfile,
    ): ReleaseArtifactScanReport.Finding {
        if (inputJarBytes <= 0L) {
            return ReleaseArtifactScanReport.Finding("perf-budget", true, "no-input-baseline")
        }
        val outputBytes = try {
            Files.size(outputJarPath)
        } catch (_: Exception) {
            return ReleaseArtifactScanReport.Finding("perf-budget", profile != HardenedProtectionProfile.RELEASE_HARDENED, "output-size-unavailable")
        }
        val nativeCompressedBytes = try {
            JarFile(outputJarPath.toFile()).use { jar ->
                jar.entries().asSequence()
                    .filter { entry -> entry.name.endsWith(".dll") || entry.name.endsWith(".so") }
                    .sumOf { entry -> entry.compressedSize.coerceAtLeast(0L) }
            }
        } catch (_: Exception) {
            0L
        }
        val payloadBytes = (outputBytes - nativeCompressedBytes).coerceAtLeast(0L)
        val nativeRuntimeAllowance = if (nativeCompressedBytes > 0L) {
            nativeCompressedBytes * 2L + 256L * 1024L
        } else {
            0L
        }
        val allowedPayloadBytes = (
            inputJarBytes.toDouble() * io.github.hht0rro.javashroud.model.config.HardenedPerfBudget.ARTIFACT_SIZE_MULTIPLIER +
                nativeRuntimeAllowance
            ).toLong()
        val ratio = payloadBytes.toDouble() / inputJarBytes.toDouble()
        val within = payloadBytes <= allowedPayloadBytes
        val ok = within || profile != HardenedProtectionProfile.RELEASE_HARDENED
        return ReleaseArtifactScanReport.Finding(
            "perf-budget",
            ok,
            "sizeRatio=${"%.2f".format(ratio)} output=$outputBytes payload=$payloadBytes nativeCompressed=$nativeCompressedBytes " +
                "allowedPayload=$allowedPayloadBytes input=$inputJarBytes" +
                " startupBudget=${io.github.hht0rro.javashroud.model.config.HardenedPerfBudget.STARTUP_MULTIPLIER}" +
                " callBudget=${io.github.hht0rro.javashroud.model.config.HardenedPerfBudget.CALL_OVERHEAD_MULTIPLIER}",
        )
    }

    private fun scanFreshCwdReproducibility(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val needles = listOf(
            "C:\\Users\\",
            "C:/Users/",
            "/home/",
            "AppData\\Local\\Temp",
            "AppData/Local/Temp",
        )
        val haystacks = artifact.classArtifacts.map { it.bytes } + artifact.jarEntries.map { it.bytes }
        val hit = needles.firstOrNull { needle -> haystacks.any { bytes -> containsAscii(bytes, needle) } }
        return ReleaseArtifactScanReport.Finding(
            "fresh-cwd-reproducibility",
            hit == null,
            hit ?: "absent",
        )
    }

    private fun scanBlockingJdk(profile: HardenedProtectionProfile): ReleaseArtifactScanReport.Finding {
        val feature = io.github.hht0rro.javashroud.model.config.HardenedJdkMatrix.currentFeature()
        if (profile != HardenedProtectionProfile.RELEASE_HARDENED) {
            return ReleaseArtifactScanReport.Finding("jdk-blocking-matrix", true, "jdk=$feature")
        }
        val ok = io.github.hht0rro.javashroud.model.config.HardenedJdkMatrix.isBlockingRuntime(feature)
        return ReleaseArtifactScanReport.Finding(
            "jdk-blocking-matrix",
            ok,
            if (ok) "jdk=$feature" else "jdk=$feature not in ${io.github.hht0rro.javashroud.model.config.HardenedJdkMatrix.BLOCKING}",
        )
    }

    private fun scanAkenEvaluatorDirectRecovery(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val marker = byteArrayOf('A'.code.toByte(), 'K'.code.toByte(), 'E'.code.toByte(), '1'.code.toByte())
        var overlays = 0
        val haystacks = artifact.classArtifacts.map { it.bytes } + artifact.jarEntries.map { it.bytes }
        haystacks.forEach { bytes ->
            var index = 0
            while (index <= bytes.size - marker.size) {
                if (bytes[index] == marker[0] &&
                    bytes[index + 1] == marker[1] &&
                    bytes[index + 2] == marker[2] &&
                    bytes[index + 3] == marker[3]
                ) {
                    if (coversThirtyTwoByteDek(bytes, index)) overlays++
                    index += 4
                } else {
                    index++
                }
            }
        }
        return ReleaseArtifactScanReport.Finding(
            "aken-evaluator-direct-recovery",
            overlays == 0,
            if (overlays == 0) "absent" else "dek-overlay=$overlays",
        )
    }

    private fun coversThirtyTwoByteDek(bytes: ByteArray, markerIndex: Int): Boolean {
        if (markerIndex + 6 >= bytes.size) return false
        val fragmentCount = bytes[markerIndex + 5].toInt() and 0xFF
        if (fragmentCount !in 4..12) return false
        val covered = BooleanArray(32)
        var cursor = markerIndex + 6 + 12 + 16 + 32 + 32 + 32
        repeat(fragmentCount) {
            if (cursor + 5 > bytes.size) return false
            val offset = bytes[cursor].toInt() and 0xFF
            val length = bytes[cursor + 1].toInt() and 0xFF
            cursor += 5
            if (length == 0 || offset + length > 32) return false
            for (index in offset until offset + length) {
                if (covered[index]) return false
                covered[index] = true
            }
            if (cursor + 4 > bytes.size) return false
            val tokenLen = readScanU32(bytes, cursor) ?: return false
            cursor += 4 + tokenLen + 16
            if (cursor + 4 > bytes.size) return false
            val encodedLen = readScanU32(bytes, cursor) ?: return false
            cursor += 4 + encodedLen + 16
        }
        return covered.all { it }
    }

    private fun readScanU32(bytes: ByteArray, offset: Int): Int? {
        if (offset + 4 > bytes.size) return null
        val value = ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)
        return if (value in 0..4096) value else null
    }

    private fun scanExceptionBodyClone(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val markers = mutableListOf<String>()
        artifact.classArtifacts.forEach { classArtifact ->
            val node = ClassNode()
            ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_DEBUG)
            node.fields.orEmpty().forEach { field ->
                if (field.name.contains("\$jsv\$")) {
                    markers += "${node.name}#${field.name}:${field.desc}"
                }
            }
            node.methods.orEmpty().forEach { method ->
                if (method.name.contains("\$jsv\$")) {
                    markers += "${node.name}#${method.name}${method.desc}"
                }
            }
        }
        return ReleaseArtifactScanReport.Finding(
            "exception-body-clone",
            markers.isEmpty(),
            if (markers.isEmpty()) "absent" else "jsv-markers=${markers.take(3).joinToString(",")}",
        )
    }

    private fun scanCfgFixedTemplate(
        artifact: BytecodeArtifact,
        enabledPasses: List<String>,
    ): ReleaseArtifactScanReport.Finding {
        var suspiciousGotoNext = 0
        var generatedGotoNext = 0
        var sameSwitch = 0
        var deadStore = 0
        var suspiciousModular = 0
        var generatedModular = 0
        val hasControlFlowPass = enabledPasses.any { it == "control-flow-obfuscation" || it == "control-flow-flattening" }
        artifact.classArtifacts.forEach { classArtifact ->
            val node = ClassNode()
            ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_DEBUG)
            node.methods.orEmpty().forEach { method ->
                val insns = method.instructions ?: return@forEach
                val array = insns.toArray()
                val loaded = loadedIntLocals(array)
                array.forEachIndexed { index, insn ->
                    when (insn) {
                        is JumpInsnNode -> if (insn.opcode == Opcodes.GOTO && isGotoNext(insn)) {
                            if (hasControlFlowPass && isGeneratedGotoNext(array, index, insn)) {
                                generatedGotoNext++
                            } else if (isSuspiciousGotoNext(insn)) {
                                suspiciousGotoNext++
                            }
                        }
                        is TableSwitchInsnNode -> if (sameSwitchTarget(insn.dflt, insn.labels)) sameSwitch++
                        is LookupSwitchInsnNode -> if (sameSwitchTarget(insn.dflt, insn.labels)) sameSwitch++
                        is VarInsnNode -> if (isUnreadConstStoreBeforeGoto(insn, loaded)) deadStore++
                    }
                }
                val modularMatches = fixedModularPredicateCount(array)
                val generatedMatches = if (hasControlFlowPass) generatedModularPredicateCount(array) else 0
                generatedModular += minOf(modularMatches, generatedMatches)
                suspiciousModular += (modularMatches - generatedMatches).coerceAtLeast(0)
            }
        }
        val failures = buildList {
            if (suspiciousGotoNext > 0) add("goto-next=$suspiciousGotoNext")
            if (sameSwitch > 0) add("same-switch=$sameSwitch")
            if (deadStore > 0) add("dead-store=$deadStore")
            if (suspiciousModular > 0) add("modular=$suspiciousModular")
        }
        val generated = buildList {
            if (generatedGotoNext > 0) add("goto-next=$generatedGotoNext")
            if (generatedModular > 0) add("modular=$generatedModular")
        }
        return ReleaseArtifactScanReport.Finding(
            "cfg-fixed-template",
            failures.isEmpty(),
            when {
                failures.isNotEmpty() -> failures.joinToString(",")
                generated.isNotEmpty() -> "generated-control-flow:${generated.joinToString(",")}"
                else -> "absent"
            },
        )
    }

    private fun loadedIntLocals(insns: Array<AbstractInsnNode>): Set<Int> {
        val loaded = hashSetOf<Int>()
        insns.forEach { insn ->
            when (insn) {
                is VarInsnNode -> if (insn.opcode == Opcodes.ILOAD) loaded += insn.`var`
                is IincInsnNode -> loaded += insn.`var`
            }
        }
        return loaded
    }

    private fun isGotoNext(goto: JumpInsnNode): Boolean {
        var cursor = goto.next
        while (cursor != null) {
            if (cursor is LabelNode) {
                return cursor === goto.label
            }
            if (cursor.opcode >= 0) return false
            cursor = cursor.next
        }
        return false
    }

    private fun isSuspiciousGotoNext(goto: JumpInsnNode): Boolean {
        val previous = previousOpcode(goto) ?: return false
        return previous.opcode == Opcodes.NOP ||
            (previous is JumpInsnNode && previous.label === goto.label)
    }

    private fun isGeneratedGotoNext(
        insns: Array<AbstractInsnNode>,
        index: Int,
        goto: JumpInsnNode,
    ): Boolean {
        val previous = previousOpcode(goto) as? JumpInsnNode ?: return false
        if (previous.label !== goto.label) return false
        if (previous.opcode != Opcodes.GOTO) {
            return when (val load = previousOpcode(previous)) {
                is VarInsnNode -> load.opcode == Opcodes.ILOAD && previous.opcode == Opcodes.IFNE
                is FieldInsnNode ->
                    load.opcode == Opcodes.GETSTATIC &&
                        load.name.startsWith("__js_flow_state") &&
                        previous.opcode == Opcodes.IFEQ
                else -> false
            }
        }
        var cursor = index - 1
        var inspected = 0
        while (cursor >= 0 && inspected < 24) {
            val candidate = insns[cursor--]
            if (candidate.opcode < 0) continue
            inspected++
            if (candidate is TableSwitchInsnNode || candidate is LookupSwitchInsnNode) return true
        }
        return false
    }

    private fun sameSwitchTarget(defaultLabel: LabelNode?, labels: List<LabelNode>?): Boolean {
        val all = ArrayList<LabelNode>(1 + (labels?.size ?: 0))
        if (defaultLabel != null) all += defaultLabel
        labels?.let(all::addAll)
        if (all.size < 2) return false
        val first = all[0]
        return all.all { it === first }
    }

    private fun isUnreadConstStoreBeforeGoto(store: VarInsnNode, loaded: Set<Int>): Boolean {
        if (store.opcode != Opcodes.ISTORE || store.`var` in loaded) return false
        val prev = previousOpcode(store) ?: return false
        val constPrev = prev.opcode in Opcodes.ICONST_M1..Opcodes.ICONST_5 || prev is LdcInsnNode
        if (!constPrev) return false
        var cursor = store.next
        while (cursor != null && (cursor.opcode < 0 || cursor.opcode == Opcodes.NOP)) {
            cursor = cursor.next
        }
        return cursor?.opcode == Opcodes.GOTO
    }

    private fun previousOpcode(insn: AbstractInsnNode): AbstractInsnNode? {
        var cursor = insn.previous
        while (cursor != null) {
            if (cursor.opcode >= 0) return cursor
            cursor = cursor.previous
        }
        return null
    }

    private fun fixedModularPredicateCount(insns: Array<AbstractInsnNode>): Int =
        modularPredicateStarts(insns.filter { it.opcode >= 0 }).size

    private fun generatedModularPredicateCount(insns: Array<AbstractInsnNode>): Int {
        val real = insns.filter { it.opcode >= 0 }
        return modularPredicateStarts(real).count { start ->
            if (start > 8 || start + 8 >= real.size) return@count false
            val jump = real[start + 7] as? JumpInsnNode ?: return@count false
            if (jump.opcode != Opcodes.IFNE || real[start + 8].opcode != Opcodes.NOP) return@count false
            var cursor = real[start + 8].next
            while (cursor != null && cursor.opcode < 0) {
                if (cursor is LabelNode && cursor === jump.label) return@count true
                cursor = cursor.next
            }
            false
        }
    }

    private fun modularPredicateStarts(real: List<AbstractInsnNode>): List<Int> {
        if (real.size < 7) return emptyList()
        val starts = mutableListOf<Int>()
        for (index in 0..(real.size - 7)) {
            val left = scanIntConstant(real[index]) ?: continue
            val right = scanIntConstant(real[index + 3]) ?: continue
            if (left !in 2..7 || right != left) continue
            if (
                real[index + 1].opcode == Opcodes.DUP &&
                real[index + 2].opcode == Opcodes.IMUL &&
                real[index + 4].opcode == Opcodes.IADD &&
                scanIntConstant(real[index + 5]) == 2 &&
                real[index + 6].opcode == Opcodes.IREM
            ) {
                starts += index
            }
        }
        return starts
    }

    private fun scanIntConstant(insn: AbstractInsnNode): Int? = when {
        insn.opcode in Opcodes.ICONST_M1..Opcodes.ICONST_5 -> insn.opcode - Opcodes.ICONST_0
        insn is IntInsnNode && insn.opcode in setOf(Opcodes.BIPUSH, Opcodes.SIPUSH) -> insn.operand
        insn is LdcInsnNode && insn.cst is Int -> insn.cst as Int
        else -> null
    }

    private fun scanRotationStrategyDiversity(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val strategies = linkedMapOf<String, Int>()
        artifact.classArtifacts.forEach { classArtifact ->
            val node = ClassNode()
            ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_DEBUG)
            node.methods.orEmpty().forEach { method ->
                method.instructions?.forEach { insn ->
                    val indy = insn as? InvokeDynamicInsnNode ?: return@forEach
                    val bsm = indy.bsm ?: return@forEach
                    if (bsm.owner != "io/github/hht0rro/javashroud/transforms/protection/CallsiteRotationHelper") return@forEach
                    if (bsm.name != "createRotatingCallSite") return@forEach
                    val strategy = indy.bsmArgs.orEmpty().getOrNull(1) as? String ?: return@forEach
                    strategies[strategy] = (strategies[strategy] ?: 0) + 1
                }
            }
        }
        val siteCount = strategies.values.sum()
        if (siteCount < 4) {
            return ReleaseArtifactScanReport.Finding(
                "rotation-strategy-diversity",
                true,
                if (siteCount == 0) "no-rotation" else "sites=$siteCount",
            )
        }
        val unique = strategies.size
        return ReleaseArtifactScanReport.Finding(
            "rotation-strategy-diversity",
            unique >= 2,
            if (unique >= 2) "strategies=$unique sites=$siteCount" else "single-strategy=${strategies.keys.single()} sites=$siteCount",
        )
    }

    private fun scanIndyTargets(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        var leaked = 0
        artifact.classArtifacts.forEach { classArtifact ->
            val node = ClassNode()
            ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_DEBUG)
            node.methods.orEmpty().forEach { method ->
                method.instructions?.forEach { insn ->
                    val indy = insn as? InvokeDynamicInsnNode ?: return@forEach
                    indy.bsmArgs.orEmpty().forEach { arg ->
                        val handle = arg as? Handle ?: return@forEach
                        if (IndyTargetTokenEnvelope.isBusinessTargetHandle(handle)) leaked++
                    }
                }
            }
        }
        return ReleaseArtifactScanReport.Finding("indy-target-opacity", leaked == 0, if (leaked == 0) "opaque" else "leakedHandles=" + leaked)
    }

    private fun scanStringKeyTriples(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        var triples = 0
        artifact.classArtifacts.forEach { classArtifact ->
            val node = ClassNode()
            ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_DEBUG)
            val clinit = node.methods.orEmpty().firstOrNull { it.name == "<clinit>" } ?: return@forEach
            val ldcs = clinit.instructions?.toArray()?.filterIsInstance<LdcInsnNode>()?.map { it.cst } ?: return@forEach
            val texts = ldcs.filterIsInstance<String>()
            val hasDes = texts.any { it.contains("DES/CBC") }
            val hasKey = texts.any { it.length >= 8 && it.length <= 32 } && ldcs.any { it is ByteArray }
            if (hasDes) triples++
            if (hasDes && hasKey) triples++
        }
        return ReleaseArtifactScanReport.Finding("string-key-triple", triples == 0, if (triples == 0) "absent" else "desOrTriple=" + triples)
    }

    private fun scanStringStaticTriple(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        var triples = 0
        val hits = mutableListOf<String>()
        artifact.classArtifacts.forEach { classArtifact ->
            val node = ClassNode()
            ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_DEBUG)
            node.methods.orEmpty().forEach { method ->
                val methodTriples = countStaticStringTriples(method)
                triples += methodTriples
                if (methodTriples > 0 && hits.size < 3) {
                    hits += "${node.name}#${method.name}${method.desc}:$methodTriples"
                }
            }
        }
        return ReleaseArtifactScanReport.Finding(
            "string-static-triple",
            triples == 0,
            if (triples == 0) "absent" else "triples=$triples hits=${hits.joinToString(",")}",
        )
    }

    private sealed class ScanValue {
        data class IntConst(val value: Int) : ScanValue()
        data class ByteArrayConst(val length: Int) : ScanValue()
        object Other : ScanValue()
    }

    private fun countStaticStringTriples(method: org.objectweb.asm.tree.MethodNode): Int {
        val stack = ArrayList<ScanValue>()
        fun push(value: ScanValue) {
            stack += value
        }
        fun pop(): ScanValue = if (stack.isEmpty()) ScanValue.Other else stack.removeAt(stack.lastIndex)
        var triples = 0
        method.instructions?.forEach { insn ->
            when (val opcode = insn.opcode) {
                in Opcodes.ICONST_M1..Opcodes.ICONST_5 -> push(ScanValue.IntConst(opcode - Opcodes.ICONST_0))
                Opcodes.BIPUSH, Opcodes.SIPUSH -> push(ScanValue.IntConst((insn as IntInsnNode).operand))
                Opcodes.LDC -> {
                    val constant = (insn as LdcInsnNode).cst
                    if (constant is Int) push(ScanValue.IntConst(constant)) else push(ScanValue.Other)
                }
                Opcodes.NEWARRAY -> {
                    val length = pop()
                    val type = (insn as IntInsnNode).operand
                    if (type == Opcodes.T_BYTE && length is ScanValue.IntConst && length.value in 1..4096) {
                        push(ScanValue.ByteArrayConst(length.value))
                    } else {
                        push(ScanValue.Other)
                    }
                }
                Opcodes.DUP -> if (stack.isEmpty()) push(ScanValue.Other) else push(stack.last())
                Opcodes.BASTORE -> {
                    pop()
                    pop()
                    pop()
                }
                Opcodes.INVOKESTATIC, Opcodes.INVOKEDYNAMIC -> {
                    val descriptor = when (insn) {
                        is MethodInsnNode -> insn.desc
                        is InvokeDynamicInsnNode -> insn.desc
                        else -> null
                    } ?: return@forEach
                    val argCount = Type.getArgumentTypes(descriptor).size
                    val args = List(argCount) { pop() }.asReversed()
                    if (
                        insn is MethodInsnNode &&
                            insn.opcode == Opcodes.INVOKESTATIC &&
                            insn.desc == "([BI[B)Ljava/lang/String;" &&
                            isHandlePageProofTriple(args)
                    ) triples++
                    if (Type.getReturnType(descriptor).sort != Type.VOID) push(ScanValue.Other)
                }
                else -> {
                    if (opcode in Opcodes.IFEQ..Opcodes.GOTO || opcode == Opcodes.ATHROW ||
                        opcode in Opcodes.IRETURN..Opcodes.RETURN
                    ) {
                        stack.clear()
                    }
                }
            }
        }
        return triples
    }

    private fun isHandlePageProofTriple(args: List<ScanValue>): Boolean {
        if (args.size != 3) return false
        val handle = args[0] as? ScanValue.ByteArrayConst ?: return false
        val page = args[1] as? ScanValue.IntConst ?: return false
        val proof = args[2] as? ScanValue.ByteArrayConst ?: return false
        return handle.length == 24 && proof.length in 1..4096 && page.value >= 0
    }

    private fun scanDiagnostics(
        artifact: BytecodeArtifact,
        nativeBytes: List<ByteArray>,
        profile: HardenedProtectionProfile,
    ): ReleaseArtifactScanReport.Finding {
        if (profile.allowsDiagnostics) {
            return ReleaseArtifactScanReport.Finding("diagnostics", true, "analysis-only")
        }
        val needles = listOf(
            "JS_NATIVE_CFG_EVIDENCE",
            "JS_AKEN_JNI_FIXTURE_DIAGNOSTICS",
            "js_vm_parse_program",
            "js_vm_profile_fetch_operand",
        )
        val haystacks = artifact.jarEntries.map { it.bytes } + artifact.classArtifacts.map { it.bytes } + nativeBytes
        val hit = needles.firstOrNull { needle -> haystacks.any { bytes -> containsAscii(bytes, needle) } }
        return ReleaseArtifactScanReport.Finding("diagnostics", hit == null, hit ?: "absent")
    }

    private fun scanVbc4FixedMaterial(
        artifact: BytecodeArtifact,
        nativeBytes: List<ByteArray>,
    ): ReleaseArtifactScanReport.Finding {
        val labels = listOf(
            "javashroud-aken-r1-vbc4-inner-crypto-v3",
            "javashroud-aken-r1-vbc4-inner-state-binding-v3",
            "javashroud-aken-r1-vm-build-key-v3",
            "javashroud-aken-r1-vm-dialect-v1",
            "javashroud-aken-v4-vbc4-inner-crypto-v2",
            "javashroud-aken-r1-vbc4-inner-crypto-v2",
            "vbc4-session-integrity-v2",
            "vbc4-aes-key",
            "vbc4-aes-iv",
        )
        val classHay = artifact.classArtifacts.map { it.bytes } + artifact.jarEntries.map { it.bytes }
        val labelHit = labels.firstOrNull { needle -> (classHay + nativeBytes).any { bytes -> containsAscii(bytes, needle) } }
        if (labelHit != null) {
            return ReleaseArtifactScanReport.Finding("vbc4-fixed-material", false, labelHit)
        }
        val magic = byteArrayOf('V'.code.toByte(), 'B'.code.toByte(), 'C'.code.toByte(), '4'.code.toByte())
        val magicHit = classHay.any { bytes -> containsBytes(bytes, magic) }
        return ReleaseArtifactScanReport.Finding(
            "vbc4-fixed-material",
            !magicHit,
            if (magicHit) "VBC4" else "absent",
        )
    }

    private fun scanDebugMapProvenance(
        outputJarPath: Path,
        artifact: BytecodeArtifact,
    ): ReleaseArtifactScanReport.Finding {
        val embedded = artifact.jarEntries.firstOrNull { entry ->
            entry.name.endsWith(".debugmap") ||
                (entry.bytes.size >= 4 &&
                    entry.bytes.copyOfRange(0, 4).toString(Charsets.US_ASCII) == ProtectionFormat.DEBUG_MAP_MAGIC)
        }
        if (embedded != null) {
            return ReleaseArtifactScanReport.Finding("debug-map-provenance", false, "embedded=${embedded.name}")
        }
        val sidecar = SignedDebugMap.sidecarPath(outputJarPath)
        if (!Files.isRegularFile(sidecar)) {
            return ReleaseArtifactScanReport.Finding("debug-map-provenance", true, "no-sidecar")
        }
        return try {
            val map = SignedDebugMap.parse(Files.readAllBytes(sidecar))
            val jarDigest = SignedDebugMap.sha256(outputJarPath)
            val problems = mutableListOf<String>()
            if (map.issuerKeyId.isBlank() || map.issuerKeyId == "ephemeral") problems += "issuer"
            if (map.buildId.isBlank()) problems += "buildId"
            if (map.transformVersion.isBlank()) problems += "transformVersion"
            if (map.targetTriple.isBlank()) problems += "targetTriple"
            if (!isNonZeroDigest(map.passConfigDigest)) problems += "passConfigDigest"
            if (!isNonZeroDigest(map.nativeSha256)) problems += "nativeSha256"
            if (!isNonZeroDigest(map.abiDigest)) problems += "abiDigest"
            if (!isNonZeroDigest(map.specializationDigest)) problems += "specializationDigest"
            if (!map.artifactSha256.contentEquals(jarDigest)) problems += "artifactDigest"
            ReleaseArtifactScanReport.Finding(
                "debug-map-provenance",
                problems.isEmpty(),
                if (problems.isEmpty()) "bound" else problems.joinToString(","),
            )
        } catch (error: Throwable) {
            ReleaseArtifactScanReport.Finding(
                "debug-map-provenance",
                false,
                "parse-failed:${error.javaClass.simpleName}",
            )
        }
    }

    private fun scanNativeSecrets(nativeBytes: List<ByteArray>, profile: HardenedProtectionProfile): ReleaseArtifactScanReport.Finding {
        if (nativeBytes.isEmpty()) {
            return ReleaseArtifactScanReport.Finding("native-secrets", true, "no-native")
        }
        val needles = listOf("native_secrets", "bindingSalt", "public-root", "javashroud-aken-v4-vbc4-inner-crypto-v2")
        val hit = needles.firstOrNull { needle -> nativeBytes.any { bytes -> containsAscii(bytes, needle) } }
        val ok = hit == null || profile.allowsDiagnostics
        return ReleaseArtifactScanReport.Finding("native-secrets", ok, hit ?: "absent")
    }

    private fun containsAscii(bytes: ByteArray, needle: String): Boolean {
        val target = needle.toByteArray(Charsets.US_ASCII)
        if (target.isEmpty() || bytes.size < target.size) return false
        outer@ for (i in 0..(bytes.size - target.size)) {
            for (j in target.indices) {
                if (bytes[i + j] != target[j]) continue@outer
            }
            return true
        }
        return false
    }
}
