package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.transforms.protection.qp.catalog.QpArtifactDirectory
import java.io.InputStream
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
    private const val MAX_NATIVE_SCAN_BYTES = 256L * 1024L * 1024L
    private const val NATIVE_SCAN_BUFFER_BYTES = 32 * 1024
    private val NATIVE_DIAGNOSTIC_MARKERS = listOf(
        "QP_CFG_EVIDENCE",
        "jsrt_diag",
        "debug_export",
        "test_only_export",
    )
    private val NATIVE_CORE_MARKERS = listOf(
        "full-core",
        "full_core",
        "microcode-corpus",
        "microcode_corpus",
        "stage-1",
    )
    private val NATIVE_DIAGNOSTIC_NAME_MARKERS = listOf("debug-export", "test-only-export")
    private val NATIVE_CORE_NAME_MARKERS = listOf("stage1", "full-core", "microcode-corpus")
    private val FORBIDDEN_RELEASE_MAGIC_BYTES: List<ByteArray> by lazy {
        ProtectionFormat.FORBIDDEN_RELEASE_MAGIC_HEX.map(::decodeHex)
    }

    fun scan(
        outputJarPath: Path,
        artifact: BytecodeArtifact,
        profile: HardenedProtectionProfile,
        enabledPasses: List<String>,
        nativeBytes: List<ByteArray> = emptyList(),
        inputJarBytes: Long = -1L,
        requiredNativePlatforms: Set<String> = emptySet(),
    ): ReleaseArtifactScanReport {
        val digest = SignedDebugMap.sha256(outputJarPath)
        val findings = mutableListOf<ReleaseArtifactScanReport.Finding>()
        findings += scanCurrentFormat(artifact, nativeBytes, enabledPasses)
        findings += scanRenameMaps(artifact)
        findings += FixedGeneratedNameArtifactScan.scanArtifact(artifact)
        findings += scanFixedGeneratedNamesInOutputJar(outputJarPath)
        findings += scanLegacyPaths(artifact)
        findings += scanLegacyMagics(artifact)
        findings += scanIndyTargets(artifact)
        findings += scanStringKeyTriples(artifact)
        findings += scanStringStaticTriple(artifact)
        findings += scanJavaKeyLanes(artifact)
        findings += scanTargetTokenAad(artifact)
        findings += scanRuntimeBinding(artifact)
        findings += scanRotationStrategyDiversity(artifact)
        findings += scanCfgFixedTemplate(artifact, enabledPasses)
        findings += scanExceptionBodyClone(artifact)
        findings += scanQpEvaluatorDirectRecovery(artifact)
        findings += scanRetiredEvaluatorDomainSalt(artifact, nativeBytes)
        findings += scanQpFixedMaterial(artifact, nativeBytes)
        findings += scanJavaCryptoOracles(artifact)
        findings += scanDebugMapProvenance(outputJarPath, artifact)
        findings += scanBlockingJdk(profile)
        findings += scanFreshCwdReproducibility(artifact)
        findings += scanPerfBudget(outputJarPath, inputJarBytes, profile)
        findings += scanDiagnostics(artifact, nativeBytes)
        findings += scanNativeSecrets(nativeBytes)
        findings += scanPublicToolSurface(artifact, nativeBytes)
        findings += scanNativeContents(artifact, nativeBytes)
        findings += scanDualNativePlatforms(artifact, enabledPasses)
        findings += scanStrictNativePlatformMatrix(artifact, enabledPasses, profile, requiredNativePlatforms)
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
            protocolVersion = ProtectionFormat.CURRENT_LABEL,
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

    fun scanJarFile(
        outputJarPath: Path,
        profile: HardenedProtectionProfile,
        enabledPasses: List<String>,
        requiredNativePlatforms: Set<String> = emptySet(),
    ): ReleaseArtifactScanReport {
        JarFile(outputJarPath.toFile()).use { jar ->
            val names = jar.entries().toList().map { it.name }
            val findings = mutableListOf<ReleaseArtifactScanReport.Finding>()
            val entries = jar.entries().toList()
            findings += scanJarCurrentFormat(jar, entries, enabledPasses)
            val idxHit = names.any(ProtectionFormat::isForbiddenReleaseRenameIndexPath)
            findings += ReleaseArtifactScanReport.Finding("rename-map", !idxHit, if (idxHit) "production JAR contains rename idx" else "absent")
            findings += FixedGeneratedNameArtifactScan.scanJarFile(jar)
            val forbiddenPath = names.firstOrNull(ProtectionFormat::isForbiddenReleaseResourcePath)
            findings += ReleaseArtifactScanReport.Finding(
                "legacy-path",
                forbiddenPath == null,
                forbiddenPath ?: "absent",
            )
            findings += scanJarNativeContents(jar, entries)
            findings += scanJarPublicToolSurface(jar, entries)
            findings += scanJarJavaCryptoOracles(jar, entries)
            findings += scanJarNativePlatformMatrix(jar, entries, enabledPasses, profile, requiredNativePlatforms)
            val passed = if (profile == HardenedProtectionProfile.MINIMAL) {
                findings.filter { it.check == FixedGeneratedNameArtifactScan.CHECK }.all { it.passed }
            } else {
                findings.all { it.passed }
            }
            val digest = SignedDebugMap.sha256(outputJarPath)
            return ReleaseArtifactScanReport(
                profile = profile,
                artifactDigestHex = digest.joinToString("") { b -> "%02x".format(b) },
                protocolVersion = ProtectionFormat.CURRENT_LABEL,
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
        val hit = artifact.jarEntries.firstOrNull { entry ->
            FORBIDDEN_RELEASE_MAGIC_BYTES.any { magic -> startsWithBytes(entry.bytes, magic) }
        }
        return ReleaseArtifactScanReport.Finding(
            "legacy-magic",
            hit == null,
            hit?.let { "forbidden-header-in:${it.name}" } ?: "absent",
        )
    }

    private fun scanJavaKeyLanes(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
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
            "java-key-lane-absent",
            !hit,
            if (hit) "concatenated AES key lanes present" else "absent",
        )
    }

    private fun scanTargetTokenAad(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val magic = byteArrayOf(0x49, 0x54, 0x4B, 0x31).map { it.toByte() }.toByteArray()
        val aad = byteArrayOf(
            0x4A, 0x53, 0x49, 0x54, 0x4B, 0x41, 0x41, 0x44, 0x03,
        )
        val hasMagic = artifact.classArtifacts.any { containsBytes(it.bytes, magic) } ||
            artifact.jarEntries.any { containsBytes(it.bytes, magic) }
        if (!hasMagic) {
            return ReleaseArtifactScanReport.Finding("target-token-aad-used", true, "no-legacy-token-lane")
        }
        val hasAad = artifact.classArtifacts.any { containsBytes(it.bytes, aad) } ||
            artifact.jarEntries.any { containsBytes(it.bytes, aad) }
        return ReleaseArtifactScanReport.Finding(
            "target-token-aad-used",
            hasAad,
            if (hasAad) "aad-domain-present" else "legacy token marker present without AAD domain",
        )
    }

    private fun scanRuntimeBinding(
        artifact: BytecodeArtifact,
    ): List<ReleaseArtifactScanReport.Finding> {
        val selection = selectCatalogDirectory(artifact.jarEntries.map { it.name to it.bytes })
        if (selection.error != null) {
            return listOf(
                ReleaseArtifactScanReport.Finding("runtime-binding-nonzero", false, selection.error),
                ReleaseArtifactScanReport.Finding("runtime-binding-match", false, selection.error),
            )
        }
        val catalog = selection.entries.singleOrNull()
        if (catalog == null) {
            val detail = if (artifact.jarEntries.any { isCatalogIndexName(it.name) }) {
                "catalog-index-target-missing"
            } else {
                "not-applicable:no-q-page-catalog"
            }
            val passed = detail.startsWith("not-applicable:")
            return listOf(
                ReleaseArtifactScanReport.Finding("runtime-binding-nonzero", passed, detail),
                ReleaseArtifactScanReport.Finding("runtime-binding-match", passed, detail),
            )
        }
        return try {
            val directory = QpArtifactDirectory.decode(catalog.second)
            try {
                val native = directory.runtimeBindingDigest.nativeSha256
                val abi = directory.runtimeBindingDigest.abiDigest
                val spec = directory.runtimeBindingDigest.specializationDigest
                val nonzero = isNonZeroDigest(native) && isNonZeroDigest(abi) && isNonZeroDigest(spec)
                val nativeMatch = artifact.jarEntries.any { entry ->
                    (entry.name.replace('\\', '/').lowercase(java.util.Locale.ROOT).endsWith(".dll") ||
                        entry.name.replace('\\', '/').lowercase(java.util.Locale.ROOT).endsWith(".so")) &&
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
                        if (nativeMatch) "catalog native SHA-256 matches a library entry" else "catalog native SHA-256 does not match native library",
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

    private fun scanQpEvaluatorDirectRecovery(artifact: BytecodeArtifact): ReleaseArtifactScanReport.Finding {
        val marker = byteArrayOf(0x41, 0x4B, 0x45, 0x31).map { it.toByte() }.toByteArray()
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
            "qp-evaluator-direct-recovery",
            overlays == 0,
            if (overlays == 0) "absent" else "dek-overlay=$overlays",
        )
    }

    /**
     * Hardened-native profile check: the retired evaluator domain salt must
     * not appear in any class, resource, or native byte. Any hit means legacy
     * evaluator material survived into the artifact and the offline
     * materialization chain may be reconstructible.
     */
    private fun scanRetiredEvaluatorDomainSalt(
        artifact: BytecodeArtifact,
        nativeBytes: List<ByteArray>,
    ): ReleaseArtifactScanReport.Finding {
        val salt = byteArrayOf(
            0xA1.toByte(), 0xE1.toByte(), 0x09, 0xC3.toByte(),
            0x77, 0x2B, 0xD4.toByte(), 0x18,
        )
        val haystacks = artifact.classArtifacts.map { it.bytes } +
            artifact.jarEntries.map { it.bytes } +
            nativeBytes
        val hits = haystacks.count { bytes -> containsBytes(bytes, salt) }
        return ReleaseArtifactScanReport.Finding(
            "hardened-native-retired-evaluator-domain",
            hits == 0,
            if (hits == 0) "absent" else "retired-evaluator-domain-hits=$hits",
        )
    }

    private fun coversThirtyTwoByteDek(bytes: ByteArray, markerIndex: Int): Boolean {        if (markerIndex + 6 >= bytes.size) return false
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
                    if (bsm.owner != "io/github/hht0rro/javashroud/transforms/protection/qp/QpCallsiteBridge") return@forEach
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
                    // Standard JVM lambdas intentionally keep their implementation
                    // handle at the LambdaMetafactory boundary. They are not Qp
                    // business targets and must not be mistaken for a leaked Qp
                    // target description.
                    if (indy.bsm?.owner == "java/lang/invoke/LambdaMetafactory") return@forEach
                    indy.bsmArgs.orEmpty().forEach { arg ->
                        val handle = arg as? Handle ?: return@forEach
                        if (QpTargetTokenEnvelope.isBusinessTargetHandle(handle)) leaked++
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
                    val returnsString = Type.getReturnType(descriptor).sort == Type.OBJECT &&
                        Type.getReturnType(descriptor).internalName == "java/lang/String"
                    if (returnsString && stack.size >= 3 && isHandlePageProofTriple(stack.takeLast(3))) {
                        triples++
                    }
                    val args = List(argCount) { pop() }.asReversed()
                    if (
                        insn is MethodInsnNode &&
                            insn.opcode == Opcodes.INVOKESTATIC &&
                            (insn.desc == "([BI[B)Ljava/lang/String;" || insn.desc == "([B)Ljava/lang/String;") &&
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
    ): ReleaseArtifactScanReport.Finding {
        val needles = listOf(
            "JS_NATIVE_CFG_EVIDENCE",
            "js_vm_parse_program",
            "js_vm_profile_fetch_operand",
        )
        val haystacks = artifact.jarEntries.map { it.bytes } + artifact.classArtifacts.map { it.bytes } + nativeBytes
        val retiredFixtureMarker = byteArrayOf(
            0x4A, 0x53, 0x5F, 0x41, 0x4B, 0x45, 0x4E, 0x5F,
            0x4A, 0x4E, 0x49, 0x5F, 0x46, 0x49, 0x58, 0x54,
            0x55, 0x52, 0x45, 0x5F, 0x44, 0x49, 0x41, 0x47,
            0x4E, 0x4F, 0x53, 0x54, 0x49, 0x43, 0x53,
        ).map { it.toByte() }.toByteArray()
        val hit = needles.firstOrNull { needle -> haystacks.any { bytes -> containsAscii(bytes, needle) } }
            ?: if (haystacks.any { bytes -> containsBytes(bytes, retiredFixtureMarker) }) {
                "diagnostic-fixture-signature"
            } else {
                null
            }
        return ReleaseArtifactScanReport.Finding("diagnostics", hit == null, hit ?: "absent")
    }

    private fun scanQpFixedMaterial(
        artifact: BytecodeArtifact,
        nativeBytes: List<ByteArray>,
    ): ReleaseArtifactScanReport.Finding {
        val labels = listOf(
            "javashroud-qp-qp-inner-crypto-v3",
            "javashroud-qp-qp-inner-state-binding-v3",
            "javashroud-qp-vm-build-key-v3",
            "javashroud-qp-vm-dialect-v1",
            "javashroud-qp-qp-inner-crypto-v2",
            "qp-session-integrity-v2",
            "qp-aes-key",
            "qp-aes-iv",
            "javashroud-qp-page-key-v4",
            "javashroud-qp-secret-pack-root-v4",
            "javashroud-qp-secret-commitment-v4",
        )
        val classHay = artifact.classArtifacts.map { it.bytes } + artifact.jarEntries.map { it.bytes }
        val labelHit = labels.firstOrNull { needle -> (classHay + nativeBytes).any { bytes -> containsAscii(bytes, needle) } }
        if (labelHit != null) {
            return ReleaseArtifactScanReport.Finding("qp-fixed-material", false, labelHit)
        }
        val magic = byteArrayOf(0x56, 0x42, 0x43, 0x34).map { it.toByte() }.toByteArray()
        val magicHit = classHay.any { bytes -> containsBytes(bytes, magic) }
        return ReleaseArtifactScanReport.Finding(
            "qp-fixed-material",
            !magicHit,
            if (magicHit) "retired-fixed-material-signature" else "absent",
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

    private fun scanNativeSecrets(nativeBytes: List<ByteArray>): ReleaseArtifactScanReport.Finding {
        if (nativeBytes.isEmpty()) {
            return ReleaseArtifactScanReport.Finding("native-secrets", true, "no-native")
        }
        val needles = listOf(
            "native_secrets",
            "bindingSalt",
            "public-root",
            "QP_SP_S",
            "qp_sp_combine",
            "native0.Loader",
            "Hidden0",
            "javashroud-qp-page-key-v4",
            "Java_com_",
            "Java_io_github_hht0rro",
            "expand 32-byte k",
            ".rustup/toolchains",
            "rustc/src/",
        )
        val hit = needles.firstOrNull { needle -> nativeBytes.any { bytes -> containsAscii(bytes, needle) } }
        return ReleaseArtifactScanReport.Finding("native-secrets", hit == null, hit ?: "absent")
    }

    private fun scanPublicToolSurface(
        artifact: BytecodeArtifact,
        nativeBytes: List<ByteArray>,
    ): List<ReleaseArtifactScanReport.Finding> {
        val javaStar = (nativeBytes + artifact.jarEntries.map { it.bytes }).firstOrNull { bytes ->
            containsAscii(bytes, "Java_com_") || containsAscii(bytes, "Java_io_github_hht0rro")
        }
        val jnicClass = artifact.classArtifacts.firstOrNull { classArtifact ->
            val name = classArtifact.summary.internalName
            name.endsWith("native0/Loader") || name.endsWith("Hidden0") || name.contains("native0/Loader")
        }?.summary?.internalName
        val jnicNative = nativeBytes.firstOrNull { containsAscii(it, "native0.Loader") || containsAscii(it, "Hidden0") }
        val locatorPresent = artifact.jarEntries.any { entry ->
            normalizePath(entry.name).endsWith("native.locator")
        }
        val mzEntries = artifact.jarEntries.filter { entry ->
            isUnsealedMzPath(entry.name) &&
                entry.bytes.size >= 2 &&
                entry.bytes[0] == 'M'.code.toByte() &&
                entry.bytes[1] == 'Z'.code.toByte()
        }
        val unsealedMz = mzEntries.size == 1 && !locatorPresent
        val rustcPath = (nativeBytes + artifact.jarEntries.map { it.bytes }).firstOrNull { bytes ->
            containsAscii(bytes, ".rustup/toolchains") || containsAscii(bytes, "rustc/src/")
        }
        return listOf(
            ReleaseArtifactScanReport.Finding(
                "java-star-export",
                javaStar == null,
                if (javaStar == null) "absent" else "Java_* business export",
            ),
            ReleaseArtifactScanReport.Finding(
                "jnic-loader",
                jnicClass == null && jnicNative == null,
                jnicClass ?: if (jnicNative != null) "native0.Loader" else "absent",
            ),
            ReleaseArtifactScanReport.Finding(
                "unsealed-mz",
                !unsealedMz,
                if (unsealedMz) "single-raw-mz-without-locator" else "absent",
            ),
            ReleaseArtifactScanReport.Finding(
                "rustc-path",
                rustcPath == null,
                if (rustcPath == null) "absent" else "rustc-path-fragment",
            ),
        )
    }

    /** The production bootstrap must not carry a reusable Java token decryptor.
     * Build-time sealing code may still use JCA; scope this check to the
     * embedded runtime helper classes rather than the whole artifact. */
    private fun scanJavaCryptoOracles(
        artifact: BytecodeArtifact,
    ): ReleaseArtifactScanReport.Finding {
        val hit = artifact.classArtifacts.firstOrNull { classArtifact ->
            containsBootstrapCryptoOracle(classArtifact.bytes)
        }?.summary?.internalName
        return ReleaseArtifactScanReport.Finding("java-crypto-oracle", hit == null, hit ?: "absent")
    }

    /**
     * Release-only contract checks for the current artifact generation.  The
     * format number is a build contract, not a runtime magic: requiring a
     * marker in every class/resource would create a new static anchor and would
     * reject small loader-only fixtures.  The existing legacy-magic scan handles
     * retired wire signatures separately.
     */
    private fun scanCurrentFormat(
        artifact: BytecodeArtifact,
        nativeBytes: List<ByteArray>,
        enabledPasses: List<String>,
    ): List<ReleaseArtifactScanReport.Finding> {
        val loaderRequested = enabledPasses.any { it == "jni-microkernel-loader" }
        val nativePresent = !loaderRequested || nativeBytes.isNotEmpty() || artifact.jarEntries.any { entry ->
            val name = entry.name.replace('\\', '/').lowercase(java.util.Locale.ROOT)
            name.endsWith(".dll") || name.endsWith(".so")
        }
        return listOf(
            scanCatalogFormat(
                artifact.jarEntries.map { entry -> entry.name to entry.bytes },
            ),
            ReleaseArtifactScanReport.Finding(
                "native-loader-contract",
                nativePresent,
                if (nativePresent) "native-material-present-or-not-requested" else "native-material-missing",
            ),
        )
    }

    private fun scanJarCurrentFormat(
        jar: JarFile,
        entries: List<java.util.jar.JarEntry>,
        enabledPasses: List<String>,
    ): List<ReleaseArtifactScanReport.Finding> {
        val names = entries.map { it.name }
        val loaderRequested = enabledPasses.any { it == "jni-microkernel-loader" }
        val nativePresent = !loaderRequested || names.any { name ->
            val normalized = name.replace('\\', '/').lowercase(java.util.Locale.ROOT)
            normalized.endsWith(".dll") || normalized.endsWith(".so")
        }
        val indexEntries = entries.filter { isCatalogIndexName(it.name) }
        val currentFormat = when {
            indexEntries.isEmpty() -> {
                val orphan = entries.firstOrNull { isCatalogEntryName(it.name) }
                ReleaseArtifactScanReport.Finding(
                    "current-format",
                    orphan == null,
                    orphan?.let { "catalog-entry-without-index:${it.name}" }
                        ?: "not-applicable:no-q-page-catalog",
                )
            }
            indexEntries.size != 1 -> ReleaseArtifactScanReport.Finding(
                "current-format",
                false,
                "catalog-index-count=${indexEntries.size};expected=1",
            )
            else -> scanJarCatalogFormat(jar, entries, indexEntries.single())
        }
        return listOf(
            currentFormat,
            ReleaseArtifactScanReport.Finding(
                "native-loader-contract",
                nativePresent,
                if (nativePresent) "native-entry-present-or-not-requested" else "native-entry-missing",
            ),
        )
    }

    private fun scanJarCatalogFormat(
        jar: JarFile,
        entries: List<java.util.jar.JarEntry>,
        indexEntry: java.util.jar.JarEntry,
    ): ReleaseArtifactScanReport.Finding {
        var indexBytes: ByteArray? = null
        var directoryBytes: ByteArray? = null
        return try {
            indexBytes = jar.getInputStream(indexEntry).use { it.readBytes() }
            val reference = resolveCatalogDirectoryReference(indexEntry.name, indexBytes)
            if (reference.error != null) {
                return ReleaseArtifactScanReport.Finding("current-format", false, reference.error)
            }
            val directoryEntries = entries.filter { normalizePath(it.name) == reference.normalizedPath }
            if (directoryEntries.size != 1) {
                return ReleaseArtifactScanReport.Finding(
                    "current-format",
                    false,
                    "directory-entry-count=${directoryEntries.size};expected=1",
                )
            }
            val directoryEntry = directoryEntries.single()
            directoryBytes = jar.getInputStream(directoryEntry).use { it.readBytes() }
            scanCatalogFormat(listOf(indexEntry.name to indexBytes, directoryEntry.name to directoryBytes))
        } catch (error: Throwable) {
            ReleaseArtifactScanReport.Finding(
                "current-format",
                false,
                "catalog-read-failed:${error.javaClass.simpleName}",
            )
        } finally {
            indexBytes?.fill(0)
            directoryBytes?.fill(0)
        }
    }

    private fun scanCatalogFormat(
        entries: List<Pair<String, ByteArray>>,
    ): ReleaseArtifactScanReport.Finding {
        val selection = selectCatalogDirectory(entries)
        if (selection.error != null) {
            return ReleaseArtifactScanReport.Finding("current-format", false, selection.error)
        }
        if (selection.entries.isEmpty()) {
            val hasIndex = entries.any { isCatalogIndexName(it.first) }
            val orphan = entries.firstOrNull { isCatalogEntryName(it.first) }
            return ReleaseArtifactScanReport.Finding(
                "current-format",
                !hasIndex && orphan == null,
                when {
                    hasIndex -> "catalog-index-target-missing"
                    orphan != null -> "catalog-entry-without-index:${orphan.first}"
                    else -> "not-applicable:no-q-page-catalog"
                },
            )
        }
        if (selection.entries.size != 1) {
            return ReleaseArtifactScanReport.Finding(
                "current-format",
                false,
                "directory-entry-count=${selection.entries.size};expected=1",
            )
        }
        val (name, bytes) = selection.entries.single()
        var directory: QpArtifactDirectory? = null
        val failure = try {
            directory = QpArtifactDirectory.decode(bytes)
            null
        } catch (error: Throwable) {
            "$name:decode-failed:${error.javaClass.simpleName}"
        } finally {
            directory?.wipe()
        }
        return ReleaseArtifactScanReport.Finding(
            "current-format",
            failure == null,
            failure ?: "directory=$name;parser-accepted-current-format",
        )
    }

    private data class CatalogSelection(
        val entries: List<Pair<String, ByteArray>>,
        val error: String? = null,
    )

    private data class CatalogDirectoryReference(
        val normalizedPath: String? = null,
        val error: String? = null,
    )

    /** Select the directory named by the on-disk catalog index; never treat the page bundle as a directory. */
    private fun selectCatalogDirectory(entries: List<Pair<String, ByteArray>>): CatalogSelection {
        val indexes = entries.filter { isCatalogIndexName(it.first) }
        if (indexes.isEmpty()) return CatalogSelection(emptyList())
        if (indexes.size != 1) {
            return CatalogSelection(emptyList(), "catalog-index-count=${indexes.size};expected=1")
        }
        val index = indexes.single()
        val reference = resolveCatalogDirectoryReference(index.first, index.second)
        if (reference.error != null) return CatalogSelection(emptyList(), reference.error)
        val candidate = checkNotNull(reference.normalizedPath)
        val matches = entries.filter { normalizePath(it.first) == candidate }
        return CatalogSelection(matches)
    }

    private fun resolveCatalogDirectoryReference(
        indexName: String,
        indexBytes: ByteArray,
    ): CatalogDirectoryReference {
        val lines = try {
            String(indexBytes, StandardCharsets.US_ASCII)
                .lineSequence()
                .map(String::trim)
                .filter(String::isNotEmpty)
                .toList()
        } catch (error: Throwable) {
            return CatalogDirectoryReference(error = "catalog-index-decode-failed:${error.javaClass.simpleName}")
        }
        val invalid = lines.firstOrNull { line ->
            line.length > 4096 ||
                line.any { char -> char.code < 0x20 || char == '\\' } ||
                line.startsWith('/') ||
                ".." in line
        }
        if (invalid != null) return CatalogDirectoryReference(error = "catalog-index-path-invalid")
        val directories = lines.filter { '/' !in it }
        if (directories.size != 1) {
            return CatalogDirectoryReference(error = "catalog-index-directory-count=${directories.size};expected=1")
        }
        val indexParent = normalizePath(indexName).substringBeforeLast('/')
        return CatalogDirectoryReference(
            normalizedPath = "$indexParent/catalog/${normalizePath(directories.single())}",
        )
    }

    private fun normalizePath(name: String): String =
        name.replace('\\', '/').lowercase(java.util.Locale.ROOT)

    private fun isCatalogIndexName(name: String): Boolean =
        normalizePath(name).endsWith("/catalog.index")

    private fun isCatalogEntryName(name: String): Boolean {
        val normalized = normalizePath(name)
        return normalized.startsWith("meta-inf/") && "/catalog/" in normalized && !normalized.endsWith('/')
    }

    private data class NativeMarkerHit(val source: String, val marker: String)

    private data class NativeMarkerScan(
        val diagnostic: NativeMarkerHit? = null,
        val core: NativeMarkerHit? = null,
        val scannedSources: Int = 0,
        val error: String? = null,
    )

    /** Scan both caller-provided native bytes and the bytes that will actually be written to the JAR. */
    private fun scanNativeContents(
        artifact: BytecodeArtifact,
        nativeBytes: List<ByteArray>,
    ): List<ReleaseArtifactScanReport.Finding> {
        var diagnostic: NativeMarkerHit? = null
        var core: NativeMarkerHit? = null
        var scanned = 0
        nativeBytes.forEachIndexed { index, bytes ->
            if (bytes.size.toLong() > MAX_NATIVE_SCAN_BYTES) {
                return nativeMarkerFindings(
                    NativeMarkerScan(error = "native-bytes-too-large:$index:${bytes.size}"),
                )
            }
            scanned++
            if (diagnostic == null) {
                NATIVE_DIAGNOSTIC_MARKERS.firstOrNull { containsAscii(bytes, it) }
                    ?.let { diagnostic = NativeMarkerHit("nativeBytes[$index]", it) }
            }
            if (core == null) {
                NATIVE_CORE_MARKERS.firstOrNull { containsAscii(bytes, it) }
                    ?.let { core = NativeMarkerHit("nativeBytes[$index]", it) }
            }
        }
        artifact.jarEntries.filter { isNativeEntryName(it.name) }.forEach { entry ->
            if (entry.bytes.size.toLong() > MAX_NATIVE_SCAN_BYTES) {
                return nativeMarkerFindings(
                    NativeMarkerScan(error = "native-entry-too-large:${entry.name}:${entry.bytes.size}"),
                )
            }
            scanned++
            val normalizedName = normalizePath(entry.name)
            if (diagnostic == null) {
                NATIVE_DIAGNOSTIC_NAME_MARKERS.firstOrNull(normalizedName::contains)
                    ?.let { diagnostic = NativeMarkerHit(entry.name, it) }
            }
            if (core == null) {
                NATIVE_CORE_NAME_MARKERS.firstOrNull(normalizedName::contains)
                    ?.let { core = NativeMarkerHit(entry.name, it) }
            }
            if (diagnostic == null) {
                NATIVE_DIAGNOSTIC_MARKERS.firstOrNull { containsAscii(entry.bytes, it) }
                    ?.let { diagnostic = NativeMarkerHit(entry.name, it) }
            }
            if (core == null) {
                NATIVE_CORE_MARKERS.firstOrNull { containsAscii(entry.bytes, it) }
                    ?.let { core = NativeMarkerHit(entry.name, it) }
            }
        }
        return nativeMarkerFindings(NativeMarkerScan(diagnostic, core, scanned))
    }

    /** Standalone scan reads Native entries from the final JAR instead of trusting their file names. */
    private fun scanJarNativeContents(
        jar: JarFile,
        entries: List<java.util.jar.JarEntry>,
    ): List<ReleaseArtifactScanReport.Finding> {
        var diagnostic: NativeMarkerHit? = null
        var core: NativeMarkerHit? = null
        var scanned = 0
        for (entry in entries.filter { !it.isDirectory && isNativeEntryName(it.name) }) {
            val normalizedName = normalizePath(entry.name)
            if (diagnostic == null) {
                NATIVE_DIAGNOSTIC_NAME_MARKERS.firstOrNull(normalizedName::contains)
                    ?.let { diagnostic = NativeMarkerHit(entry.name, it) }
            }
            if (core == null) {
                NATIVE_CORE_NAME_MARKERS.firstOrNull(normalizedName::contains)
                    ?.let { core = NativeMarkerHit(entry.name, it) }
            }
            if (entry.size > MAX_NATIVE_SCAN_BYTES) {
                return nativeMarkerFindings(
                    NativeMarkerScan(error = "native-entry-too-large:${entry.name}:${entry.size}"),
                )
            }
            val result = try {
                jar.getInputStream(entry).use(::scanNativeStream)
            } catch (error: Throwable) {
                return nativeMarkerFindings(
                    NativeMarkerScan(error = "native-entry-read-failed:${entry.name}:${error.javaClass.simpleName}"),
                )
            }
            if (result.error != null) {
                return nativeMarkerFindings(
                    NativeMarkerScan(error = "${result.error}:${entry.name}"),
                )
            }
            scanned++
            if (diagnostic == null && result.diagnostic != null) {
                diagnostic = NativeMarkerHit(entry.name, result.diagnostic.marker)
            }
            if (core == null && result.core != null) {
                core = NativeMarkerHit(entry.name, result.core.marker)
            }
        }
        return nativeMarkerFindings(NativeMarkerScan(diagnostic, core, scanned))
    }

    private fun scanNativeStream(input: InputStream): NativeMarkerScan {
        val markers = (NATIVE_DIAGNOSTIC_MARKERS + NATIVE_CORE_MARKERS).distinct()
        val overlapLength = (markers.maxOfOrNull(String::length) ?: 1) - 1
        val buffer = ByteArray(NATIVE_SCAN_BUFFER_BYTES)
        var carry = ByteArray(0)
        var total = 0L
        var diagnostic: NativeMarkerHit? = null
        var core: NativeMarkerHit? = null
        try {
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                total += read
                if (total > MAX_NATIVE_SCAN_BYTES) {
                    return NativeMarkerScan(error = "native-entry-exceeds-scan-limit")
                }
                val window = ByteArray(carry.size + read)
                try {
                    carry.copyInto(window)
                    buffer.copyInto(window, carry.size, 0, read)
                    if (diagnostic == null) {
                        NATIVE_DIAGNOSTIC_MARKERS.firstOrNull { containsAscii(window, it) }
                            ?.let { diagnostic = NativeMarkerHit("stream", it) }
                    }
                    if (core == null) {
                        NATIVE_CORE_MARKERS.firstOrNull { containsAscii(window, it) }
                            ?.let { core = NativeMarkerHit("stream", it) }
                    }
                    carry.fill(0)
                    val retained = minOf(overlapLength, window.size)
                    carry = window.copyOfRange(window.size - retained, window.size)
                } finally {
                    window.fill(0)
                }
            }
            return NativeMarkerScan(diagnostic, core, scannedSources = 1)
        } finally {
            buffer.fill(0)
            carry.fill(0)
        }
    }

    private fun nativeMarkerFindings(scan: NativeMarkerScan): List<ReleaseArtifactScanReport.Finding> {
        if (scan.error != null) {
            return listOf(
                ReleaseArtifactScanReport.Finding("native-export-surface", false, scan.error),
                ReleaseArtifactScanReport.Finding(
                    "native-core-image",
                    false,
                    "${scan.error};runtime-memory-absence-unverified",
                ),
            )
        }
        val diagnostic = scan.diagnostic
        val core = scan.core
        val sourceDetail = if (scan.scannedSources == 0) "not-applicable:no-native-content" else "scanned=${scan.scannedSources}"
        return listOf(
            ReleaseArtifactScanReport.Finding(
                "native-export-surface",
                diagnostic == null,
                diagnostic?.let { "marker=${it.marker};source=${it.source}" }
                    ?: "$sourceDetail;diagnostic-surface-absent",
            ),
            ReleaseArtifactScanReport.Finding(
                "native-core-image",
                core == null,
                core?.let { "forbidden-static-marker=${it.marker};source=${it.source};runtime-memory-absence-unverified" }
                    ?: "$sourceDetail;runtime-memory-absence-unverified",
            ),
        )
    }

    private fun isNativeEntryName(name: String): Boolean {
        val normalized = normalizePath(name)
        return normalized.endsWith(".dll") || normalized.endsWith(".so") || normalized.endsWith(".dylib")
    }

    /** Detranspiler `--mode standard` looks for a lone top-level PE, not META-INF sealed natives. */
    private fun isUnsealedMzPath(name: String): Boolean {
        val normalized = normalizePath(name)
        return '/' !in normalized && normalized.endsWith(".dll")
    }

    private fun scanJarPublicToolSurface(
        jar: JarFile,
        entries: List<java.util.jar.JarEntry>,
    ): List<ReleaseArtifactScanReport.Finding> {
        val locatorPresent = entries.any { entry ->
            !entry.isDirectory && normalizePath(entry.name).endsWith("native.locator")
        }
        var javaStar = false
        var jnic = false
        var rustcPath = false
        var mzCount = 0
        for (entry in entries.filter { !it.isDirectory }) {
            val bytes = try {
                jar.getInputStream(entry).use { it.readBytes() }
            } catch (_: Throwable) {
                continue
            }
            try {
                if (isUnsealedMzPath(entry.name) &&
                    bytes.size >= 2 &&
                    bytes[0] == 'M'.code.toByte() &&
                    bytes[1] == 'Z'.code.toByte()
                ) {
                    mzCount++
                }
                if (containsAscii(bytes, "Java_com_") || containsAscii(bytes, "Java_io_github_hht0rro")) {
                    javaStar = true
                }
                if (containsAscii(bytes, "native0.Loader") || containsAscii(bytes, "Hidden0")) {
                    jnic = true
                }
                if (containsAscii(bytes, ".rustup/toolchains") || containsAscii(bytes, "rustc/src/")) {
                    rustcPath = true
                }
            } finally {
                bytes.fill(0)
            }
        }
        val unsealedMz = mzCount == 1 && !locatorPresent
        return listOf(
            ReleaseArtifactScanReport.Finding("java-star-export", !javaStar, if (javaStar) "Java_* business export" else "absent"),
            ReleaseArtifactScanReport.Finding("jnic-loader", !jnic, if (jnic) "native0.Loader" else "absent"),
            ReleaseArtifactScanReport.Finding("unsealed-mz", !unsealedMz, if (unsealedMz) "single-raw-mz-without-locator" else "absent"),
            ReleaseArtifactScanReport.Finding("rustc-path", !rustcPath, if (rustcPath) "rustc-path-fragment" else "absent"),
        )
    }

    private fun scanJarJavaCryptoOracles(
        jar: JarFile,
        entries: List<java.util.jar.JarEntry>,
    ): ReleaseArtifactScanReport.Finding {
        for (entry in entries.filter { !it.isDirectory && it.name.endsWith(".class") }) {
            val bytes = try {
                jar.getInputStream(entry).use { it.readBytes() }
            } catch (error: Throwable) {
                return ReleaseArtifactScanReport.Finding(
                    "java-crypto-oracle",
                    false,
                    "read-failed:${entry.name}:${error.javaClass.simpleName}",
                )
            }
            try {
                if (containsBootstrapCryptoOracle(bytes)) {
                    return ReleaseArtifactScanReport.Finding(
                        "java-crypto-oracle",
                        false,
                        entry.name,
                    )
                }
            } finally {
                bytes.fill(0)
            }
        }
        return ReleaseArtifactScanReport.Finding("java-crypto-oracle", true, "absent")
    }

    private fun containsBootstrapCryptoOracle(bytes: ByteArray): Boolean =
        containsAscii(bytes, "AES/CBC/PKCS5Padding") &&
            containsAscii(bytes, "SecretKeySpec") &&
            containsAscii(bytes, "Invalid encrypted bootstrap payload")

    private fun scanStrictNativePlatformMatrix(
        artifact: BytecodeArtifact,
        enabledPasses: List<String>,
        profile: HardenedProtectionProfile,
        requiredNativePlatforms: Set<String>,
    ): ReleaseArtifactScanReport.Finding {
        if (enabledPasses.none { it == "jni-microkernel-loader" }) {
            return ReleaseArtifactScanReport.Finding("native-platform-matrix", true, "not-required")
        }
        return scanNativePlatformMatrix(
            entries = artifact.jarEntries.map { entry -> entry.name to entry.bytes },
            profile = profile,
            requiredNativePlatforms = requiredNativePlatforms,
        )
    }

    private fun scanJarNativePlatformMatrix(
        jar: JarFile,
        entries: List<java.util.jar.JarEntry>,
        enabledPasses: List<String>,
        profile: HardenedProtectionProfile,
        requiredNativePlatforms: Set<String>,
    ): ReleaseArtifactScanReport.Finding {
        if (enabledPasses.none { it == "jni-microkernel-loader" }) {
            return ReleaseArtifactScanReport.Finding("native-platform-matrix", true, "not-required")
        }
        val nativeEntries = entries.filter { !it.isDirectory && isNativeEntryName(it.name) }
        val snapshots = ArrayList<Pair<String, ByteArray>>(nativeEntries.size)
        try {
            for (entry in nativeEntries) {
                val header = ByteArray(4)
                var offset = 0
                jar.getInputStream(entry).use { input ->
                    while (offset < header.size) {
                        val read = input.read(header, offset, header.size - offset)
                        if (read < 0) break
                        if (read == 0) continue
                        offset += read
                    }
                }
                snapshots += entry.name to header
            }
            return scanNativePlatformMatrix(snapshots, profile, requiredNativePlatforms)
        } catch (error: Throwable) {
            return ReleaseArtifactScanReport.Finding(
                "native-platform-matrix",
                false,
                "native-header-read-failed:${error.javaClass.simpleName}",
            )
        } finally {
            snapshots.forEach { (_, bytes) -> bytes.fill(0) }
        }
    }

    private fun scanNativePlatformMatrix(
        entries: List<Pair<String, ByteArray>>,
        profile: HardenedProtectionProfile,
        requiredNativePlatforms: Set<String>,
    ): ReleaseArtifactScanReport.Finding {
        val nativeEntries = entries.filter { isNativeEntryName(it.first) }
        val unsupported = nativeEntries.firstOrNull { entry ->
            val name = normalizePath(entry.first)
            name.endsWith(".dylib") || name.contains("macos") || name.contains("darwin")
        }
        val windows = nativeEntries.any { entry ->
            normalizePath(entry.first).endsWith(".dll") &&
                entry.second.size >= 2 &&
                entry.second[0] == 'M'.code.toByte() &&
                entry.second[1] == 'Z'.code.toByte()
        }
        val linux = nativeEntries.any { entry ->
            normalizePath(entry.first).endsWith(".so") &&
                entry.second.size >= 4 &&
                entry.second[0] == 0x7F.toByte() &&
                entry.second[1] == 'E'.code.toByte() &&
                entry.second[2] == 'L'.code.toByte() &&
                entry.second[3] == 'F'.code.toByte()
        }
        val expected = requiredNativePlatforms.map(String::trim).filter(String::isNotEmpty).toSet()
        val unknownExpected = expected - setOf("windows-x64", "linux-x64")
        val missing = buildList {
            if ("windows-x64" in expected && !windows) add("windows-x64")
            if ("linux-x64" in expected && !linux) add("linux-x64")
        }
        val hasSupported = windows || linux
        val passed = unsupported == null && unknownExpected.isEmpty() && missing.isEmpty() && hasSupported
        return ReleaseArtifactScanReport.Finding(
            "native-platform-matrix",
            passed,
            when {
                unsupported != null -> "unsupported=${unsupported.first}"
                unknownExpected.isNotEmpty() -> "unknown-required=${unknownExpected.joinToString(",")}"
                missing.isNotEmpty() -> "missing=${missing.joinToString(",")}" + if (windows || linux) ";observed=" + observedPlatforms(windows, linux) else ""
                windows && linux -> "windows+linux"
                windows -> "windows-only"
                linux -> "linux-only"
                else -> "native-entry-missing"
            },
        )
    }

    private fun observedPlatforms(windows: Boolean, linux: Boolean): String = when {
        windows && linux -> "windows+linux"
        windows -> "windows"
        linux -> "linux"
        else -> "none"
    }

    private fun scanDualNativePlatforms(
        artifact: BytecodeArtifact,
        enabledPasses: List<String>,
    ): ReleaseArtifactScanReport.Finding {
        if (enabledPasses.none { it == "jni-microkernel-loader" }) {
            return ReleaseArtifactScanReport.Finding("native-dual-platform", true, "not-required")
        }
        var windows = false
        var linux = false
        artifact.jarEntries.forEach { entry ->
            val name = entry.name.replace('\\', '/').lowercase()
            if (name.contains("meta-inf/jsrt")) return@forEach
            if (name.endsWith(".dll") && entry.bytes.size >= 2 &&
                entry.bytes[0] == 'M'.code.toByte() && entry.bytes[1] == 'Z'.code.toByte()
            ) {
                windows = true
            }
            if (name.endsWith(".so") && entry.bytes.size >= 4 &&
                entry.bytes[0] == 0x7F.toByte() && entry.bytes[1] == 'E'.code.toByte() &&
                entry.bytes[2] == 'L'.code.toByte() && entry.bytes[3] == 'F'.code.toByte()
            ) {
                linux = true
            }
        }
        val passed = windows || linux
        val detail = when {
            windows && linux -> "windows+linux"
            windows -> "host-only-windows"
            linux -> "host-only-linux"
            else -> "windows=false linux=false"
        }
        return ReleaseArtifactScanReport.Finding("native-dual-platform", passed, detail)
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

    private fun startsWithBytes(bytes: ByteArray, target: ByteArray): Boolean =
        target.isNotEmpty() && bytes.size >= target.size && target.indices.all { index -> bytes[index] == target[index] }

    private fun decodeHex(value: String): ByteArray {
        require(value.length % 2 == 0) { "hex signature length must be even" }
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
