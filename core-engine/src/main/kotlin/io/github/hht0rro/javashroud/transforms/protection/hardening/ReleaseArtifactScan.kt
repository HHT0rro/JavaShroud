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
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LdcInsnNode

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
        findings += scanDiagnostics(artifact, nativeBytes, profile)
        findings += scanNativeSecrets(nativeBytes, profile)
        val failed = findings.any { !it.passed }
        val passed = when (profile) {
            HardenedProtectionProfile.RELEASE_HARDENED -> !failed
            HardenedProtectionProfile.ANALYSIS_ONLY -> findings.filter { it.check != "diagnostics" }.all { it.passed }
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
