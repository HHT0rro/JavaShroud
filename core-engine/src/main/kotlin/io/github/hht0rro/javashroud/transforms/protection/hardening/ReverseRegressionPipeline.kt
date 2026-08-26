package io.github.hht0rro.javashroud.transforms.protection.hardening

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.R1ArtifactDirectory
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import org.objectweb.asm.ClassReader
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode

/**
 * Maps [ReleaseArtifactScan] findings onto the reverse-regression stages in the
 * offline hardening plan. Does not copy external reverse-work tools into the tree.
 */
internal object ReverseRegressionPipeline {
    val STAGE_NAMES: List<String> = listOf(
        "build-protected-sample",
        "input-output-sha256",
        "page-extraction",
        "vm-page-regrouping",
        "vm-parser",
        "string-literalization-probe",
        "itk-token-probe",
        "exception-clone-detector",
        "cfg-fixed-template-detector",
        "native-catalog-cleanup-probe",
        "semantic-equivalence",
        "generate-stage-manifest",
    )

    private val STAGE_CHECKS: Map<String, List<String>> = mapOf(
        "page-extraction" to listOf("aken-evaluator-direct-recovery", "runtime-binding-nonzero", "runtime-binding-match"),
        "vm-page-regrouping" to listOf("native-secrets", "vbc4-fixed-material"),
        "vm-parser" to listOf("aken-evaluator-direct-recovery", "native-secrets", "vbc4-fixed-material"),
        "string-literalization-probe" to listOf("string-key-triple", "string-static-triple"),
        "itk-token-probe" to listOf("itk-aad-used", "itk-key-lane-absent", "indy-target-opacity"),
        "exception-clone-detector" to listOf("exception-body-clone"),
        "cfg-fixed-template-detector" to listOf("cfg-fixed-template"),
        "native-catalog-cleanup-probe" to listOf(
            "rename-map",
            "legacy-path",
            "legacy-magic",
            "native-secrets",
            "diagnostics",
            "fixed-generated-name",
            "debug-map-provenance",
        ),
        "semantic-equivalence" to listOf("jdk-blocking-matrix", "perf-budget"),
    )

    data class StageRecord(
        val name: String,
        val passed: Boolean,
        val checks: List<ReleaseArtifactScanReport.Finding>,
        val failClosed: String,
    )

    data class Manifest(
        val protocolVersion: String,
        val inputSha256: String,
        val outputSha256: String,
        val enabledPasses: List<String>,
        val targetTriple: String,
        val nativeSha256: String,
        val abiDigest: String,
        val specializationDigest: String,
        val methodCount: Int,
        val pageCount: Int,
        val instructionCount: Int,
        val constantCount: Int,
        val jdk: String,
        val toolVersion: String,
        val cwd: String,
        val envSummary: String,
        val stages: List<StageRecord>,
        val passed: Boolean,
    ) {
        fun toText(): String {
            val builder = StringBuilder()
            builder.append("protocol=").append(protocolVersion).append('\n')
            builder.append("inputSha256=").append(inputSha256).append('\n')
            builder.append("outputSha256=").append(outputSha256).append('\n')
            builder.append("enabledPasses=").append(enabledPasses.joinToString(",")).append('\n')
            builder.append("targetTriple=").append(targetTriple).append('\n')
            builder.append("nativeSha256=").append(nativeSha256).append('\n')
            builder.append("abiDigest=").append(abiDigest).append('\n')
            builder.append("specializationDigest=").append(specializationDigest).append('\n')
            builder.append("methodCount=").append(methodCount).append('\n')
            builder.append("pageCount=").append(pageCount).append('\n')
            builder.append("instructionCount=").append(instructionCount).append('\n')
            builder.append("constantCount=").append(constantCount).append('\n')
            builder.append("jdk=").append(jdk).append('\n')
            builder.append("toolVersion=").append(toolVersion).append('\n')
            builder.append("cwd=").append(cwd).append('\n')
            builder.append("env=").append(envSummary).append('\n')
            builder.append("passed=").append(passed).append('\n')
            stages.forEach { stage ->
                builder.append('\n').append("[stage ").append(stage.name).append("]\n")
                builder.append("status=").append(if (stage.passed) "PASS" else "FAIL").append('\n')
                builder.append("checks=").append(stage.checks.joinToString(",") { it.check }).append('\n')
                builder.append("detail=").append(stage.checks.joinToString("; ") { it.check + "=" + it.detail }).append('\n')
                builder.append("failClosed=").append(stage.failClosed).append('\n')
            }
            return builder.toString()
        }
    }

    fun run(
        outputJarPath: Path,
        artifact: BytecodeArtifact,
        profile: HardenedProtectionProfile,
        enabledPasses: List<String>,
        inputJarPath: Path? = null,
        nativeBytes: List<ByteArray> = emptyList(),
        inputJarBytes: Long = -1L,
    ): Pair<Manifest, Path> {
        val report = ReleaseArtifactScan.scan(
            outputJarPath,
            artifact,
            profile,
            enabledPasses,
            nativeBytes,
            inputJarBytes,
        )
        val binding = readBinding(artifact)
        val counts = countArtifact(artifact)
        val findingsByCheck = report.findings.groupBy { it.check }
        val stages = STAGE_NAMES.map { name -> stageRecord(name, findingsByCheck, report) }
        val manifest = Manifest(
            protocolVersion = report.protocolVersion,
            inputSha256 = inputJarPath?.let { hex(SignedDebugMap.sha256(it)) } ?: "none",
            outputSha256 = report.artifactDigestHex,
            enabledPasses = enabledPasses,
            targetTriple = binding.targetTriple,
            nativeSha256 = binding.nativeSha256,
            abiDigest = binding.abiDigest,
            specializationDigest = binding.specializationDigest,
            methodCount = counts.methods,
            pageCount = binding.pageCount,
            instructionCount = counts.instructions,
            constantCount = counts.constants,
            jdk = System.getProperty("java.specification.version") ?: "unknown",
            toolVersion = ProtectionFormat.CURRENT,
            cwd = Path.of("").toAbsolutePath().toString(),
            envSummary = envSummary(),
            stages = stages,
            passed = stages.all { it.passed },
        )
        val path = outputJarPath.resolveSibling(
            outputJarPath.fileName.toString().removeSuffix(".jar") + ".stage-manifest.txt",
        )
        Files.write(path, manifest.toText().toByteArray(StandardCharsets.UTF_8))
        return manifest to path
    }

    private fun stageRecord(
        name: String,
        findingsByCheck: Map<String, List<ReleaseArtifactScanReport.Finding>>,
        report: ReleaseArtifactScanReport,
    ): StageRecord {
        val checks = STAGE_CHECKS[name].orEmpty().flatMap { check -> findingsByCheck[check].orEmpty() }
        val passed = when (name) {
            "build-protected-sample" -> report.artifactDigestHex.length == 64
            "input-output-sha256" -> report.artifactDigestHex.length == 64
            "generate-stage-manifest" -> true
            else -> checks.isEmpty() || checks.all { it.passed }
        }
        val failClosed = checks.filter { !it.passed }.joinToString(";") { it.check + ":" + it.detail }
            .ifEmpty { "none" }
        return StageRecord(name, passed, checks, failClosed)
    }

    private data class BindingView(
        val targetTriple: String,
        val nativeSha256: String,
        val abiDigest: String,
        val specializationDigest: String,
        val pageCount: Int,
    )

    private fun readBinding(artifact: BytecodeArtifact): BindingView {
        val catalog = artifact.jarEntries.firstOrNull { it.name == "META-INF/jsrt/catalog/directory.jsr1" }
            ?: return BindingView("absent", "absent", "absent", "absent", 0)
        return try {
            val directory = R1ArtifactDirectory.decode(catalog.bytes)
            try {
                val runtime = directory.runtimeBindingDigest
                try {
                    BindingView(
                        targetTriple = runtime.targetTriple,
                        nativeSha256 = hex(runtime.nativeSha256),
                        abiDigest = hex(runtime.abiDigest),
                        specializationDigest = hex(runtime.specializationDigest),
                        pageCount = directory.size,
                    )
                } finally {
                    runtime.wipe()
                }
            } finally {
                directory.wipe()
            }
        } catch (_: Throwable) {
            BindingView("decode-failed", "decode-failed", "decode-failed", "decode-failed", 0)
        }
    }

    private data class Counts(val methods: Int, val instructions: Int, val constants: Int)

    private fun countArtifact(artifact: BytecodeArtifact): Counts {
        var methods = 0
        var instructions = 0
        var constants = 0
        artifact.classArtifacts.forEach { classArtifact ->
            val node = ClassNode()
            ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_DEBUG)
            methods += node.methods.orEmpty().size
            node.methods.orEmpty().forEach { method ->
                method.instructions?.forEach { insn ->
                    if (insn.opcode >= 0) instructions++
                    if (insn is LdcInsnNode) constants++
                }
            }
        }
        return Counts(methods, instructions, constants)
    }

    private fun envSummary(): String {
        val locale = java.util.Locale.getDefault().toLanguageTag()
        val os = System.getProperty("os.name") ?: "unknown"
        val arch = System.getProperty("os.arch") ?: "unknown"
        return "os=$os;arch=$arch;locale=$locale"
    }

    private fun hex(bytes: ByteArray): String =
        bytes.joinToString("") { b -> "%02x".format(b) }
}
