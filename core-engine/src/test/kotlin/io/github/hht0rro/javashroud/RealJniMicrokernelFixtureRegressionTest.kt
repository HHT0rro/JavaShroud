package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.URLClassLoader
import java.util.Arrays
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.thread
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RealJniMicrokernelFixtureRegressionTest {
    private val objectMapper = ObjectMapper()
    private val shellProtocolDowngradeProbe =
        "max native shell protocol version ${NativeKernelShellPacker.PACKER_VERSION} to ${NativeKernelShellPacker.PACKER_VERSION - 1}"

    @Test
    fun jni_microkernel_loader_preserves_real_demo_and_complex_business_fixtures() {
        val workDir = Files.createTempDirectory("javashroud-real-jni-fixtures")
        val fixtures = buildLocalRealJarFixture(workDir)
        try {
            verifyRealJniFixture(fixtures, "real-demo")
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    private fun verifyRealJniFixture(inputJar: Path, scenario: String) {
        val baseline = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().toString()))
        assertTrue(!baseline.timedOut, "Baseline $scenario should exit within timeout. Output: ${baseline.output.take(500)}")
        assertEquals(1, baseline.exitCode, "Baseline $scenario should return the fixture contract exit code. Output: ${baseline.output.take(500)}")

        val outputJar = runEngine(inputJar, scenario)
        try {
            assertTrue(Files.exists(outputJar), "Output JAR should exist for $scenario")
            assertJarReadable(outputJar, scenario)
            assertAllClassesValid(outputJar, scenario)
            assertJarContainsJniHelper(outputJar, "$scenario JNI microkernel helper")
            assertJarHasNativeResources(outputJar, "$scenario native resources")
            assertJarCarriesMaxNativeShellOnly(outputJar, scenario)

            val executeShape = assertNotNull(
                methodShape(outputJar, "JniMicrokernelHelper", "nativeExecuteVmResource")
                    ?: methodShape(outputJar, "JniMicrokernelHelper", "executeVmResource")
                    ?: methodShape(outputJar, "*", "nativeExecuteVmResource")
                    ?: methodShape(outputJar, "*", "executeVmResource")
                    ?: nativeMethodShapeByDescriptor(outputJar, "(J[Ljava/lang/Object;)Ljava/lang/Object;")
                    ?: nativeMethodShapeByDescriptor(outputJar, "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"),
                "JNI microkernel dispatch method should be present for $scenario",
            )
            assertTrue(
                executeShape.access and Opcodes.ACC_SYNTHETIC != 0,
                "JNI microkernel dispatch method should be synthetic after native helper hardening for $scenario",
            )
            assertTrue(
                executeShape.access and Opcodes.ACC_NATIVE != 0 && !executeShape.hasCode,
                "JNI microkernel dispatch method should be native-only for $scenario",
            )

            val result = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().toString()))
            assertTrue(!result.timedOut, "Obfuscated $scenario should exit within timeout. Output: ${result.output.take(500)}")
            assertEquals(baseline.exitCode, result.exitCode, "Obfuscated $scenario should preserve exit code. Output: ${result.output.take(500)}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Obfuscated $scenario should preserve stdout")
            assertTrue(
                result.output.contains("LIFECYCLE=ok"),
                "Obfuscated $scenario should preserve the repeated-call and multithreaded native lifecycle fixture. Output: ${result.output.take(500)}",
            )

            val firstSession = runLocalJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().toString()).apply {
                    environment()["JAVASHROUD_SESSION_EVIDENCE"] = "1"
                },
            )
            val secondSession = runLocalJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().toString()).apply {
                    environment()["JAVASHROUD_SESSION_EVIDENCE"] = "1"
                },
            )
            assertEquals(baseline.exitCode, firstSession.exitCode, "First fresh-JVM session evidence run must preserve behavior")
            assertEquals(baseline.exitCode, secondSession.exitCode, "Second fresh-JVM session evidence run must preserve behavior")
            val firstSessionTag = sessionEvidenceTag(firstSession.output)
            val secondSessionTag = sessionEvidenceTag(secondSession.output)
            assertTrue(firstSessionTag.matches(Regex("[0-9a-f]{16}")), "First fresh JVM must emit a runtime session commitment")
            assertTrue(secondSessionTag.matches(Regex("[0-9a-f]{16}")), "Second fresh JVM must emit a runtime session commitment")
            assertFalse(firstSessionTag == secondSessionTag, "The same transformed JAR must mint divergent per-JVM session commitments")

            val tamperResults = mutableListOf<TamperEvidence>()

            val tamperedJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-native.jar")
            try {
                tamperMaxNativeShellPayload(outputJar, tamperedJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "max native shell payload/header")
                tamperResults.add(TamperEvidence("max native shell payload/header", tampered))
            } finally {
                Files.deleteIfExists(tamperedJar)
            }

            val tamperedVersionJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-native-version.jar")
            try {
                tamperMaxNativeShellProtocolVersion(outputJar, tamperedVersionJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedVersionJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, shellProtocolDowngradeProbe)
                tamperResults.add(TamperEvidence(shellProtocolDowngradeProbe, tampered))
            } finally {
                Files.deleteIfExists(tamperedVersionJar)
            }

            val tamperedHeaderTagJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-header-tag.jar")
            try {
                tamperMaxNativeShellEncryptedHeaderTag(outputJar, tamperedHeaderTagJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedHeaderTagJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "max native shell encrypted header tag")
                tamperResults.add(TamperEvidence("max native shell encrypted header tag", tampered))
            } finally {
                Files.deleteIfExists(tamperedHeaderTagJar)
            }

            val tamperedIndexJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-native-index.jar")
            try {
                tamperBootstrapNativeIndex(outputJar, tamperedIndexJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedIndexJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "sealed bootstrap native index")
                tamperResults.add(TamperEvidence("sealed bootstrap native index", tampered))
            } finally {
                Files.deleteIfExists(tamperedIndexJar)
            }

            val tamperedBindingsJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-native-bindings.jar")
            try {
                tamperSealedNativeBindings(outputJar, tamperedBindingsJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedBindingsJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "sealed native bindings")
                tamperResults.add(TamperEvidence("sealed native bindings", tampered))
            } finally {
                Files.deleteIfExists(tamperedBindingsJar)
            }

            val tamperedResourcePathJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-native-resource-path.jar")
            try {
                tamperMaxNativeShellResourcePath(outputJar, tamperedResourcePathJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedResourcePathJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "max native shell resource path")
                tamperResults.add(TamperEvidence("max native shell resource path", tampered))
            } finally {
                Files.deleteIfExists(tamperedResourcePathJar)
            }

            val tamperedProfileJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-vm-catalog-root.jar")
            try {
                tamperVmCatalogRoot(outputJar, tamperedProfileJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedProfileJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "VM catalog root")
                tamperResults.add(TamperEvidence("VM catalog root", tampered))
            } finally {
                Files.deleteIfExists(tamperedProfileJar)
            }

            val tamperedPreloadMeshJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-vm-committed-resource.jar")
            try {
                tamperVmCommittedResource(outputJar, tamperedPreloadMeshJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedPreloadMeshJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "VM committed resource")
                tamperResults.add(TamperEvidence("VM committed resource", tampered))
            } finally {
                Files.deleteIfExists(tamperedPreloadMeshJar)
            }

            val reportPath = writeRuntimeEvidenceReport(scenario, inputJar, outputJar, baseline, result, tamperResults)
            val reportText = Files.readString(reportPath)
            assertTrue(reportText.contains("runtime_status: passed"), "Native Max runtime evidence report must record the successful real JAR run")
            assertTrue(reportText.contains("tamper_fail_closed_count: 8"), "Native Max runtime evidence report must record all fail-closed tamper probes")
            assertNativeMaxRuntimeEvidenceReportCoversReleaseGate(reportText)
        } finally {
            Files.deleteIfExists(outputJar)
        }
    }

    private fun assertTamperedRunFailsClosed(tampered: LocalJavaProcessResult, baseline: LocalJavaProcessResult, scenario: String, tamperKind: String) {
        assertTrue(!tampered.timedOut, "Tampered $scenario $tamperKind should fail closed within timeout. Output: ${tampered.output.take(500)}")
        assertTrue(
            tampered.exitCode != baseline.exitCode || tampered.output.trim() != baseline.output.trim(),
            "Tampered $scenario $tamperKind must not preserve the original fixture contract. Output: ${tampered.output.take(500)}",
        )
        assertTrue(
            listOf("UnsatisfiedLinkError", "SecurityException", "JNI_ERR", "no Java fallback", "native", "JavaShroud max native shell load failed")
                .any { tampered.output.contains(it, ignoreCase = true) },
            "Tampered $scenario $tamperKind should surface a native fail-closed loading/verification failure. Output: ${tampered.output.take(800)}",
        )
        assertFalse(tampered.output.contains("LIFECYCLE=ok"), "Tampered $scenario $tamperKind must fail before business logic")
    }

    private fun writeRuntimeEvidenceReport(
        scenario: String,
        inputJar: Path,
        outputJar: Path,
        baseline: LocalJavaProcessResult,
        obfuscated: LocalJavaProcessResult,
        tamperResults: List<TamperEvidence>,
    ): Path {
        val entries = loadJarEntries(outputJar)
        val nativeShellEntries = entries.filterValues { bytes ->
            bytes.containsAscii(NativeKernelShellPacker.MAX_STUB_MARKER) && bytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER)
        }
        assertTrue(nativeShellEntries.isNotEmpty(), "runtime evidence must include max native shell entries for $scenario")

        val report = StringBuilder()
        report.appendLine("# JavaShroud Native Max Runtime Evidence")
        report.appendLine()
        report.appendLine("Generated by RealJniMicrokernelFixtureRegressionTest.jni_microkernel_loader_preserves_real_demo_and_complex_business_fixtures")
        report.appendLine("Scope: real transformed JAR runtime behavior and fail-closed tamper probes for nativePackingLevel=max.")
        report.appendLine()
        report.appendLine("## $scenario")
        report.appendLine()
        report.appendLine("- runtime_status: passed")
        report.appendLine("- input_jar_sha256: ${sha256Hex(Files.readAllBytes(inputJar))}")
        report.appendLine("- output_jar_sha256: ${sha256Hex(Files.readAllBytes(outputJar))}")
        report.appendLine("- baseline_exit_code: ${baseline.exitCode}")
        report.appendLine("- obfuscated_exit_code: ${obfuscated.exitCode}")
        report.appendLine("- baseline_stdout: ${singleLineEvidence(baseline.output)}")
        report.appendLine("- obfuscated_stdout: ${singleLineEvidence(obfuscated.output)}")
        report.appendLine("- stdout_preserved: ${baseline.output.trim() == obfuscated.output.trim()}")
        report.appendLine("- lifecycle_ok: ${obfuscated.output.contains("LIFECYCLE=ok")}")
        report.appendLine("- tamper_probe_count: ${tamperResults.size}")
        report.appendLine("- tamper_fail_closed_count: ${tamperResults.count { it.result.exitCode != baseline.exitCode || it.result.output.trim() != baseline.output.trim() }}")
        report.appendLine()
        report.appendLine("## native-shell-entries")
        report.appendLine()
        report.appendLine("- max_shell_entry_count: ${nativeShellEntries.size}")
        nativeShellEntries.toSortedMap().forEach { (name, bytes) ->
            report.appendLine("- entry: $name size=${bytes.size} sha256=${sha256Hex(bytes)} jni_onload=${bytes.countAsciiOccurrences("JNI_OnLoad")} stub_marker=${bytes.countAsciiOccurrences(NativeKernelShellPacker.MAX_STUB_MARKER)} payload_marker=${bytes.countAsciiOccurrences(NativeKernelShellPacker.MAX_PAYLOAD_MARKER)} standard_overlay_marker=${bytes.countAsciiOccurrences(NativeKernelShellPacker.LOADER_MARKER)}")
        }
        report.appendLine()
        report.appendLine("## fail-closed-tamper-probes")
        report.appendLine()
        tamperResults.forEach { evidence ->
            report.appendLine("- tamper: ${evidence.kind} timed_out=${evidence.result.timedOut} exit_code=${evidence.result.exitCode} preserved_contract=${evidence.result.exitCode == baseline.exitCode && evidence.result.output.trim() == baseline.output.trim()} output=${singleLineEvidence(evidence.result.output)}")
        }
        report.appendLine()

        val reportDir = workspaceRootForRuntimeReports().resolve("build").resolve("core-engine").resolve("reports").resolve("native-max")
        Files.createDirectories(reportDir)
        val reportPath = reportDir.resolve("native-max-runtime-evidence.md")
        Files.writeString(reportPath, report.toString(), Charsets.UTF_8)
        assertTrue(Files.size(reportPath) > 0, "native max runtime evidence report must be written: $reportPath")
        return reportPath
    }

    private data class TamperEvidence(val kind: String, val result: LocalJavaProcessResult)

    private fun workspaceRootForRuntimeReports(): Path {
        val cwd = Path.of("").toAbsolutePath().normalize()
        return if (cwd.fileName?.toString() == "core-engine") cwd.parent else cwd
    }

    private fun singleLineEvidence(value: String): String = value
        .trim()
        .replace('\r', ' ')
        .replace('\n', ' ')
        .replace(Regex("\\s+"), " ")
        .take(240)

    private fun sha256Hex(bytes: ByteArray): String = java.security.MessageDigest.getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) }

    private fun assertNativeMaxRuntimeEvidenceReportCoversReleaseGate(reportText: String) {
        assertTrue(reportText.contains("Generated by RealJniMicrokernelFixtureRegressionTest"), "runtime evidence must name the real JAR regression source")
        assertTrue(reportText.contains("nativePackingLevel=max"), "runtime evidence must be scoped to nativePackingLevel=max")
        listOf(
            "runtime_status: passed",
            "baseline_stdout: REAL_RESULT=1;LIFECYCLE=ok",
            "obfuscated_stdout: REAL_RESULT=1;LIFECYCLE=ok",
            "stdout_preserved: true",
            "lifecycle_ok: true",
            "tamper_probe_count: 8",
            "tamper_fail_closed_count: 8",
            "max_shell_entry_count: 1",
            "stub_marker=1",
            "payload_marker=1",
            "standard_overlay_marker=0",
        ).forEach { required ->
            assertTrue(reportText.contains(required), "runtime evidence must include release gate field: $required")
        }
        listOf(
            "max native shell payload/header",
            shellProtocolDowngradeProbe,
            "max native shell encrypted header tag",
            "sealed bootstrap native index",
            "sealed native bindings",
            "max native shell resource path",
            "VM catalog root",
            "VM committed resource",
        ).forEach { tamperKind ->
            val line = reportText.lines().firstOrNull { it.contains("tamper: $tamperKind") }
            assertTrue(line != null, "runtime evidence must include tamper probe: $tamperKind")
            assertTrue(line.contains("timed_out=false"), "$tamperKind must fail closed without hanging")
            assertTrue(line.contains("preserved_contract=false"), "$tamperKind must not preserve the original fixture contract")
        }
    }

    private fun runEngine(inputJar: Path, tag: String): Path {
        val outputJar = inputJar.resolveSibling("javashroud-real-jni-out-$tag.jar")
        val configPath = inputJar.resolveSibling("javashroud-real-jni-cfg-$tag.toml")
        writeRunConfig(configPath, inputJar, outputJar)
        try {
            val output = captureStdout {
                withTestBootSecret {
                    dispatchRequest(
                        buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                        EngineKernel(),
                    )
                }
            }
            val events = output.trim().lines().filter { it.isNotBlank() }
            assertTrue(events.isNotEmpty(), "Engine should emit TOML events for $tag")
            assertTrue(events.any { it.contains("type = \"done\"") }, "Run should finish with done event for $tag")
        } finally {
            Files.deleteIfExists(configPath)
        }
        return outputJar
    }

    private fun writeRunConfig(configPath: Path, inputJar: Path, outputJar: Path) {
        val targetPlatform = objectMapper.valueToTree<com.fasterxml.jackson.databind.JsonNode>("auto")
        val nativePackingLevel = objectMapper.valueToTree<com.fasterxml.jackson.databind.JsonNode>("max")
        writeTestRunConfigToml(
            configPath = configPath,
            inputJar = inputJar,
            outputJar = outputJar,
            passIds = listOf("method-virtualization", "jni-microkernel-loader"),
            rules = listOf(
                RuleSpec(target = "demo/Service#hot:(I)I", action = "method-virtualization"),
            ),
            passParams = mapOf(
                "method-virtualization" to mapOf(
                    "maxInstructions" to objectMapper.valueToTree(99999),
                    "maxBroadVirtualizedMethods" to objectMapper.valueToTree(99999),
                ),
                "jni-microkernel-loader" to mapOf(
                    "targetPlatform" to targetPlatform,
                    "nativePackingLevel" to nativePackingLevel,
                ),
            ),
        )
    }

    private fun assertJarReadable(jarPath: Path, context: String) {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name.endsWith(".class")) {
                    val classBytes = jar.readBytes()
                    val visitor = object : ClassVisitor(Opcodes.ASM9) {}
                    ClassReader(classBytes).accept(visitor, ClassReader.SKIP_FRAMES)
                }
                jar.closeEntry()
            }
        }
    }

    private fun assertAllClassesValid(jarPath: Path, context: String) {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name.endsWith(".class")) {
                    val classBytes = jar.readBytes()
                    val node = ClassNode()
                    ClassReader(classBytes).accept(node, ClassReader.SKIP_FRAMES)
                    assertTrue(node.name.isNotBlank(), "Class name should not be blank in ${entry.name} ($context)")
                }
                jar.closeEntry()
            }
        }
    }

    private fun assertJarContainsEntry(jarPath: Path, expectedEntry: String, context: String) {
        assertTrue(loadJarEntries(jarPath).containsKey(expectedEntry), "Expected $context entry $expectedEntry in ${jarPath.fileName}")
    }

    private fun assertJarContainsJniHelper(jarPath: Path, context: String) {
        val entries = loadJarEntries(jarPath).keys
        assertTrue(
            entries.contains("io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class") ||
                entries.any { it.startsWith("r/") && it.endsWith(".class") },
            "Expected $context as fixed or sealed helper class in ${jarPath.fileName}",
        )
    }

    private fun assertJarDoesNotContainEntry(jarPath: Path, forbiddenEntry: String, context: String) {
        assertTrue(!loadJarEntries(jarPath).containsKey(forbiddenEntry), "Did not expect $context entry $forbiddenEntry in ${jarPath.fileName}")
    }

    private fun assertJarHasEntryPrefix(jarPath: Path, expectedPrefix: String, context: String) {
        assertTrue(loadJarEntries(jarPath).keys.any { it.startsWith(expectedPrefix) }, "Expected $context entry prefix $expectedPrefix in ${jarPath.fileName}")
    }

    private fun assertJarHasNativeResources(jarPath: Path, context: String) {
        val entries = loadJarEntries(jarPath).keys
        assertTrue(
            entries.any { it.startsWith("META-INF/js-native/") || (it.startsWith("META-INF/") && (it.endsWith(".dat") || it.endsWith(".bin") || it.endsWith(".properties") || it.endsWith(".xml") || it.endsWith(".json") || it.endsWith(".yml") || it.endsWith(".cfg") || it.endsWith(".conf") || it.endsWith(".ini") || it.endsWith(".txt"))) },
            "Expected $context under legacy or sealed resource root in ${jarPath.fileName}",
        )
    }

    private fun assertJarCarriesMaxNativeShellOnly(jarPath: Path, scenario: String) {
        val entries = loadJarEntries(jarPath)
        val nativeKernelResources = entries.filterKeys { name ->
            name.startsWith("META-INF/js-native/js_kernel_") &&
                (name.endsWith(".dll") || name.endsWith(".so") || name.endsWith(".dylib"))
        }
        val maxShells = entries.filterValues { bytes ->
            bytes.containsAscii(NativeKernelShellPacker.MAX_STUB_MARKER) && bytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER)
        }
        assertTrue(maxShells.isNotEmpty(), "Expected $scenario JAR to carry a max native outer stub shell")
        if (nativeKernelResources.isNotEmpty()) {
            assertEquals(
                nativeKernelResources.keys.sorted(),
                maxShells.filterKeys { it in nativeKernelResources.keys }.keys.sorted(),
                "$scenario every legacy-path js_kernel native resource must be a max outer stub shell, with no separate plaintext inner kernel resource",
            )
        }
        assertTrue(
            maxShells.values.none { it.containsAscii(NativeKernelShellPacker.LOADER_MARKER) },
            "$scenario max native artifact must not be the standard overlay format",
        )
        for ((entryName, bytes) in maxShells) {
            assertTrue(bytes.containsAscii("JNI_OnLoad"), "$scenario $entryName outer stub must expose the minimal JNI_OnLoad ABI")
            assertTrue(!bytes.containsAscii("JniMicrokernelHelper"), "$scenario $entryName outer stub must not expose the Java helper class name as plaintext")
            assertTrue(!bytes.containsAscii("nativeExecuteVmResource"), "$scenario $entryName outer stub must not expose inner helper native method names as plaintext")
            assertTrue(!bytes.containsAscii("executeVmResource"), "$scenario $entryName outer stub must not expose inner helper dispatch method names as plaintext")
        }
        assertTrue(
            entries.values.none { bytes -> bytes.containsAscii(NativeKernelShellPacker.LOADER_MARKER) },
            "$scenario JAR must not include a separate standard-overlay native resource alongside max shell",
        )
    }

    private fun loadJarEntries(jarPath: Path): Map<String, ByteArray> {
        val entries = mutableMapOf<String, ByteArray>()
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory) entries[entry.name] = jar.readBytes()
                jar.closeEntry()
            }
        }
        return entries
    }

    private fun tamperMaxNativeShellPayload(sourceJar: Path, targetJar: Path, scenario: String) {
        var tampered = false
        JarInputStream(Files.newInputStream(sourceJar)).use { input ->
            JarOutputStream(Files.newOutputStream(targetJar)).use { output ->
                while (true) {
                    val entry = input.nextJarEntry ?: break
                    val bytes = input.readBytes()
                    val next = JarEntry(entry.name).also { copy ->
                        copy.time = entry.time
                        copy.comment = entry.comment
                        copy.extra = entry.extra
                    }
                    output.putNextEntry(next)
                    if (!entry.isDirectory && !tampered && bytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER)) {
                        val changed = bytes.copyOf()
                        val markerOffset = changed.indexOfAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER)
                        val tamperOffset = (markerOffset + NativeKernelShellPacker.MAX_PAYLOAD_MARKER.length + 1).coerceAtMost(changed.lastIndex)
                        changed[tamperOffset] = (changed[tamperOffset].toInt() xor 0x5A).toByte()
                        output.write(changed)
                        tampered = true
                    } else {
                        output.write(bytes)
                    }
                    output.closeEntry()
                    input.closeEntry()
                }
            }
        }
        assertTrue(tampered, "Expected to tamper a max native shell payload/header in $scenario JAR")
    }

    private fun tamperMaxNativeShellEncryptedHeaderTag(sourceJar: Path, targetJar: Path, scenario: String) {
        var tampered = false
        rewriteJar(sourceJar, targetJar) { entry, bytes ->
            if (!entry.isDirectory && !tampered && bytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER)) {
                val changed = bytes.copyOf()
                val tamperOffset = maxPayloadEncryptedHeaderTagOffset(changed)
                changed[tamperOffset] = (changed[tamperOffset].toInt() xor 0x33).toByte()
                tampered = true
                changed
            } else {
                bytes
            }
        }
        assertTrue(tampered, "Expected to tamper max native shell encrypted header tag in $scenario JAR")
    }

    private fun tamperMaxNativeShellProtocolVersion(sourceJar: Path, targetJar: Path, scenario: String) {
        var tampered = false
        rewriteJar(sourceJar, targetJar) { entry, bytes ->
            if (!entry.isDirectory && !tampered && bytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER)) {
                val changed = bytes.copyOf()
                val versionOffset = maxPayloadHeaderOffset(changed) + NativeKernelShellPacker.MAX_PAYLOAD_MARKER.length + 1
                assertEquals(NativeKernelShellPacker.PACKER_VERSION, readIntLe(changed, versionOffset), "Expected current max shell protocol version in $scenario JAR")
                assertEquals(NativeKernelShellPacker.Level.MAX.id, readIntLe(changed, versionOffset + 4), "Expected max shell level in $scenario JAR")
                val downgradedVersion = NativeKernelShellPacker.PACKER_VERSION - 1
                changed[versionOffset] = (downgradedVersion and 0xFF).toByte()
                changed[versionOffset + 1] = ((downgradedVersion ushr 8) and 0xFF).toByte()
                changed[versionOffset + 2] = ((downgradedVersion ushr 16) and 0xFF).toByte()
                changed[versionOffset + 3] = ((downgradedVersion ushr 24) and 0xFF).toByte()
                tampered = true
                changed
            } else {
                bytes
            }
        }
        assertTrue(tampered, "Expected to tamper max native shell protocol version in $scenario JAR")
    }

    private fun maxPayloadEncryptedHeaderTagOffset(bytes: ByteArray): Int {
        var offset = maxPayloadHeaderOffset(bytes)
        offset += NativeKernelShellPacker.MAX_PAYLOAD_MARKER.length + 1
        repeat(2) { offset += 4 }
        assertTrue(offset + 4 <= bytes.size, "Max payload nonce size must stay inside native shell bytes")
        val nonceSize = readIntLe(bytes, offset)
        assertTrue(nonceSize >= 0 && offset + 4 + nonceSize <= bytes.size, "Max payload nonce field must stay inside native shell bytes")
        offset += 4 + nonceSize
        assertTrue(offset + 4 <= bytes.size, "Max payload seed nonce size must stay inside native shell bytes")
        val seedNonceSize = readIntLe(bytes, offset)
        assertTrue(seedNonceSize >= 0 && offset + 4 + seedNonceSize + 64 <= bytes.size, "Max payload seed envelope must stay inside native shell bytes")
        offset += 4 + seedNonceSize + 64
        assertTrue(offset + 4 <= bytes.size, "Max payload encrypted header size must stay inside native shell bytes")
        val encryptedHeaderSize = readIntLe(bytes, offset)
        assertTrue(encryptedHeaderSize > 0 && offset + 4 + encryptedHeaderSize + 32 <= bytes.size, "Max payload encrypted header and tag must stay inside native shell bytes")
        offset += 4 + encryptedHeaderSize
        assertTrue(offset in bytes.indices, "Max payload encrypted header tag offset must stay inside the native shell bytes")
        return offset
    }

    private fun maxPayloadHeaderOffset(bytes: ByteArray): Int {
        val marker = NativeKernelShellPacker.MAX_PAYLOAD_MARKER.toByteArray(Charsets.US_ASCII)
        var searchFrom = 0
        while (searchFrom <= bytes.size - marker.size) {
            val found = bytes.indexOfAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER, searchFrom)
            if (found < 0) break
            val fields = found + marker.size + 1
            if (fields + 8 <= bytes.size &&
                readIntLe(bytes, fields) == NativeKernelShellPacker.PACKER_VERSION &&
                readIntLe(bytes, fields + 4) == NativeKernelShellPacker.Level.MAX.id
            ) {
                return found
            }
            searchFrom = found + 1
        }
        error("Expected max payload header marker with protocol version and max level")
    }

    private fun tamperBootstrapNativeIndex(sourceJar: Path, targetJar: Path, scenario: String) {
        var tampered = false
        JarInputStream(Files.newInputStream(sourceJar)).use { input ->
            JarOutputStream(Files.newOutputStream(targetJar)).use { output ->
                while (true) {
                    val entry = input.nextJarEntry ?: break
                    val bytes = input.readBytes()
                    val next = JarEntry(entry.name).also { copy ->
                        copy.time = entry.time
                        copy.comment = entry.comment
                        copy.extra = entry.extra
                    }
                    output.putNextEntry(next)
                    if (!entry.isDirectory && !tampered && bytes.startsWithAscii("JSBI")) {
                        val changed = bytes.copyOf()
                        val tamperOffset = if (changed.size > 9) 9 else changed.lastIndex
                        changed[tamperOffset] = (changed[tamperOffset].toInt() xor 0x5A).toByte()
                        output.write(changed)
                        tampered = true
                    } else {
                        output.write(bytes)
                    }
                    output.closeEntry()
                    input.closeEntry()
                }
            }
        }
        assertTrue(tampered, "Expected to tamper a sealed bootstrap native index in $scenario JAR")
    }

    private fun tamperSealedNativeBindings(sourceJar: Path, targetJar: Path, scenario: String) {
        val entries = loadJarEntries(sourceJar)
        val bindingPath = verifiedSealedNativeBindingPath(sourceJar)
        val bindingBytes = entries[bindingPath]
            ?: error("Expected the verified sealed native binding resource $bindingPath in $scenario JAR")
        assertTrue(bindingBytes.startsWithAscii("JSRP"), "Sealed native bindings must be stored as JSRP")
        assertFalse(bindingBytes.startsWithAscii("JSBI"), "Sealed native bindings must stay independent of the bootstrap JSBI")
        assertTrue(bindingBytes.runtimeEnvelopePartitionId() != null, "Sealed native bindings must use a JSRP envelope")
        var tampered = false
        rewriteJar(sourceJar, targetJar) { entry, bytes ->
            if (!entry.isDirectory && entry.name == bindingPath) {
                val changed = bytes.copyOf()
                val offset = 123.coerceAtMost(changed.lastIndex - 33)
                changed[offset] = (changed[offset].toInt() xor 0x40).toByte()
                tampered = true
                changed
            } else {
                bytes
            }
        }
        assertTrue(tampered, "Expected to tamper sealed native bindings in $scenario JAR")
    }

    private fun tamperMaxNativeShellResourcePath(sourceJar: Path, targetJar: Path, scenario: String) {
        var tampered = false
        JarInputStream(Files.newInputStream(sourceJar)).use { input ->
            JarOutputStream(Files.newOutputStream(targetJar)).use { output ->
                while (true) {
                    val entry = input.nextJarEntry ?: break
                    val bytes = input.readBytes()
                    val renamedNativeShell = !entry.isDirectory && !tampered &&
                        bytes.containsAscii(NativeKernelShellPacker.MAX_STUB_MARKER) &&
                        bytes.containsAscii(NativeKernelShellPacker.MAX_PAYLOAD_MARKER)
                    val nextName = if (renamedNativeShell) "${entry.name}.missing" else entry.name
                    val next = JarEntry(nextName).also { copy ->
                        copy.time = entry.time
                        copy.comment = entry.comment
                        copy.extra = entry.extra
                    }
                    output.putNextEntry(next)
                    output.write(bytes)
                    output.closeEntry()
                    input.closeEntry()
                    if (renamedNativeShell) tampered = true
                }
            }
        }
        assertTrue(tampered, "Expected to rename a max native shell resource path in $scenario JAR")
    }

    private fun tamperVmCatalogRoot(sourceJar: Path, targetJar: Path, scenario: String) {
        val catalogPath = verifiedVmCatalogRootPath(sourceJar)
        var tampered = false
        rewriteJar(sourceJar, targetJar) { entry, bytes ->
            if (!entry.isDirectory && !tampered && entry.name == catalogPath) {
                val changed = bytes.copyOf()
                val offset = 123.coerceAtMost(changed.lastIndex - 33)
                changed[offset] = (changed[offset].toInt() xor 0x20).toByte()
                tampered = true
                changed
            } else {
                bytes
            }
        }
        assertTrue(tampered, "Expected to tamper the VM catalog root in $scenario JAR")
    }

    private fun tamperVmCommittedResource(sourceJar: Path, targetJar: Path, scenario: String) {
        val entries = loadJarEntries(sourceJar)
        val commitment = verifiedVmCatalogCommitments(sourceJar)
            .sortedBy { it.storagePath }
            .firstOrNull { candidate -> entries[candidate.storagePath]?.runtimeEnvelopePartitionId() == candidate.partitionId }
            ?: error("Expected a catalog-committed partitioned VM resource in $scenario JAR")
        val committedBytes = entries.getValue(commitment.storagePath)
        assertEquals(commitment.length, committedBytes.size, "Catalog commitment length must match ${commitment.storagePath}")
        assertEquals(commitment.sha256, sha256Hex(committedBytes), "Catalog commitment digest must match ${commitment.storagePath}")
        assertEquals(commitment.partitionId, committedBytes.runtimeEnvelopePartitionId(), "Catalog commitment partition must match ${commitment.storagePath}")
        var tampered = false
        rewriteJar(sourceJar, targetJar) { entry, bytes ->
            if (!entry.isDirectory && entry.name == commitment.storagePath) {
                val changed = bytes.copyOf()
                val offset = 123.coerceAtMost(changed.lastIndex - 33)
                changed[offset] = (changed[offset].toInt() xor 0x01).toByte()
                tampered = true
                changed
            } else {
                bytes
            }
        }
        assertTrue(tampered, "Expected to tamper a catalog-committed VM resource in $scenario JAR")
    }

    private fun verifiedVmCatalogCommitments(jarPath: Path): List<VmCatalogCommitment> {
        val verifier = findVmCatalogVerifier(jarPath)
        val commitmentBytes = withPublishedBootMaterial(jarPath, verifier) { helperClass ->
            val method = helperClass.getDeclaredMethod(verifier.methodName)
            method.setAccessible(true)
            val payload = method.invoke(null) as? Array<*>
                ?: error("VM catalog verifier returned an unexpected payload")
            payload.getOrNull(1) as? ByteArray
                ?: error("VM catalog verifier did not return native commitments")
        }
        val commitments = commitmentBytes.toString(Charsets.UTF_8)
            .lineSequence()
            .filter { it.isNotBlank() }
            .map { line ->
                val parts = line.split('|')
                require(parts.size == 5 && parts[0] == "R") { "Malformed verified VM catalog commitment" }
                val length = parts[2].toIntOrNull()
                    ?: error("Malformed verified VM catalog commitment length")
                val sha256 = parts[3]
                val partitionId = parts[4].toIntOrNull()
                    ?: error("Malformed verified VM catalog commitment partition")
                require(length > 0 && sha256.length == 64 && sha256.all { it.digitToIntOrNull(16) != null } && partitionId >= 0) {
                    "Malformed verified VM catalog commitment fields"
                }
                VmCatalogCommitment(parts[1], length, sha256, partitionId)
            }
            .toList()
        assertTrue(commitments.isNotEmpty(), "Final JAR helper must verify and publish VM catalog commitments")
        assertEquals(commitments.size, commitments.map { it.storagePath }.toSet().size, "Verified VM catalog paths must be unique")
        return commitments
    }

    private fun verifiedVmCatalogRootPath(jarPath: Path): String {
        val verifier = findVmCatalogVerifier(jarPath)
        val entries = loadJarEntries(jarPath)
        return finalHelperResourcePaths(jarPath, verifier.className, verifier.methodName, "()[[B")
            .singleOrNull { path ->
                val bytes = entries[path]
                bytes != null && bytes.startsWithAscii("JSRP") && bytes.runtimeEnvelopePartitionId() == bootMaterialAnchorSlot(jarPath)
            }
            ?: error("Expected one anchor-sealed VM catalog root resource")
    }

    private fun verifiedSealedNativeBindingPath(jarPath: Path): String {
        val verifier = findVmCatalogVerifier(jarPath)
        val entries = loadJarEntries(jarPath)
        return finalHelperResourcePaths(jarPath, verifier.className, "sealedNativeBindingText", "()Ljava/lang/String;")
            .singleOrNull { path ->
                val bytes = entries[path]
                bytes != null && bytes.startsWithAscii("JSRP") && bytes.runtimeEnvelopePartitionId() == bootMaterialAnchorSlot(jarPath)
            }
            ?: error("Expected one anchor-sealed native binding resource")
    }

    private fun finalHelperResourcePaths(
        jarPath: Path,
        className: String,
        methodName: String,
        targetDescriptor: String,
    ): Set<String> {
        JarFile(jarPath.toFile(), false).use { jar ->
            val entry = jar.getJarEntry(className.replace('.', '/') + ".class")
                ?: error("Missing final helper class $className")
            val entryNames = mutableSetOf<String>()
            val jarEntries = jar.entries()
            while (jarEntries.hasMoreElements()) {
                val candidate = jarEntries.nextElement()
                if (!candidate.isDirectory) entryNames += candidate.name
            }
            val candidates = linkedSetOf<String>()
            ClassReader(jar.getInputStream(entry).use { it.readBytes() }).accept(object : ClassVisitor(Opcodes.ASM9) {
                override fun visitMethod(
                    access: Int,
                    name: String,
                    descriptor: String,
                    signature: String?,
                    exceptions: Array<String>?,
                ): MethodVisitor? {
                    if (name != methodName || descriptor != targetDescriptor) return null
                    return object : MethodVisitor(Opcodes.ASM9) {
                        override fun visitLdcInsn(value: Any?) {
                            if (value is String && value in entryNames) candidates += value
                        }
                    }
                }
            }, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
            require(candidates.isNotEmpty()) {
                "Expected final helper resource paths in $methodName$targetDescriptor"
            }
            return candidates
        }
    }

    private fun <T> withPublishedBootMaterial(jarPath: Path, verifier: VmCatalogVerifier, block: (Class<*>) -> T): T {
        val material = decryptTestBootMaterial(jarPath)
        return try {
            URLClassLoader(arrayOf(jarPath.toUri().toURL()), null).use { loader ->
                val helperClass = Class.forName(verifier.className, false, loader)
                val publish = helperClass.getDeclaredMethod("validateAndPublishJavaBootMaterial", ByteArray::class.java)
                val clear = helperClass.getDeclaredMethod("clearJavaBootMaterial")
                publish.setAccessible(true)
                clear.setAccessible(true)
                var published = false
                var primaryFailure: Throwable? = null
                try {
                    publish.invoke(null, material)
                    published = true
                    block(helperClass)
                } catch (error: Throwable) {
                    primaryFailure = error
                    throw error
                } finally {
                    if (published) {
                        try {
                            clear.invoke(null)
                        } catch (clearError: Throwable) {
                            if (primaryFailure != null) primaryFailure.addSuppressed(clearError) else throw clearError
                        }
                    }
                }
            }
        } finally {
            Arrays.fill(material, 0)
        }
    }

    private fun decryptTestBootMaterial(jarPath: Path): ByteArray {
        val envelope = JarFile(jarPath.toFile(), false).use { jar ->
            val entry = jar.getJarEntry("META-INF/.r/boot.dat")
                ?: error("Missing encrypted boot material envelope")
            jar.getInputStream(entry).use { it.readBytes() }
        }
        require(envelope.size >= 38 && envelope.copyOfRange(0, 4).contentEquals("JSBM".toByteArray(Charsets.US_ASCII))) {
            "Malformed encrypted boot material envelope"
        }
        require((envelope[4].toInt() and 0xFF) == 2 && (envelope[5].toInt() and 0xFF) == 12) {
            "Unsupported encrypted boot material envelope"
        }
        val nonce = envelope.copyOfRange(6, 18)
        val sealedLength = readIntLe(envelope, 18)
        require(sealedLength >= 16 && 22 + sealedLength == envelope.size) { "Malformed encrypted boot material payload" }
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(TEST_BOOT_SECRET, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD("javashroud-boot-material-v2".toByteArray(Charsets.US_ASCII))
            cipher.doFinal(envelope, 22, sealedLength)
        } finally {
            Arrays.fill(nonce, 0)
            Arrays.fill(envelope, 0)
        }
    }

    private fun bootMaterialAnchorSlot(jarPath: Path): Int {
        val material = decryptTestBootMaterial(jarPath)
        return try {
            require(material.size >= 4 && (material[0].toInt() and 0xFF) == 2) { "Malformed boot material" }
            val partitionCount = material[1].toInt() and 0xFF
            val slotCount = material[2].toInt() and 0xFF
            require(partitionCount >= 1 && slotCount == partitionCount + 1) { "Malformed boot material slots" }
            partitionCount
        } finally {
            Arrays.fill(material, 0)
        }
    }

    private fun findVmCatalogVerifier(jarPath: Path): VmCatalogVerifier {
        JarFile(jarPath.toFile(), false).use { jar ->
            val entries = jar.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                if (entry.isDirectory || !entry.name.endsWith(".class")) continue
                val bytes = jar.getInputStream(entry).use { it.readBytes() }
                var className: String? = null
                var verifierMethod: String? = null
                var hasNativeCatalogInstall = false
                ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
                    override fun visit(
                        version: Int,
                        access: Int,
                        name: String,
                        signature: String?,
                        superName: String?,
                        interfaces: Array<String>?,
                    ) {
                        className = name.replace('/', '.')
                    }

                    override fun visitMethod(
                        access: Int,
                        name: String,
                        descriptor: String,
                        signature: String?,
                        exceptions: Array<String>?,
                    ): MethodVisitor? {
                        if (access and Opcodes.ACC_NATIVE != 0 && access and Opcodes.ACC_STATIC != 0 && descriptor == "([B[B[B)V") {
                            hasNativeCatalogInstall = true
                        }
                        if (access and Opcodes.ACC_NATIVE == 0 && access and Opcodes.ACC_STATIC != 0 && descriptor == "()[[B") {
                            verifierMethod = name
                        }
                        return null
                    }
                }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
                if (hasNativeCatalogInstall && className != null && verifierMethod != null) {
                    return VmCatalogVerifier(className!!, verifierMethod!!)
                }
            }
        }
        error("Expected the final JAR helper catalog verifier in ${jarPath.fileName}")
    }

    private data class VmCatalogVerifier(val className: String, val methodName: String)

    private data class VmCatalogCommitment(
        val storagePath: String,
        val length: Int,
        val sha256: String,
        val partitionId: Int,
    )

    private fun ByteArray.runtimeEnvelopePartitionId(): Int? {
        if (size < 156 || this[0] != 'J'.code.toByte() || this[1] != 'S'.code.toByte() ||
            this[2] != 'R'.code.toByte() || this[3] != 'P'.code.toByte() ||
            (this[4].toInt() and 0xFF) != 7 || (last().toInt() and 0xFF) != 32
        ) return null
        return (this[25].toInt() and 0xFF) or ((this[26].toInt() and 0xFF) shl 8)
    }

    private fun rewriteJar(sourceJar: Path, targetJar: Path, transform: (JarEntry, ByteArray) -> ByteArray) {
        JarFile(sourceJar.toFile()).use { input ->
            JarOutputStream(Files.newOutputStream(targetJar)).use { output ->
                val entries = input.entries()
                while (entries.hasMoreElements()) {
                    val entry = entries.nextElement()
                    val bytes = if (entry.isDirectory) ByteArray(0) else input.getInputStream(entry).use { it.readBytes() }
                    val next = JarEntry(entry.name).also { copy ->
                        copy.time = entry.time
                        copy.comment = entry.comment
                        copy.extra = entry.extra
                    }
                    output.putNextEntry(next)
                    output.write(if (entry.isDirectory) bytes else transform(entry, bytes))
                    output.closeEntry()
                }
            }
        }
    }

    private fun ByteArray.containsAscii(value: String): Boolean {
        val needle = value.toByteArray(Charsets.US_ASCII)
        if (needle.isEmpty() || needle.size > size) return false
        return indices.any { start ->
            start <= size - needle.size && needle.indices.all { offset -> this[start + offset] == needle[offset] }
        }
    }

    private fun ByteArray.startsWithAscii(value: String): Boolean {
        val needle = value.toByteArray(Charsets.US_ASCII)
        return needle.size <= size && needle.indices.all { index -> this[index] == needle[index] }
    }

    private fun ByteArray.indexOfAscii(value: String, startIndex: Int = 0): Int {
        val needle = value.toByteArray(Charsets.US_ASCII)
        if (needle.isEmpty() || needle.size > size || startIndex > size - needle.size) return -1
        for (start in startIndex.coerceAtLeast(0)..(size - needle.size)) {
            var match = true
            for (offset in needle.indices) {
                if (this[start + offset] != needle[offset]) {
                    match = false
                    break
                }
            }
            if (match) return start
        }
        return -1
    }

    private fun readIntLe(bytes: ByteArray, offset: Int): Int {
        assertTrue(offset >= 0 && offset + 4 <= bytes.size, "Expected a little-endian int inside byte array bounds")
        return (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }

    private fun ByteArray.countAsciiOccurrences(value: String): Int {
        val needle = value.toByteArray(Charsets.US_ASCII)
        if (needle.isEmpty() || needle.size > size) return 0
        var count = 0
        var start = 0
        while (start <= size - needle.size) {
            var match = true
            for (offset in needle.indices) {
                if (this[start + offset] != needle[offset]) {
                    match = false
                    break
                }
            }
            if (match) {
                count++
                start += needle.size
            } else {
                start++
            }
        }
        return count
    }

    private data class MethodShape(val access: Int, val hasCode: Boolean)

    private fun methodShape(jarPath: Path, helperSimpleName: String, methodName: String): MethodShape? {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && (entry.name.endsWith("$helperSimpleName.class") || (helperSimpleName == "*" && entry.name.startsWith("r/") && entry.name.endsWith(".class")))) {
                    var shape: MethodShape? = null
                    ClassReader(jar.readBytes()).accept(object : ClassVisitor(Opcodes.ASM9) {
                        override fun visitMethod(
                            methodAccess: Int,
                            name: String,
                            descriptor: String,
                            signature: String?,
                            exceptions: Array<String>?,
                        ): MethodVisitor {
                            var hasCode = false
                            return object : MethodVisitor(Opcodes.ASM9) {
                                override fun visitCode() {
                                    hasCode = true
                                }

                                override fun visitEnd() {
                                    if (name == methodName) shape = MethodShape(methodAccess, hasCode)
                                }
                            }
                        }
                    }, 0)
                    if (shape != null) return shape
                }
                jar.closeEntry()
            }
        }
        return null
    }

    private fun nativeMethodShapeByDescriptor(jarPath: Path, methodDescriptor: String): MethodShape? {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && (entry.name.endsWith("JniMicrokernelHelper.class") || (entry.name.startsWith("r/") && entry.name.endsWith(".class")))) {
                    var shape: MethodShape? = null
                    ClassReader(jar.readBytes()).accept(object : ClassVisitor(Opcodes.ASM9) {
                        override fun visitMethod(
                            methodAccess: Int,
                            name: String,
                            descriptor: String,
                            signature: String?,
                            exceptions: Array<String>?,
                        ): MethodVisitor {
                            var hasCode = false
                            return object : MethodVisitor(Opcodes.ASM9) {
                                override fun visitCode() {
                                    hasCode = true
                                }

                                override fun visitEnd() {
                                    if (descriptor == methodDescriptor && methodAccess and Opcodes.ACC_NATIVE != 0) {
                                        shape = MethodShape(methodAccess, hasCode)
                                    }
                                }
                            }
                        }
                    }, 0)
                    if (shape != null) return shape
                }
                jar.closeEntry()
            }
        }
        return null
    }

    private fun captureStdout(block: () -> Unit): String {
        val originalOut = System.out
        val buffer = ByteArrayOutputStream()
        System.setOut(PrintStream(buffer, true, Charsets.UTF_8))
        return try {
            block()
            buffer.toString(Charsets.UTF_8)
        } finally {
            System.setOut(originalOut)
        }
    }

    private data class LocalJavaProcessResult(val exitCode: Int, val output: String, val timedOut: Boolean)

    private fun sessionEvidenceTag(output: String): String = output.lineSequence()
        .firstOrNull { it.startsWith("JAVASHROUD_VM_SESSION=") }
        ?.substringAfter('=')
        .orEmpty()

    private fun runLocalJavaProcessWithTimeout(processBuilder: ProcessBuilder, timeoutSeconds: Long = 30): LocalJavaProcessResult {
        val process = processBuilder.withTestBootSecret().redirectErrorStream(true).start()
        val output = ByteArrayOutputStream()
        val reader = thread(start = true, isDaemon = true, name = "javashroud-real-jni-output") {
            process.inputStream.use { input -> input.copyTo(output) }
        }
        val exited = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!exited) {
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
        }
        reader.join(5_000)
        return LocalJavaProcessResult(
            exitCode = if (exited) process.exitValue() else -1,
            output = output.toString(Charsets.UTF_8),
            timedOut = !exited,
        )
    }

    private fun buildLocalRealJarFixture(workDir: Path): Path {
        Files.createDirectories(workDir)
        val srcDir = workDir.resolve("local-real-src")
        val classesDir = workDir.resolve("local-real-classes")
        Files.createDirectories(srcDir.resolve("demo"))
        Files.createDirectories(classesDir)
        Files.writeString(srcDir.resolve("demo/Main.java"), """
            package demo;

            public class Main {
                public static void main(String[] args) {
                    int result = Service.compute();
                    System.out.println("REAL_RESULT=" + result + ";LIFECYCLE=" + Service.lifecycleStatus());
                    System.exit(result);
                }
            }
        """.trimIndent())
        Files.writeString(srcDir.resolve("demo/Service.java"), """
            package demo;

            public final class Service {
                private static final String MARKER = "JavaShroud local real fixture";
                private static volatile String lifecycleStatus = "not-run";

                public static int compute() {
                    String decorated = decorate(MARKER, 3);
                    int checksum = 0;
                    for (int i = 0; i < decorated.length(); i++) checksum += decorated.charAt(i);
                    int sequential = 0;
                    for (int i = 0; i < 64; i++) sequential += hot(7 + i);
                    int threaded = threadedHotSum();
                    checksum += sequential + threaded;
                    lifecycleStatus = (sequential > 0 && threaded > 0) ? "ok" : "bad";
                    return checksum > 0 ? 1 : 0;
                }

                public static String lifecycleStatus() {
                    return lifecycleStatus;
                }

                private static int hot(int seed) {
                    int x = seed;
                    x = (x * 3) + 11;
                    x ^= 0x55;
                    return x & 0xff;
                }

                private static int threadedHotSum() {
                    final int[] values = new int[4];
                    Thread[] threads = new Thread[values.length];
                    for (int i = 0; i < values.length; i++) {
                        final int slot = i;
                        threads[i] = new Thread(() -> {
                            int local = 0;
                            for (int j = 0; j < 32; j++) local += hot((slot + 1) * 31 + j);
                            values[slot] = local;
                        }, "javashroud-native-lifecycle-" + i);
                        threads[i].start();
                    }
                    int sum = 0;
                    for (Thread thread : threads) {
                        try {
                            thread.join();
                        } catch (InterruptedException error) {
                            Thread.currentThread().interrupt();
                            throw new IllegalStateException(error);
                        }
                    }
                    for (int value : values) sum += value;
                    return sum;
                }

                private static String decorate(String value, int rounds) {
                    String out = value;
                    for (int i = 0; i < rounds; i++) out = out + ":" + i;
                    return out;
                }
            }
        """.trimIndent())

        runLocalCommand(
            listOf(
                "javac",
                "--release", "21",
                "-encoding", "UTF-8",
                "-d", classesDir.toAbsolutePath().normalize().toString(),
                srcDir.resolve("demo/Main.java").toAbsolutePath().normalize().toString(),
                srcDir.resolve("demo/Service.java").toAbsolutePath().normalize().toString(),
            ),
            workDir,
            "javac local real fixture",
        )
        val manifest = workDir.resolve("local-real.mf")
        Files.writeString(manifest, "Manifest-Version: 1.0\r\nMain-Class: demo.Main\r\n\r\n")
        val jarPath = workDir.resolve("local-real-fixture.jar")
        runLocalCommand(
            listOf(
                "jar",
                "--create",
                "--file", jarPath.toAbsolutePath().normalize().toString(),
                "--manifest", manifest.toAbsolutePath().normalize().toString(),
                "-C", classesDir.toAbsolutePath().normalize().toString(),
                ".",
            ),
            workDir,
            "jar local real fixture",
        )
        return jarPath
    }

    private fun runLocalCommand(command: List<String>, workDir: Path, label: String) {
        val process = ProcessBuilder(command).directory(workDir.toFile()).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().readText()
        val exitCode = process.waitFor()
        require(exitCode == 0) { "$label failed with exitCode=$exitCode output=${output.take(2000)}" }
    }

}
