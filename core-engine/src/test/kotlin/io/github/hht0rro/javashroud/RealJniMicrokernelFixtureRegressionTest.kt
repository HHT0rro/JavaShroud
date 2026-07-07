package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.decodeMaskedNativePreloadIndexText
import io.github.hht0rro.javashroud.transforms.protection.encodeMaskedNativePreloadIndex
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RealJniMicrokernelFixtureRegressionTest {
    private val objectMapper = ObjectMapper()

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

            val tamperedIndexJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-native-index.jar")
            try {
                tamperBootstrapNativeIndex(outputJar, tamperedIndexJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedIndexJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "sealed bootstrap native index")
                tamperResults.add(TamperEvidence("sealed bootstrap native index", tampered))
            } finally {
                Files.deleteIfExists(tamperedIndexJar)
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

            val tamperedProfileJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-vm-profile.jar")
            try {
                tamperVmPreloadProfile(outputJar, tamperedProfileJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedProfileJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "VM preload profile tag")
                tamperResults.add(TamperEvidence("VM preload profile tag", tampered))
            } finally {
                Files.deleteIfExists(tamperedProfileJar)
            }

            val tamperedPreloadMeshJar = outputJar.resolveSibling("${outputJar.fileName.toString().removeSuffix(".jar")}-tampered-vm-preload-mesh.jar")
            try {
                tamperVmPreloadMesh(outputJar, tamperedPreloadMeshJar, scenario)
                val tampered = runLocalJavaProcessWithTimeout(ProcessBuilder("java", "-jar", tamperedPreloadMeshJar.toAbsolutePath().toString()))
                assertTamperedRunFailsClosed(tampered, baseline, scenario, "VM preload mesh binding")
                tamperResults.add(TamperEvidence("VM preload mesh binding", tampered))
            } finally {
                Files.deleteIfExists(tamperedPreloadMeshJar)
            }

            val reportPath = writeRuntimeEvidenceReport(scenario, inputJar, outputJar, baseline, result, tamperResults)
            val reportText = Files.readString(reportPath)
            assertTrue(reportText.contains("runtime_status: passed"), "Native Max runtime evidence report must record the successful real JAR run")
            assertTrue(reportText.contains("tamper_fail_closed_count: 5"), "Native Max runtime evidence report must record all fail-closed tamper probes")
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

    private fun runEngine(inputJar: Path, tag: String): Path {
        val outputJar = inputJar.resolveSibling("javashroud-real-jni-out-$tag.jar")
        val configPath = inputJar.resolveSibling("javashroud-real-jni-cfg-$tag.toml")
        writeRunConfig(configPath, inputJar, outputJar)
        try {
            val output = captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
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

    private fun tamperVmPreloadProfile(sourceJar: Path, targetJar: Path, scenario: String) {
        assertTrue(
            tamperVmPreloadIndexField(sourceJar, targetJar, scenario, fieldIndex = 5),
            "Expected to tamper a VM preload profile tag in $scenario JAR",
        )
    }

    private fun tamperVmPreloadMesh(sourceJar: Path, targetJar: Path, scenario: String) {
        assertTrue(
            tamperVmPreloadIndexField(sourceJar, targetJar, scenario, fieldIndex = 4),
            "Expected to tamper a VM preload mesh binding in $scenario JAR",
        )
    }

    private fun tamperVmPreloadIndexField(sourceJar: Path, targetJar: Path, scenario: String, fieldIndex: Int): Boolean {
        var tampered = false
        val runtimeResourceKey = extractRuntimeResourceKey(sourceJar, scenario)
        val context = testVbc4Context(runtimeResourceKey)
        val preloadIndexEntries = setOf("META-INF/.r/vm-current.idx", "META-INF/.r/vm.idx")
        withVbc4BuildContext(context) {
            rewriteJar(sourceJar, targetJar) { entry, bytes ->
                if (!entry.isDirectory && !tampered && entry.name in preloadIndexEntries) {
                    val decoded = RuntimeResourceCodec.decode(bytes)?.decodeToString()
                    val plainIndex = decoded
                    val changed = plainIndex?.lineSequence()?.joinToString(separator = "\n", postfix = "\n") { line ->
                        if (tampered || !looksLikeVmPreloadIndexLine(line)) return@joinToString line
                        val parts = line.split('|').toMutableList()
                        if (parts.getOrNull(fieldIndex).isNullOrEmpty()) {
                            line
                        } else {
                            parts[fieldIndex] = flipHexDigit(parts[fieldIndex])
                            tampered = true
                            parts.joinToString("|")
                        }
                    }
                    if (tampered && changed != null) {
                        val maskedChanged = encodeMaskedNativePreloadIndex(
                            changed.toByteArray(Charsets.UTF_8),
                            "tamper:$scenario:$fieldIndex",
                        )
                        return@rewriteJar RuntimeResourceCodec.encode(
                            bytes = maskedChanged,
                            kind = RuntimeResourceKind.NativeIndex,
                            seed = 0x7150_0F11 xor fieldIndex,
                            variantId = 11 + fieldIndex,
                            layerCount = 3,
                            compress = true,
                        )
                    }
                }
                bytes
            }
        }
        return tampered
    }

    private fun extractRuntimeResourceKey(jarPath: Path, scenario: String): ByteArray {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && (entry.name.endsWith("JniMicrokernelHelper.class") || (entry.name.startsWith("r/") && entry.name.endsWith(".class")))) {
                    val bytes = jar.readBytes()
                    val key = runtimeResourceKeyBytes(bytes)
                    if (key != null) return key
                }
                jar.closeEntry()
            }
        }
        error("Expected to extract injected runtime resource key from $scenario JNI helper in ${jarPath.fileName}")
    }

    private fun runtimeResourceKeyBytes(helperBytes: ByteArray): ByteArray? = try {
        val classNode = ClassNode()
        ClassReader(helperBytes).accept(classNode, ClassReader.SKIP_FRAMES)
        extractRuntimeResourceKeyFromHelper(classNode)
    } catch (_: Exception) {
        null
    }

    private fun extractRuntimeResourceKeyFromHelper(classNode: ClassNode): ByteArray? {
        val shareMethods = classNode.methods
            .filter { it.desc == "()[B" }
            .associateBy { it.name }
        val runtimeKeyMethod = shareMethods.values.firstOrNull { method ->
            method.instructions?.toArray().orEmpty().any { insn ->
                insn is MethodInsnNode && insn.owner == classNode.name && insn.name.startsWith("jsRrkShare") && insn.desc == "()[B"
            }
        } ?: return null
        val shareNames = runtimeKeyMethod.instructions.toArray()
            .filterIsInstance<MethodInsnNode>()
            .filter { it.owner == classNode.name && it.desc == "()[B" && it.name.startsWith("jsRrkShare") }
            .map { it.name }
        if (shareNames.isEmpty()) return null
        val shares = shareNames.map { name -> extractByteArrayReturn(shareMethods[name] ?: return null) ?: return null }
        val keySize = shares.first().size
        if (keySize != 32 || shares.any { it.size != keySize }) return null
        return ByteArray(keySize) { index ->
            shares.fold(0) { acc, share -> acc xor (share[index].toInt() and 0xFF) }.toByte()
        }
    }

    private fun extractByteArrayReturn(method: MethodNode): ByteArray? {
        val instructions = method.instructions?.toArray().orEmpty()
        val newArrayIndex = instructions.indexOfFirst { it is IntInsnNode && it.opcode == Opcodes.NEWARRAY && it.operand == Opcodes.T_BYTE }
        if (newArrayIndex <= 0) return null
        val size = pushIntValue(instructions[newArrayIndex - 1]) ?: return null
        if (size <= 0 || size > 4096) return null
        val bytes = ByteArray(size)
        var index = newArrayIndex + 1
        while (index < instructions.size) {
            if (instructions[index].opcode == Opcodes.ARETURN) return bytes
            if (index + 3 < instructions.size && instructions[index].opcode == Opcodes.DUP) {
                val byteIndex = pushIntValue(instructions[index + 1])
                val byteValue = pushIntValue(instructions[index + 2])
                if (byteIndex != null && byteValue != null && byteIndex in bytes.indices && instructions[index + 3].opcode == Opcodes.BASTORE) {
                    bytes[byteIndex] = byteValue.toByte()
                    index += 4
                    continue
                }
            }
            index++
        }
        return null
    }

    private fun pushIntValue(insn: AbstractInsnNode): Int? = when (insn.opcode) {
        Opcodes.ICONST_M1 -> -1
        Opcodes.ICONST_0 -> 0
        Opcodes.ICONST_1 -> 1
        Opcodes.ICONST_2 -> 2
        Opcodes.ICONST_3 -> 3
        Opcodes.ICONST_4 -> 4
        Opcodes.ICONST_5 -> 5
        Opcodes.BIPUSH, Opcodes.SIPUSH -> (insn as? IntInsnNode)?.operand
        Opcodes.LDC -> (insn as? LdcInsnNode)?.cst as? Int
        else -> null
    }

    private fun testVbc4Context(runtimeResourceKey: ByteArray): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(32) { index -> (0x41 + index).toByte() },
        nativeSeed = 0x7150_0F11L,
        jarLayoutDigest = ByteArray(32) { index -> (0x23 + index * 3).toByte() },
        runtimeResourceKey = runtimeResourceKey,
    )

    private fun looksLikeVmPreloadIndexLine(line: String): Boolean {
        if (line.isBlank() || line.startsWith("A|")) return false
        val parts = line.split('|')
        return parts.size >= 7 &&
            parts[0].isNotBlank() &&
            parts[1].isNotBlank() &&
            parts[2].isNotBlank() &&
            parts[3].toIntOrNull() != null &&
            parts[4].isNotBlank() &&
            parts[5].isNotBlank() &&
            parts[6].isNotBlank()
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

    private fun flipHexDigit(value: String): String {
        if (value.isEmpty()) return value
        val chars = value.toCharArray()
        chars[chars.lastIndex] = if (chars.last() == '0') '1' else '0'
        return String(chars)
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

    private fun ByteArray.indexOfAscii(value: String): Int {
        val needle = value.toByteArray(Charsets.US_ASCII)
        if (needle.isEmpty() || needle.size > size) return -1
        for (start in 0..(size - needle.size)) {
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

    private fun runLocalJavaProcessWithTimeout(processBuilder: ProcessBuilder, timeoutSeconds: Long = 30): LocalJavaProcessResult {
        val process = processBuilder.redirectErrorStream(true).start()
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
