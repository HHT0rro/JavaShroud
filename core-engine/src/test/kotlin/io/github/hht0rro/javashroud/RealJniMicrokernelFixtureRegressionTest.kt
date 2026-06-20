package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class RealJniMicrokernelFixtureRegressionTest {
    private val objectMapper = ObjectMapper()

    @Test
    fun jni_microkernel_loader_preserves_real_demo_and_complex_business_fixtures() {
        val workDir = Files.createTempDirectory("javashroud-real-jni-fixtures")
        val fixtures = buildRealJarFixtures(workDir)
        try {
            verifyRealJniFixture(fixtures.demoJar, "real-demo")
            verifyRealJniFixture(fixtures.complexJar, "complex-business")
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    private fun verifyRealJniFixture(inputJar: Path, scenario: String) {
        val baseline = runJavaProcessWithTimeout(ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().toString()))
        assertTrue(!baseline.timedOut, "Baseline $scenario should exit within timeout. Output: ${baseline.output.take(500)}")
        assertEquals(1, baseline.exitCode, "Baseline $scenario should return the fixture contract exit code. Output: ${baseline.output.take(500)}")

        val outputJar = runEngine(inputJar, scenario)
        try {
            assertTrue(Files.exists(outputJar), "Output JAR should exist for $scenario")
            assertJarReadable(outputJar, scenario)
            assertAllClassesValid(outputJar, scenario)
            assertJarContainsJniHelper(outputJar, "$scenario JNI microkernel helper")
            assertJarHasNativeResources(outputJar, "$scenario native resources")

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

            val result = runJavaProcessWithTimeout(ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().toString()))
            assertTrue(!result.timedOut, "Obfuscated $scenario should exit within timeout. Output: ${result.output.take(500)}")
            assertEquals(baseline.exitCode, result.exitCode, "Obfuscated $scenario should preserve exit code. Output: ${result.output.take(500)}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Obfuscated $scenario should preserve stdout")
        } finally {
            Files.deleteIfExists(outputJar)
        }
    }

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
        writeTestRunConfigToml(
            configPath = configPath,
            inputJar = inputJar,
            outputJar = outputJar,
            passIds = listOf("method-body-delayed-decryption", "jni-microkernel-loader"),
            passParams = mapOf("jni-microkernel-loader" to mapOf("targetPlatform" to objectMapper.valueToTree("auto"))),
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
}
