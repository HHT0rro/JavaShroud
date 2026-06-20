package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode

class EndToEndConfigRunVerificationTest {

    @Test
    fun end_to_end_pass_scenarios_covering_single_pair_and_full_combinations() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-e2e-input", ".jar"))
        try {
            val scenarios = listOf(
                listOf("strip-compile-debug-info"),
                listOf("member-hide"),
                listOf("strip-compile-debug-info", "member-hide"),
            )

            for (passes in scenarios) {
                val passKey = passes.joinToString("-")
                val outputJar = inputJar.resolveSibling("javashroud-e2e-output-$passKey.jar")
                val configPath = inputJar.resolveSibling("javashroud-e2e-config-$passKey.toml")
                writeRunConfig(configPath = configPath, inputJar = inputJar, outputJar = outputJar, passIds = passes)

                val output = captureStdout {
                    dispatchRequest(
                        buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                        EngineKernel(),
                    )
                }

                val events = output.trim().lines().filter { it.isNotBlank() }.map(::parseEventType)
                assertTrue(events.isNotEmpty(), "Engine should emit events for passes=$passKey")
                assertTrue(events.any { it == "done" }, "Run should finish with a done event for passes=$passKey")
                assertTrue(Files.exists(outputJar), "Output jar should exist for passes=$passKey")
                assertJarReadable(outputJar, passKey)
                assertChangedBytecode(inputJar, outputJar, passes)
            }
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    private fun writeRunConfig(configPath: Path, inputJar: Path, outputJar: Path, passIds: List<String>) {
        writeTestRunConfigToml(configPath, inputJar, outputJar, passIds)
    }

    private fun assertJarReadable(jarPath: Path, context: String) {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name.endsWith(".class")) {
                    val classBytes = jar.readAllBytes()
                    val visitor = object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {}
                    ClassReader(classBytes).accept(visitor, ClassReader.SKIP_FRAMES)
                }
                jar.closeEntry()
            }
        }
        assertTrue(Files.exists(jarPath), "Jar should exist: $context")
    }

    private fun assertChangedBytecode(inputJar: Path, outputJar: Path, passes: List<String>) {
        val inputBytes = loadJarClassBytes(inputJar)
        val outputBytes = loadJarClassBytes(outputJar)
        assertEquals(inputBytes.keys, outputBytes.keys, "Class set should remain stable for passes=$passes")

        val inputAttributes = inputBytes.mapValues { (_, bytes) -> collectClassBytecodeAttributes(bytes) }
        val outputAttributes = outputBytes.mapValues { (_, bytes) -> collectClassBytecodeAttributes(bytes) }
        val inputNodes = inputBytes.mapValues { (_, bytes) -> readClassNode(bytes) }
        val outputNodes = outputBytes.mapValues { (_, bytes) -> readClassNode(bytes) }

        for (className in inputBytes.keys) {
            val before = inputAttributes.getValue(className)
            val after = outputAttributes.getValue(className)

            val stripsDebug = passes.contains("strip-compile-debug-info")
            val stripsLines = passes.contains("strip-compile-debug-info")
            val marksSynthetic = passes.contains("member-hide")

            if (stripsDebug) {
                assertFalse(after.sourceFilePresent, "SourceFile should be stripped for $className, passes=$passes")
                assertFalse(after.sourceDebugPresent, "SourceDebugExtension should be stripped for $className, passes=$passes")
            } else {
                assertEquals(before.sourceFilePresent, after.sourceFilePresent, "SourceFile must remain unchanged for $className")
                assertEquals(before.sourceDebugPresent, after.sourceDebugPresent, "SourceDebugExtension must remain unchanged for $className")
            }

            if (stripsLines) {
                assertEquals(0, after.lineCount, "LineNumberTable should be stripped for $className, passes=$passes")
            } else {
                assertEquals(before.lineCount, after.lineCount, "LineNumberTable must remain unchanged for $className")
            }

            if (marksSynthetic) {
                val beforeNode = inputNodes.getValue(className)
                val afterNode = outputNodes.getValue(className)
                if (beforeNode.access and Opcodes.ACC_INTERFACE != 0) continue
                for (method in afterNode.methods) {
                    if (method.name.startsWith("<")) continue
                    val isSyntheticNow = method.access and Opcodes.ACC_SYNTHETIC != 0
                    assertTrue(isSyntheticNow, "All methods should be synthetic after member-hide: ${className}#${method.name}:${method.desc}")
                }
                for (field in afterNode.fields) {
                    val isSyntheticNow = field.access and Opcodes.ACC_SYNTHETIC != 0
                    assertTrue(isSyntheticNow, "All fields should be synthetic after member-hide: ${className}#${field.name}:${field.desc}")
                }
            }

            assertEquals(before.hasInnerClasses, after.hasInnerClasses, "InnerClasses must remain stable for $className")
            assertEquals(before.hasOuterClass, after.hasOuterClass, "OuterClass must remain stable for $className")
            assertEquals(before.hasTryCatch, after.hasTryCatch, "TryCatch must remain stable for $className")
            assertEquals(before.hasExceptions, after.hasExceptions, "Exceptions attribute must remain stable for $className")
            assertEquals(before.hasSignature, after.hasSignature, "Signature attribute must remain stable for $className")
        }
    }

    private fun readClassNode(classBytes: ByteArray): ClassNode {
        val classNode = ClassNode()
        ClassReader(classBytes).accept(classNode, ClassReader.SKIP_FRAMES)
        return classNode
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
    private fun parseEventType(line: String): String {
        val match = Regex("""type\s*=\s*"((?:\\.|[^"])*)"""").find(line)
        return match?.groupValues?.get(1) ?: error("Engine event line missing type: $line")
    }}
