package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.config.RuleSpec
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode

class EndToEndTargetedConfigRunVerificationTest {

    @Test
    fun targeted_pass_combinations_validate_bytecode_semantics() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-e2e-targeted-input", ".jar"))
        try {
            val scenarios = listOf(
                TargetedScenario(
                    passIds = listOf("strip-compile-debug-info"),
                    targetedClasses = setOf("e2e/Root", "e2e/Impl"),
                ),
                TargetedScenario(
                    passIds = listOf("strip-compile-debug-info"),
                    targetedClasses = setOf("e2e/Root"),
                    targetedMembers = setOf("e2e/Root#call:()I"),
                ),
                TargetedScenario(
                    passIds = listOf("member-hide"),
                    targetedClasses = setOf("e2e/Root"),
                ),
                TargetedScenario(
                    passIds = listOf("strip-compile-debug-info", "member-hide"),
                    targetedClasses = setOf("e2e/Root"),
                ),
            )

            for (scenario in scenarios) {
                val passKey = scenario.passIds.joinToString("-")
                val outputJar = inputJar.resolveSibling("javashroud-e2e-targeted-output-$passKey.jar")
                val configPath = inputJar.resolveSibling("javashroud-e2e-targeted-config-$passKey.toml")
                writeTargetedRunConfig(configPath = configPath, inputJar = inputJar, outputJar = outputJar, scenario = scenario)

                val output = captureStdout {
                    dispatchRequest(
                        buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                        EngineKernel(),
                    )
                }

                val events = output.trim().lines().filter { it.isNotBlank() }.map(::parseEventType)
                assertTrue(events.any { it == "done" }, "Run should finish for scenario=$passKey")
                assertTrue(Files.exists(outputJar), "Output jar should exist for scenario=$passKey")
                assertJarReadable(outputJar, passKey)
                assertTargetedTransformationHolds(inputJar, outputJar, scenario)
            }
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    private fun writeTargetedRunConfig(configPath: Path, inputJar: Path, outputJar: Path, scenario: TargetedScenario) {
        val rules = mutableListOf<RuleSpec>()
        for (target in scenario.targetedClasses) {
            rules += RuleSpec(target = target, action = scenario.passIds.first())
        }
        for (target in scenario.targetedMembers) {
            rules += RuleSpec(target = target, action = "member-hide")
        }
        writeTestRunConfigToml(configPath, inputJar, outputJar, scenario.passIds, rules)
    }

    private fun assertTargetedTransformationHolds(inputJar: Path, outputJar: Path, scenario: TargetedScenario) {
        val inputBytes = loadJarClassBytes(inputJar)
        val outputBytes = loadJarClassBytes(outputJar)
        assertEquals(inputBytes.keys, outputBytes.keys, "Class set must remain stable for $scenario")

        val inputAttributes = inputBytes.mapValues { (_, bytes) -> collectClassBytecodeAttributes(bytes) }
        val outputAttributes = outputBytes.mapValues { (_, bytes) -> collectClassBytecodeAttributes(bytes) }
        val inputNodes = inputBytes.mapValues { (_, bytes) -> readClassNode(bytes) }
        val outputNodes = outputBytes.mapValues { (_, bytes) -> readClassNode(bytes) }

        for (className in inputBytes.keys) {
            val before = inputAttributes.getValue(className)
            val after = outputAttributes.getValue(className)
            val isTargetedClass = scenario.targetedClasses.contains(className)
            val targetedMembersForClass = scenario.targetedMembers.filter { it.startsWith("$className#") }.toSet()

            if (scenario.passIds.contains("strip-compile-debug-info") && isTargetedClass) {
                assertFalse(after.sourceFilePresent, "SourceFile should be stripped for $className")
                assertFalse(after.sourceDebugPresent, "SourceDebugExtension should be stripped for $className")
            } else {
                assertEquals(before.sourceFilePresent, after.sourceFilePresent, "SourceFile must stay unchanged for $className")
                assertEquals(before.sourceDebugPresent, after.sourceDebugPresent, "SourceDebugExtension must stay unchanged for $className")
            }

            if (scenario.passIds.contains("strip-compile-debug-info") && (isTargetedClass || targetedMembersForClass.isNotEmpty())) {
                assertEquals(0, after.lineCount, "LineNumberTable should be stripped for targeted scope on $className")
            } else {
                assertEquals(before.lineCount, after.lineCount, "LineNumberTable must remain unchanged for $className")
            }

            if (scenario.passIds.contains("member-hide") && isTargetedClass) {
                val beforeNode = inputNodes.getValue(className)
                val afterNode = outputNodes.getValue(className)
                for (method in afterNode.methods) {
                    if (method.name.startsWith("<")) continue
                    val key = "$className#${method.name}:${method.desc}"
                    val wasSynthetic = beforeNode.methods.first { it.name == method.name && it.desc == method.desc }.access and Opcodes.ACC_SYNTHETIC != 0
                    val isSyntheticNow = method.access and Opcodes.ACC_SYNTHETIC != 0
                    assertTrue(isSyntheticNow, "Targeted class method $key should be synthetic")
                }
                for (field in afterNode.fields) {
                    val key = "$className#${field.name}:${field.desc}"
                    val isSyntheticNow = field.access and Opcodes.ACC_SYNTHETIC != 0
                    assertTrue(isSyntheticNow, "Targeted class field $key should be synthetic")
                }
            }

            assertEquals(before.hasInnerClasses, after.hasInnerClasses, "InnerClasses structure must remain stable for $className")
            assertEquals(before.hasOuterClass, after.hasOuterClass, "OuterClass structure must remain stable for $className")
            assertEquals(before.hasTryCatch, after.hasTryCatch, "TryCatch structure must remain stable for $className")
        }
    }

    private fun assertJarReadable(jarPath: Path, context: String) {
        val bytes = loadJarClassBytes(jarPath)
        val visitor = object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {}
        for ((className, classBytes) in bytes) {
            ClassReader(classBytes).accept(visitor, ClassReader.SKIP_FRAMES)
        }
        assertTrue(Files.exists(jarPath), "Jar should exist: $context")
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
    }
    private data class TargetedScenario(
        val passIds: List<String>,
        val targetedClasses: Set<String> = emptySet(),
        val targetedMembers: Set<String> = emptySet(),
    )
}
