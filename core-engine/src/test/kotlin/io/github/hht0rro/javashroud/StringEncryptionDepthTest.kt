package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.config.RuleSpec
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Depth verification for string encryption and anti-dump constant pool perturbation.
 */
class StringEncryptionDepthTest {
    private val objectMapper = ObjectMapper()

    private val fixtureStrings = listOf(
        "Hello from JavaShroud",
        "SecretMessage123",
        "LambdaRunner",
    )

    @Test
    fun string_encryption_removes_original_literals_from_bytecode() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-strenc-depth", ".jar"))
        try {
            val outputJar = runEngine(
                inputJar,
                listOf("string-encryption"),
                rules = listOf(RuleSpec(target = "e2e/*", action = "string-encryption")),
            )
            try {
                assertTrue(Files.exists(outputJar), "Output JAR should exist")

                val entries = loadJarEntries(outputJar)
                for ((name, bytes) in entries) {
                    if (!name.endsWith(".class")) continue
                    if (name.contains("StringEncryption")) continue

                    val remainingStrings = scanForStringConstants(bytes)
                    for (original in fixtureStrings) {
                        val stillPresent = remainingStrings.any { it == original }
                        assertTrue(
                            !stillPresent,
                            "Original string '$original' should be removed from $name after encryption. Found: $remainingStrings",
                        )
                    }
                }
            } finally {
                Files.deleteIfExists(outputJar)
            }
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun string_encryption_bytecode_differs_from_original() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-strenc-helper", ".jar"))
        try {
            val outputJar = runEngine(
                inputJar,
                listOf("string-encryption"),
                rules = listOf(RuleSpec(target = "e2e/*", action = "string-encryption")),
            )
            try {
                assertTrue(Files.exists(outputJar), "Output JAR should exist")

                val inputEntries = loadJarEntries(inputJar)
                val outputEntries = loadJarEntries(outputJar)
                var anyDifferent = false
                for ((name, inputBytes) in inputEntries) {
                    if (!name.endsWith(".class")) continue
                    val outputBytes = outputEntries.find { it.name == name }?.bytes ?: continue
                    if (!inputBytes.contentEquals(outputBytes)) {
                        anyDifferent = true
                        break
                    }
                }
                assertTrue(anyDifferent, "At least one class should have different bytecode after string encryption")
            } finally {
                Files.deleteIfExists(outputJar)
            }
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun string_encrypted_jar_runs_correctly() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-strenc-run", ".jar"))
        try {
            val outputJar = runEngine(
                inputJar,
                listOf("string-encryption"),
                rules = listOf(RuleSpec(target = "e2e/*", action = "string-encryption")),
            )
            try {
                val process = ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().toString())
                    .redirectErrorStream(true)
                    .start()
                val output = process.inputStream.bufferedReader().readText()
                val exitCode = process.waitFor()
                assertEquals(
                    1,
                    exitCode,
                    "String-encrypted JAR should preserve call()=1 behavior. Output: ${output.take(500)}",
                )
            } finally {
                Files.deleteIfExists(outputJar)
            }
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun anti_symbolic_execution_preserves_runtime_behavior() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-antidump", ".jar"))
        try {
            val outputJar = runEngine(
                inputJar,
                listOf("strip-compile-debug-info", "anti-symbolic-execution"),
            )
            try {
                assertTrue(Files.exists(outputJar), "Output JAR should exist")

                val process = ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().toString())
                    .redirectErrorStream(true)
                    .start()
                val output = process.inputStream.bufferedReader().readText()
                val exitCode = process.waitFor()
                assertEquals(
                    1,
                    exitCode,
                    "Anti-symbolic JAR should preserve call()=1 behavior. Output: ${output.take(500)}",
                )
            } finally {
                Files.deleteIfExists(outputJar)
            }
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    private fun scanForStringConstants(classBytes: ByteArray): List<String> {
        val strings = mutableListOf<String>()
        val cr = ClassReader(classBytes)
        val cv = object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor {
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitLdcInsn(value: Any) {
                        if (value is String) strings.add(value)
                    }
                }
            }
        }
        cr.accept(cv, ClassReader.SKIP_DEBUG)
        return strings
    }

    private data class JarEntryData(val name: String, val bytes: ByteArray)

    private fun loadJarEntries(jarPath: Path): List<JarEntryData> {
        val entries = mutableListOf<JarEntryData>()
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory) {
                    entries.add(JarEntryData(entry.name, jar.readBytes()))
                }
                jar.closeEntry()
            }
        }
        return entries
    }

    private fun runEngine(inputJar: Path, passIds: List<String>, rules: List<RuleSpec> = emptyList()): Path {
        val tag = safeTag(passIds.joinToString("-"), "javashroud-strenc-")
        val outputJar = inputJar.resolveSibling("javashroud-strenc-out-$tag.jar")
        val configPath = inputJar.resolveSibling("javashroud-strenc-cfg-$tag.toml")
        writeRunConfig(configPath, inputJar, outputJar, passIds, rules)
        try {
            dispatchRequest(
                buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                EngineKernel(),
            )
        } finally {
            Files.deleteIfExists(configPath)
        }
        return outputJar
    }

    private fun writeRunConfig(
        configPath: Path,
        inputJar: Path,
        outputJar: Path,
        passIds: List<String>,
        rules: List<RuleSpec> = emptyList(),
    ) {
        writeTestRunConfigToml(configPath, inputJar, outputJar, passIds, rules)
    }

    private fun safeTag(raw: String, prefix: String): String {
        val clean = raw.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val maxLen = 180 - prefix.length
        return if (clean.length > maxLen) clean.substring(0, maxLen) else clean
    }
}
