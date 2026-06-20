package io.github.hht0rro.javashroud

import com.fasterxml.jackson.dataformat.toml.TomlMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

class EngineCliDispatchSupportTest {
    private val tomlMapper: TomlMapper = TomlMapper()

    @Test
    fun dispatchRequest_writes_schema_payload_to_stdout() {
        val output = captureConsole {
            dispatchRequest(buildCommandRequest(EngineCommand.Schema, arrayOf("-schema")), EngineKernel())
        }
        val stdoutLines = output.stdout.lineSequence().filter { it.isNotBlank() }.toList()
        assertEquals("", output.stderr, "Schema command should not write stderr")
        assertTrue(stdoutLines.isNotEmpty(), "Schema command should emit a TOML payload")

        val payload = tomlMapper.readTree(output.stdout)

        assertTrue(payload.isObject)
        assertTrue(payload.has("schemaVersion"))
        assertTrue(payload.has("modules"))
        assertTrue(payload.has("defaultPipeline"))
        assertTrue(payload.has("compatibility"))
        assertTrue(payload.has("orderingConstraints"))
    }

    @Test
    fun engine_jar_schema_command_emits_single_json_payload() {
        val engineJar = engineJarPath()
        assumeTrue(Files.isRegularFile(engineJar), "Skipping: obfuscator-engine.jar not built at $engineJar")

        val result = runCommand(listOf("java", "-jar", engineJar.toString(), "-schema"), engineJar.parent)
        val stdoutLines = result.stdout.lineSequence().filter { it.isNotBlank() }.toList()

        assertEquals(0, result.exitCode, "Schema process should exit successfully. stderr=${result.stderr.take(500)}")
        assertEquals("", result.stderr, "Schema process should not write stderr")
        assertTrue(stdoutLines.isNotEmpty(), "Schema process should emit a TOML payload")

        val payload = tomlMapper.readTree(result.stdout)
        assertTrue(payload.isObject)
        assertTrue(payload.has("schemaVersion"))
        assertTrue(payload.has("modules"))
        assertTrue(payload.has("defaultPipeline"))
        assertTrue(payload.has("compatibility"))
        assertTrue(payload.has("orderingConstraints"))
    }

    @Test
    fun dispatchRequest_writes_inspection_payload_to_stdout() {
        val jarPath = Files.createTempFile("javashroud-cli-inspect", ".jar")
        writeInspectionFixture(jarPath)

        try {
            val output = captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Inspect, arrayOf("-inspect", jarPath.toString())),
                    EngineKernel(),
                )
            }
            val payload = tomlMapper.readTree(output)

            assertEquals(jarPath.toAbsolutePath().normalize().toString(), payload.path("jarPath").asText())
            assertEquals(1, payload.path("classCount").asInt())
            assertEquals(1, payload.path("packageCount").asInt())
        } finally {
            Files.deleteIfExists(jarPath)
        }
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

    private fun captureConsole(block: () -> Unit): CapturedConsole {
        val originalOut = System.out
        val originalErr = System.err
        val stdoutBuffer = ByteArrayOutputStream()
        val stderrBuffer = ByteArrayOutputStream()
        System.setOut(PrintStream(stdoutBuffer, true, Charsets.UTF_8))
        System.setErr(PrintStream(stderrBuffer, true, Charsets.UTF_8))
        return try {
            block()
            CapturedConsole(
                stdout = stdoutBuffer.toString(Charsets.UTF_8),
                stderr = stderrBuffer.toString(Charsets.UTF_8),
            )
        } finally {
            System.setOut(originalOut)
            System.setErr(originalErr)
        }
    }

    private fun engineJarPath(): Path {
        val candidates = listOf(
            Path.of("..", "build", "core-engine", "libs", "obfuscator-engine.jar"),
            Path.of("build", "core-engine", "libs", "obfuscator-engine.jar"),
        ).map { it.toAbsolutePath().normalize() }
        return candidates.firstOrNull { Files.isRegularFile(it) } ?: candidates.first()
    }

    private fun runCommand(command: List<String>, workDir: Path): CommandResult {
        val process = ProcessBuilder(command)
            .directory(workDir.toFile())
            .redirectErrorStream(false)
            .start()
        val stdoutBuffer = ByteArrayOutputStream()
        val stderrBuffer = ByteArrayOutputStream()
        val stdoutThread = kotlin.concurrent.thread(start = true, isDaemon = true) { process.inputStream.use { it.copyTo(stdoutBuffer) } }
        val stderrThread = kotlin.concurrent.thread(start = true, isDaemon = true) { process.errorStream.use { it.copyTo(stderrBuffer) } }
        val exited = process.waitFor(60, TimeUnit.SECONDS)
        if (!exited) {
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
        }
        stdoutThread.join(5_000)
        stderrThread.join(5_000)
        return CommandResult(
            exitCode = if (exited) process.exitValue() else -1,
            stdout = stdoutBuffer.toString(Charsets.UTF_8),
            stderr = stderrBuffer.toString(Charsets.UTF_8),
        )
    }

    private fun writeInspectionFixture(jarPath: Path): Unit {
        JarOutputStream(Files.newOutputStream(jarPath)).use { jarOutputStream: JarOutputStream ->
            jarOutputStream.putNextEntry(JarEntry("sample/Foo.class"))
            jarOutputStream.write(sampleClassBytes())
            jarOutputStream.closeEntry()
        }
    }

    private fun sampleClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/Foo", null, "java/lang/Object", null)
        writer.visitEnd()
        return writer.toByteArray()
    }

    private data class CapturedConsole(
        val stdout: String,
        val stderr: String,
    )

    private data class CommandResult(
        val exitCode: Int,
        val stdout: String,
        val stderr: String,
    )
}
