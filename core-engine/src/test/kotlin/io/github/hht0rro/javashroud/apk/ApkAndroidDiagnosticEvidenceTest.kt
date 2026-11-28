package io.github.hht0rro.javashroud.apk

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.tools.ToolProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertSame
import kotlin.test.assertTrue
import org.junit.jupiter.api.io.TempDir

class ApkAndroidDiagnosticEvidenceTest {
    @TempDir
    lateinit var directory: Path

    private val java = Path.of(System.getProperty("java.home"), "bin", if (System.getProperty("os.name").startsWith("Windows")) "java.exe" else "java").toString()

    @Test
    fun repeatedLabelsRetainEveryInvocationSampleAndRawOutput() {
        val evidence = AndroidDeviceEvidence(directory)
        for (token in listOf("original-token", "protected-token")) {
            evidence.invocationToken = token
            repeat(2) {
                val observation = evidence.sample("markers") {
                    evidence.record("repeated-label", listOf(java, "-version"), 10_000)
                    mapOf("pid" to "6074", "marker" to "web=42")
                }
                assertEquals("web=42", observation["marker"])
            }
        }
        val commands = journal("commands.jsonl")
        val samples = journal("samples.jsonl")
        assertEquals(4, commands.size)
        assertEquals(4, samples.size)
        assertEquals(4, commands.map { it["output"].asText() }.toSet().size)
        assertEquals(listOf(1, 2, 3, 4), samples.map { it["sample"].asInt() })
        commands.zip(samples).forEachIndexed { index, (command, sample) ->
            assertEquals(index + 1, command["sequence"].asInt())
            assertEquals(command["sequence"], sample["first_command"])
            assertEquals(command["sequence"], sample["last_command"])
            assertEquals(command["token"], sample["token"])
            assertEquals(command["sample"], sample["sample"])
            assertEquals(if (index < 2) "original-token" else "protected-token", command["token"].asText())
            assertEquals(0, command["exit_code"].asInt())
            assertFalse(command["timed_out"].asBoolean())
            val output = directory.resolve(command["output"].asText())
            assertEquals(Files.size(output), command["output_bytes"].asLong())
            val hash = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(output))
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            assertEquals(hash, command["output_sha256"].asText())
            assertTrue(Files.readString(output).contains("version"))
            assertTrue(Files.isRegularFile(directory.resolve(command["command_file"].asText())))
            assertTrue(command["started_utc"].asText().endsWith("Z"))
            assertEquals("web=42", sample["observation"]["marker"].asText())
        }
    }

    @Test
    fun missingToolsAndNonzeroDiagnosticsPreserveOriginalFailureAndCleanup() {
        val evidence = AndroidDeviceEvidence(directory)
        evidence.invocationToken = "failed-invocation"
        val original = AssertionError("owned process disappeared")
        val caught = try {
            try {
                evidence.captureFailure(original, listOf(
                    "missing-tool" to listOf(directory.resolve("missing-adb-executable").toString()),
                    "denied-or-unsupported" to listOf(java, "-invalid-owned-diagnostic-option"),
                    "remaining-diagnostic" to listOf(java, "-version"),
                ))
                throw original
            } finally {
                evidence.record("cleanup", listOf(java, "-version"), 10_000)
            }
        } catch (error: AssertionError) {
            error
        }
        assertSame(original, caught)
        assertEquals(2, caught.suppressed.size)
        val commands = journal("commands.jsonl")
        assertEquals(listOf("missing-tool", "denied-or-unsupported", "remaining-diagnostic", "cleanup"), commands.map { it["label"].asText() })
        assertTrue(commands[0]["exit_code"].isNull)
        assertFalse(commands[0]["error"].isNull)
        assertTrue(commands[1]["exit_code"].asInt() != 0)
        assertEquals(0, commands[2]["exit_code"].asInt())
        assertEquals(0, commands[3]["exit_code"].asInt())
        assertTrue(commands.all { it["token"].asText() == "failed-invocation" })
    }

    @Test
    fun timeoutRetainsRawEvidenceAndFollowingCommandsStillRun() {
        val source = directory.resolve("OwnedDiagnosticWait.java")
        Files.writeString(source, "class OwnedDiagnosticWait { public static void main(String[] args) throws Exception { Thread.sleep(30000); } }")
        val evidence = AndroidDeviceEvidence(directory)
        val result = evidence.record("bounded-timeout", listOf(java, source.toString()), 100)
        assertTrue(result.timedOut)
        assertEquals(-1, result.exitCode)
        assertEquals(0, evidence.record("after-timeout", listOf(java, "-version"), 10_000).exitCode)
        val commands = journal("commands.jsonl")
        assertEquals(2, commands.size)
        assertTrue(commands[0]["timed_out"].asBoolean())
        assertEquals(-1, commands[0]["exit_code"].asInt())
        assertTrue(Files.isRegularFile(directory.resolve(commands[0]["output"].asText())))
        assertEquals(0, commands[1]["exit_code"].asInt())
    }

    @Test
    fun cancellationStillCapturesEachDiagnosticAndRestoresInterruptForCleanup() {
        val evidence = AndroidDeviceEvidence(directory)
        val original = InterruptedException("fixture cancelled")
        try {
            Thread.currentThread().interrupt()
            evidence.captureFailure(original, listOf(
                "crash" to listOf(java, "-version"),
                "exit-info" to listOf(java, "-version"),
            ))
            assertTrue(Thread.currentThread().isInterrupted)
            assertTrue(original.suppressed.isEmpty())
        } finally {
            Thread.interrupted()
            assertEquals(0, evidence.record("cleanup", listOf(java, "-version"), 10_000).exitCode)
        }
        assertEquals(listOf("crash", "exit-info", "cleanup"), journal("commands.jsonl").map { it["label"].asText() })
    }

    @Test
    fun nonUtf8SubprocessOutputRetainsRawBytesAndExitStatus() {
        val command = rawOutputCommand()
        val evidence = AndroidDeviceEvidence(directory)
        for (exitCode in listOf(0, 7)) {
            val result = evidence.record("raw-exit-$exitCode", command + exitCode.toString(), 10_000)
            assertEquals(exitCode, result.exitCode)
            assertFalse(result.timedOut)
            assertEquals(rawOutput.toString(Charsets.UTF_8), result.output)
            assertTrue(result.output.contains('\uFFFD'))
        }
        journal("commands.jsonl").forEachIndexed { index, entry ->
            assertEquals(if (index == 0) 0 else 7, entry["exit_code"].asInt())
            assertFalse(entry["timed_out"].asBoolean())
            assertTrue(entry["error"].isNull)
            assertRawOutput(entry)
        }
    }

    @Test
    fun nonUtf8TimeoutRetainsRawBytesAndTimeoutStatus() {
        val command = rawOutputCommand()
        val evidence = AndroidDeviceEvidence(directory)
        val result = evidence.record("raw-timeout", command + "wait", 5_000)
        assertTrue(Files.isRegularFile(directory.resolve("ready")))
        assertTrue(result.timedOut)
        assertEquals(-1, result.exitCode)
        assertEquals(rawOutput.toString(Charsets.UTF_8), result.output)
        assertEquals(0, evidence.record("after-raw-timeout", listOf(java, "-version"), 10_000).exitCode)
        val commands = journal("commands.jsonl")
        assertEquals(2, commands.size)
        assertEquals(-1, commands[0]["exit_code"].asInt())
        assertTrue(commands[0]["timed_out"].asBoolean())
        assertTrue(commands[0]["error"].isNull)
        assertRawOutput(commands[0])
        assertEquals(0, commands[1]["exit_code"].asInt())
    }

    @Test
    fun interruptionRetainsNonUtf8OutputAndExitStatus() {
        val command = rawOutputCommand()
        val evidence = AndroidDeviceEvidence(directory)
        val failure = AtomicReference<Throwable>()
        val interrupted = AtomicBoolean()
        val worker = Thread {
            try {
                evidence.record("raw-interrupted", command + "wait", 30_000)
            } catch (error: Throwable) {
                failure.set(error)
                interrupted.set(Thread.currentThread().isInterrupted)
            }
        }
        worker.start()
        val ready = directory.resolve("ready")
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (!Files.isRegularFile(ready) && worker.isAlive && System.nanoTime() < deadline) Thread.sleep(10)
            assertTrue(Files.isRegularFile(ready), "Child must flush its raw output before interruption")
        } finally {
            worker.interrupt()
            worker.join(10_000)
        }
        assertFalse(worker.isAlive)
        assertIs<InterruptedException>(failure.get())
        assertTrue(interrupted.get())
        val commands = journal("commands.jsonl")
        assertEquals(1, commands.size)
        assertFalse(commands[0]["exit_code"].isNull)
        assertTrue(commands[0]["exit_code"].asInt() != 0)
        assertFalse(commands[0]["timed_out"].isNull)
        assertFalse(commands[0]["timed_out"].asBoolean())
        assertTrue(commands[0]["error"].asText().contains("InterruptedException"))
        assertRawOutput(commands[0])
        val pid = Files.readString(ready).toLong()
        assertFalse(ProcessHandle.of(pid).map { it.isAlive }.orElse(false))
        assertEquals(0, evidence.record("after-interruption", listOf(java, "-version"), 10_000).exitCode)
        assertEquals(2, journal("commands.jsonl").size)
    }

    private val rawOutput = byteArrayOf(0x41, 0xc3.toByte(), 0x28, 0xff.toByte(), 0, 0xe2.toByte(), 0x82.toByte())

    private fun rawOutputCommand(): List<String> {
        val source = directory.resolve("OwnedRawDiagnostic.java")
        Files.writeString(source, """
            import java.nio.file.Files;
            import java.nio.file.Path;
            class OwnedRawDiagnostic {
                public static void main(String[] args) throws Exception {
                    System.out.write(Files.readAllBytes(Path.of(args[0])));
                    System.out.flush();
                    if (args[2].equals("wait")) {
                        Files.writeString(Path.of(args[1]), Long.toString(ProcessHandle.current().pid()));
                        Thread.sleep(30000);
                    } else {
                        System.exit(Integer.parseInt(args[2]));
                    }
                }
            }
        """.trimIndent())
        val payload = directory.resolve("raw.bin")
        Files.write(payload, rawOutput)
        assertEquals(0, ToolProvider.getSystemJavaCompiler().run(null, null, null, "-d", directory.toString(), source.toString()))
        return listOf(java, "-cp", directory.toString(), "OwnedRawDiagnostic", payload.toString(), directory.resolve("ready").toString())
    }

    private fun assertRawOutput(command: JsonNode) {
        val output = directory.resolve(command["output"].asText())
        assertContentEquals(rawOutput, Files.readAllBytes(output))
        assertEquals(rawOutput.size.toLong(), command["output_bytes"].asLong())
        val hash = MessageDigest.getInstance("SHA-256").digest(rawOutput)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
        assertEquals(hash, command["output_sha256"].asText())
    }

    private fun journal(name: String): List<JsonNode> = Files.readAllLines(directory.resolve(name))
        .map { ObjectMapper().readTree(it) }
}
