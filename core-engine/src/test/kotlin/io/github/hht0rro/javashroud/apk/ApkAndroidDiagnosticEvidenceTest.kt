package io.github.hht0rro.javashroud.apk

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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

    private fun journal(name: String): List<JsonNode> = Files.readAllLines(directory.resolve(name))
        .map { ObjectMapper().readTree(it) }
}
