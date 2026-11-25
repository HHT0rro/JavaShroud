package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.InspectCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.SchemaCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.resolveRequestOrFail
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files

class EngineCliAdapterTest {
    @Test
    fun resolveRequestOrFail_returns_schema_request() {
        assertEquals(SchemaCommandRequest, resolveRequestOrFail(arrayOf("-schema")))
    }

    @Test
    fun resolveRequestOrFail_returns_typed_inspect_request() {
        val request = resolveRequestOrFail(arrayOf("-inspect", "C:/tmp/input.jar"))
        val inspectRequest = assertIs<InspectCommandRequest>(request)
        assertEquals(
            java.nio.file.Path.of("C:/tmp/input.jar").toAbsolutePath().normalize(),
            inspectRequest.inputJarPath,
        )
    }

    @Test
    fun resolveRequestOrFail_fails_for_invalid_arguments() {
        assertFailsWith<IllegalArgumentException> {
            resolveRequestOrFail(emptyArray())
        }
    }

    @Test
    fun resolveRequestOrFail_writes_run_request_failures_as_error_event() {
        val missingConfig = Files.createTempDirectory("javashroud-cli-missing-config").resolve("missing.json")
        val stdout = captureStdout {
            assertFailsWith<IllegalArgumentException> {
                resolveRequestOrFail(arrayOf("-config", missingConfig.toString()))
            }
        }

        assertTrue(stdout.contains("type = \"error\""), stdout)
        assertTrue(stdout.contains("Engine execution failed"), stdout)
        assertTrue(stdout.contains("missing.json"), stdout)
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

