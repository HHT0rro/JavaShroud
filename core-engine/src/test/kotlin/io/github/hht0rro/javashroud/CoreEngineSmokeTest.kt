package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandUsageErrorMessage
import io.github.hht0rro.javashroud.adapters.protocol.parseCommand
import io.github.hht0rro.javashroud.adapters.protocol.parseConfigPath
import io.github.hht0rro.javashroud.adapters.protocol.parseInspectJarPath
import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CoreEngineSmokeTest {
    @Test
    fun parseCommand_supports_schema_inspect_and_run() {
        assertEquals(EngineCommand.Schema, parseCommand(arrayOf("-schema")))
        assertEquals(EngineCommand.Run, parseCommand(arrayOf("-config", "C:/tmp/config.json")))
        assertEquals(EngineCommand.Inspect, parseCommand(arrayOf("-inspect", "C:/tmp/in.jar")))
    }

    @Test
    fun parseCommand_rejects_invalid_args() {
        val error = assertFailsWith<IllegalArgumentException> {
            parseCommand(emptyArray())
        }

        assertEquals(buildCommandUsageErrorMessage(), error.message)
    }

    @Test
    fun parsePathHelpers_normalize_absolute_paths() {
        assertEquals(Path.of("C:/tmp/config.json").toAbsolutePath().normalize(), parseConfigPath(arrayOf("-config", "C:/tmp/config.json")))
        assertEquals(Path.of("C:/tmp/in.jar").toAbsolutePath().normalize(), parseInspectJarPath(arrayOf("-inspect", "C:/tmp/in.jar")))
    }

    @Test
    fun buildEngineSchemaPayload_exposes_modules_and_tags() {
        val schema = buildEngineSchemaPayload()
        assertTrue(schema.schemaVersion.isNotBlank())
        assertTrue(schema.engineVersion.isNotBlank())
        assertTrue(schema.tags.isNotEmpty())
        assertTrue(schema.modules.isNotEmpty())
        assertTrue(schema.tags.any { it.id == "metadata" })
        assertTrue(schema.tags.any { it.id == "renaming" })
        assertTrue(schema.modules.any { it.id == "strip-compile-debug-info" })
        assertTrue(schema.modules.any { it.id == "rename-classes" })
    }
}
