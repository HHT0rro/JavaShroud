package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.InspectCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.SchemaCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class EngineCliRequestSupportTest {
    @Test
    fun buildCommandRequest_returns_schema_request_for_schema_command() {
        assertEquals(SchemaCommandRequest, buildCommandRequest(EngineCommand.Schema, arrayOf("-schema")))
    }

    @Test
    fun buildCommandRequest_normalizes_inspect_jar_path() {
        val request = buildCommandRequest(
            EngineCommand.Inspect,
            arrayOf("-inspect", "C:/tmp/input.jar"),
        )

        val inspectRequest = assertIs<InspectCommandRequest>(request)
        assertEquals(
            java.nio.file.Path.of("C:/tmp/input.jar").toAbsolutePath().normalize(),
            inspectRequest.inputJarPath,
        )
    }
}
