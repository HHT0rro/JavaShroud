package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.serializeProtocolPayload
import kotlin.test.Test
import kotlin.test.assertTrue

class ProtocolJsonSupportTest {
    @Test
    fun serializeProtocolPayload_writes_toml_fields() {
        val toml = serializeProtocolPayload(
            linkedMapOf(
                "message" to "ok",
                "details" to mapOf("count" to 1),
            ),
        )

        assertTrue(toml.contains("message"))
        assertTrue(toml.contains("ok"))
        assertTrue(toml.contains("details"))
        assertTrue(toml.contains("count = 1"))
    }
}
