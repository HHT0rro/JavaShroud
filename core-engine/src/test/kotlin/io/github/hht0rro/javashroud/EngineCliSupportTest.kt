package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.buildFailureEvent
import io.github.hht0rro.javashroud.adapters.protocol.buildFailureMessage
import kotlin.test.Test
import kotlin.test.assertEquals

class EngineCliSupportTest {
    @Test
    fun buildFailureMessage_uses_exception_message_when_present() {
        val error = IllegalArgumentException("bad-input")
        assertEquals("Engine execution failed: detail=bad-input", buildFailureMessage(error))
    }

    @Test
    fun buildFailureEvent_preserves_error_protocol_shape() {
        val event = buildFailureEvent(IllegalStateException("boom"))

        assertEquals("error", event.level)
        assertEquals("error", event.type)
        assertEquals("Engine execution failed: detail=boom", event.message)
        assertEquals(null, event.progress)
        assertEquals(null, event.outPath)
    }
}
