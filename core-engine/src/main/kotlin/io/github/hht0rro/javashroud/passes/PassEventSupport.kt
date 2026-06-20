package io.github.hht0rro.javashroud.passes

import io.github.hht0rro.javashroud.model.protocol.EngineEvent

fun createPassEvent(message: String): EngineEvent = EngineEvent(
    level = "info",
    type = "log",
    message = message,
    progress = null,
    outPath = null,
)
