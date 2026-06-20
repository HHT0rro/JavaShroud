package io.github.hht0rro.javashroud.adapters.protocol

internal fun writeProtocolLine(payload: Map<String, *>): Unit {
    writeProtocolTextLine(writeProtocolPayload(payload))
}

internal fun writeProtocolTextLine(payload: String): Unit {
    System.out.write((payload.trimEnd() + "\n").toByteArray(Charsets.UTF_8))
    System.out.flush()
}
