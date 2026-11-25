package io.github.hht0rro.javashroud.adapters.protocol

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.toml.TomlMapper

private val defaultProtocolTomlMapper: ObjectMapper = buildProtocolTomlMapper()

internal fun buildProtocolTomlMapper(): ObjectMapper = TomlMapper()

internal fun serializeProtocolPayload(
    payload: Map<String, *>,
    mapper: ObjectMapper = defaultProtocolTomlMapper,
): String = mapper.writeValueAsString(payload)

fun writeProtocolPayload(payload: Map<String, *>): String = serializeProtocolPayload(payload)
