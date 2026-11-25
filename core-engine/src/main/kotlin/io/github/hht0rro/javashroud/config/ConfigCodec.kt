package io.github.hht0rro.javashroud.config

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.toml.TomlMapper
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.absolutePathString

private val configMapper: ObjectMapper = TomlMapper()
    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)

fun parseConfig(configPath: Path): ObfuscationConfig {
    val content = Files.readString(configPath)
    return try {
        val rootNode = configMapper.readTree(content)
        decodeConfig(rootNode, configPath)
    } catch (error: JsonProcessingException) {
        throw IllegalArgumentException(
            "Invalid config TOML: path=${configPath.absolutePathString()}, reason=${error.originalMessage}",
            error,
        )
    }
}
