package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.config.loadValidatedConfig
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import java.nio.file.Path

internal data class EngineRunRequest(
    val configPath: Path,
    val config: ObfuscationConfig,
)

internal fun buildRunRequest(args: Array<String>): EngineRunRequest {
    val configPath: Path = parseConfigPath(args)
    return loadRunRequest(configPath)
}

internal fun loadRunRequest(configPath: Path): EngineRunRequest = EngineRunRequest(
    configPath = configPath,
    config = loadValidatedConfig(configPath),
)
