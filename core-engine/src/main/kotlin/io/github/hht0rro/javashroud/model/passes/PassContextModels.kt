package io.github.hht0rro.javashroud.model.passes

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.protocol.EngineEvent

data class PassContext(
    val config: ObfuscationConfig,
    val artifact: BytecodeArtifact,
    val events: List<EngineEvent>,
)
