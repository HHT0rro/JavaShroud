package io.github.hht0rro.javashroud.passes

import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec

fun buildRegisteredPasses(config: ObfuscationConfig): List<RegisteredPass> =
    config.passes.map { spec: PassSpec ->
        RegisteredPass(
            spec = spec,
            executable = requireExecutablePass(spec.id),
        )
    }

fun requireExecutablePass(passId: String): ExecutablePass = executablePassRegistry[passId]
    ?: throw IllegalArgumentException(buildUnknownPassMessage(passId))
