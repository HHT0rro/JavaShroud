package io.github.hht0rro.javashroud.passes

import io.github.hht0rro.javashroud.modules.ObfuscationModule
import io.github.hht0rro.javashroud.modules.buildModuleRegistry

internal fun buildExecutablePassRegistry(): Map<String, ExecutablePass> = buildModuleRegistry().values
    .associateBy { module: ObfuscationModule -> module.definition.id }
    .mapValues { entry: Map.Entry<String, ObfuscationModule> -> executablePass(module = entry.value) }
