package io.github.hht0rro.javashroud.passes

import io.github.hht0rro.javashroud.modules.ObfuscationModule

internal fun passDescriptor(module: ObfuscationModule): PassDescriptor = PassDescriptor(
    id = module.definition.id,
    definition = module.definition,
)

internal fun executablePass(module: ObfuscationModule): ExecutablePass = ExecutablePass(
    descriptor = passDescriptor(module = module),
    module = module,
)
