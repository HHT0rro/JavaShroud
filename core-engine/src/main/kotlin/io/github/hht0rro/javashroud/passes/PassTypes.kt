package io.github.hht0rro.javashroud.passes

import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.modules.ObfuscationModule

data class PassDescriptor(
    val id: String,
    val definition: ModuleDefinition,
)

data class ExecutablePass(
    val descriptor: PassDescriptor,
    val module: ObfuscationModule,
)
