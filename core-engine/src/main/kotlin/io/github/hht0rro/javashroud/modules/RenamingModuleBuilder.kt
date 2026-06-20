package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildRenamingCapabilityDefinitions

internal fun buildRenamingModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildRenamingCapabilityDefinitions(),
    bindings = renamingModuleBindings(),
)
