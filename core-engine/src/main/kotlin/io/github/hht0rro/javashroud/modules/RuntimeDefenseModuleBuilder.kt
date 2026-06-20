package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildRuntimeDefenseCapabilityDefinitions

internal fun buildRuntimeDefenseModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildRuntimeDefenseCapabilityDefinitions(),
    bindings = runtimeDefenseModuleBindings(),
)
