package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildHidingCapabilityDefinitions

internal fun buildHidingModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildHidingCapabilityDefinitions(),
    bindings = hidingModuleBindings(),
)
