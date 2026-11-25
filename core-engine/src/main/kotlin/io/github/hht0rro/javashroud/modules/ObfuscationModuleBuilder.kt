package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildObfuscationCapabilityDefinitions

internal fun buildObfuscationModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildObfuscationCapabilityDefinitions(),
    bindings = obfuscationModuleBindings(),
)
