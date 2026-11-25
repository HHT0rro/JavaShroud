package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildVmProtectionCapabilityDefinitions

internal fun buildVmProtectionModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildVmProtectionCapabilityDefinitions(),
    bindings = vmProtectionModuleBindings(),
)
