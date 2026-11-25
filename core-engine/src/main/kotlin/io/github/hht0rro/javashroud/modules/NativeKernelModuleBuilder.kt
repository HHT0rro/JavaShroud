package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildNativeKernelCapabilityDefinitions

internal fun buildNativeKernelModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildNativeKernelCapabilityDefinitions(),
    bindings = nativeKernelModuleBindings(),
)
