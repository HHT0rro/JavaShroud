package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildLoaderProtectionCapabilityDefinitions

internal fun buildLoaderProtectionModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildLoaderProtectionCapabilityDefinitions(),
    bindings = loaderProtectionModuleBindings(),
)
