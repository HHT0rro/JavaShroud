package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildHelperDeploymentCapabilityDefinitions

internal fun buildHelperDeploymentModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildHelperDeploymentCapabilityDefinitions(),
    bindings = helperDeploymentModuleBindings(),
)
