package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildMetadataCapabilityDefinitions

internal fun buildMetadataModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildMetadataCapabilityDefinitions(),
    bindings = metadataModuleBindings(),
)
