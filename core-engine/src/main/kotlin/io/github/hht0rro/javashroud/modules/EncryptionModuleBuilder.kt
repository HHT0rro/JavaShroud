package io.github.hht0rro.javashroud.modules

import io.github.hht0rro.javashroud.capabilities.buildEncryptionCapabilityDefinitions

internal fun buildEncryptionModules(): List<ObfuscationModule> = assembledModuleSet(
    definitions = buildEncryptionCapabilityDefinitions(),
    bindings = encryptionModuleBindings(),
)
