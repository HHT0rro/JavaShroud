package io.github.hht0rro.javashroud.modules

fun buildModuleRegistry(): Map<String, ObfuscationModule> =
    (
        buildRenamingModules() +
            buildMetadataModules() +
            buildEncryptionModules() +
            buildObfuscationModules() +
            buildHidingModules() +
            buildLoaderProtectionModules() +
            buildHelperDeploymentModules() +
            buildRuntimeDefenseModules() +
            buildVmProtectionModules() + buildNativeKernelModules()
        ).associateBy { module: ObfuscationModule -> module.definition.id }
