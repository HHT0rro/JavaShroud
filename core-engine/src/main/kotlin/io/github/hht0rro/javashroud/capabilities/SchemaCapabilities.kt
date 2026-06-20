package io.github.hht0rro.javashroud.capabilities

import io.github.hht0rro.javashroud.compatibility.buildPassCompatibilityRules
import io.github.hht0rro.javashroud.compatibility.buildOrderingConstraints
import io.github.hht0rro.javashroud.model.schema.EngineSchemaPayload
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition

fun buildEngineSchemaPayload(): EngineSchemaPayload = EngineSchemaPayload(
    schemaVersion = engineSchemaVersion(),
    engineVersion = engineVersion(),
    vbcVersion = vbcVersion(),
    tags = sortedCapabilityTagDefinitions(),
    modules = buildSchemaModuleDefinitions(),
    compatibility = buildPassCompatibilityRules(),
    defaultPipeline = buildDefaultPipeline(),
    orderingConstraints = buildOrderingConstraints(),
)

/**
 * Recommended default pipeline: only stable/experimental-safe passes
 * that do not require runtime flags or platform-specific support.
 */
internal fun buildDefaultPipeline(): List<String> = listOf(
    "strip-compile-debug-info",
)

internal fun buildSchemaModuleDefinitions(): List<ModuleDefinition> =
    (
        buildMetadataCapabilityDefinitions() +
            buildRenamingCapabilityDefinitions() +
            buildEncryptionCapabilityDefinitions() +
            buildObfuscationCapabilityDefinitions() +
            buildHidingCapabilityDefinitions() +
            buildLoaderProtectionCapabilityDefinitions() +
            buildHelperDeploymentCapabilityDefinitions() +
            buildRuntimeDefenseCapabilityDefinitions() +
            buildVmProtectionCapabilityDefinitions() + buildNativeKernelCapabilityDefinitions()
        ).sortedBy { definition: ModuleDefinition -> definition.id }
