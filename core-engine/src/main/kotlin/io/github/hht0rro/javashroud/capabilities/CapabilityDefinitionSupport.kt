package io.github.hht0rro.javashroud.capabilities

import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ModuleTargetingCapability
import io.github.hht0rro.javashroud.model.schema.ParamSchema
import io.github.hht0rro.javashroud.model.schema.VariantRequirement

internal const val LAYOUT_SENSITIVE_COMPATIBILITY_NOTE = "Java 8 classfile 兼容：不应抬升输入 classfile major version；但可能改变类文件布局、反射可见性或运行时初始化路径，发布前请用目标业务场景验证。"
internal const val RUNTIME_HELPER_COMPATIBILITY_NOTE = "会注入运行时 helper 或 native 入口；目标产物通常需要 Java 11+ 运行时和当前平台 helper/native 支持，请确认目标环境、监控工具和加载策略兼容。"

internal val CLASS_TARGETING = ModuleTargetingCapability(
    supported = true,
    targetKinds = listOf("class"),
)

internal val CLASS_AND_METHOD_TARGETING = ModuleTargetingCapability(
    supported = true,
    targetKinds = listOf("class", "method"),
)

fun capabilityDefinition(
    id: String,
    name: String,
    description: String,
    tagIds: List<String>,
    stability: String,
    params: List<ParamSchema> = emptyList(),
    risk: String = "low",
    requiresRuntimeFlags: List<String> = emptyList(),
    platformConstraints: List<String> = emptyList(),
    compatibilityNotes: String = "",
    requiredPassIds: List<String> = emptyList(),
    requiresAnyPassIds: List<String> = emptyList(),
    variantRequirements: List<VariantRequirement> = emptyList(),
    defaultEnabled: Boolean = true,
    requiresOptIn: Boolean = false,
    targeting: ModuleTargetingCapability,
): ModuleDefinition = ModuleDefinition(
    id = id,
    name = name,
    description = description,
    tagIds = tagIds,
    params = params,
    stability = stability,
    risk = risk,
    requiresRuntimeFlags = requiresRuntimeFlags,
    platformConstraints = platformConstraints,
    compatibilityNotes = compatibilityNotes,
    requiredPassIds = requiredPassIds,
    requiresAnyPassIds = requiresAnyPassIds,
    variantRequirements = variantRequirements,
    defaultEnabled = defaultEnabled,
    requiresOptIn = requiresOptIn || risk == "high",
    targeting = targeting,
)

internal fun capabilityDefinitions(bindings: List<CapabilityBinding>): List<ModuleDefinition> =
    bindings.map { binding: CapabilityBinding ->
        capabilityDefinition(
            id = binding.id,
            name = binding.name,
            description = binding.description,
            tagIds = binding.tagIds,
            stability = binding.stability,
            params = binding.params,
            risk = binding.risk,
            requiresRuntimeFlags = binding.requiresRuntimeFlags,
            platformConstraints = binding.platformConstraints,
            compatibilityNotes = binding.compatibilityNotes,
            requiredPassIds = binding.requiredPassIds,
            requiresAnyPassIds = binding.requiresAnyPassIds,
            variantRequirements = binding.variantRequirements,
            defaultEnabled = binding.defaultEnabled,
            requiresOptIn = binding.requiresOptIn,
            targeting = binding.targeting,
        )
    }
