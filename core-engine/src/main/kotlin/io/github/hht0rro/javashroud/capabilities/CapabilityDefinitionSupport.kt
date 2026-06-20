package io.github.hht0rro.javashroud.capabilities

import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ParamSchema

internal const val LAYOUT_SENSITIVE_COMPATIBILITY_NOTE = "可能改变类文件布局、反射可见性或运行时初始化路径；发布前请用目标业务场景验证。"
internal const val RUNTIME_HELPER_COMPATIBILITY_NOTE = "会注入运行时 helper 或 native 入口；请确认目标环境、监控工具和加载策略兼容。"

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
    defaultEnabled: Boolean = true,
    requiresOptIn: Boolean = false,
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
    defaultEnabled = defaultEnabled,
    requiresOptIn = requiresOptIn || risk == "high" || risk == "ultra-high",
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
            defaultEnabled = binding.defaultEnabled,
            requiresOptIn = binding.requiresOptIn,
        )
    }
