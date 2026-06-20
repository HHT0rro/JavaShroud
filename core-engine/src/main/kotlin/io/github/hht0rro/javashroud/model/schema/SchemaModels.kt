package io.github.hht0rro.javashroud.model.schema

import com.fasterxml.jackson.databind.JsonNode

data class ParamSchema(
    val key: String,
    val type: String,
    val defaultValue: JsonNode?,
    val options: List<String>?,
    val description: String,
    val hidden: Boolean = false,
)

fun ParamSchema.toJsonMap(): Map<String, Any?> = buildMap {
    put("key", key)
    put("type", type)
    // TOML 无 null 类型；为 null（含 Jackson NullNode）时省略键，避免 TomlMapper 写出空字符串 ''。
    if (defaultValue != null && !defaultValue.isNull) put("defaultValue", defaultValue)
    if (options != null) put("options", options)
    put("description", description)
    put("hidden", hidden)
}

data class ModuleTagDefinition(
    val id: String,
    val name: String,
    val description: String,
    val order: Int,
)

fun ModuleTagDefinition.toJsonMap(): Map<String, Any> = mapOf(
    "id" to id,
    "name" to name,
    "description" to description,
    "order" to order,
)

data class ModuleDefinition(
    val id: String,
    val name: String,
    val description: String,
    val tagIds: List<String>,
    val params: List<ParamSchema>,
    val stability: String,
    val risk: String = "low",
    val requiresRuntimeFlags: List<String> = emptyList(),
    val platformConstraints: List<String> = emptyList(),
    val compatibilityNotes: String = "",
    val requiredPassIds: List<String> = emptyList(),
    val requiresAnyPassIds: List<String> = emptyList(),
    val defaultEnabled: Boolean = true,
    val requiresOptIn: Boolean = false,
)

fun ModuleDefinition.toJsonMap(): Map<String, Any> = buildMap {
    put("id", id)
    put("name", name)
    put("description", description)
    put("tagIds", tagIds)
    put("params", params.map(ParamSchema::toJsonMap))
    put("stability", stability)
    put("risk", risk)
    if (requiresOptIn) put("requiresOptIn", true)
    if (!defaultEnabled) put("defaultEnabled", false)
    if (requiresRuntimeFlags.isNotEmpty()) put("requiresRuntimeFlags", requiresRuntimeFlags)
    if (platformConstraints.isNotEmpty()) put("platformConstraints", platformConstraints)
    if (compatibilityNotes.isNotBlank()) put("compatibilityNotes", compatibilityNotes)
    if (requiredPassIds.isNotEmpty()) put("requiredPassIds", requiredPassIds)
    if (requiresAnyPassIds.isNotEmpty()) put("requiresAnyPassIds", requiresAnyPassIds)
}

data class PassCompatibilityRule(
    val passIds: List<String>,
    val severity: String,
    val description: String,
)

fun PassCompatibilityRule.toJsonMap(): Map<String, Any> = mapOf(
    "passIds" to passIds,
    "severity" to severity,
    "description" to description,
)

/**
 * Declares a dependency or ordering constraint between passes.
 * The planner uses these to auto-order or reject incompatible combinations.
 */
data class OrderingConstraint(
    val before: String,
    val after: String,
    val reason: String,
    val hard: Boolean = true,
)

fun OrderingConstraint.toJsonMap(): Map<String, Any> = mapOf(
    "before" to before,
    "after" to after,
    "reason" to reason,
    "hard" to hard,
)

data class EngineSchemaPayload(
    val schemaVersion: String,
    val engineVersion: String,
    val vbcVersion: String,
    val tags: List<ModuleTagDefinition>,
    val modules: List<ModuleDefinition>,
    val compatibility: List<PassCompatibilityRule> = emptyList(),
    val defaultPipeline: List<String> = emptyList(),
    val orderingConstraints: List<OrderingConstraint> = emptyList(),
)
