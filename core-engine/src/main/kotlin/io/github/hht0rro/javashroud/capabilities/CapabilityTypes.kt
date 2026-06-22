package io.github.hht0rro.javashroud.capabilities

import io.github.hht0rro.javashroud.model.schema.ParamSchema

private const val schemaVersion: String = "2"
private const val engineVersion: String = "Dev-0.7.5"
private const val vbcVersion: String = "4.52 "

internal data class CapabilityBinding(
    val id: String,
    val name: String,
    val description: String,
    val tagIds: List<String>,
    val stability: String,
    val params: List<ParamSchema> = emptyList(),
    val risk: String = "low",
    val requiresRuntimeFlags: List<String> = emptyList(),
    val platformConstraints: List<String> = emptyList(),
    val compatibilityNotes: String = "",
    val requiredPassIds: List<String> = emptyList(),
    val requiresAnyPassIds: List<String> = emptyList(),
    val defaultEnabled: Boolean = true,
    val requiresOptIn: Boolean = false,
)

fun engineSchemaVersion(): String = schemaVersion

fun engineVersion(): String = engineVersion

fun vbcVersion(): String = vbcVersion
