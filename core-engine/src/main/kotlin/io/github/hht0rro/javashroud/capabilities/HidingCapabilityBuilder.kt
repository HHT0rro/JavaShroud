package io.github.hht0rro.javashroud.capabilities

import io.github.hht0rro.javashroud.model.schema.ModuleDefinition

internal fun hidingCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        id = "member-hide",
        name = "Member Hide",
        description = "Mark fields and methods with the ACC_SYNTHETIC flag to hide them from IDEs and decompilers.",
        tagIds = listOf("hiding"),
        stability = "experimental",
        risk = "medium",
        requiresOptIn = true,
        defaultEnabled = false,
        compatibilityNotes = LAYOUT_SENSITIVE_COMPATIBILITY_NOTE,
    ),
)

fun buildHidingCapabilityDefinitions(): List<ModuleDefinition> = capabilityDefinitions(hidingCapabilityBindings())
