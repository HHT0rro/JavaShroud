package io.github.hht0rro.javashroud.capabilities

import io.github.hht0rro.javashroud.model.schema.ModuleDefinition

internal fun metadataCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        id = "strip-compile-debug-info",
        name = "Strip Compile Debug Info",
        description = "Remove source, debug, line number, parameter, and local variable metadata from matched classes.",
        tagIds = listOf("metadata"),
        stability = "stable",
        risk = "low",
        compatibilityNotes = "移除调试属性，不改变业务字节码语义；仍建议确认调试、堆栈和诊断链路预期。",
    ),
)

fun buildMetadataCapabilityDefinitions(): List<ModuleDefinition> = capabilityDefinitions(metadataCapabilityBindings())
