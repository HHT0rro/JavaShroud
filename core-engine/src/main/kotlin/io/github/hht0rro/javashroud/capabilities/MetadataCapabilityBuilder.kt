package io.github.hht0rro.javashroud.capabilities

import io.github.hht0rro.javashroud.model.schema.ModuleDefinition

internal fun metadataCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        targeting = CLASS_TARGETING,
        id = "strip-compile-debug-info",
        name = "Strip Compile Debug Info",
        description = "Remove source, debug, line number, parameter, and local variable metadata from matched classes.",
        tagIds = listOf("metadata"),
        stability = "stable",
        risk = "low",
        compatibilityNotes = "移除调试属性，不改变业务字节码语义，也不应抬升输入 classfile major version；仍建议确认调试、堆栈和诊断链路预期。",
    ),
    CapabilityBinding(
        targeting = CLASS_TARGETING,
        id = "member-shuffle",
        name = "Member Shuffle",
        description = "Reorder classes, fields, methods, and JAR entries with independent build-local entropy.",
        tagIds = listOf("metadata"),
        stability = "stable",
        risk = "low",
        compatibilityNotes = "仅改变类、字段、方法和 JAR 条目的物理顺序，不改变声明与调用语义。",
    ),
)

fun buildMetadataCapabilityDefinitions(): List<ModuleDefinition> = capabilityDefinitions(metadataCapabilityBindings())
