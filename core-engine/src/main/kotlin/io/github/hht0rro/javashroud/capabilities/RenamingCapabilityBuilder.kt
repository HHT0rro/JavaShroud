package io.github.hht0rro.javashroud.capabilities

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ParamSchema

private val renamingParams = listOf(
    ParamSchema(
        key = "dictionaryStyle",
        type = "enum",
        defaultValue = JsonNodeFactory.instance.textNode("sequential"),
        options = listOf("iiliii", "ooO0oO", "nnmnmnm", "sequential", "unicode-confusable", "custom-file"),
        description = "Naming dictionary style: iiliii (homoglyph i/l), ooO0oO (homoglyph o/O/0), " +
            "nnmnmnm (homoglyph n/m), sequential (C0000/m0000), " +
            "unicode-confusable (visually similar Unicode characters), " +
            "custom-file (load from dictionaryFile param).",
    ),
    ParamSchema(
        key = "seed",
        type = "number",
        defaultValue = JsonNodeFactory.instance.nullNode(),
        options = null,
        description = "Deterministic seed for name generation. Null or absent means random. " +
            "Enables reproducible builds for identical input.",
    ),
    ParamSchema(
        key = "preservePackageDepth",
        type = "number",
        defaultValue = JsonNodeFactory.instance.numberNode(0),
        options = null,
        description = "Number of leading package segments to preserve when renaming packages. " +
            "0 means rename all segments; 1 keeps the top-level package.",
    ),
    ParamSchema(
        key = "collisionPolicy",
        type = "enum",
        defaultValue = JsonNodeFactory.instance.textNode("append-index"),
        options = listOf("append-index", "rehash", "fail"),
        description = "Policy for handling name collisions: append-index (add _N suffix), " +
            "rehash (generate a new name from seed), fail (throw on collision).",
    ),
    ParamSchema(
        key = "dictionaryFile",
        type = "string",
        defaultValue = JsonNodeFactory.instance.textNode(""),
        options = null,
        description = "Path to custom dictionary file (one name per line) when dictionaryStyle=custom-file.",
    ),
)

private val packageRenamingParams = renamingParams + ParamSchema(
    key = "shufflePackageSegmentCount",
    type = "boolean",
    defaultValue = JsonNodeFactory.instance.booleanNode(true),
    options = null,
    description = "开启后，包路径重命名会同时改变重命名后的包段数量，避免暴露原始包路径层级。" +
        "关闭后，每个原始包段对应一个重命名包段。",
)

internal fun renamingCapabilityBindings(): List<CapabilityBinding> = listOf(
    CapabilityBinding(
        id = "rename-classes",
        name = "Rename Classes",
        description = "Rename matched classes and rewrite bytecode references with configurable dictionary styles, " +
            "collision policies, and deterministic seeding.",
        tagIds = listOf("renaming"),
        stability = "stable",
        risk = "medium",
        requiresOptIn = true,
        compatibilityNotes = "May change reflection, resource loading, and application class-loader behavior unless keep rules preserve externally observed names.",
        params = renamingParams,
    ),
    CapabilityBinding(
        id = "rename-packages",
        name = "Rename Packages",
        description = "Randomize package paths for matched classes with configurable depth preservation, " +
            "dictionary styles, and collision handling.",
        tagIds = listOf("renaming"),
        stability = "stable",
        risk = "medium",
        requiresOptIn = true,
        compatibilityNotes = "May break resource lookup and custom class-loader code that depends on original package paths.",
        params = packageRenamingParams,
    ),
    CapabilityBinding(
        id = "rename-methods",
        name = "Rename Methods",
        description = "Rename matched methods with configurable dictionary styles, seed-based deterministic naming, " +
            "and collision policies while preserving interface method consistency.",
        tagIds = listOf("renaming"),
        stability = "stable",
        risk = "medium",
        requiresOptIn = true,
        compatibilityNotes = "May break reflection, inheritance-sensitive lookups, serialization hooks, and framework method discovery without explicit keep rules.",
        params = renamingParams,
    ),
    CapabilityBinding(
        id = "rename-fields",
        name = "Rename Fields",
        description = "Rename matched fields with configurable dictionary styles and collision policies.",
        tagIds = listOf("renaming"),
        stability = "stable",
        risk = "medium",
        requiresOptIn = true,
        compatibilityNotes = "May break reflective field access, serializers, dependency injection, and framework data binding without explicit keep rules.",
        params = renamingParams,
    ),
)

fun buildRenamingCapabilityDefinitions(): List<ModuleDefinition> = capabilityDefinitions(renamingCapabilityBindings())
