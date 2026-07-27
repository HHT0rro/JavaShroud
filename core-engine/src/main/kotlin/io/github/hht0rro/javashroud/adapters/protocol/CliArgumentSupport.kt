package io.github.hht0rro.javashroud.adapters.protocol

import java.nio.file.Path

sealed interface EngineCommand {
    data object Schema : EngineCommand
    data object Inspect : EngineCommand
    data object Run : EngineCommand
    data object GarbageCollect : EngineCommand
}

internal data class EngineCommandSpec(
    val command: EngineCommand,
    val flag: String,
    val expectedArgCount: Int,
    val usageSuffix: String,
)

internal val schemaCommandSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.Schema,
    flag = "-schema",
    expectedArgCount = 1,
    usageSuffix = "-schema",
)

internal val runCommandSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.Run,
    flag = "-config",
    expectedArgCount = 2,
    usageSuffix = "-config <absolute-config-path>",
)

internal val inspectCommandSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.Inspect,
    flag = "-inspect",
    expectedArgCount = 2,
    usageSuffix = "-inspect <absolute-jar-path>",
)

internal val garbageCollectPreviewCommandSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.GarbageCollect,
    flag = "-gc",
    expectedArgCount = 1,
    usageSuffix = "-gc",
)

internal val garbageCollectApplyCommandSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.GarbageCollect,
    flag = "-gc",
    expectedArgCount = 2,
    usageSuffix = "-gc --apply",
)

internal val supportedCommandSpecs: List<EngineCommandSpec> = listOf(
    schemaCommandSpec,
    runCommandSpec,
    inspectCommandSpec,
    garbageCollectPreviewCommandSpec,
    garbageCollectApplyCommandSpec,
)

fun parseCommand(args: Array<String>): EngineCommand {
    return supportedCommandSpecs.firstOrNull { spec: EngineCommandSpec -> matchesCommand(spec, args) }?.command
        ?: throw IllegalArgumentException(buildCommandUsageErrorMessage())
}

fun parseConfigPath(args: Array<String>): Path {
    ensureCommand(runCommandSpec, args)
    return normalizedArgumentPath(args[1])
}

fun parseInspectJarPath(args: Array<String>): Path {
    ensureCommand(inspectCommandSpec, args)
    return normalizedArgumentPath(args[1])
}

fun parseGarbageCollectApply(args: Array<String>): Boolean {
    return when {
        matchesCommand(garbageCollectPreviewCommandSpec, args) -> false
        matchesCommand(garbageCollectApplyCommandSpec, args) && args[1] == "--apply" -> true
        else -> throw IllegalArgumentException(buildCommandUsageErrorMessage(garbageCollectApplyCommandSpec, args))
    }
}
