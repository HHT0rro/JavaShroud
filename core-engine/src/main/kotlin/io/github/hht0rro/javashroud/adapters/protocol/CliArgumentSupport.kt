package io.github.hht0rro.javashroud.adapters.protocol

import java.nio.file.Path

sealed interface EngineCommand {
    data object Schema : EngineCommand
    data object Inspect : EngineCommand
    data object Run : EngineCommand
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

internal val supportedCommandSpecs: List<EngineCommandSpec> = listOf(
    schemaCommandSpec,
    runCommandSpec,
    inspectCommandSpec,
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
