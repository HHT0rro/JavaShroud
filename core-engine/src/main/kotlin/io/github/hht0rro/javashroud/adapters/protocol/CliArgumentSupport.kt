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

internal val runApkCommandSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.Run,
    flag = "-config",
    expectedArgCount = 3,
    usageSuffix = "-config <absolute-config-path> --apk",
)

internal val runLogCommandSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.Run,
    flag = "-config",
    expectedArgCount = 4,
    usageSuffix = "-config <absolute-config-path> --log-file <absolute-path>",
)

internal val runApkLogCommandSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.Run,
    flag = "-config",
    expectedArgCount = 5,
    usageSuffix = "-config <absolute-config-path> --apk --log-file <absolute-path>",
)

/** Config-less direct run: input/output paths as CLI flag values. */
internal val directRunSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.Run,
    flag = "--input",
    expectedArgCount = 4,
    usageSuffix = "--input <absolute-input-path> --output <absolute-output-path>",
)

internal val directRunLogSpec: EngineCommandSpec = EngineCommandSpec(
    command = EngineCommand.Run,
    flag = "--input",
    expectedArgCount = 6,
    usageSuffix = "--input <absolute-input-path> --output <absolute-output-path> --log-file <absolute-path>",
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
    runApkCommandSpec,
    runLogCommandSpec,
    runApkLogCommandSpec,
    directRunSpec,
    directRunLogSpec,
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

/** Optional run-command flags: --apk forces APK mode, --log-file redirects verbose logs. */
data class RunCommandFlags(
    val configPath: Path,
    val forceApk: Boolean,
    val logFilePath: Path?,
    /** Direct (config-less) input path from --input; implies --output. */
    val directInput: Path? = null,
    val directOutput: Path? = null,
)

fun parseRunFlags(args: Array<String>): RunCommandFlags {
    val spec = supportedCommandSpecs.firstOrNull { candidate -> matchesCommand(candidate, args) }
        ?: throw IllegalArgumentException(buildCommandUsageErrorMessage())
    return when (spec) {
        runCommandSpec -> RunCommandFlags(normalizedArgumentPath(args[1]), forceApk = false, logFilePath = null)
        runApkCommandSpec -> RunCommandFlags(normalizedArgumentPath(args[1]), forceApk = true, logFilePath = null)
        runLogCommandSpec -> RunCommandFlags(normalizedArgumentPath(args[1]), forceApk = false, logFilePath = normalizedArgumentPath(args[3]))
        runApkLogCommandSpec -> RunCommandFlags(normalizedArgumentPath(args[1]), forceApk = true, logFilePath = normalizedArgumentPath(args[4]))
        directRunSpec -> RunCommandFlags(
            configPath = normalizedArgumentPath(args[1]),
            forceApk = false,
            logFilePath = null,
            directInput = normalizedArgumentPath(args[1]),
            directOutput = normalizedArgumentPath(args[3]),
        )
        directRunLogSpec -> RunCommandFlags(
            configPath = normalizedArgumentPath(args[1]),
            forceApk = false,
            logFilePath = normalizedArgumentPath(args[5]),
            directInput = normalizedArgumentPath(args[1]),
            directOutput = normalizedArgumentPath(args[3]),
        )
        else -> throw IllegalArgumentException(buildCommandUsageErrorMessage(spec, args))
    }
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
