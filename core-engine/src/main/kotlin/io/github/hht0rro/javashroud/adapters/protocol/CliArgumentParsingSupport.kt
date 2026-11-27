package io.github.hht0rro.javashroud.adapters.protocol

import java.nio.file.Path

internal fun matchesCommand(spec: EngineCommandSpec, args: Array<String>): Boolean =
    args.size == spec.expectedArgCount && args.firstOrNull() == spec.flag && when (spec) {
        garbageCollectApplyCommandSpec -> args.getOrNull(1) == "--apply"
        runApkCommandSpec -> args.getOrNull(2) == "--apk"
        runLogCommandSpec -> args.getOrNull(2) == "--log-file"
        runApkLogCommandSpec -> args.getOrNull(2) == "--apk" && args.getOrNull(3) == "--log-file"
        directRunSpec -> args.getOrNull(2) == "--output"
        directRunLogSpec -> args.getOrNull(2) == "--output" && args.getOrNull(4) == "--log-file"
        else -> true
    }

internal fun ensureCommand(spec: EngineCommandSpec, args: Array<String>): Unit {
    if (!matchesCommand(spec, args)) {
        throw IllegalArgumentException(buildCommandUsageErrorMessage(spec, args))
    }
}

internal fun normalizedArgumentPath(argument: String): Path = Path.of(argument).toAbsolutePath().normalize()
