package io.github.hht0rro.javashroud.adapters.protocol

import java.nio.file.Path

internal fun matchesCommand(spec: EngineCommandSpec, args: Array<String>): Boolean =
    args.size == spec.expectedArgCount && args.firstOrNull() == spec.flag

internal fun ensureCommand(spec: EngineCommandSpec, args: Array<String>): Unit {
    if (!matchesCommand(spec, args)) {
        throw IllegalArgumentException(buildCommandUsageErrorMessage(spec, args))
    }
}

internal fun normalizedArgumentPath(argument: String): Path = Path.of(argument).toAbsolutePath().normalize()