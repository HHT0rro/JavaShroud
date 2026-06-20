package io.github.hht0rro.javashroud.adapters.protocol

import java.nio.file.Path

internal sealed interface EngineCliRequest {
    val command: EngineCommand
}

internal data object SchemaCommandRequest : EngineCliRequest {
    override val command: EngineCommand = EngineCommand.Schema
}

internal data class InspectCommandRequest(
    val inputJarPath: Path,
) : EngineCliRequest {
    override val command: EngineCommand = EngineCommand.Inspect
}

internal data class RunCommandRequest(
    val runRequest: EngineRunRequest,
) : EngineCliRequest {
    override val command: EngineCommand = EngineCommand.Run
}

internal fun buildCommandRequest(command: EngineCommand, args: Array<String>): EngineCliRequest = when (command) {
    EngineCommand.Schema -> SchemaCommandRequest
    EngineCommand.Inspect -> InspectCommandRequest(parseInspectJarPath(args))
    EngineCommand.Run -> RunCommandRequest(buildRunRequest(args))
}
