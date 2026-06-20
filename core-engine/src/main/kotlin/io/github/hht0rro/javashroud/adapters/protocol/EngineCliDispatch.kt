package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.protocol.EngineEvent

// --- single dispatch entry point ---

internal fun handleResolvedRequest(request: EngineCliRequest, kernel: EngineKernel): Unit {
    try {
        dispatchRequest(request = request, kernel = kernel)
    } catch (error: Throwable) {
        handleCommandFailure(request.command, error)
    }
}

internal fun dispatchRequest(request: EngineCliRequest, kernel: EngineKernel): Unit {
    when (request) {
        SchemaCommandRequest -> handleSchemaCommand()
        is InspectCommandRequest -> handleInspectCommand(request = request, kernel = kernel)
        is RunCommandRequest -> handleRunCommand(request = request.runRequest, kernel = kernel)
    }
}

// --- per-command handlers ---

private fun handleSchemaCommand(): Unit {
    writeEngineSchemaPayload(buildEngineSchemaPayload())
}

private fun handleInspectCommand(request: InspectCommandRequest, kernel: EngineKernel): Unit {
    writeJarInspectionPayload(kernel.inspectJar(request.inputJarPath))
}

private fun handleRunCommand(request: EngineRunRequest, kernel: EngineKernel): Unit {
    kernel.run(request.config, request.configPath, ::writeEvent)
}

// --- failure handling ---

fun handleCommandFailure(command: EngineCommand, error: Throwable): Nothing {
    return when (command) {
        EngineCommand.Run -> failWithEvent(error)
        EngineCommand.Schema, EngineCommand.Inspect -> failWithStderr(error)
    }
}

fun buildFailureMessage(error: Throwable): String {
    val detail = error.message ?: error::class.qualifiedName ?: "unknown-error"
    return "Engine execution failed: detail=" + detail
}

internal fun buildFailureEvent(error: Throwable): EngineEvent = EngineEvent(
    level = "error",
    type = "error",
    message = buildFailureMessage(error),
    progress = null,
    outPath = null,
)

fun failWithEvent(error: Throwable): Nothing {
    writeEvent(buildFailureEvent(error))
    throw error
}

fun failWithStderr(error: Throwable): Nothing {
    System.err.println(buildFailureMessage(error))
    throw error
}
