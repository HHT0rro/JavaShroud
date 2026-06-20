package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.kernel.EngineKernel

class EngineCliAdapter(
    private val kernel: EngineKernel = EngineKernel(),
) {
    fun handle(args: Array<String>): Unit {
        val request: EngineCliRequest = resolveRequestOrFail(args)
        handleResolvedRequest(request = request, kernel = kernel)
    }
}

internal fun resolveRequestOrFail(args: Array<String>): EngineCliRequest {
    val command = try {
        parseCommand(args)
    } catch (error: Throwable) {
        failWithStderr(error)
    }
    return try {
        buildCommandRequest(command = command, args = args)
    } catch (error: Throwable) {
        handleCommandFailure(command = command, error = error)
    }
}


