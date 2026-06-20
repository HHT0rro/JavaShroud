package io.github.hht0rro.javashroud.kernel

import io.github.hht0rro.javashroud.model.passes.PassContext
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import io.github.hht0rro.javashroud.passes.RegisteredPass
import io.github.hht0rro.javashroud.passes.applyRegisteredPassWithMetrics

data class PassExecutionResult(
    val context: PassContext,
    val events: List<EngineEvent>,
    val executedPassCount: Int = 0,
    val totalTransformedClasses: Int = 0,
    val totalTransformedMembers: Int = 0,
    val totalPlannedRenames: Int = 0,
)

fun buildRunEvents(
    bootstrapEvents: List<EngineEvent>,
    summaryEvent: EngineEvent,
    passExecution: PassExecutionResult,
    doneEvent: EngineEvent,
): List<EngineEvent> = bootstrapEvents + summaryEvent + passExecution.events + passExecution.context.events + doneEvent

fun executeRegisteredPasses(
    initialContext: PassContext,
    registeredPasses: List<RegisteredPass>,
    emit: (EngineEvent) -> Unit = {},
): PassExecutionResult {
    if (registeredPasses.isEmpty()) {
        return PassExecutionResult(context = initialContext, events = emptyList())
    }

    var totalTransformedClasses = 0
    var totalTransformedMembers = 0
    var totalPlannedRenames = 0

    val finalContext = registeredPasses.foldIndexed(initialContext) { index: Int, context: PassContext, registeredPass: RegisteredPass ->
        emit(buildPassTickEvent(passId = registeredPass.spec.id, passIndex = index, totalPassCount = registeredPasses.size, isStart = true))
        val result = applyRegisteredPassWithMetrics(
            spec = registeredPass.spec,
            executable = registeredPass.executable,
            context = context,
        )
        totalTransformedClasses += result.transformedClassCount
        totalTransformedMembers += result.transformedMemberCount
        totalPlannedRenames = result.plannedRenameCount
        emit(buildPassTickEvent(passId = registeredPass.spec.id, passIndex = index, totalPassCount = registeredPasses.size, isStart = false))
        result.context
    }
    return PassExecutionResult(
        context = finalContext,
        events = emptyList(),
        executedPassCount = registeredPasses.size,
        totalTransformedClasses = totalTransformedClasses,
        totalTransformedMembers = totalTransformedMembers,
        totalPlannedRenames = totalPlannedRenames,
    )
}