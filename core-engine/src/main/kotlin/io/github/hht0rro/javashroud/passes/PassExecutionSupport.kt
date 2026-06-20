package io.github.hht0rro.javashroud.passes

import io.github.hht0rro.javashroud.analysis.buildRenamePlan
import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.artifact.classSummaryIndex
import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.passes.PassContext
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment

internal data class PassApplyResult(
    val context: PassContext,
    val transformedClassCount: Int,
    val transformedMemberCount: Int,
    val plannedRenameCount: Int,
)

internal fun applyRegisteredPass(spec: PassSpec, executable: ExecutablePass, context: PassContext): PassContext =
    applyRegisteredPassWithMetrics(spec, executable, context).context

internal fun applyRegisteredPassWithMetrics(spec: PassSpec, executable: ExecutablePass, context: PassContext): PassApplyResult {
    if (!spec.enabled) {
        return PassApplyResult(
            context = context.copy(events = context.events + createPassEvent(message = buildDisabledPassMessage(spec.id))),
            transformedClassCount = 0,
            transformedMemberCount = 0,
            plannedRenameCount = 0,
        )
    }

    val artifact = context.artifact
    val currentSummary = artifact.currentAnalysisSummary(context)
    val ruleMatches = currentSummary.ruleMatches
    val passParams: Map<String, Any> = spec.params.mapValues { (_, v) ->
        when {
            v.isTextual -> v.asText()
            v.isIntegralNumber && v.canConvertToInt() -> v.asInt()
            v.isIntegralNumber -> v.asLong()
            v.isNumber -> v.asDouble()
            v.isBoolean -> v.asBoolean()
            else -> v.asText()
        }
    }
    val effectivePassParams = if (spec.id == "method-virtualization") {
        require(EmbeddedHelperDeployment.hasLoadableNativeKernel()) {
            "method-virtualization requires a bundled sealed JNI VM kernel; " +
                "no compatible native kernel resource is available, so refusing to emit a native-only VM stub that would return default values at runtime"
        }
        passParams + ("__nativeOnlyInterpreter" to true)
    } else {
        passParams
    }
    val transformResult = executable.module.transform.apply(artifact, ruleMatches, effectivePassParams)

    return PassApplyResult(
        context = context.copy(artifact = transformResult.artifact),
        transformedClassCount = transformResult.transformedClassCount,
        transformedMemberCount = transformResult.transformedMemberCount,
        plannedRenameCount = currentSummary.renamePlan.entries.size,
    )
}

private fun io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact.currentAnalysisSummary(context: PassContext): JarAnalysisSummary {
    val currentClassSummaries = classArtifacts.map { it.summary }
    val currentRuleMatches = buildRuleMatches(context.config.ruleSet, currentClassSummaries)
    return analysisSummary.copy(
        classCount = currentClassSummaries.size,
        resourceCount = resourceCount(jarEntries, currentClassSummaries.size),
        classSummaries = currentClassSummaries,
        classNameIndex = classSummaryIndex(currentClassSummaries),
        ruleMatches = currentRuleMatches,
        renamePlan = buildRenamePlan(currentRuleMatches, currentClassSummaries),
    )
}
