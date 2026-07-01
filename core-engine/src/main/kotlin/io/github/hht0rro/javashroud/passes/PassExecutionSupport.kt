package io.github.hht0rro.javashroud.passes

import io.github.hht0rro.javashroud.analysis.buildRenamePlan
import io.github.hht0rro.javashroud.analysis.buildRuleMatches
import io.github.hht0rro.javashroud.analysis.matchesClassPattern
import io.github.hht0rro.javashroud.analysis.parseTargetSelector
import io.github.hht0rro.javashroud.artifact.classSummaryIndex
import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.model.passes.PassContext
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_PRELOAD_INDEX_RESOURCE

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
    if (preservesExistingVmRuntime(artifact) && spec.id in priorVmAbiPreservingSkippedPasses) {
        return PassApplyResult(
            context = context.copy(events = context.events + createPassEvent(message = "Skipped pass for prior sealed VM ABI preservation: id=${spec.id}")),
            transformedClassCount = 0,
            transformedMemberCount = 0,
            plannedRenameCount = 0,
        )
    }
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
        context = context.copy(
            config = remapConfigRulesAfterClassRename(context.config, artifact, transformResult.artifact, spec.id),
            artifact = transformResult.artifact,
        ),
        transformedClassCount = transformResult.transformedClassCount,
        transformedMemberCount = transformResult.transformedMemberCount,
        plannedRenameCount = currentSummary.renamePlan.entries.size,
    )
}

private val priorVmAbiPreservingSkippedPasses = setOf(
    "anti-decompiler-structure",
    "anti-dump-protection",
    "anti-instrumentation",
    "anti-symbolic-execution",
    "callsite-rotation-protection",
    "condy-constant-indirection",
    "control-flow-flattening",
    "control-flow-obfuscation",
    "exception-semantic-virtualization",
    "field-string-encryption",
    "integer-constant-obfuscation",
    "invoke-dynamic-indirection",
    "jni-microkernel-loader",
    "method-body-delayed-decryption",
    "method-virtualization",
    "reference-proxy",
    "static-init-perturbation",
    "string-encryption",
    "strip-compile-debug-info",
)

private fun preservesExistingVmRuntime(artifact: io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact): Boolean =
    artifact.jarEntries.any { it.name == VBC4_VM_PRELOAD_INDEX_RESOURCE } &&
        artifact.jarEntries.none { it.name == VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE }

private fun remapConfigRulesAfterClassRename(
    config: ObfuscationConfig,
    before: io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact,
    after: io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact,
    passId: String,
): ObfuscationConfig {
    if (passId !in setOf("rename-classes", "rename-packages")) return config
    val classRenameMap = before.classArtifacts.zip(after.classArtifacts)
        .mapNotNull { (oldClass, newClass) ->
            val oldName = oldClass.summary.internalName
            val newName = newClass.summary.internalName
            if (oldName == newName) null else oldName to newName
        }
        .toMap()
    if (classRenameMap.isEmpty()) return config
    return config.copy(ruleSet = remapRuleSetClassTargets(config.ruleSet, before.analysisSummary.classSummaries.map { it.internalName }, classRenameMap))
}

private fun remapRuleSetClassTargets(ruleSet: RuleSet, originalClassNames: List<String>, classRenameMap: Map<String, String>): RuleSet {
    val remappedRules = ruleSet.rules.flatMap { rule -> remapRuleClassTarget(rule, originalClassNames, classRenameMap) }
    return RuleSet(remappedRules.distinct())
}

private fun remapRuleClassTarget(rule: RuleSpec, originalClassNames: List<String>, classRenameMap: Map<String, String>): List<RuleSpec> {
    val selector = parseTargetSelector(rule.target)
    val memberSuffix = rule.target.substringAfter('#', missingDelimiterValue = "").let { suffix ->
        if ('#' in rule.target) "#$suffix" else ""
    }
    val matchedRenames = originalClassNames
        .filter { originalName -> matchesClassPattern(originalName, selector.classPattern) }
        .mapNotNull { originalName -> classRenameMap[originalName] }
        .distinct()
    if (matchedRenames.isEmpty()) return listOf(rule)
    return matchedRenames.map { renamedClassName -> rule.copy(target = renamedClassName + memberSuffix) }
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
