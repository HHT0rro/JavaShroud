package io.github.hht0rro.javashroud.transforms.protection

import com.fasterxml.jackson.databind.JsonNode
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.transforms.unchangedTransformResult
import io.github.hht0rro.javashroud.model.schema.OrderingConstraint

/**
 * Pass Ordering Planner transform.
 *
 * Upgrades from config-order-driven execution to automatic ordering based on
 * dependency relationships, conflict relationships, and side effects between passes.
 *
 * Capabilities:
 * - Validates pass existence against the capability registry
 * - Validates pass ordering against declared constraints
 * - Auto-sorts passes with deterministic tie-breaking when mode=auto-sort
 * - Rejects incompatible combinations when mode=reject-conflicts
 * - Emits warnings for soft conflicts and redundant combinations
 *
 * This is a meta-pass that modifies the PassContext to reorder subsequent passes.
 */
fun applyPassOrderingPlanner(
    artifact: BytecodeArtifact,
    ruleMatches: List<RuleMatch>,
    params: Map<String, Any>,
): TransformResult {
    // The planner itself doesn't transform bytecode.
    // It operates at the pass-orchestration level.
    // This transform is a no-op at the bytecode level;
    // the actual planning happens in the pass execution pipeline.
    return unchangedTransformResult(artifact)
}

/**
 * Plan pass ordering based on constraints and configuration.
 *
 * Guarantees:
 * - Deterministic: same input always produces the same output.
 * - Explainable: every reordering or rejection has a diagnostic message.
 * - Optimal: constraints satisfied with minimal disruption to user intent.
 *
 * @param passIds The pass IDs from the user's config, in their specified order.
 * @param orderingConstraints The declared ordering constraints.
 * @param hardConflicts The set of hard-conflicting pass pairs.
 * @param softConflicts The set of soft-conflicting pass pairs.
 * @param availablePassIds If provided, validates all requested pass IDs exist in this set.
 * @param optInPassIds Set of pass IDs that require explicit opt-in (warn when present).
 * @param mode Planning mode: "auto-sort", "validate-only", "reject-conflicts"
 * @param strictness Strictness level: "silent", "warn", "reject"
 * @param passParams Parameters keyed by enabled pass ID. Resolver-profile variants
 * use these to select their strict, parameter-aware ordering path.
 * @return A PlanningResult with the reordered passes and any diagnostics.
 */
fun planPassOrdering(
    passIds: List<String>,
    orderingConstraints: List<OrderingConstraint>,
    hardConflicts: Set<Pair<String, String>>,
    softConflicts: Set<Pair<String, String>>,
    availablePassIds: Set<String>? = null,
    optInPassIds: Set<String> = emptySet(),
    mode: String = "auto-sort",
    strictness: String = "warn",
    passParams: Map<String, Map<String, Any?>> = emptyMap(),
): PlanningResult {
    val diagnostics = mutableListOf<PlanningDiagnostic>()
    val resolverProfileActive = isResolverProfileRequest(passIds, passParams)

    // 1. Validate requested passes exist in the capability registry
    if (availablePassIds != null) {
        val missingPasses = passIds.filter { it !in availablePassIds }
        if (missingPasses.isNotEmpty()) {
            diagnostics.add(
                PlanningDiagnostic(
                    level = "error",
                    passes = missingPasses,
                    message = "Missing capabilities: ${missingPasses.joinToString(", ")}. " +
                        "Available: ${availablePassIds.sorted().joinToString(", ")}",
                    causeId = "missing-capability",
                ),
            )
            return PlanningResult(
                orderedPasses = rejectedPassOrder(passIds, resolverProfileActive),
                diagnostics = diagnostics,
                accepted = false,
                resolverProfileActive = resolverProfileActive,
            )
        }
    }

    // 2. Warn about opt-in passes
    val unwarrantedOptIns = passIds.filter { it in optInPassIds }
    if (unwarrantedOptIns.isNotEmpty() && strictness != "silent") {
        diagnostics.add(
            PlanningDiagnostic(
                level = "warn",
                passes = unwarrantedOptIns,
                message = "Opt-in passes selected: ${unwarrantedOptIns.joinToString(", ")}. " +
                    "These require explicit opt-in and may have higher risk.",
                causeId = "opt-in-warning",
            ),
        )
    }

    // 3. Check hard conflicts
    for (conflict in hardConflicts) {
        if (passIds.contains(conflict.first) && passIds.contains(conflict.second)) {
            diagnostics.add(
                PlanningDiagnostic(
                    level = "error",
                    passes = listOf(conflict.first, conflict.second),
                    message = "Hard conflict: '${conflict.first}' and '${conflict.second}' cannot run together.",
                    causeId = "hard-conflict",
                ),
            )
        }
    }

    if ((mode == "reject-conflicts" || resolverProfileActive) && diagnostics.any { it.level == "error" }) {
        return PlanningResult(
            orderedPasses = rejectedPassOrder(passIds, resolverProfileActive),
            diagnostics = diagnostics,
            accepted = false,
            resolverProfileActive = resolverProfileActive,
        )
    }

    // 4. Warn about soft conflicts and redundant combinations
    for (conflict in softConflicts) {
        if (passIds.contains(conflict.first) && passIds.contains(conflict.second)) {
            diagnostics.add(
                PlanningDiagnostic(
                    level = "warn",
                    passes = listOf(conflict.first, conflict.second),
                    message = "Soft conflict: '${conflict.first}' and '${conflict.second}' have overlapping effects.",
                    causeId = "soft-conflict",
                ),
            )
        }
    }

    // 5. Auto-sort using deterministic topological sort
    val effectiveConstraints = if (resolverProfileActive) {
        resolverProfileOrderingConstraints(passIds, orderingConstraints)
    } else {
        orderingConstraints
    }
    val orderedPasses = if (mode == "auto-sort") {
        topologicalSort(passIds, effectiveConstraints, diagnostics)
            ?: rejectedPassOrder(passIds, resolverProfileActive)
    } else {
        // Validate-only: check that existing order satisfies constraints
        validateOrdering(passIds, effectiveConstraints, diagnostics)
        if (resolverProfileActive && diagnostics.any { it.level == "error" }) emptyList() else passIds
    }

    return PlanningResult(
        orderedPasses = orderedPasses,
        diagnostics = diagnostics,
        accepted = diagnostics.none { it.level == "error" },
        resolverProfileActive = resolverProfileActive,
    )
}

private fun rejectedPassOrder(passIds: List<String>, resolverProfileActive: Boolean): List<String> =
    if (resolverProfileActive) emptyList() else passIds

private fun isResolverProfileRequest(
    passIds: List<String>,
    passParams: Map<String, Map<String, Any?>>,
): Boolean {
    val selectedParams = passParams.filterKeys { passId -> passId in passIds }
    fun paramsOf(passId: String): Map<String, Any?> = selectedParams[passId] ?: emptyMap()

    if (planningParamText(paramsOf("string-encryption")["decoderBackend"]) == "jvm-resolver") {
        return true
    }
    if (planningParamText(paramsOf("integer-constant-obfuscation")["rewriteMode"]) == "resolver") {
        return true
    }
    if (planningParamText(paramsOf("invoke-dynamic-indirection")["callSiteForm"]) == "constant-resolver") {
        return true
    }
    val flowParams = paramsOf("control-flow-obfuscation")
    val branchInjection = planningParamText(flowParams["branchInjection"])
    if (branchInjection != null && branchInjection != "none") {
        return true
    }
    val handlerSplit = planningParamText(flowParams["handlerSplit"])
    if (handlerSplit != null && handlerSplit != "none") {
        return true
    }

    val renameParams = paramsOf("rename-methods")
    return planningParamText(renameParams["descriptorPadding"]) in setOf("fixed", "random") ||
        planningParamText(renameParams["parameterPacking"]) == "object-array" ||
        planningParamBoolean(renameParams["returnSensitiveNaming"])
}

private fun planningParamText(value: Any?): String? = when (value) {
    is String -> value
    is JsonNode -> if (value.isTextual) value.asText() else null
    else -> null
}

private fun planningParamBoolean(value: Any?): Boolean = when (value) {
    is Boolean -> value
    is JsonNode -> value.isBoolean && value.booleanValue()
    else -> false
}

private fun resolverProfileOrderingConstraints(
    passIds: List<String>,
    baseConstraints: List<OrderingConstraint>,
): List<OrderingConstraint> {
    val selectedPassIds = passIds.toSet()
    val overriddenLegacyPairs = setOf("rename-methods" to "string-encryption")
    val constraints = baseConstraints
        .filterNot { constraint -> (constraint.before to constraint.after) in overriddenLegacyPairs }
        .toMutableList()

    fun add(before: String, after: String, reason: String) {
        if (before !in selectedPassIds || after !in selectedPassIds) return
        if (constraints.any { it.before == before && it.after == after }) return
        constraints += OrderingConstraint(before = before, after = after, reason = reason)
    }

    // The public rename-methods pass owns descriptor expansion, direct-call
    // rewriting, Object[] lowering, and final name allocation as one atomic
    // transform. Keep it ahead of indy conversion so its direct call sites are
    // still available to the descriptor rewriter.
    add("integer-constant-obfuscation", "rename-methods", "Constant resolvers must be emitted before method descriptor rewriting.")
    add("string-encryption", "rename-methods", "String resolvers must be emitted before method descriptor rewriting.")
    add("rename-methods", "invoke-dynamic-indirection", "Descriptor and Object[] rewrites must complete before invokedynamic callsite conversion.")
    add("invoke-dynamic-indirection", "control-flow-obfuscation", "Invokedynamic resolver callsites must be established before CFG and handler rewriting.")
    add("rename-methods", "control-flow-obfuscation", "Descriptor and Object[] rewrites must complete before CFG and handler rewriting.")
    return constraints
}

/**
 * Deterministic topological sort using Kahn's algorithm.
 *
 * When multiple zero-in-degree nodes exist, the one with the smallest
 * original index (user selection order) is chosen first. This guarantees:
 * - All ordering constraints are satisfied.
 * - Passes without mutual constraints preserve their original relative order.
 * - The result is fully deterministic for a given input.
 *
 * @return The sorted pass IDs, or null when the selected constraints are cyclic.
 */
private fun topologicalSort(
    passIds: List<String>,
    constraints: List<OrderingConstraint>,
    diagnostics: MutableList<PlanningDiagnostic>,
): List<String>? {
    // Original index for deterministic tie-breaking
    val originalIndex = passIds.withIndex().associate { (i, id) -> id to i }

    // Build adjacency list from relevant constraints only
    val passIdSet = passIds.toSet()
    val relevantConstraints = constraints.filter {
        it.before in passIdSet && it.after in passIdSet
    }

    val adjacency = mutableMapOf<String, MutableList<String>>()
    val inDegree = mutableMapOf<String, Int>()

    for (passId in passIds) {
        adjacency.getOrPut(passId) { mutableListOf() }
        inDegree.getOrPut(passId) { 0 }
    }

    for (constraint in relevantConstraints) {
        adjacency.getOrPut(constraint.before) { mutableListOf() }.add(constraint.after)
        inDegree[constraint.after] = (inDegree[constraint.after] ?: 0) + 1
    }

    // Use a sorted set to pick the smallest original-index node first
    val comparator = compareBy<String> { originalIndex[it] ?: Int.MAX_VALUE }
    val zeroQueue = java.util.TreeSet(comparator)
    for ((passId, degree) in inDegree) {
        if (degree == 0) zeroQueue.add(passId)
    }

    val sorted = mutableListOf<String>()
    while (zeroQueue.isNotEmpty()) {
        val current = zeroQueue.first()
        zeroQueue.remove(current)
        sorted.add(current)
        for (neighbor in adjacency[current].orEmpty()) {
            inDegree[neighbor] = inDegree[neighbor]!! - 1
            if (inDegree[neighbor] == 0) {
                zeroQueue.add(neighbor)
            }
        }
    }

    // Detect cycles
    if (sorted.size != passIds.size) {
        val unresolvedPasses = passIds.filter { it !in sorted }.toMutableSet()
        val cyclePasses = buildMinimalCyclePasses(passIds, relevantConstraints, unresolvedPasses)
        diagnostics.add(
            PlanningDiagnostic(
                level = "error",
                passes = cyclePasses.toList(),
                message = "Circular dependency detected among: ${cyclePasses.sorted().joinToString(", ")}",
                causeId = "circular-dependency",
            ),
        )
        return null
    }

    // Only emit reorder diagnostic if the order actually changed
    if (sorted != passIds) {
        diagnostics.add(
            PlanningDiagnostic(
                level = "info",
                passes = emptyList(),
                message = "Pass ordering adjusted: ${passIds.joinToString(" -> ")} => ${sorted.joinToString(" -> ")}",
                causeId = "reordered",
            ),
        )
    }

    return sorted
}

private fun buildMinimalCyclePasses(
    passIds: List<String>,
    relevantConstraints: List<OrderingConstraint>,
    unresolvedPasses: Set<String>,
): Set<String> {
    val unresolvedSet = unresolvedPasses.toMutableSet()
    val adjacency = mutableMapOf<String, MutableList<String>>()
    for (passId in unresolvedSet) {
        adjacency.getOrPut(passId) { mutableListOf() }
    }
    for (constraint in relevantConstraints) {
        if (constraint.before in unresolvedSet && constraint.after in unresolvedSet) {
            adjacency.getOrPut(constraint.before) { mutableListOf() }.add(constraint.after)
        }
    }

    // Use standard 3-color DFS cycle extraction so that only nodes that participate
    // in an actual directed cycle are reported. The previous heuristic treated any
    // node reachable from an unresolved start node as part of the cycle, which
    // incorrectly included non-cyclic unresolved nodes in the error message.
    val notVisited = 0
    val inProgress = 1
    val finished = 2
    val state = mutableMapOf<String, Int>()
    val cycleNodes = mutableSetOf<String>()

    fun dfs(node: String): Boolean {
        val s = state[node] ?: notVisited
        if (s == finished) return false
        if (s == inProgress) {
            cycleNodes += node
            return true
        }
        state[node] = inProgress
        var hitCycle = false
        for (neighbor in adjacency[node].orEmpty()) {
            if (dfs(neighbor)) hitCycle = true
        }
        state[node] = finished
        if (hitCycle) cycleNodes += node
        return hitCycle
    }

    for (passId in passIds) {
        if (passId in unresolvedSet && (state[passId] ?: notVisited) == notVisited) {
            dfs(passId)
        }
    }

    return if (cycleNodes.isEmpty()) unresolvedSet else cycleNodes
}

/**
 * Validate that existing pass order satisfies constraints.
 * Reports violations as errors (hard constraints) or warnings (soft constraints).
 */
private fun validateOrdering(
    passIds: List<String>,
    constraints: List<OrderingConstraint>,
    diagnostics: MutableList<PlanningDiagnostic>,
) {
    val passIndex = passIds.withIndex().associate { (i, id) -> id to i }

    for (constraint in constraints) {
        val beforeIdx = passIndex[constraint.before] ?: continue
        val afterIdx = passIndex[constraint.after] ?: continue

        if (beforeIdx > afterIdx) {
            diagnostics.add(
                PlanningDiagnostic(
                    level = if (constraint.hard) "error" else "warn",
                    passes = listOf(constraint.before, constraint.after),
                    message = "Ordering violation: '${constraint.before}' must run before '${constraint.after}'. Reason: ${constraint.reason}",
                    causeId = "ordering-violation",
                ),
            )
        }
    }
}

data class PlanningResult(
    val orderedPasses: List<String>,
    val diagnostics: List<PlanningDiagnostic>,
    val accepted: Boolean,
    val resolverProfileActive: Boolean = false,
)

data class PlanningDiagnostic(
    val level: String,
    val passes: List<String>,
    val message: String,
    val causeId: String? = null,
)
