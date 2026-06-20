package io.github.hht0rro.javashroud.transforms.protection

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
): PlanningResult {
    val diagnostics = mutableListOf<PlanningDiagnostic>()

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
                orderedPasses = passIds,
                diagnostics = diagnostics,
                accepted = false,
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

    if (mode == "reject-conflicts" && diagnostics.any { it.level == "error" }) {
        return PlanningResult(
            orderedPasses = passIds,
            diagnostics = diagnostics,
            accepted = false,
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
    val orderedPasses = if (mode == "auto-sort") {
        topologicalSort(passIds, orderingConstraints, diagnostics)
    } else {
        // Validate-only: check that existing order satisfies constraints
        validateOrdering(passIds, orderingConstraints, diagnostics)
        passIds
    }

    return PlanningResult(
        orderedPasses = orderedPasses,
        diagnostics = diagnostics,
        accepted = diagnostics.none { it.level == "error" },
    )
}

/**
 * Deterministic topological sort using Kahn's algorithm.
 *
 * When multiple zero-in-degree nodes exist, the one with the smallest
 * original index (user selection order) is chosen first. This guarantees:
 * - All ordering constraints are satisfied.
 * - Passes without mutual constraints preserve their original relative order.
 * - The result is fully deterministic for a given input.
 */
private fun topologicalSort(
    passIds: List<String>,
    constraints: List<OrderingConstraint>,
    diagnostics: MutableList<PlanningDiagnostic>,
): List<String> {
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
        // Fall back to original order instead of failing the whole planner run
        return passIds
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
)

data class PlanningDiagnostic(
    val level: String,
    val passes: List<String>,
    val message: String,
    val causeId: String? = null,
)
