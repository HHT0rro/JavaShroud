package io.github.hht0rro.javashroud.model.analysis

data class RenamePlanEntry(
    val owner: String,
    val kind: MemberKind,
    val originalName: String,
    val descriptor: String,
    val plannedName: String,
)

data class RenamePlan(
    val entries: List<RenamePlanEntry>,
)
