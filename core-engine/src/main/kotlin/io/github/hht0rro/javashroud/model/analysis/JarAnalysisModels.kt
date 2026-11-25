package io.github.hht0rro.javashroud.model.analysis

data class JarAnalysisSummary(
    val classCount: Int,
    val resourceCount: Int,
    val manifestPresent: Boolean,
    val classSummaries: List<ClassAnalysisSummary>,
    val classNameIndex: Map<String, ClassAnalysisSummary>,
    val ruleMatches: List<RuleMatch>,
    val renamePlan: RenamePlan,
)
