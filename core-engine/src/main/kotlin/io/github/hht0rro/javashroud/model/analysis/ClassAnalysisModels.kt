package io.github.hht0rro.javashroud.model.analysis

data class ClassAnalysisSummary(
    val internalName: String,
    val superName: String?,
    val interfaceNames: List<String>,
    val accessFlags: Int,
    val fieldCount: Int,
    val methodCount: Int,
    val fieldSummaries: List<MemberSummary>,
    val methodSummaries: List<MemberSummary>,
)
