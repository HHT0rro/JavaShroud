package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.protocol.ClassTreeNode

fun buildClassTreeNodes(classSummaries: List<ClassAnalysisSummary>): List<ClassTreeNode> =
    buildPackageIndex(classSummaries).map { entry: Map.Entry<String, List<ClassAnalysisSummary>> ->
        buildPackageNode(
            packageName = entry.key,
            classSummaries = entry.value,
        )
    }

fun countPackageNodes(nodes: List<ClassTreeNode>): Int = packageNodes(nodes).size

internal fun buildPackageNode(packageName: String, classSummaries: List<ClassAnalysisSummary>): ClassTreeNode {
    val packageLabel = if (packageName.isBlank()) "<default>" else packageName.substringAfterLast('/')
    return ClassTreeNode(
        id = if (packageName.isBlank()) "package:<default>" else "package:${packageName}",
        label = packageLabel,
        qualifiedName = if (packageName.isBlank()) "<default>" else packageName.replace('/', '.'),
        internalName = packageName,
        kind = "package",
        children = classSummaries.map(::buildClassNode),
    )
}

private fun buildClassNode(classSummary: ClassAnalysisSummary): ClassTreeNode {
    val label = classSummary.internalName.substringAfterLast('/')
    return ClassTreeNode(
        id = "class:${classSummary.internalName}",
        label = label,
        qualifiedName = classSummary.internalName.replace('/', '.'),
        internalName = classSummary.internalName,
        kind = "class",
        children = buildMemberNodes(classSummary),
    )
}

private fun buildMemberNodes(classSummary: ClassAnalysisSummary): List<ClassTreeNode> {
    val fieldNodes = classSummary.fieldSummaries
        .sortedWith(compareBy<MemberSummary> { memberSummary: MemberSummary -> memberSummary.name }.thenBy { memberSummary: MemberSummary -> memberSummary.descriptor })
        .map { memberSummary: MemberSummary -> buildMemberNode(classSummary, memberSummary) }
    val methodNodes = classSummary.methodSummaries
        .sortedWith(compareBy<MemberSummary> { memberSummary: MemberSummary -> memberSummary.name }.thenBy { memberSummary: MemberSummary -> memberSummary.descriptor })
        .map { memberSummary: MemberSummary -> buildMemberNode(classSummary, memberSummary) }
    return fieldNodes + methodNodes
}

private fun buildMemberNode(classSummary: ClassAnalysisSummary, memberSummary: MemberSummary): ClassTreeNode {
    val memberKind = buildMemberNodeKind(memberSummary.kind)
    val target = "${classSummary.internalName}#${memberSummary.name}:${memberSummary.descriptor}"
    return ClassTreeNode(
        id = "${memberKind}:${target}",
        label = "${memberSummary.name} ${memberSummary.descriptor}",
        qualifiedName = "${classSummary.internalName.replace('/', '.')}#${memberSummary.name}${memberSummary.descriptor}",
        internalName = target,
        kind = memberKind,
        children = emptyList(),
    )
}

private fun buildMemberNodeKind(memberKind: MemberKind): String {
    return when (memberKind) {
        MemberKind.FIELD -> "field"
        MemberKind.METHOD -> "method"
    }
}

internal fun buildPackageIndex(classSummaries: List<ClassAnalysisSummary>): LinkedHashMap<String, List<ClassAnalysisSummary>> {
    val packageIndex = linkedMapOf<String, List<ClassAnalysisSummary>>()
    classSummaries.forEach { classSummary: ClassAnalysisSummary ->
        val packageName = packageName(classSummary)
        val currentPackageClasses = packageIndex[packageName] ?: emptyList()
        packageIndex[packageName] = currentPackageClasses + classSummary
    }
    return packageIndex
}

internal fun packageNodes(nodes: List<ClassTreeNode>): List<ClassTreeNode> =
    nodes.filter { node: ClassTreeNode -> node.kind == "package" }

private fun packageName(classSummary: ClassAnalysisSummary): String =
    classSummary.internalName.substringBeforeLast('/', missingDelimiterValue = "")
