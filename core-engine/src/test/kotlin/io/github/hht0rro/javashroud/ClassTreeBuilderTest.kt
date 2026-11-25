package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.buildClassTreeNodes
import io.github.hht0rro.javashroud.analysis.countPackageNodes
import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import kotlin.test.Test
import kotlin.test.assertEquals

class ClassTreeBuilderTest {
    @Test
    fun buildClassTreeNodes_groups_packages_and_sorts_members() {
        val classSummary = ClassAnalysisSummary(
            internalName = "sample/Foo",
            superName = "java/lang/Object",
            interfaceNames = emptyList(),
            accessFlags = 0,
            fieldCount = 1,
            methodCount = 2,
            fieldSummaries = listOf(
                MemberSummary(kind = MemberKind.FIELD, name = "zField", descriptor = "I", accessFlags = 0),
            ),
            methodSummaries = listOf(
                MemberSummary(kind = MemberKind.METHOD, name = "bMethod", descriptor = "()V", accessFlags = 0),
                MemberSummary(kind = MemberKind.METHOD, name = "aMethod", descriptor = "()V", accessFlags = 0),
            ),
        )

        val nodes = buildClassTreeNodes(listOf(classSummary))

        assertEquals(1, countPackageNodes(nodes))
        assertEquals("package:sample", nodes.single().id)
        assertEquals("sample", nodes.single().label)
        val classNode = nodes.single().children.single()
        assertEquals("class:sample/Foo", classNode.id)
        assertEquals(listOf("zField I", "aMethod ()V", "bMethod ()V"), classNode.children.map { child -> child.label })
        assertEquals(listOf("field", "method", "method"), classNode.children.map { child -> child.kind })
    }

    @Test
    fun buildClassTreeNodes_uses_default_package_node_for_root_classes() {
        val classSummary = ClassAnalysisSummary(
            internalName = "RootClass",
            superName = "java/lang/Object",
            interfaceNames = emptyList(),
            accessFlags = 0,
            fieldCount = 0,
            methodCount = 0,
            fieldSummaries = emptyList(),
            methodSummaries = emptyList(),
        )

        val nodes = buildClassTreeNodes(listOf(classSummary))

        assertEquals(1, countPackageNodes(nodes))
        assertEquals("package:<default>", nodes.single().id)
        assertEquals("<default>", nodes.single().label)
        assertEquals("class:RootClass", nodes.single().children.single().id)
    }
}
