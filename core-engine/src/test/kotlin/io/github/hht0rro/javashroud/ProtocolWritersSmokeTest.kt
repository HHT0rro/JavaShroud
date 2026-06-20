package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.buildClassTreeNodePayload
import io.github.hht0rro.javashroud.adapters.protocol.buildEventPayload
import io.github.hht0rro.javashroud.model.protocol.ClassTreeNode
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProtocolWritersSmokeTest {
    @Test
    fun buildClassTreeNodePayload_serializes_children_recursively() {
        val child = ClassTreeNode(
            id = "member:foo",
            label = "foo_desc",
            qualifiedName = "sample.Foo#foo_desc",
            internalName = "sample/Foo#foo:desc",
            kind = "method",
            children = emptyList(),
        )
        val root = ClassTreeNode(
            id = "class:sample/Foo",
            label = "Foo",
            qualifiedName = "sample.Foo",
            internalName = "sample/Foo",
            kind = "class",
            children = listOf(child),
        )

        val payload = buildClassTreeNodePayload(root)
        assertEquals("class:sample/Foo", payload["id"])
        assertEquals("class", payload["kind"])
        val children = payload["children"] as List<*>
        assertEquals(1, children.size)
        val childPayload = children.single() as Map<*, *>
        assertEquals("member:foo", childPayload["id"])
        assertEquals("method", childPayload["kind"])
        assertTrue((childPayload["children"] as List<*>).isEmpty())
    }

    @Test
    fun buildEventPayload_preserves_nullable_fields() {
        val payload = buildEventPayload(
            EngineEvent(
                level = "error",
                type = "error",
                message = "boom",
                progress = null,
                outPath = null,
            ),
        )

        assertEquals("error", payload["level"])
        assertEquals("error", payload["type"])
        assertEquals("boom", payload["message"])
        assertEquals(null, payload["progress"])
        assertEquals(null, payload["outPath"])
    }
}
