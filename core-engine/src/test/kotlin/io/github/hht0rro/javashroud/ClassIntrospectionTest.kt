package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals

class ClassIntrospectionTest {
    @Test
    fun analyzeClassBytes_collects_members_and_metadata() {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/Foo", null, "java/lang/Object", arrayOf("java/io/Serializable"))
        writer.visitField(Opcodes.ACC_PRIVATE, "name", "Ljava/lang/String;", null, null).visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null).visitEnd()
        writer.visitEnd()

        val summary = analyzeClassBytes(writer.toByteArray())

        assertEquals("sample/Foo", summary.internalName)
        assertEquals("java/lang/Object", summary.superName)
        assertEquals(listOf("java/io/Serializable"), summary.interfaceNames)
        assertEquals(1, summary.fieldCount)
        assertEquals(1, summary.methodCount)
        assertEquals("name", summary.fieldSummaries.single().name)
        assertEquals("run", summary.methodSummaries.single().name)
    }
}
