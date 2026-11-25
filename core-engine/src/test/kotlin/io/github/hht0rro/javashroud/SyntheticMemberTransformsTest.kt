package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.metadata.markSyntheticMembers
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SyntheticMemberTransformsTest {
    @Test
    fun markSyntheticMembers_refreshes_member_summaries() {
        val classBytes = buildClassBytes()
        val classArtifact = ClassArtifact(
            entryName = "sample/Foo.class",
            summary = analyzeClassBytes(classBytes),
            bytes = classBytes,
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(classArtifact),
            jarEntries = listOf(JarEntryData("sample/Foo.class", classBytes)),
            config = testConfig(inputJarPath = "in.jar", outputJarPath = "out.jar"),
        )

        val result = markSyntheticMembers(artifact, emptyList(), emptyMap())
        val updatedSummary = result.artifact.analysisSummary.classSummaries.single()

        assertEquals(1, result.transformedClassCount)
        assertEquals(2, result.transformedMemberCount)
        assertTrue(updatedSummary.fieldSummaries.single().accessFlags and Opcodes.ACC_SYNTHETIC != 0)
        assertTrue(updatedSummary.methodSummaries.single().accessFlags and Opcodes.ACC_SYNTHETIC != 0)
    }

    private fun buildClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/Foo", null, "java/lang/Object", null)
        writer.visitField(Opcodes.ACC_PRIVATE, "field", "I", null, null).visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null).visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }
}
