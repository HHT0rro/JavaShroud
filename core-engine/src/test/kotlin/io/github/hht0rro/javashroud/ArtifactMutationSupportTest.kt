package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.artifact.updateArtifactClassSet
import io.github.hht0rro.javashroud.artifact.updateRenamedArtifactClasses
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ArtifactMutationSupportTest {
    @Test
    fun updateArtifactClassSet_refreshes_class_indexes_and_summaries() {
        val original = testAttachedArtifact(classArtifacts = listOf(testClassArtifact("sample/Foo", bytes = byteArrayOf(1))))
        val updatedClass = testClassArtifact("sample/Bar", bytes = byteArrayOf(2))

        val updated = updateArtifactClassSet(original, listOf(updatedClass))

        assertEquals(listOf(updatedClass), updated.classArtifacts)
        assertTrue(updated.classArtifactIndex.containsKey("sample/Bar"))
        assertEquals(listOf(updatedClass.summary), updated.analysisSummary.classSummaries)
        assertTrue(updated.analysisSummary.classNameIndex.containsKey("sample/Bar"))
    }

    @Test
    fun updateRenamedArtifactClasses_renames_class_entries_and_preserves_resources() {
        val original = testAttachedArtifact(classArtifacts = listOf(testClassArtifact("sample/Foo", bytes = byteArrayOf(1))))
        val updatedClass = testClassArtifact("sample/Renamed", bytes = byteArrayOf(2))
        val updated = updateRenamedArtifactClasses(
            artifact = original.copy(jarEntries = original.jarEntries + JarEntryData("META-INF/MANIFEST.MF", byteArrayOf(9))),
            updatedClassArtifacts = listOf(updatedClass),
            classRenameMap = mapOf("sample/Foo" to "sample/Renamed"),
        )

        assertTrue(updated.jarEntries.any { it.name == "sample/Renamed.class" })
        assertTrue(updated.classArtifactIndex.containsKey("sample/Renamed"))
        assertEquals(1, updated.analysisSummary.classCount)
        assertEquals(1, updated.analysisSummary.resourceCount)
        assertTrue(updated.analysisSummary.classNameIndex.containsKey("sample/Renamed"))
        assertEquals("sample/Renamed", updated.classArtifacts.single().summary.internalName)
    }
}
