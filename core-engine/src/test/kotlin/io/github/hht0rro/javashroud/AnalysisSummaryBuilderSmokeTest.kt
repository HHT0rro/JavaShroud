package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.attachAnalysisSummary
import io.github.hht0rro.javashroud.analysis.buildJarAnalysisSummary
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.PassSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AnalysisSummaryBuilderSmokeTest {
    @Test
    fun buildJarAnalysisSummary_aggregates_counts_and_indexes() {
        val classArtifact = testClassArtifact("sample/Foo", bytes = byteArrayOf(1, 2, 3))
        val summary = buildJarAnalysisSummary(
            config = testConfig(passes = listOf(PassSpec(id = "strip-compile-debug-info", enabled = true, params = emptyMap()))),
            jarEntries = listOf(JarEntryData("sample/Foo.class", byteArrayOf(1)), JarEntryData("sample/readme.txt", byteArrayOf(2))),
            classArtifacts = listOf(classArtifact),
            manifestPresent = true,
        )
        assertEquals(1, summary.classCount)
        assertEquals(1, summary.resourceCount)
        assertTrue(summary.manifestPresent)
        assertTrue(summary.classNameIndex.containsKey("sample/Foo"))
        assertEquals("sample/Foo", summary.classSummaries.single().internalName)
    }

    @Test
    fun attachAnalysisSummary_populates_artifact_index() {
        val classArtifact = testClassArtifact("sample/Foo", bytes = byteArrayOf(1, 2, 3))
        val artifact = attachAnalysisSummary(
            config = testConfig(passes = listOf(PassSpec(id = "strip-compile-debug-info", enabled = true, params = emptyMap()))),
            jarEntries = listOf(JarEntryData("sample/Foo.class", byteArrayOf(1)), JarEntryData("sample/readme.txt", byteArrayOf(2))),
            classArtifacts = listOf(classArtifact),
            manifestPresent = true,
        )

        assertTrue(artifact.classArtifactIndex.containsKey("sample/Foo"))
        assertEquals("sample/Foo.class", artifact.classArtifactIndex.getValue("sample/Foo").entryName)
        assertEquals(1, artifact.analysisSummary.resourceCount)
    }
}
