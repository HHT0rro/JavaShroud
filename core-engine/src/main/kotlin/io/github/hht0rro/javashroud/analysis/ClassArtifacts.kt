package io.github.hht0rro.javashroud.analysis

import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import java.nio.file.Path
import java.util.jar.JarEntry
import kotlin.io.path.absolutePathString

internal fun buildJarEntryData(entries: List<JarReadEntry>): List<JarEntryData> =
    entries.map { jarReadEntry: JarReadEntry -> JarEntryData(name = jarReadEntry.name, bytes = jarReadEntry.bytes) }

internal fun buildRawClassEntries(entries: List<JarReadEntry>): List<RawClassEntry> = classReadEntries(entries)
    .map { classReadEntry: ClassReadEntry ->
        RawClassEntry(entry = JarEntry(classReadEntry.entryName), bytes = classReadEntry.classBytes)
    }

internal fun classReadEntries(entries: List<JarReadEntry>): List<ClassReadEntry> = entries
    .filter(::isClassEntry)
    .map { jarReadEntry: JarReadEntry -> ClassReadEntry(entryName = jarReadEntry.name, classBytes = jarReadEntry.bytes) }

internal fun rawClassReadEntries(entries: List<RawClassEntry>): List<ClassReadEntry> = entries
    .map { rawClassEntry: RawClassEntry -> ClassReadEntry(entryName = rawClassEntry.entry.name, classBytes = rawClassEntry.bytes) }

private fun isClassEntry(entry: JarReadEntry): Boolean = entry.name.endsWith(".class")

internal data class ClassReadEntry(
    val entryName: String,
    val classBytes: ByteArray,
)

internal fun buildClassArtifacts(entries: List<ClassReadEntry>, inputJarPath: Path): List<ClassArtifact> =
    entries.map { classReadEntry: ClassReadEntry ->
        analyzedClassArtifact(
            inputJarPath = inputJarPath,
            entryName = classReadEntry.entryName,
            classBytes = classReadEntry.classBytes,
        )
    }

private fun analyzedClassArtifact(
    inputJarPath: Path,
    entryName: String,
    classBytes: ByteArray,
): ClassArtifact = ClassArtifact(
    entryName = entryName,
    summary = analyzeClassEntry(classBytes, inputJarPath, entryName),
    bytes = classBytes,
)

internal fun buildClassArtifactsFromJarEntries(entries: List<JarReadEntry>, inputJarPath: Path): List<ClassArtifact> =
    buildClassArtifacts(entries = classReadEntries(entries), inputJarPath = inputJarPath)

internal fun buildClassArtifactsFromRawEntries(classEntries: List<RawClassEntry>, inputJarPath: Path): List<ClassArtifact> =
    buildClassArtifacts(entries = rawClassReadEntries(classEntries), inputJarPath = inputJarPath)

fun analyzeClassEntry(classBytes: ByteArray, inputJarPath: Path, entryName: String): ClassAnalysisSummary {
    return try {
        analyzeClassBytes(classBytes)
    } catch (error: RuntimeException) {
        throw IllegalArgumentException(
            "Failed to parse class entry: jar=${inputJarPath.absolutePathString()}, entry=${entryName}, reason=${error.message}",
            error,
        )
    }
}
