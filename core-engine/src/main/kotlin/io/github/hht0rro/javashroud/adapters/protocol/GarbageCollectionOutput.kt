package io.github.hht0rro.javashroud.adapters.protocol

import io.github.hht0rro.javashroud.maintenance.RuntimeGarbageCollector.GarbageCollectionResult

internal fun buildGarbageCollectionReport(result: GarbageCollectionResult): String {
    val lines = mutableListOf<String>()
    val mode = if (result.applied) "apply" else "preview"
    lines += "JavaShroud runtime garbage collector: mode=$mode"
    lines += "Candidates: ${result.candidates.size}; files=${result.totalFiles}; directories=${result.totalDirectories}; bytes=${result.totalBytes}"
    if (result.candidates.isEmpty()) {
        lines += "No JavaShroud runtime cache directories were found."
    } else {
        result.candidates.forEach { candidate ->
            lines += "- ${candidate.kind}: ${candidate.path} files=${candidate.files} directories=${candidate.directories} bytes=${candidate.bytes}"
        }
    }
    if (result.deleted.isNotEmpty()) {
        lines += "Deleted:"
        result.deleted.forEach { path -> lines += "- $path" }
    }
    if (result.skipped.isNotEmpty()) {
        lines += "Skipped:"
        result.skipped.forEach { skipped -> lines += "- $skipped" }
    }
    if (!result.applied && result.candidates.isNotEmpty()) {
        lines += "Run with -gc --apply to delete these directories."
    }
    return lines.joinToString(System.lineSeparator())
}
