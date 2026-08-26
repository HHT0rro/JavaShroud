package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.FinalNativeBinding
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.PageKey
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.R1ArtifactDirectorySerializer
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.R1ArtifactPage
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.RuntimeBindingDigest
import java.security.MessageDigest
import java.util.Arrays

private const val CATALOG_INDEX = "META-INF/jsrt/catalog.index"
private const val CATALOG_PREFIX = "META-INF/jsrt/catalog/"

internal fun attachAkenR1CatalogSidecar(
    artifact: BytecodeArtifact,
    nativeBinding: FinalNativeBinding,
): BytecodeArtifact {
    if (artifact.jarEntries.any { it.name == CATALOG_INDEX }) return artifact
    val layout = currentVbc4BuildContextOrNull()?.akenVbc4FinalizationLayoutOrNull() ?: return artifact
    val extras = ArrayList<JarEntryData>()
    layout.withNativeCompileInputsForBuild { inputs ->
        if (inputs.isEmpty()) return@withNativeCompileInputsForBuild
        val pages = ArrayList<R1ArtifactPage>(inputs.size)
        val runtime = RuntimeBindingDigest.create(
            artifactCommitment = layout.copyArtifactCommitmentForBuild().let { src ->
                if (src.size == 32) src else MessageDigest.getInstance("SHA-256").digest(src)
            },
            binding = nativeBinding,
        )
        try {
            val builtEntries = layout.entriesForBuild()
            inputs.forEachIndexed { index, input ->
                val relative = "pages/p-" + input.pageIndex + "-" + index + ".bin"
                val container = builtEntries.firstOrNull { it.name == input.resourcePath }?.copyBytesForBuild()
                    ?: return@forEachIndexed
                val start = input.resourceOffset
                val length = input.storedLength
                if (start < 0 || length <= 0 || start > container.size - length) return@forEachIndexed
                val pageBytes = container.copyOfRange(start, start + length)
                extras += JarEntryData(CATALOG_PREFIX + relative, pageBytes)
                val handle = input.copyEncodedHandleForCompiler()
                val locator = input.copyPageBindingDigestForCompiler().copyOf(AkenHandle.LOCATOR_TOKEN_SIZE)
                val key = PageKey.create(input.resourceKind, input.pageIndex, handle, locator)
                try {
                    pages += R1ArtifactPage.create(
                        key = key,
                        relativePath = relative,
                        offset = input.resourceOffset,
                        storedLength = pageBytes.size,
                        descriptor = input.copyResolvedDescriptorForCompiler(),
                        envelope = input.copyNativeEnvelopeForCompiler(),
                        runtimeBindingDigest = runtime,
                    )
                } finally {
                    key.wipe()
                    Arrays.fill(handle, 0)
                    Arrays.fill(locator, 0)
                }
            }
            if (pages.isEmpty()) return@withNativeCompileInputsForBuild
            val directory = R1ArtifactDirectorySerializer.encode(runtime, pages)
            extras += JarEntryData(CATALOG_PREFIX + "directory.jsr1", directory)
            val index = pages.joinToString("\n") { it.relativePath } + "\ndirectory.jsr1\n"
            extras += JarEntryData(CATALOG_INDEX, index.toByteArray(Charsets.US_ASCII))
            pages.forEach { it.wipe() }
        } finally {
            runtime.wipe()
        }
    }
    if (extras.isEmpty()) return artifact
    val jarEntries = artifact.jarEntries + extras
    return artifact.copy(
        jarEntries = jarEntries,
        analysisSummary = artifact.analysisSummary.copy(
            resourceCount = jarEntries.size,
        ),
    )
}
