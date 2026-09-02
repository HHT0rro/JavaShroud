package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.catalog.FinalRuntimeBinding
import io.github.hht0rro.javashroud.transforms.protection.qp.catalog.PageKey
import io.github.hht0rro.javashroud.transforms.protection.qp.catalog.QpDirectorySerializer
import io.github.hht0rro.javashroud.transforms.protection.qp.catalog.QpArtifactPage
import io.github.hht0rro.javashroud.transforms.protection.qp.catalog.RuntimeBindingDigest
import io.github.hht0rro.javashroud.transforms.protection.qp.qpCatalogIndexPath
import io.github.hht0rro.javashroud.transforms.protection.qp.qpCatalogPrefix
import io.github.hht0rro.javashroud.transforms.protection.qp.qpDirectoryFileName
import io.github.hht0rro.javashroud.transforms.protection.qp.qpPageBundlePath
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.util.Arrays

internal fun attachQpCatalogEmitter(
    artifact: BytecodeArtifact,
    nativeBinding: FinalRuntimeBinding,
): BytecodeArtifact {
    val catalogIndex = qpCatalogIndexPath()
    val catalogPrefix = qpCatalogPrefix()
    val directoryFile = qpDirectoryFileName()
    if (artifact.jarEntries.any { it.name == catalogIndex }) return artifact
    val layout = currentQpBuildContextOrNull()?.qpFinalizationLayoutOrNull() ?: return artifact
    val extras = ArrayList<JarEntryData>()
    val droppedContainers = LinkedHashSet<String>()
    layout.withNativeCompileInputsForBuild { inputs ->
        if (inputs.isEmpty()) return@withNativeCompileInputsForBuild
        val pages = ArrayList<QpArtifactPage>(inputs.size)
        val runtime = RuntimeBindingDigest.create(
            artifactCommitment = layout.copyArtifactCommitmentForBuild().let { src ->
                if (src.size == 32) src else MessageDigest.getInstance("SHA-256").digest(src)
            },
            binding = nativeBinding,
        )
        try {
            val builtEntries = layout.entriesForBuild()
            val originalContainers = LinkedHashSet<String>()
            val packed = ByteArrayOutputStream()
            val bundlePath = qpPageBundlePath()
            inputs.forEach { input ->
                val container = builtEntries.firstOrNull { it.name == input.resourcePath }?.copyBytesForBuild()
                    ?: artifact.jarEntries.firstOrNull { it.name == input.resourcePath }?.bytes?.copyOf()
                    ?: error("Qp catalog is missing page container ${input.resourcePath}")
                try {
                    val start = input.resourceOffset
                    val length = input.storedLength
                    require(start >= 0 && length > 0 && start <= container.size - length) {
                        "Qp catalog page range is invalid for ${input.resourcePath}: offset=$start length=$length size=${container.size}"
                    }
                    val packedOffset = packed.size()
                    packed.write(container, start, length)
                    originalContainers += input.resourcePath
                    val handle = input.copyEncodedHandleForCompiler()
                    val locator = input.copyPageBindingDigestForCompiler().copyOf(QpHandle.LOCATOR_TOKEN_SIZE)
                    val key = PageKey.create(input.resourceKind, input.pageIndex, handle, locator)
                    try {
                        pages += QpArtifactPage.create(
                            key = key,
                            relativePath = bundlePath,
                            offset = packedOffset,
                            storedLength = length,
                            descriptor = input.copyResolvedDescriptorForCompiler(),
                            envelope = input.copyNativeEnvelopeForCompiler(),
                            runtimeBindingDigest = runtime,
                        )
                    } finally {
                        key.wipe()
                        Arrays.fill(handle, 0)
                        Arrays.fill(locator, 0)
                    }
                } finally {
                    Arrays.fill(container, 0)
                }
            }
            if (pages.isEmpty()) return@withNativeCompileInputsForBuild
            val directory = QpDirectorySerializer.encode(runtime, pages)
            extras += JarEntryData(catalogPrefix + directoryFile, directory)
            extras += JarEntryData(bundlePath, packed.toByteArray())
            val index = bundlePath + "\n" + directoryFile + "\n"
            extras += JarEntryData(catalogIndex, index.toByteArray(Charsets.US_ASCII))
            droppedContainers += originalContainers
            pages.forEach { it.wipe() }
        } finally {
            runtime.wipe()
        }
    }
    if (extras.isEmpty()) return artifact
    val jarEntries = artifact.jarEntries.filterNot { entry ->
        entry.name in droppedContainers &&
            !entry.name.endsWith(".class") &&
            !entry.name.endsWith(".dll") &&
            !entry.name.endsWith(".so")
    } + extras
    return artifact.copy(
        jarEntries = jarEntries,
        analysisSummary = artifact.analysisSummary.copy(
            resourceCount = jarEntries.size,
        ),
    )
}
