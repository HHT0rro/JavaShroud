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
            val buildContext = checkNotNull(currentQpBuildContextOrNull())
            val directoryPlain = QpDirectorySerializer.encode(runtime, pages)
            val nameSeed = io.github.hht0rro.javashroud.transforms.protection.qp.currentNameSeed()
            val cryptoDomain = buildContext.copyFrozenPackCryptoDomainOrNull()
                ?: io.github.hht0rro.javashroud.transforms.protection.QpInnerMaterial
                    .copyCryptoDomainMaterial(buildContext)
            val sealNonce = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
            val directory = io.github.hht0rro.javashroud.transforms.protection.qp.catalog.QpDirectorySeal
                .seal(directoryPlain, nameSeed, cryptoDomain, sealNonce, nativeBinding.nativeSha256)
            Arrays.fill(directoryPlain, 0)
            Arrays.fill(nameSeed, 0)
            Arrays.fill(cryptoDomain, 0)
            Arrays.fill(sealNonce, 0)
            extras += JarEntryData(catalogPrefix + directoryFile, directory)
            extras += JarEntryData(bundlePath, packed.toByteArray())
            val context = currentQpBuildContextOrNull()
            val packPlatforms = context?.nativeSealedPackPlatforms().orEmpty().sorted()
            val records = ArrayList<ByteArray>(packPlatforms.size)
            for (platform in packPlatforms) {
                val blob = context!!.copyNativeSealedPackBlob(platform)
                val packFile = "pk" + MessageDigest.getInstance("SHA-256")
                    .digest((bundlePath + "|" + platform).toByteArray(Charsets.US_ASCII))
                    .joinToString("") { "%02x".format(it) }
                    .take(12)
                extras += JarEntryData(catalogPrefix + packFile, blob.copyOf())
                records += catalogIndexRecord(
                    kind = CATALOG_INDEX_KIND_PACK,
                    platform = catalogIndexPlatform(platform),
                    token = packFile,
                )
                Arrays.fill(blob, 0)
            }
            extras += JarEntryData(
                catalogIndex,
                encodeCatalogIndex(
                    listOf(
                        catalogIndexRecord(
                            kind = CATALOG_INDEX_KIND_BUNDLE,
                            platform = CATALOG_INDEX_PLATFORM_NONE,
                            token = bundlePath.removePrefix(catalogPrefix),
                        ),
                        catalogIndexRecord(
                            kind = CATALOG_INDEX_KIND_DIRECTORY,
                            platform = CATALOG_INDEX_PLATFORM_NONE,
                            token = directoryFile,
                        ),
                    ) + records,
                ),
            )
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

internal const val CATALOG_INDEX_MAGIC: Byte = 0x6C
internal const val CATALOG_INDEX_VERSION: Byte = 1
internal const val CATALOG_INDEX_RECORD_SIZE: Int = 40
internal const val CATALOG_INDEX_KIND_BUNDLE: Byte = 1
internal const val CATALOG_INDEX_KIND_DIRECTORY: Byte = 2
internal const val CATALOG_INDEX_KIND_PACK: Byte = 3
internal const val CATALOG_INDEX_PLATFORM_NONE: Byte = 0
internal const val CATALOG_INDEX_PLATFORM_WINDOWS: Byte = 1
internal const val CATALOG_INDEX_PLATFORM_LINUX: Byte = 2

internal data class CatalogIndexRecord(
    val kind: Byte,
    val platform: Byte,
    val token: String,
)

internal fun catalogIndexPlatform(platform: String): Byte = when (platform) {
    "windows-x64" -> CATALOG_INDEX_PLATFORM_WINDOWS
    "linux-x64" -> CATALOG_INDEX_PLATFORM_LINUX
    else -> error("Qp catalog pack platform is unsupported: $platform")
}

internal fun catalogIndexPlatformKey(platform: Byte): String? = when (platform) {
    CATALOG_INDEX_PLATFORM_NONE -> null
    CATALOG_INDEX_PLATFORM_WINDOWS -> "windows-x64"
    CATALOG_INDEX_PLATFORM_LINUX -> "linux-x64"
    else -> null
}

internal fun catalogIndexRecord(kind: Byte, platform: Byte, token: String): ByteArray {
    require(token.isNotEmpty() && token.length <= 36 && '/' !in token && '\\' !in token) {
        "Qp catalog index token is invalid"
    }
    val record = ByteArray(CATALOG_INDEX_RECORD_SIZE)
    record[0] = kind
    record[1] = platform
    val encoded = token.toByteArray(Charsets.US_ASCII)
    encoded.copyInto(record, 4)
    Arrays.fill(encoded, 0)
    return record
}

internal fun encodeCatalogIndex(records: List<ByteArray>): ByteArray {
    require(records.size in 1..0xFFFF)
    val out = ByteArray(4 + records.size * CATALOG_INDEX_RECORD_SIZE)
    out[0] = CATALOG_INDEX_MAGIC
    out[1] = CATALOG_INDEX_VERSION
    out[2] = ((records.size ushr 8) and 0xFF).toByte()
    out[3] = (records.size and 0xFF).toByte()
    records.forEachIndexed { index, record ->
        require(record.size == CATALOG_INDEX_RECORD_SIZE)
        record.copyInto(out, 4 + index * CATALOG_INDEX_RECORD_SIZE)
    }
    return out
}

internal fun decodeCatalogIndex(bytes: ByteArray): List<CatalogIndexRecord> {
    if (bytes.size < 4 || bytes[0] != CATALOG_INDEX_MAGIC || bytes[1] != CATALOG_INDEX_VERSION) {
        error("Qp catalog index shell is invalid")
    }
    val count = ((bytes[2].toInt() and 0xFF) shl 8) or (bytes[3].toInt() and 0xFF)
    if (count <= 0 || bytes.size != 4 + count * CATALOG_INDEX_RECORD_SIZE) {
        error("Qp catalog index length is invalid")
    }
    return (0 until count).map { index ->
        val offset = 4 + index * CATALOG_INDEX_RECORD_SIZE
        val kind = bytes[offset]
        val platform = bytes[offset + 1]
        if (bytes[offset + 2].toInt() != 0 || bytes[offset + 3].toInt() != 0) {
            error("Qp catalog index record is reserved")
        }
        val tokenBytes = bytes.copyOfRange(offset + 4, offset + CATALOG_INDEX_RECORD_SIZE)
        val end = tokenBytes.indexOfFirst { it == 0.toByte() }.let { if (it < 0) tokenBytes.size else it }
        val token = String(tokenBytes, 0, end, Charsets.US_ASCII)
        Arrays.fill(tokenBytes, 0)
        if (token.isEmpty() || '/' in token || '\\' in token) {
            error("Qp catalog index token is invalid")
        }
        CatalogIndexRecord(kind, platform, token)
    }
}
