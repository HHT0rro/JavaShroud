package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import java.io.ByteArrayOutputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

internal const val VBC4_VM_CATALOG_RESOURCE = "META-INF/.r/vm.catalog"
internal const val RUNTIME_VM_CATALOG_METHOD_AUTH_DOMAIN = "jsc1-method-auth-v1"

internal data class RuntimeVmCatalogMethod(
    val entryToken: Long,
    val resourcePath: String,
    val manifestPath: String,
    val shardCount: Int,
    val mesh: String,
    val methodLocalProfile: Int,
    val originalResourcePath: String? = null,
    val originalManifestPath: String? = null,
) {
    init {
        require(resourcePath.isNotBlank() && '|' !in resourcePath && '\n' !in resourcePath)
        require(manifestPath.isNotBlank() && '|' !in manifestPath && '\n' !in manifestPath)
        require(shardCount > 0)
        require(mesh.length == 64 && mesh.all { it.digitToIntOrNull(16) != null })
    }

    internal fun encodedLine(): String {
        val tokenHex = entryToken.toULong().toString(16)
        val profileHex = methodLocalProfile.toUInt().toString(16)
        val authTag = RuntimeVmCatalog.runtimeVmCatalogMethodAuthTag(
            tokenHex = tokenHex,
            resourcePath = resourcePath,
            manifestPath = manifestPath,
            shardCount = shardCount.toString(),
            mesh = mesh,
            profile = profileHex,
        )
        val fields = mutableListOf(tokenHex, resourcePath, manifestPath, shardCount.toString(), mesh, profileHex, authTag)
        if (originalResourcePath != null || originalManifestPath != null) {
            fields += requireNotNull(originalResourcePath)
            fields += requireNotNull(originalManifestPath)
        }
        return fields.joinToString("|")
    }
}

internal data class RuntimeVmCatalogPlan(
    val methods: List<RuntimeVmCatalogMethod>,
    private val aliases: Map<String, String> = emptyMap(),
) {
    init {
        require(methods.isNotEmpty()) { "VM catalog plan requires at least one method" }
        require(methods.map { it.entryToken }.toSet().size == methods.size) { "VM catalog method tokens must be unique" }
        require(aliases.all { (logical, storage) ->
            logical.isNotBlank() && storage.isNotBlank() && '|' !in logical && '|' !in storage && '\n' !in logical && '\n' !in storage
        }) { "VM catalog aliases must use valid resource paths" }
    }

    fun resourceNames(): Set<String> = methods.flatMapTo(linkedSetOf()) { listOf(it.resourcePath, it.manifestPath) }

    fun renamed(resourceRenameMap: Map<String, String>): RuntimeVmCatalogPlan = RuntimeVmCatalogPlan(
        methods = methods.map { method ->
            method.copy(
                resourcePath = resourceRenameMap[method.resourcePath] ?: method.resourcePath,
                manifestPath = resourceRenameMap[method.manifestPath] ?: method.manifestPath,
                originalResourcePath = method.resourcePath,
                originalManifestPath = method.manifestPath,
            )
        },
        aliases = resourceRenameMap.toMap(),
    )

    internal fun catalogRecords(): List<Pair<String, String>> =
        methods.map { method -> method.resourcePath to method.encodedLine() } +
            aliases.map { (logicalPath, storagePath) -> storagePath to "A|$logicalPath|$storagePath" }
}

internal data class RuntimeVmCatalogArtifacts(
    val entries: List<JarEntryData>,
    val catalogId: ByteArray,
)

internal object RuntimeVmCatalog {
    private val rootAuthDomain = "jsc1-root-auth-v1".toByteArray(Charsets.US_ASCII)
    private val leafDomain = "JSL1".toByteArray(Charsets.US_ASCII)
    private val partitionRootDomain = "JSP1".toByteArray(Charsets.US_ASCII)
    private val catalogRootDomain = "JSC1-root".toByteArray(Charsets.US_ASCII)

    fun build(
        runtimeEntries: List<JarEntryData>,
        plan: RuntimeVmCatalogPlan,
        rootResourcePath: String,
        seed: Long,
    ): RuntimeVmCatalogArtifacts {
        val context = requireVbc4BuildContext()
        val partitions = context.runtimeKeyPartitions
        val catalogId = catalogId(context.jarLayoutDigest, seed)
        val resources = runtimeEntries.mapNotNull { entry ->
            val partitionId = RuntimeResourceCodec.partitionId(entry.bytes) ?: return@mapNotNull null
            require(partitionId in 0 until partitions.resourcePartitionCount) {
                "runtime resource ${entry.name} uses invalid partition $partitionId"
            }
            CatalogResource(
                path = entry.name,
                partitionId = partitionId,
                length = entry.bytes.size,
                digest = sha256(entry.bytes),
            )
        }
        require(resources.isNotEmpty()) { "VM catalog requires partitioned runtime resources" }
        val resourcesByPath = resources.associateBy { it.path }
        require(resourcesByPath.size == resources.size) { "VM catalog resource paths must be unique" }

        val methodLinesByPartition = Array(partitions.resourcePartitionCount) { mutableListOf<String>() }
        plan.catalogRecords().forEach { (storagePath, line) ->
            val resource = resourcesByPath[storagePath]
                ?: error("VM preload entry references missing sealed resource: $storagePath")
            methodLinesByPartition[resource.partitionId] += line
        }

        val directoryEntries = mutableListOf<JarEntryData>()
        val descriptors = mutableListOf<CatalogDirectory>()
        val reservedNames = runtimeEntries.mapTo(linkedSetOf()) { it.name }.apply { add(rootResourcePath) }
        for (partitionId in 0 until partitions.resourcePartitionCount) {
            val partitionResources = resources.filter { it.partitionId == partitionId }.sortedBy { it.path }
            val partitionRoot = merkleRoot(
                partitionResources.map { resourceLeaf(catalogId, it) },
                catalogId,
                partitionId,
            )
            val directoryPlain = buildDirectory(
                catalogId = catalogId,
                partitionId = partitionId,
                methodLines = methodLinesByPartition[partitionId],
                resources = partitionResources,
                partitionRoot = partitionRoot,
            )
            val directoryPath = uniqueDirectoryPath(catalogId, partitionId, seed, reservedNames)
            reservedNames += directoryPath
            val directoryBytes = RuntimeResourceCodec.encodeForPartition(
                bytes = directoryPlain,
                kind = RuntimeResourceKind.NativeIndex,
                seed = digestSeed(directoryPlain),
                variantId = partitionId + 1,
                layerCount = 3,
                partitionId = partitionId,
                compress = true,
            )
            directoryEntries += JarEntryData(directoryPath, directoryBytes)
            descriptors += CatalogDirectory(
                partitionId = partitionId,
                path = directoryPath,
                length = directoryBytes.size,
                digest = sha256(directoryBytes),
                methodCount = methodLinesByPartition[partitionId].size,
                resourceCount = partitionResources.size,
                partitionRoot = partitionRoot,
            )
        }

        val catalogRoot = catalogRoot(catalogId, descriptors)
        val rootBody = buildString {
            append("JSC1|")
            append(catalogId.toHexLower())
            append('|')
            append(partitions.resourcePartitionCount)
            append('|')
            append(methodLinesByPartition.sumOf { it.size })
            append('|')
            append(resources.size)
            append('|')
            append(catalogRoot.toHexLower())
            append('\n')
            descriptors.sortedBy { it.partitionId }.forEach { directory ->
                append("D|")
                append(directory.partitionId)
                append('|')
                append(directory.path)
                append('|')
                append(directory.length)
                append('|')
                append(directory.digest.toHexLower())
                append('|')
                append(directory.methodCount)
                append('|')
                append(directory.resourceCount)
                append('|')
                append(directory.partitionRoot.toHexLower())
                append('\n')
            }
        }.toByteArray(Charsets.UTF_8)
        val anchorKey = partitions.copyAnchorKey()
        val rootTag = try {
            hmacSha256(anchorKey, rootAuthDomain, rootBody)
        } finally {
            Arrays.fill(anchorKey, 0)
        }
        val rootPlain = rootBody + "H|${rootTag.toHexLower()}\n".toByteArray(Charsets.US_ASCII)
        val rootBytes = RuntimeResourceCodec.encodeForAnchor(
            bytes = rootPlain,
            kind = RuntimeResourceKind.NativeIndex,
            seed = digestSeed(rootPlain),
            variantId = 0,
            layerCount = 3,
            compress = true,
        )
        return RuntimeVmCatalogArtifacts(
            entries = directoryEntries + JarEntryData(rootResourcePath, rootBytes),
            catalogId = catalogId,
        )
    }

    private fun buildDirectory(
        catalogId: ByteArray,
        partitionId: Int,
        methodLines: List<String>,
        resources: List<CatalogResource>,
        partitionRoot: ByteArray,
    ): ByteArray = buildString {
        append("JSD1|")
        append(catalogId.toHexLower())
        append('|')
        append(partitionId)
        append('|')
        append(methodLines.size)
        append('|')
        append(resources.size)
        append('|')
        append(partitionRoot.toHexLower())
        append('\n')
        methodLines.forEach { line -> append("M|").append(line).append('\n') }
        resources.forEach { resource ->
            append("R|")
            append(resource.path)
            append('|')
            append(resource.path)
            append('|')
            append(resource.length)
            append('|')
            append(resource.digest.toHexLower())
            append('\n')
        }
    }.toByteArray(Charsets.UTF_8)

    private fun catalogId(layoutDigest: ByteArray, seed: Long): ByteArray {
        val entropy = ByteArray(32).also(SecureRandom()::nextBytes)
        return sha256(
            "jsc1-catalog-id-v1".toByteArray(Charsets.US_ASCII) +
                longBytes(seed) + layoutDigest + entropy,
        ).copyOfRange(0, 16)
    }

    private fun uniqueDirectoryPath(catalogId: ByteArray, partitionId: Int, seed: Long, reserved: Set<String>): String {
        var attempt = 0
        while (true) {
            val digest = sha256(
                "jsc1-directory-path-v1".toByteArray(Charsets.US_ASCII) + catalogId + intBytes(partitionId) +
                    longBytes(seed) + intBytes(attempt++),
            ).toHexLower()
            val candidate = "META-INF/${digest.take(2)}/${digest.substring(2, 22)}"
            if (candidate !in reserved) return candidate
        }
    }

    private fun resourceLeaf(catalogId: ByteArray, resource: CatalogResource): ByteArray = sha256(
        leafDomain + catalogId + intBytes(resource.partitionId) + frame(resource.path) + frame(resource.path) +
            longBytes(resource.length.toLong()) + resource.digest,
    )

    private fun merkleRoot(leaves: List<ByteArray>, catalogId: ByteArray, partitionId: Int): ByteArray {
        if (leaves.isEmpty()) return sha256(partitionRootDomain + catalogId + intBytes(partitionId))
        var level = leaves.sortedWith(::compareBytes)
        while (level.size > 1) {
            val next = ArrayList<ByteArray>((level.size + 1) / 2)
            var index = 0
            while (index < level.size) {
                val left = level[index]
                val right = level.getOrElse(index + 1) { left }
                next += sha256(partitionRootDomain + left + right)
                index += 2
            }
            level = next
        }
        return level.single()
    }

    private fun catalogRoot(catalogId: ByteArray, directories: List<CatalogDirectory>): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(catalogRootDomain)
        out.write(catalogId)
        directories.sortedBy { it.partitionId }.forEach { directory ->
            out.write(intBytes(directory.partitionId))
            out.write(directory.partitionRoot)
        }
        return sha256(out.toByteArray())
    }

    private fun compareBytes(left: ByteArray, right: ByteArray): Int {
        val length = minOf(left.size, right.size)
        for (index in 0 until length) {
            val comparison = (left[index].toInt() and 0xFF).compareTo(right[index].toInt() and 0xFF)
            if (comparison != 0) return comparison
        }
        return left.size.compareTo(right.size)
    }

    private fun frame(value: String): ByteArray {
        val bytes = value.toByteArray(Charsets.UTF_8)
        return intBytes(bytes.size) + bytes
    }

    private fun digestSeed(bytes: ByteArray): Int = sha256(bytes).take(4).fold(0) { acc, byte ->
        (acc shl 8) or (byte.toInt() and 0xFF)
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach(mac::update)
        return mac.doFinal()
    }

    internal fun runtimeVmCatalogMethodAuthTag(
        tokenHex: String,
        resourcePath: String,
        manifestPath: String,
        shardCount: String,
        mesh: String,
        profile: String,
    ): String = sha256(
        RUNTIME_VM_CATALOG_METHOD_AUTH_DOMAIN.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            tokenHex.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            resourcePath.toByteArray(Charsets.UTF_8) + byteArrayOf(0) +
            manifestPath.toByteArray(Charsets.UTF_8) + byteArrayOf(0) +
            shardCount.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            mesh.toByteArray(Charsets.US_ASCII) + byteArrayOf(0) +
            profile.toByteArray(Charsets.US_ASCII),
    ).copyOfRange(0, 8).toHexLower()

    private fun intBytes(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

    private fun longBytes(value: Long): ByteArray = ByteArray(8) { index ->
        (value ushr (56 - index * 8)).toByte()
    }

    private data class CatalogResource(
        val path: String,
        val partitionId: Int,
        val length: Int,
        val digest: ByteArray,
    )

    private data class CatalogDirectory(
        val partitionId: Int,
        val path: String,
        val length: Int,
        val digest: ByteArray,
        val methodCount: Int,
        val resourceCount: Int,
        val partitionRoot: ByteArray,
    )
}
