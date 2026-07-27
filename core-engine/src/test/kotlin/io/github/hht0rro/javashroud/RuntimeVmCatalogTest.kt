package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.RuntimeKeyPartitions
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper
import io.github.hht0rro.javashroud.transforms.protection.RuntimeVmCatalog
import io.github.hht0rro.javashroud.transforms.protection.RuntimeVmCatalogMethod
import io.github.hht0rro.javashroud.transforms.protection.RuntimeVmCatalogPlan
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_CATALOG_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.io.ByteArrayOutputStream
import java.lang.reflect.InvocationTargetException
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RuntimeVmCatalogTest {
    @Test
    fun root_hmac_authenticates_the_complete_catalog_body() = withCatalogContext { context ->
        val fixture = catalogFixture(context)
        val root = parseRoot(fixture.artifacts.getValue(VBC4_VM_CATALOG_RESOURCE))
        val anchorKey = context.runtimeKeyPartitions!!.copyAnchorKey()
        val expectedTag = try {
            hmacSha256(anchorKey, ROOT_AUTH_DOMAIN, root.body)
        } finally {
            anchorKey.fill(0)
        }

        assertContentEquals(expectedTag, root.tag, "catalog root tag must authenticate every root descriptor")

        val tamperedBody = root.body.copyOf().also { bytes ->
            val index = bytes.indexOfFirst { it == '|'.code.toByte() } + 1
            bytes[index] = (bytes[index].toInt() xor 0x01).toByte()
        }
        val secondAnchorKey = context.runtimeKeyPartitions!!.copyAnchorKey()
        val tamperedTag = try {
            hmacSha256(secondAnchorKey, ROOT_AUTH_DOMAIN, tamperedBody)
        } finally {
            secondAnchorKey.fill(0)
        }
        assertFalse(MessageDigest.isEqual(root.tag, tamperedTag), "changing root metadata must invalidate its HMAC")
    }

    @Test
    fun partition_directories_cover_every_runtime_resource_and_match_all_merkle_roots() = withCatalogContext { context ->
        val fixture = catalogFixture(context)
        val root = parseRoot(fixture.artifacts.getValue(VBC4_VM_CATALOG_RESOURCE))
        val partitionCount = context.runtimeKeyPartitions!!.resourcePartitionCount

        assertEquals(partitionCount, root.partitionCount)
        assertEquals(partitionCount, root.directories.size, "catalog must emit one authenticated directory per key partition")
        assertEquals(fixture.runtimeEntries.size, root.resourceCount)

        val coveredPaths = linkedSetOf<String>()
        val actualPartitionRoots = mutableListOf<ByteArray>()
        var totalMethods = 0
        var totalResources = 0
        for (descriptor in root.directories.sortedBy { it.partitionId }) {
            val directoryRaw = fixture.artifacts.getValue(descriptor.path)
            assertEquals(descriptor.length, directoryRaw.size)
            assertContentEquals(descriptor.digest, sha256(directoryRaw))
            assertEquals(descriptor.partitionId, RuntimeResourceCodec.partitionId(directoryRaw))

            val directoryPlain = RuntimeResourceCodec.decode(directoryRaw)
                ?: error("catalog directory ${descriptor.path} did not decode")
            val directory = parseDirectory(directoryPlain)
            assertContentEquals(root.catalogId, directory.catalogId)
            assertEquals(descriptor.partitionId, directory.partitionId)
            assertEquals(descriptor.methodCount, directory.methodCount)
            assertEquals(descriptor.resourceCount, directory.resourceCount)
            assertContentEquals(descriptor.partitionRoot, directory.partitionRoot)

            val leaves = directory.resources.map { resource ->
                val runtimeEntry = fixture.runtimeByPath.getValue(resource.storagePath)
                assertTrue(coveredPaths.add(resource.storagePath), "runtime resource must occur in exactly one directory")
                assertEquals(resource.length, runtimeEntry.bytes.size)
                assertContentEquals(resource.digest, sha256(runtimeEntry.bytes))
                assertEquals(descriptor.partitionId, RuntimeResourceCodec.partitionId(runtimeEntry.bytes))
                resourceLeaf(root.catalogId, descriptor.partitionId, resource)
            }
            val actualPartitionRoot = merkleRoot(leaves, root.catalogId, descriptor.partitionId)
            assertContentEquals(descriptor.partitionRoot, actualPartitionRoot)
            actualPartitionRoots += actualPartitionRoot
            totalMethods += directory.methodCount
            totalResources += directory.resourceCount
        }

        assertEquals(fixture.runtimeByPath.keys, coveredPaths, "directories must cover referenced and otherwise-unused business JSRP resources")
        assertTrue(UNUSED_RESOURCE_PATH in coveredPaths, "an uncalled business resource still belongs to the startup commitment")
        assertEquals(root.methodCount, totalMethods)
        assertEquals(root.resourceCount, totalResources)
        assertContentEquals(root.catalogRoot, catalogRoot(root.catalogId, actualPartitionRoots))
    }

    @Test
    fun duplicate_runtime_resource_paths_are_rejected() = withCatalogContext { context ->
        val entry = runtimeEntry(PRIMARY_RESOURCE_PATH, 0, RuntimeResourceKind.VmBytecode, "primary")
        val duplicate = entry.copy(bytes = entry.bytes.copyOf())
        val plan = catalogPlan(PRIMARY_RESOURCE_PATH, PRIMARY_RESOURCE_PATH)

        val failure = assertFailsWith<IllegalArgumentException> {
            RuntimeVmCatalog.build(
                runtimeEntries = listOf(entry, duplicate),
                plan = plan,
                rootResourcePath = VBC4_VM_CATALOG_RESOURCE,
                seed = context.nativeSeed,
            )
        }
        assertTrue(failure.message.orEmpty().contains("paths must be unique"))
    }

    @Test
    fun preload_reference_to_an_omitted_business_jsrp_resource_is_rejected() = withCatalogContext { context ->
        val present = runtimeEntry(UNUSED_RESOURCE_PATH, 0, RuntimeResourceKind.VmBytecode, "present")
        val omitted = runtimeEntry(PRIMARY_RESOURCE_PATH, 1, RuntimeResourceKind.VmBytecode, "omitted")

        val failure = assertFailsWith<IllegalStateException> {
            RuntimeVmCatalog.build(
                runtimeEntries = listOf(present),
                plan = catalogPlan(omitted.name, omitted.name),
                rootResourcePath = VBC4_VM_CATALOG_RESOURCE,
                seed = context.nativeSeed,
            )
        }
        assertTrue(failure.message.orEmpty().contains("references missing sealed resource"))
    }

    @Test
    fun authenticated_outer_catalog_still_rejects_tampered_method_identity_fields() = withCatalogContext { context ->
        val fixture = catalogFixture(context)
        val root = parseRoot(fixture.artifacts.getValue(VBC4_VM_CATALOG_RESOURCE))
        val descriptor = root.directories.single { it.partitionId == 0 }
        val directoryPlain = RuntimeResourceCodec.decode(fixture.artifacts.getValue(descriptor.path))
            ?: error("catalog directory did not decode")
        val directoryLines = directoryPlain.decodeToString().lineSequence().filter { it.isNotEmpty() }.toList()
        val methodLineIndex = directoryLines.indexOfFirst { it.startsWith("M|") }
        assertTrue(methodLineIndex > 0, "fixture catalog must contain an authenticated method record")
        val originalFields = directoryLines[methodLineIndex].removePrefix("M|").split('|')
        assertEquals(7, originalFields.size)

        val alternateCommittedPath = UNUSED_RESOURCE_PATH
        val mutations = linkedMapOf(
            "entry" to (0 to "${originalFields[0]}1"),
            "resource-path" to (1 to alternateCommittedPath),
            "manifest-path" to (2 to alternateCommittedPath),
            "shard-count" to (3 to (originalFields[3].toInt() + 1).toString()),
            "mesh" to (4 to flipHex(originalFields[4])),
            "profile" to (5 to (originalFields[5].toUInt(16) + 1u).toString(16)),
            "auth-tag" to (6 to flipHex(originalFields[6])),
        )
        val committedPaths = fixture.runtimeByPath.keys
        val verifier = JniMicrokernelHelper::class.java.getDeclaredMethod(
            "verifyVmPreloadIndexBeforeNative",
            String::class.java,
            Set::class.java,
        ).also { it.isAccessible = true }

        for ((surface, mutation) in mutations) {
            val mutatedFields = originalFields.toMutableList().also { fields -> fields[mutation.first] = mutation.second }
            val mutatedLines = directoryLines.toMutableList().also { lines ->
                lines[methodLineIndex] = "M|${mutatedFields.joinToString("|")}"
            }
            val mutatedPlain = mutatedLines.joinToString(separator = "\n", postfix = "\n").toByteArray(Charsets.UTF_8)
            val mutatedDirectory = RuntimeResourceCodec.encodeForPartition(
                bytes = mutatedPlain,
                kind = RuntimeResourceKind.NativeIndex,
                seed = surface.hashCode(),
                variantId = descriptor.partitionId + 1,
                layerCount = 3,
                partitionId = descriptor.partitionId,
                compress = true,
            )

            assertContentEquals(
                mutatedPlain,
                RuntimeResourceCodec.decode(mutatedDirectory),
                "$surface fixture must retain a valid outer JSRP envelope",
            )
            val mutatedRoot = resealCatalogRoot(context, root, descriptor, mutatedDirectory)
            val parsedRoot = parseRoot(mutatedRoot)
            val parsedDescriptor = parsedRoot.directories.single { it.partitionId == descriptor.partitionId }
            assertEquals(mutatedDirectory.size, parsedDescriptor.length)
            assertContentEquals(sha256(mutatedDirectory), parsedDescriptor.digest)
            assertContentEquals(descriptor.partitionRoot, parsedDescriptor.partitionRoot)

            val failure = assertFailsWith<InvocationTargetException>(surface) {
                verifier.invoke(null, mutatedFields.joinToString("|", postfix = "\n"), committedPaths)
            }
            assertTrue(failure.cause is SecurityException, "$surface must fail in the production preload verifier")
        }
    }

    private fun catalogFixture(context: Vbc4BuildContext): CatalogFixture {
        val partitionCount = context.runtimeKeyPartitions!!.resourcePartitionCount
        val runtimeEntries = listOf(
            runtimeEntry(PRIMARY_RESOURCE_PATH, 0, RuntimeResourceKind.VmBytecode, "primary-program"),
            runtimeEntry(MANIFEST_RESOURCE_PATH, 1, RuntimeResourceKind.Manifest, "slice-manifest"),
            runtimeEntry(UNUSED_RESOURCE_PATH, minOf(2, partitionCount - 1), RuntimeResourceKind.VmBytecode, "uncalled-program"),
        )
        val built = RuntimeVmCatalog.build(
            runtimeEntries = runtimeEntries,
            plan = catalogPlan(PRIMARY_RESOURCE_PATH, MANIFEST_RESOURCE_PATH),
            rootResourcePath = VBC4_VM_CATALOG_RESOURCE,
            seed = context.nativeSeed,
        )
        return CatalogFixture(
            runtimeEntries = runtimeEntries,
            runtimeByPath = runtimeEntries.associateBy { it.name },
            artifacts = built.entries.associate { it.name to it.bytes },
        )
    }

    private fun runtimeEntry(
        path: String,
        partitionId: Int,
        kind: RuntimeResourceKind,
        text: String,
    ): JarEntryData = JarEntryData(
        name = path,
        bytes = RuntimeResourceCodec.encodeForPartition(
            bytes = text.toByteArray(Charsets.UTF_8),
            kind = kind,
            seed = text.hashCode(),
            variantId = partitionId + 1,
            layerCount = 3,
            partitionId = partitionId,
            compress = false,
        ),
    )

    private fun catalogPlan(resourcePath: String, manifestPath: String): RuntimeVmCatalogPlan {
        val mesh = sha256("catalog-mesh".toByteArray(Charsets.US_ASCII)).toHexLower()
        return RuntimeVmCatalogPlan(
            methods = listOf(
                RuntimeVmCatalogMethod(
                    entryToken = 0x1234ABCDL,
                    resourcePath = resourcePath,
                    manifestPath = manifestPath,
                    shardCount = 2,
                    mesh = mesh,
                    methodLocalProfile = 1,
                ),
            ),
        )
    }

    private fun resealCatalogRoot(
        context: Vbc4BuildContext,
        root: CatalogRoot,
        changedDescriptor: CatalogDirectory,
        changedDirectory: ByteArray,
    ): ByteArray {
        val body = root.body.decodeToString().lineSequence()
            .filter { it.isNotEmpty() }
            .joinToString(separator = "\n", postfix = "\n") { line ->
                val parts = line.split('|')
                if (parts.firstOrNull() != "D" || parts.getOrNull(1)?.toIntOrNull() != changedDescriptor.partitionId) {
                    line
                } else {
                    listOf(
                        "D",
                        changedDescriptor.partitionId,
                        changedDescriptor.path,
                        changedDirectory.size,
                        sha256(changedDirectory).toHexLower(),
                        changedDescriptor.methodCount,
                        changedDescriptor.resourceCount,
                        changedDescriptor.partitionRoot.toHexLower(),
                    ).joinToString("|")
                }
            }.toByteArray(Charsets.UTF_8)
        val anchorKey = context.runtimeKeyPartitions!!.copyAnchorKey()
        val tag = try {
            hmacSha256(anchorKey, ROOT_AUTH_DOMAIN, body)
        } finally {
            anchorKey.fill(0)
        }
        val sealedRoot = body + "H|${tag.toHexLower()}\n".toByteArray(Charsets.US_ASCII)
        val parsed = parseRoot(sealedRoot)
        assertContentEquals(tag, parsed.tag, "rewritten JSC1 body must carry a valid root HMAC")
        return sealedRoot
    }

    private fun flipHex(value: String): String {
        require(value.isNotEmpty())
        val replacement = if (value[0] == '0') '1' else '0'
        return replacement + value.substring(1)
    }

    private fun parseRoot(bytes: ByteArray): CatalogRoot {
        val lines = bytes.decodeToString().lineSequence().filter { it.isNotEmpty() }.toList()
        val header = lines.first().split('|')
        val tagLine = lines.last().split('|')
        val body = lines.dropLast(1).joinToString(separator = "\n", postfix = "\n").toByteArray(Charsets.UTF_8)
        val directories = lines.drop(1).dropLast(1).map { line ->
            val parts = line.split('|')
            assertEquals("D", parts[0])
            CatalogDirectory(
                partitionId = parts[1].toInt(),
                path = parts[2],
                length = parts[3].toInt(),
                digest = parts[4].hexToBytes(),
                methodCount = parts[5].toInt(),
                resourceCount = parts[6].toInt(),
                partitionRoot = parts[7].hexToBytes(),
            )
        }
        assertEquals("JSC1", header[0])
        assertEquals("H", tagLine[0])
        return CatalogRoot(
            catalogId = header[1].hexToBytes(),
            partitionCount = header[2].toInt(),
            methodCount = header[3].toInt(),
            resourceCount = header[4].toInt(),
            catalogRoot = header[5].hexToBytes(),
            directories = directories,
            body = body,
            tag = tagLine[1].hexToBytes(),
        )
    }

    private fun parseDirectory(bytes: ByteArray): CatalogDirectoryContents {
        val lines = bytes.decodeToString().lineSequence().filter { it.isNotEmpty() }.toList()
        val header = lines.first().split('|')
        assertEquals("JSD1", header[0])
        val resources = lines.drop(1).filter { it.startsWith("R|") }.map { line ->
            val parts = line.split('|')
            CatalogResource(
                logicalPath = parts[1],
                storagePath = parts[2],
                length = parts[3].toInt(),
                digest = parts[4].hexToBytes(),
            )
        }
        val methodCount = lines.drop(1).count { it.startsWith("M|") }
        assertEquals(header[3].toInt(), methodCount)
        assertEquals(header[4].toInt(), resources.size)
        return CatalogDirectoryContents(
            catalogId = header[1].hexToBytes(),
            partitionId = header[2].toInt(),
            methodCount = methodCount,
            resourceCount = resources.size,
            partitionRoot = header[5].hexToBytes(),
            resources = resources,
        )
    }

    private fun resourceLeaf(catalogId: ByteArray, partitionId: Int, resource: CatalogResource): ByteArray = sha256(
        LEAF_DOMAIN + catalogId + intBytes(partitionId) + frame(resource.logicalPath) + frame(resource.storagePath) +
            longBytes(resource.length.toLong()) + resource.digest,
    )

    private fun merkleRoot(leaves: List<ByteArray>, catalogId: ByteArray, partitionId: Int): ByteArray {
        if (leaves.isEmpty()) return sha256(PARTITION_ROOT_DOMAIN + catalogId + intBytes(partitionId))
        var level = leaves.sortedWith(::compareBytes)
        while (level.size > 1) {
            val next = ArrayList<ByteArray>((level.size + 1) / 2)
            var index = 0
            while (index < level.size) {
                val left = level[index]
                val right = level.getOrElse(index + 1) { left }
                next += sha256(PARTITION_ROOT_DOMAIN + left + right)
                index += 2
            }
            level = next
        }
        return level.single()
    }

    private fun catalogRoot(catalogId: ByteArray, partitionRoots: List<ByteArray>): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(CATALOG_ROOT_DOMAIN)
        out.write(catalogId)
        partitionRoots.forEachIndexed { partitionId, root ->
            out.write(intBytes(partitionId))
            out.write(root)
        }
        return sha256(out.toByteArray())
    }

    private fun compareBytes(left: ByteArray, right: ByteArray): Int {
        for (index in 0 until minOf(left.size, right.size)) {
            val comparison = (left[index].toInt() and 0xFF).compareTo(right[index].toInt() and 0xFF)
            if (comparison != 0) return comparison
        }
        return left.size.compareTo(right.size)
    }

    private fun frame(value: String): ByteArray {
        val bytes = value.toByteArray(Charsets.UTF_8)
        return intBytes(bytes.size) + bytes
    }

    private fun intBytes(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

    private fun longBytes(value: Long): ByteArray = ByteArray(8) { index ->
        (value ushr (56 - index * 8)).toByte()
    }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        parts.forEach(mac::update)
        return mac.doFinal()
    }

    private fun ByteArray.toHexLower(): String = joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) }

    private fun String.hexToBytes(): ByteArray {
        require(length % 2 == 0)
        return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private fun <T> withCatalogContext(block: (Vbc4BuildContext) -> T): T {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 11 + 3).toByte() },
            nativeSeed = 0x4A53_4331L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 7 + 5).toByte() },
            runtimeKeyPartitions = RuntimeKeyPartitions.generate(),
        )
        return try {
            withVbc4BuildContext(context) { block(context) }
        } finally {
            context.wipe()
        }
    }

    private data class CatalogFixture(
        val runtimeEntries: List<JarEntryData>,
        val runtimeByPath: Map<String, JarEntryData>,
        val artifacts: Map<String, ByteArray>,
    )

    private data class CatalogRoot(
        val catalogId: ByteArray,
        val partitionCount: Int,
        val methodCount: Int,
        val resourceCount: Int,
        val catalogRoot: ByteArray,
        val directories: List<CatalogDirectory>,
        val body: ByteArray,
        val tag: ByteArray,
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

    private data class CatalogDirectoryContents(
        val catalogId: ByteArray,
        val partitionId: Int,
        val methodCount: Int,
        val resourceCount: Int,
        val partitionRoot: ByteArray,
        val resources: List<CatalogResource>,
    )

    private data class CatalogResource(
        val logicalPath: String,
        val storagePath: String,
        val length: Int,
        val digest: ByteArray,
    )

    private companion object {
        val ROOT_AUTH_DOMAIN = "jsc1-root-auth-v1".toByteArray(Charsets.US_ASCII)
        val LEAF_DOMAIN = "JSL1".toByteArray(Charsets.US_ASCII)
        val PARTITION_ROOT_DOMAIN = "JSP1".toByteArray(Charsets.US_ASCII)
        val CATALOG_ROOT_DOMAIN = "JSC1-root".toByteArray(Charsets.US_ASCII)

        const val PRIMARY_RESOURCE_PATH = "META-INF/runtime/vm-primary.bin"
        const val MANIFEST_RESOURCE_PATH = "META-INF/runtime/vm-manifest.bin"
        const val UNUSED_RESOURCE_PATH = "META-INF/runtime/vm-uncalled.bin"
    }
}
