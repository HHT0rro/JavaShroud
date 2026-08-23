package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.RuntimeVmCatalog
import io.github.hht0rro.javashroud.transforms.protection.RuntimeVmCatalogMethod
import io.github.hht0rro.javashroud.transforms.protection.RuntimeVmCatalogPlan
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_CATALOG_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.encodeSealedNativeBindingLines
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CatalogConfidentialityTest {
    @Test
    fun catalog_root_is_anchor_encrypted_and_round_trips() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { (it * 7 + 3).toByte() },
            nativeSeed = 0x13572468L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { (it * 11 + 5).toByte() },
        )
        withVbc4BuildContext(context) {
            val resource = RuntimeResourceCodec.encodeForPartition(
                "payload".toByteArray(), RuntimeResourceKind.VmBytecode, 1, 1, 3, 0, false,
            )
            val path = "META-INF/.r/a.bin"
            val plan = RuntimeVmCatalogPlan(listOf(RuntimeVmCatalogMethod(
                entryToken = 1,
                resourcePath = path,
                manifestPath = path,
                shardCount = 1,
                mesh = MessageDigest.getInstance("SHA-256").digest("mesh".toByteArray()).joinToString("") { "%02x".format(it) },
                methodLocalProfile = 0,
            )))
            val built = RuntimeVmCatalog.build(listOf(JarEntryData(path, resource)), plan, VBC4_VM_CATALOG_RESOURCE, context.nativeSeed)
            val sealedRoot = built.entries.single { it.name == VBC4_VM_CATALOG_RESOURCE }.bytes
            assertFalse(sealedRoot.decodeToString().startsWith("JSC1|"))
            val plain = RuntimeResourceCodec.decode(sealedRoot) ?: error("catalog root did not decode")
            assertContentEquals("JSC1|".toByteArray(), plain.copyOfRange(0, 5))
        }
    }

    @Test
    fun sealed_native_locator_keeps_locator_rows_separate_from_public_aken_bindings() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { (it * 13 + 7).toByte() },
            nativeSeed = 0x24681357L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { (it * 17 + 9).toByte() },
        )
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        val helperBytes = checkNotNull(javaClass.classLoader.getResourceAsStream("$helperName.class")).use { it.readBytes() }
        val helperArtifact = ClassArtifact(
            entryName = "$helperName.class",
            summary = analyzeClassBytes(helperBytes),
            bytes = helperBytes,
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(helperArtifact),
            jarEntries = listOf(
                JarEntryData(helperArtifact.entryName, helperArtifact.bytes),
                JarEntryData("META-INF/jsrt/windows-x64/jsrt_ffi.dll", byteArrayOf('M'.code.toByte(), 'Z'.code.toByte(), 1, 2, 3)),
            ),
        )

        val sealed = withVbc4BuildContext(context) {
            RuntimeArtifactSealing.seal(artifact, context.nativeSeed, rewritesVmRuntime = false)
        }
        val nativeLocatorEntries = sealed.jarEntries.filter { entry ->
            entry.bytes.size >= 4 && entry.bytes.copyOfRange(0, 4).contentEquals(byteArrayOf(0xD7.toByte(), 0xA4.toByte(), 0x91.toByte(), 0xE3.toByte()))
        }
        val nativeLocator = nativeLocatorEntries.single()
        assertFalse(nativeLocator.bytes.containsAscii("META-INF/"), "AKEN native locator routes must remain masked")
        assertFalse(nativeLocator.bytes.containsAscii("windows-x64"), "AKEN native locator must not expose platform text")
        assertFalse(nativeLocator.bytes.startsWithAscii("JSBI"), "AKEN native locator must not use the retired JSBI envelope")
        assertFalse(nativeLocator.bytes.startsWithAscii("JSRP"), "AKEN native locator must not use the retired JSRP envelope")
        assertFalse(nativeLocator.bytes.containsAscii("B|"), "native locator must not expose class bindings")
        assertFalse(nativeLocator.bytes.containsAscii("M|"), "native locator must not expose method bindings")

        val bindingResources = sealed.jarEntries.filter { entry ->
            entry.bytes.containsAscii("B|") || entry.bytes.containsAscii("M|")
        }
        assertEquals(1, bindingResources.size, "one raw AKEN relocation-binding resource must be emitted")
        assertFalse(sealed.jarEntries.any { it.name == "META-INF/.r/bindings.dat" }, "legacy fixed binding path must not survive sealing")
        val bindingResource = bindingResources.single()
        assertTrue(bindingResource.bytes.containsAscii("B|"), "binding metadata must contain class relocation rows")
        assertFalse(bindingResource.bytes.startsWithAscii("JSRP"), "AKEN relocation metadata must not depend on the retired root-key envelope")
        assertFalse(bindingResource.bytes.startsWithAscii("JSBI"), "AKEN relocation metadata must stay independent of the bootstrap index")
        assertEquals(null, withVbc4BuildContext(context) { RuntimeResourceCodec.decode(bindingResource.bytes) })

        val rewrittenHelper = sealed.classArtifacts.single().bytes
        assertTrue(
            classUtf8Constants(rewrittenHelper).contains(bindingResource.name),
            "rewritten helper must reference the artifact-specific AKEN binding path",
        )
    }

    @Test
    fun sealed_native_binding_rows_are_raw_public_relocation_metadata() {
        val lines = listOf(
            "B|0123456789abcdef|r/ab/C0123456789abcdef012345",
            "M|fedcba9876543210|m_0123456789abcdef",
        )
        val encoded = encodeSealedNativeBindingLines(lines, 0x33557799L)
        assertEquals(lines.joinToString(separator = "\n", postfix = "\n"), encoded.decodeToString())
        assertTrue(encoded.containsAscii("B|"))
        assertTrue(encoded.containsAscii("M|"))
        assertFalse(encoded.startsWithAscii("JSRP"))
        assertFalse(encoded.startsWithAscii("JSBI"))
    }

    @Test
    fun environment_bound_keys_do_not_inject_e_rows_into_relocation_bindings() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { (it * 13 + 7).toByte() },
            nativeSeed = 0x24681357L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { (it * 17 + 9).toByte() },
        )
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        val helperBytes = checkNotNull(javaClass.classLoader.getResourceAsStream("$helperName.class")).use { it.readBytes() }
        val helperArtifact = ClassArtifact(
            entryName = "$helperName.class",
            summary = analyzeClassBytes(helperBytes),
            bytes = helperBytes,
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(helperArtifact),
            jarEntries = listOf(
                JarEntryData(helperArtifact.entryName, helperArtifact.bytes),
                JarEntryData("META-INF/jsrt/windows-x64/jsrt_ffi.dll", byteArrayOf('M'.code.toByte(), 'Z'.code.toByte(), 1, 2, 3)),
            ),
        )
        val sealed = withVbc4BuildContext(context) {
            RuntimeArtifactSealing.seal(
                artifact,
                context.nativeSeed,
                rewritesVmRuntime = false,
                envBindingMetadata = RuntimeArtifactSealing.EnvBindingMetadata(
                    bindBootSecret = false,
                    expectedFingerprint = null,
                ),
            )
        }
        val bindingResource = sealed.jarEntries.single { entry ->
            entry.bytes.containsAscii("B|") || entry.bytes.containsAscii("M|")
        }
        assertFalse(bindingResource.bytes.containsAscii("E|"), "relocation bindings must stay B/M/F only")
        bindingResource.bytes.decodeToString().lineSequence().filter { it.isNotBlank() }.forEach { line ->
            assertTrue(line.startsWith("B|") || line.startsWith("M|") || line.startsWith("F|"), line)
        }
    }

    private fun ByteArray.startsWithAscii(value: String): Boolean =
        size >= value.length && value.indices.all { index -> this[index] == value[index].code.toByte() }

    private fun ByteArray.containsAscii(value: String): Boolean {
        val needle = value.toByteArray(Charsets.US_ASCII)
        if (needle.isEmpty() || size < needle.size) return false
        return (0..size - needle.size).any { offset -> needle.indices.all { index -> this[offset + index] == needle[index] } }
    }

    private fun classUtf8Constants(bytes: ByteArray): Set<String> {
        val input = DataInputStream(ByteArrayInputStream(bytes))
        check(input.readInt() == 0xCAFEBABE.toInt())
        input.readUnsignedShort()
        input.readUnsignedShort()
        val count = input.readUnsignedShort()
        val values = linkedSetOf<String>()
        var index = 1
        while (index < count) {
            when (val tag = input.readUnsignedByte()) {
                1 -> values += input.readUTF()
                3, 4 -> input.skipBytes(4)
                5, 6 -> { input.skipBytes(8); index++ }
                7, 8, 16, 19, 20 -> input.skipBytes(2)
                9, 10, 11, 12, 17, 18 -> input.skipBytes(4)
                15 -> input.skipBytes(3)
                else -> error("unsupported class constant tag $tag")
            }
            index++
        }
        return values
    }
}
