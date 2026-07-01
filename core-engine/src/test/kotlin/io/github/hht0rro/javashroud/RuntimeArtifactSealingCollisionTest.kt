package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_VM_PRELOAD_INDEX_RESOURCE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.sealedRuntimeHelperInternalName
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path

class RuntimeArtifactSealingCollisionTest {
    @Test
    fun `sealed runtime helper names avoid existing jar entries during re-obfuscation`() {
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/AntiDumpRuntimeHelper"
        val helperBytes = loadClassBytes("$helperName.class")
        val preferredSealedName = sealedRuntimeHelperInternalName(helperName)
        val preferredIndexName = "META-INF/2b/133bbfe49e7328/ed/4922ed671e6c67376688c9616b4567.properties"
        val previousVmResourceName = "META-INF/2b/133bbfe49e7328/df/b61f2036a17bbb450b1228c6522a89.conf"
        val existingSealedBytes = simpleClassBytes(preferredSealedName)
        val helperArtifact = ClassArtifact(
            entryName = "$helperName.class",
            summary = analyzeClassBytes(helperBytes),
            bytes = helperBytes,
        )
        val existingSealedArtifact = ClassArtifact(
            entryName = "$preferredSealedName.class",
            summary = analyzeClassBytes(existingSealedBytes),
            bytes = existingSealedBytes,
        )
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(helperArtifact, existingSealedArtifact),
            jarEntries = listOf(
                JarEntryData(helperArtifact.entryName, helperArtifact.bytes),
                JarEntryData(existingSealedArtifact.entryName, existingSealedArtifact.bytes),
                JarEntryData(preferredIndexName, byteArrayOf(1, 2, 3)),
                JarEntryData(previousVmResourceName, byteArrayOf('V'.code.toByte(), 'B'.code.toByte(), 'C'.code.toByte(), '4'.code.toByte())),
            ),
        )

        val sealed = withVbc4BuildContext(defaultVbc4BuildContext()) {
            RuntimeArtifactSealing.seal(artifact, 0x4A53524CL)
        }
        val classEntries = sealed.jarEntries.map { it.name }.filter { it.endsWith(".class") }

        assertEquals(classEntries.size, classEntries.toSet().size)
        assertTrue("$preferredSealedName.class" in classEntries)
        assertFalse(helperArtifact.entryName in classEntries)
        assertTrue(classEntries.any { it.startsWith("r/") && it != "$preferredSealedName.class" })
        val sealedEntryNames = sealed.jarEntries.map { it.name }
        assertTrue(preferredIndexName in sealedEntryNames)
        assertTrue(previousVmResourceName in sealedEntryNames)
        assertTrue(sealedEntryNames.any { it.startsWith("META-INF/2b/133bbfe49e7328/") && it != preferredIndexName })
    }

    @Test
    fun `non VM runtime sealing preserves existing VM preload index and resources during re-obfuscation`() {
        val originalVmResource = "META-INF/.r/vm-existing.bin"
        val originalIndexText = "123456789abcdef0|$originalVmResource|$originalVmResource|2\n"
        val context = fixedContext()
        val legacyRuntimeUser = ClassArtifact(
            entryName = "sample/LegacyRuntimeUser.class",
            summary = analyzeClassBytes(classWithStringConstant("sample/LegacyRuntimeUser", "META-INF/.r/0.dat")),
            bytes = classWithStringConstant("sample/LegacyRuntimeUser", "META-INF/.r/0.dat"),
        )
        val artifact = artifactWithExistingVmRuntime(context, originalVmResource, originalIndexText, listOf(legacyRuntimeUser))

        val sealed = withVbc4BuildContext(context) {
            RuntimeArtifactSealing.seal(artifact, 0x4A53524CL, rewritesVmRuntime = false)
        }

        val sealedEntries = sealed.jarEntries.associateBy { it.name }
        assertTrue(originalVmResource in sealedEntries.keys, "Existing VM resource must remain at its original path when this run did not create a new VM runtime")
        assertEquals(
            "old-native-index".toByteArray(Charsets.UTF_8).toList(),
            sealedEntries.getValue("META-INF/.r/0.dat").bytes.toList(),
            "Existing sealed native bindings must remain because old VM bytecode can still resolve helper aliases through them",
        )
        val decodedIndex = withVbc4BuildContext(context) {
            RuntimeResourceCodec.decode(sealedEntries.getValue(VBC4_VM_PRELOAD_INDEX_RESOURCE).bytes)!!.decodeToString()
        }
        assertEquals(originalIndexText, decodedIndex)
        assertFalse(decodedIndex.lines().any { it.startsWith("A|") }, "Non-VM passes must not rewrite a previous VM runtime into a newer alias format")
        val legacyRuntimeUserBytes = sealedEntries.getValue("sample/LegacyRuntimeUser.class").bytes
        assertTrue(
            classContainsStringConstant(legacyRuntimeUserBytes, "META-INF/.r/0.dat"),
            "Old runtime code must keep loading its original sealed native index instead of this run's new index",
        )
    }

    @Test
    fun `VM runtime sealing rewrites existing VM preload index when this run virtualizes methods`() {
        val originalVmResource = "META-INF/.r/vm-existing.bin"
        val originalIndexText = "123456789abcdef0|$originalVmResource|$originalVmResource|2\n"
        val context = fixedContext()
        val artifact = withVbc4BuildContext(context) {
            artifactWithExistingVmRuntime(context, originalVmResource, originalIndexText).let { base ->
                base.copy(jarEntries = base.jarEntries + JarEntryData(
                    VBC4_VM_CURRENT_PRELOAD_INDEX_RESOURCE,
                    RuntimeResourceCodec.encode(
                        bytes = "abcdef|META-INF/.r/current.vm|META-INF/.r/current.vm|2\n".toByteArray(Charsets.UTF_8),
                        kind = RuntimeResourceKind.NativeIndex,
                        seed = 11,
                        variantId = 1,
                        layerCount = 4,
                        compress = false,
                    ),
                ))
            }
        }

        val sealed = withVbc4BuildContext(context) {
            RuntimeArtifactSealing.seal(artifact, 0x4A53524CL, rewritesVmRuntime = true)
        }

        val sealedEntries = sealed.jarEntries.associateBy { it.name }
        assertFalse(originalVmResource in sealedEntries.keys, "A VM-producing run should still reseal VM resources")
        assertFalse("META-INF/.r/0.dat" in sealedEntries.keys, "A VM-producing run should replace the legacy sealed native index with this run's sealed index")
        val decodedIndex = withVbc4BuildContext(context) {
            RuntimeResourceCodec.decode(sealedEntries.getValue(VBC4_VM_PRELOAD_INDEX_RESOURCE).bytes)!!.decodeToString()
        }
        assertTrue(decodedIndex.contains("|$originalVmResource|$originalVmResource\n"), "Rewritten VM index must preserve original binding paths")
        assertTrue(decodedIndex.lines().any { it.startsWith("A|$originalVmResource|") }, "VM-producing runs must retain alias metadata for sealed resource lookup")
    }

    @Test
    fun `non VM runtime sealing leaves prior sealed runtime classes byte identical`() {
        val context = fixedContext()
        val priorRuntimeName = "r/74/C9f148d72d3254a8cabd3f4f8"
        val priorRuntimeBytes = priorSealedRuntimeClassBytes(priorRuntimeName)
        val priorRuntime = ClassArtifact(
            entryName = "$priorRuntimeName.class",
            summary = analyzeClassBytes(priorRuntimeBytes),
            bytes = priorRuntimeBytes,
        )
        val priorNestedName = "r/0e/C7b908c2243e8a1135d80f05b\$Ib812e96115a80c60"
        val priorNestedBytes = simpleClassBytes(priorNestedName)
        val priorNested = ClassArtifact(
            entryName = "$priorNestedName.class",
            summary = analyzeClassBytes(priorNestedBytes),
            bytes = priorNestedBytes,
        )
        val artifact = artifactWithExistingVmRuntime(
            context = context,
            originalVmResource = "META-INF/.r/vm-existing.bin",
            originalIndexText = "123456789abcdef0|META-INF/.r/vm-existing.bin|META-INF/.r/vm-existing.bin|2\n",
            classArtifacts = listOf(priorRuntime, priorNested),
        )

        val sealed = withVbc4BuildContext(context) {
            RuntimeArtifactSealing.seal(artifact, 0x4A53524CL, rewritesVmRuntime = false)
        }

        assertEquals(
            priorRuntimeBytes.toList(),
            sealed.jarEntries.associateBy { it.name }.getValue(priorRuntime.entryName).bytes.toList(),
            "A re-obfuscation pass must not rewrite an older sealed runtime class to load this run's helper before its original helper",
        )
        assertEquals(
            priorNestedBytes.toList(),
            sealed.jarEntries.associateBy { it.name }.getValue(priorNested.entryName).bytes.toList(),
            "Nested support classes belonging to an older sealed runtime must remain byte-identical during re-obfuscation",
        )
    }

    @Test
    fun `sealed native binding publication merges with existing runtime bindings`() {
        val helperClass = Class.forName("io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper")
        val merge = helperClass.getDeclaredMethod("mergeBindingProperties", String::class.java, String::class.java).also { it.isAccessible = true }

        val merged = merge.invoke(null, "old.Owner=old.Alias\nshared.Owner=old.Shared", "new.Owner=new.Alias\nshared.Owner=new.Shared") as String

        assertEquals("old.Alias", bindingValue(merged, "old.Owner"))
        assertEquals("new.Alias", bindingValue(merged, "new.Owner"))
        assertEquals("new.Shared", bindingValue(merged, "shared.Owner"))
    }

    @Test
    fun `sealed native loader owner is scoped while bindings remain merged`() {
        val helperSource = Files.readString(Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))

        assertTrue(
            helperSource.contains("String previousLoaderOwner = System.getProperty(sealedLoaderPropertyName())"),
            "Native loading must snapshot j.l so a later re-obfuscation does not permanently redirect an older runtime helper.",
        )
        assertTrue(
            helperSource.contains("restoreLoaderProperty(previousLoaderOwner)"),
            "Native loading must restore the previous j.l owner after RegisterNatives finishes.",
        )
        assertTrue(
            helperSource.contains("System.setProperty(sealedLoaderPropertyName(), JniMicrokernelHelper.class.getName().replace('.', '/'))"),
            "The active helper still has to publish itself before registering or invoking native VM entries.",
        )
        assertTrue(
            helperSource.contains("mergeBindingProperties(System.getProperty(sealedBindingPropertyName()), bindings.toString())"),
            "Class bindings must remain merged across multiple sealed runtime generations.",
        )
        assertFalse(
            helperSource.contains("mergeLoaderProperties"),
            "j.l must not become a permanent merged owner list; it is a current-helper dispatch scope.",
        )
    }

    private fun loadClassBytes(resourceName: String): ByteArray =
        checkNotNull(Thread.currentThread().contextClassLoader.getResourceAsStream(resourceName)) {
            "missing test classpath resource $resourceName"
        }.use { it.readBytes() }

    private fun simpleClassBytes(internalName: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        val ctor = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        ctor.visitCode()
        ctor.visitVarInsn(Opcodes.ALOAD, 0)
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        ctor.visitInsn(Opcodes.RETURN)
        ctor.visitMaxs(1, 1)
        ctor.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun classWithStringConstant(internalName: String, constant: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        val field = writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "VALUE", "Ljava/lang/String;", null, constant)
        field.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun classContainsStringConstant(bytes: ByteArray, constant: String): Boolean {
        val text = bytes.toString(Charsets.ISO_8859_1)
        return constant in text
    }

    private fun priorSealedRuntimeClassBytes(internalName: String): ByteArray {
        val loaderOwner = "r/0e/C7b908c2243e8a1135d80f05b"
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_NATIVE, "m_87d26895fcb8d435", "(Ljava/lang/String;Ljava/lang/String;)V", null, null).visitEnd()
        val wrapper = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "m_56f234c58f2269ad", "(Ljava/lang/String;Ljava/lang/String;)V", null, null)
        wrapper.visitCode()
        wrapper.visitMethodInsn(Opcodes.INVOKESTATIC, loaderOwner, "isNativeLoaded", "()Z", false)
        val done = org.objectweb.asm.Label()
        wrapper.visitJumpInsn(Opcodes.IFEQ, done)
        wrapper.visitVarInsn(Opcodes.ALOAD, 0)
        wrapper.visitVarInsn(Opcodes.ALOAD, 1)
        wrapper.visitMethodInsn(Opcodes.INVOKESTATIC, internalName, "m_87d26895fcb8d435", "(Ljava/lang/String;Ljava/lang/String;)V", false)
        wrapper.visitLabel(done)
        wrapper.visitInsn(Opcodes.RETURN)
        wrapper.visitMaxs(2, 2)
        wrapper.visitEnd()
        val clinit = writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        clinit.visitCode()
        clinit.visitLdcInsn("loader")
        clinit.visitLdcInsn("auto")
        clinit.visitLdcInsn("vm-diverse")
        clinit.visitMethodInsn(Opcodes.INVOKESTATIC, loaderOwner, "m_4487bf5f5bb3efe5", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", false)
        clinit.visitInsn(Opcodes.RETURN)
        clinit.visitMaxs(3, 0)
        clinit.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun bindingValue(text: String, key: String): String? =
        text.lines().firstOrNull { it.startsWith("$key=") }?.substringAfter('=')

    private fun artifactWithExistingVmRuntime(
        context: Vbc4BuildContext,
        originalVmResource: String,
        originalIndexText: String,
        classArtifacts: List<ClassArtifact> = emptyList(),
    ) = withVbc4BuildContext(context) {
        testAttachedArtifact(
            classArtifacts = classArtifacts,
            jarEntries = listOf(
                *classArtifacts.map { JarEntryData(it.entryName, it.bytes) }.toTypedArray(),
                JarEntryData(
                    VBC4_VM_PRELOAD_INDEX_RESOURCE,
                    RuntimeResourceCodec.encode(
                        bytes = originalIndexText.toByteArray(Charsets.UTF_8),
                        kind = RuntimeResourceKind.NativeIndex,
                        seed = 7,
                        variantId = 1,
                        layerCount = 4,
                        compress = false,
                    ),
                ),
                JarEntryData(
                    originalVmResource,
                    RuntimeResourceCodec.encode(
                        bytes = "VBC4\u0000payload".toByteArray(Charsets.UTF_8),
                        kind = RuntimeResourceKind.VmBytecode,
                        seed = 9,
                        variantId = 1,
                        layerCount = 4,
                        compress = false,
                    ),
                ),
                JarEntryData("META-INF/.r/0.dat", "old-native-index".toByteArray(Charsets.UTF_8)),
            ),
        )
    }

    private fun fixedContext() = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (0x23 + index * 7).toByte() },
        nativeSeed = 0x5151_2626L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (0x41 + index * 11).toByte() },
        runtimeResourceKey = ByteArray(32) { index -> (0x31 + index * 13).toByte() },
    )
}
