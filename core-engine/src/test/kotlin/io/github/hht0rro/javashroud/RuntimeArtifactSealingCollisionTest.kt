package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.sealedRuntimeHelperInternalName
import io.github.hht0rro.javashroud.transforms.protection.sealedRuntimeHelperMethodName
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import java.nio.file.Files
import java.nio.file.Path

class RuntimeArtifactSealingCollisionTest {
    @Test
    fun `final runtime sealing preserves the native SAM bridge name`() {
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        val helperBytes = loadClassBytes("$helperName.class")
        val helperArtifact = ClassArtifact(
            entryName = "$helperName.class",
            summary = analyzeClassBytes(helperBytes),
            bytes = helperBytes,
        )

        val sealed = withVbc4BuildContext(defaultVbc4BuildContext()) {
            RuntimeArtifactSealing.seal(testAttachedArtifact(listOf(helperArtifact)), 0x4A53524CL)
        }
        val sealedHelper = sealed.classArtifacts.single { it.summary.internalName.startsWith("r/") }
        val node = ClassNode()
        org.objectweb.asm.ClassReader(sealedHelper.bytes).accept(node, org.objectweb.asm.ClassReader.SKIP_FRAMES)
        val bridgeDescriptor = "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"

        assertTrue(
            node.methods.any { it.name == "createSamLambda" && it.desc == bridgeDescriptor },
            "The native VM resolves createSamLambda by its fixed JNI method name after final sealing.",
        )
        assertTrue(
            node.methods.any { it.name == "takeExpectedShellBindingCommitment" && it.desc == "()[B" },
            "The outer shell resolves the one-shot boot binding bridge by its fixed name after final sealing.",
        )
    }

    @Test
    fun `sealed string helper removes CachePolicy and renames the String terminal`() {
        val outerName = "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper"
        val seed = 0x4A53524CL
        val outerBytes = loadClassBytes("$outerName.class")
        val outerArtifact = ClassArtifact(
            entryName = "$outerName.class",
            summary = analyzeClassBytes(outerBytes),
            bytes = outerBytes,
        )

        val sealed = withVbc4BuildContext(defaultVbc4BuildContext()) {
            RuntimeArtifactSealing.seal(
                artifact = testAttachedArtifact(
                    classArtifacts = listOf(outerArtifact),
                    jarEntries = listOf(JarEntryData(outerArtifact.entryName, outerArtifact.bytes)),
                ),
                seed = seed,
            )
        }
        val sealedOuterName = sealedRuntimeHelperInternalName(outerName, seed)
        val sealedOuter = sealed.classArtifacts.single { it.summary.internalName == sealedOuterName }
        val sealedEntryNames = sealed.jarEntries.map { it.name }.toSet()
        val sealedOuterNode = ClassNode()
        org.objectweb.asm.ClassReader(sealedOuter.bytes).accept(sealedOuterNode, org.objectweb.asm.ClassReader.SKIP_FRAMES)
        val akenStringPageDescriptor = "([BI[B)Ljava/lang/String;"
        val sealedTerminalName = sealedRuntimeHelperMethodName(
            outerName,
            "invokeAkenStringTerminal",
            akenStringPageDescriptor,
            seed,
        )
        assertFalse("$outerName.class" in sealedEntryNames)
        assertTrue("$sealedOuterName.class" in sealedEntryNames)
        assertFalse(
            sealed.classArtifacts.any { it.summary.internalName.contains("CachePolicy") } ||
                sealedEntryNames.any { it.contains("CachePolicy") } ||
                sealedOuterNode.innerClasses.any { it.name.contains("CachePolicy") },
            "The removed plaintext cache policy must not survive runtime sealing.",
        )
        assertFalse(
            sealedOuterNode.methods.any { it.name == "invokeAkenStringTerminal" && it.desc == akenStringPageDescriptor },
            "The public String terminal name must be sealed with the runtime helper.",
        )
        assertTrue(
            sealedOuterNode.methods.any { it.name == sealedTerminalName && it.desc == akenStringPageDescriptor },
            "The relocated String terminal must use its deterministic sealed method name.",
        )
    }

    @Test
    fun `sealed runtime helper names avoid existing jar entries during re-obfuscation`() {
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/DefenseKernelRuntimeHelper"
        val helperBytes = loadClassBytes("$helperName.class")
        val preferredSealedName = sealedRuntimeHelperInternalName(helperName, 0x4A53524CL)
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
            helperSource.contains("publishSealedNativeLoaderOwner()") &&
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

    private fun bindingValue(text: String, key: String): String? =
        text.lines().firstOrNull { it.startsWith("$key=") }?.substringAfter('=')

    private fun fixedContext() = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (0x23 + index * 7).toByte() },
        nativeSeed = 0x5151_2626L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (0x41 + index * 11).toByte() },
        runtimeResourceKey = ByteArray(32) { index -> (0x31 + index * 13).toByte() },
    )

}
