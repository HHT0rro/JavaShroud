package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.QpResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.QP_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.QP_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.QpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.QpLocator
import io.github.hht0rro.javashroud.transforms.protection.defaultQpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.requireQpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.sealNativeBindingBytes
import io.github.hht0rro.javashroud.transforms.protection.sealedRuntimeHelperInternalName
import io.github.hht0rro.javashroud.transforms.protection.sealedRuntimeHelperMethodName
import io.github.hht0rro.javashroud.transforms.protection.withQpBuildContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode

class RuntimeArtifactSealingCollisionTest {
    @Test
    fun `final runtime sealing does not preserve a generic SAM bridge`() {
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge"
        val helperBytes = loadClassBytes("$helperName.class")
        val helperArtifact = ClassArtifact(
            entryName = "$helperName.class",
            summary = analyzeClassBytes(helperBytes),
            bytes = helperBytes,
        )

        val sealed = withQpBuildContext(defaultQpBuildContext()) {
            RuntimeArtifactSealing.seal(testAttachedArtifact(listOf(helperArtifact)), 0x4A53524CL)
        }
        val sealedHelper = sealed.classArtifacts.single { it.summary.internalName.startsWith("jsh/") }
        val node = ClassNode()
        org.objectweb.asm.ClassReader(sealedHelper.bytes).accept(node, org.objectweb.asm.ClassReader.SKIP_FRAMES)
        assertTrue(
            node.methods.none { it.name == "createRunnableLambda" || it.name == "createSamLambda" || it.name == "resolveVmMethodHandle" },
            "Sealed helpers must not retain generic Java target entrypoints.",
        )
    }

    @Test
    fun `sealed string helper removes CachePolicy and renames the String terminal`() {
        val outerName = "io/github/hht0rro/javashroud/transforms/protection/qp/QpTextBridge"
        val seed = 0x4A53524CL
        val outerBytes = loadClassBytes("$outerName.class")
        val outerArtifact = ClassArtifact(
            entryName = "$outerName.class",
            summary = analyzeClassBytes(outerBytes),
            bytes = outerBytes,
        )

        val sealed = withQpBuildContext(defaultQpBuildContext()) {
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
        val qpTextPageDescriptor = "([B)Ljava/lang/String;"
        val sealedTerminalName = sealedRuntimeHelperMethodName(
            outerName,
            "invokeQpStringTerminal",
            qpTextPageDescriptor,
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
            sealedOuterNode.methods.any { it.name == "invokeQpStringTerminal" && it.desc == qpTextPageDescriptor },
            "The public String terminal name must be sealed with the runtime helper.",
        )
        assertTrue(
            sealedOuterNode.methods.any { it.name == sealedTerminalName && it.desc == qpTextPageDescriptor },
            "The relocated String terminal must use its deterministic sealed method name.",
        )
    }

    @Test
    fun `sealed runtime helper names avoid existing jar entries during re-obfuscation`() {
        val helperName = "io/github/hht0rro/javashroud/transforms/protection/qp/QpGuard"
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

        val sealed = withQpBuildContext(defaultQpBuildContext()) {
            RuntimeArtifactSealing.seal(artifact, 0x4A53524CL)
        }
        val classEntries = sealed.jarEntries.map { it.name }.filter { it.endsWith(".class") }

        assertEquals(classEntries.size, classEntries.toSet().size)
        assertTrue("$preferredSealedName.class" in classEntries)
        assertFalse(helperArtifact.entryName in classEntries)
        assertTrue(classEntries.any { it.startsWith("jsh/") && it != "$preferredSealedName.class" })
        val sealedEntryNames = sealed.jarEntries.map { it.name }
        assertTrue(preferredIndexName in sealedEntryNames)
        assertTrue(previousVmResourceName in sealedEntryNames)
        assertTrue(sealedEntryNames.any { it.startsWith("META-INF/2b/133bbfe49e7328/") && it != preferredIndexName })
    }

    @Test
    fun final_native_locator_binds_one_sealed_bindings_resource_by_length_and_digest() {
        val native = JarEntryData("META-INF/a/qp_ffi.dll", byteArrayOf(0x4D, 0x5A, 1, 2, 3))
        val bindings = JarEntryData(
            "META-INF/b/bindings.conf",
            sealNativeBindingBytes(ByteArray(32), "fixture binding".encodeToByteArray()),
        )
        val libraries = listOf(QpLocator.entry("windows-x64", native.name, ".dll", native.bytes))
        val bindingRow = QpLocator.bindingsEntry(bindings.name, bindings.bytes)
        val expected = QpLocator.finalNativeBindingDigest(libraries, bindingRow)

        assertContentEquals(
            expected.asBytes(),
            QpLocator.finalNativeBindingDigestFromArtifact(listOf(native, bindings), libraries, bindingRow).asBytes(),
        )
        assertFailsWith<IllegalStateException>("missing binding") {
            QpLocator.finalNativeBindingDigestFromArtifact(listOf(native), libraries, bindingRow)
        }
        val wrongDigest = bindings.bytes.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val invalidEntries = mapOf(
            "duplicate binding" to listOf(native, bindings, bindings),
            "wrong length" to listOf(native, bindings.copy(bytes = bindings.bytes.copyOf(bindings.bytes.size - 1))),
            "wrong digest" to listOf(native, bindings.copy(bytes = wrongDigest)),
        )
        for ((reason, entries) in invalidEntries) {
            assertFailsWith<IllegalArgumentException>(reason) {
                QpLocator.finalNativeBindingDigestFromArtifact(entries, libraries, bindingRow)
            }
        }
    }

    @Test
    fun native_loader_publishes_one_sealed_bootstrap_and_retains_property_rollback() {
        val owner = "io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge"
        val node = ClassNode().also { ClassReader(loadClassBytes("$owner.class")).accept(it, ClassReader.SKIP_FRAMES) }
        val loader = node.methods.single { it.name == "tryLoadQpBundledNativeResource" }
        val calls = loader.instructions.asSequence().filterIsInstance<MethodInsnNode>().toList()
        val publish = calls.single { it.owner == owner && it.name == "publishSealedNativeBootstrap" }
        val systemLoad = calls.single { it.owner == "java/lang/System" && it.name == "load" }
        assertEquals("([B[B)V", publish.desc)
        assertTrue(calls.indexOf(publish) < calls.indexOf(systemLoad), "JNI must see one sealed bootstrap before load")

        val properties = listOf("sealedLoaderPropertyName", "sealedPackPropertyName", "sealedBindingsPropertyName")
        val beforePublish = calls.take(calls.indexOf(publish))
        val snapshotted = beforePublish.zipWithNext().filter { (key, read) ->
            key.owner == owner && key.name in properties && read.owner == "java/lang/System" && read.name == "getProperty"
        }.map { (key, _) -> key.name }
        assertEquals(properties, snapshotted, "Snapshot the owner, sealed pack and sealed bindings before publication")

        val afterLoad = calls.drop(calls.indexOf(systemLoad) + 1).filter { it.owner == owner }.map { it.name }
        val restores = listOf(
            "restoreLoaderProperty", "sealedPackPropertyName", "restoreProperty", "sealedBindingsPropertyName", "restoreProperty",
        )
        assertTrue(restores in afterLoad.windowed(restores.size), "Rollback must restore all three bootstrap properties")

        val publisher = node.methods.single { it.name == publish.name && it.desc == publish.desc }
        val publication = publisher.instructions.asSequence().filterIsInstance<MethodInsnNode>().toList()
        assertTrue(publication.any { it.owner == owner && it.name == "publishSealedNativeLoaderOwner" })
        val published = publication.windowed(3).filter { (key, encode, write) ->
            key.owner == owner && encode.owner == owner && encode.name == "base64UrlEncode" &&
                write.owner == "java/lang/System" && write.name == "setProperty"
        }.map { it.first().name }
        assertEquals(properties.drop(1), published, "Publish one opaque pack and one opaque bindings resource")
        assertFalse(publication.any { it.owner == "java/lang/System" && it.name == "getProperty" })
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

    private fun fixedContext() = QpBuildContext(
        masterKey = ByteArray(QP_MASTER_KEY_SIZE) { index -> (0x23 + index * 7).toByte() },
        nativeSeed = 0x5151_2626L,
        jarLayoutDigest = ByteArray(QP_LAYOUT_DIGEST_SIZE) { index -> (0x41 + index * 11).toByte() },
        runtimeResourceKey = ByteArray(32) { index -> (0x31 + index * 13).toByte() },
    )

}
