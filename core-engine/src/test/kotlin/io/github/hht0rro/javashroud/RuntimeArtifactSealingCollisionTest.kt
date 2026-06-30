package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.sealedRuntimeHelperInternalName
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

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
}
