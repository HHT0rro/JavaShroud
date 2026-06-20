package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.loadBytecodeArtifact
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

class BytecodeArtifactLoadSupportTest {
    @Test
    fun loadBytecodeArtifact_reads_classes_and_resources() {
        val jarPath = Files.createTempFile("javashroud-load-artifact", ".jar")
        writeArtifactFixture(jarPath)

        try {
            val artifact = loadBytecodeArtifact(
                testConfig(
                    inputJarPath = jarPath.toString(),
                    outputJarPath = jarPath.resolveSibling("out.jar").toString(),
                ),
            )

            assertEquals(1, artifact.classArtifacts.size)
            assertEquals("sample/Foo.class", artifact.classArtifacts.single().entryName)
            assertTrue(artifact.classArtifactIndex.containsKey("sample/Foo"))
            assertEquals(1, artifact.analysisSummary.resourceCount)
            assertEquals(1, artifact.analysisSummary.classCount)
        } finally {
            Files.deleteIfExists(jarPath)
        }
    }

    private fun writeArtifactFixture(jarPath: Path): Unit {
        JarOutputStream(Files.newOutputStream(jarPath)).use { jarOutputStream: JarOutputStream ->
            jarOutputStream.putNextEntry(JarEntry("sample/Foo.class"))
            jarOutputStream.write(sampleClassBytes())
            jarOutputStream.closeEntry()

            jarOutputStream.putNextEntry(JarEntry("sample/readme.txt"))
            jarOutputStream.write(byteArrayOf(7, 8))
            jarOutputStream.closeEntry()
        }
    }

    private fun sampleClassBytes(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "sample/Foo", null, "java/lang/Object", null)
        writer.visitEnd()
        return writer.toByteArray()
    }
}
