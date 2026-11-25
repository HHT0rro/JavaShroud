package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.readJarEntries
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JarReadSupportTest {
    @Test
    fun readJarEntries_skips_directories_and_reads_non_directory_entries() {
        val jarPath = Files.createTempFile("javashroud-jar-read", ".jar")
        writeJarFixture(jarPath)

        try {
            val result = readJarEntries(jarPath)

            assertTrue(result.manifestPresent, "MANIFEST.MF should be preserved")
            val entryNames = result.entries.map { it.name }
            assertEquals(
                listOf("META-INF/MANIFEST.MF", "sample/Foo.class", "sample/readme.txt"),
                entryNames,
            )
            // The first entry is the manifest; Foo.class is second.
            assertEquals(byteArrayOf(1, 2, 3).toList(), result.entries[1].bytes.toList())
            assertEquals(byteArrayOf(4, 5).toList(), result.entries.last().bytes.toList())
        } finally {
            Files.deleteIfExists(jarPath)
        }
    }

    private fun writeJarFixture(jarPath: Path): Unit {
        JarOutputStream(Files.newOutputStream(jarPath)).use { jarOutputStream: JarOutputStream ->
            jarOutputStream.putNextEntry(JarEntry("META-INF/"))
            jarOutputStream.closeEntry()

            jarOutputStream.putNextEntry(JarEntry("META-INF/MANIFEST.MF"))
            jarOutputStream.write("Manifest-Version: 1.0\r\n\r\n".toByteArray())
            jarOutputStream.closeEntry()

            jarOutputStream.putNextEntry(JarEntry("sample/"))
            jarOutputStream.closeEntry()

            jarOutputStream.putNextEntry(JarEntry("sample/Foo.class"))
            jarOutputStream.write(byteArrayOf(1, 2, 3))
            jarOutputStream.closeEntry()

            jarOutputStream.putNextEntry(JarEntry("sample/readme.txt"))
            jarOutputStream.write(byteArrayOf(4, 5))
            jarOutputStream.closeEntry()
        }
    }
}