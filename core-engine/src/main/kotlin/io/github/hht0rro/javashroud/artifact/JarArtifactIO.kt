package io.github.hht0rro.javashroud.artifact

import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import java.io.BufferedOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import java.util.jar.Manifest
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import kotlin.io.path.createDirectories

fun writeBytecodeArtifact(outputJarPath: Path, artifact: BytecodeArtifact) {
    val parentPath = outputJarPath.parent
    if (parentPath != null) {
        parentPath.createDirectories()
    }

    val classArtifactByEntryName = artifact.classArtifacts.associateBy { classArtifact: ClassArtifact -> classArtifact.entryName }
    JarOutputStream(BufferedOutputStream(Files.newOutputStream(outputJarPath))).use { jarOutputStream: JarOutputStream ->
        inferredManifestEntry(artifact)?.let { manifestEntry ->
            jarOutputStream.putNextEntry(JarEntry(manifestEntry.name))
            jarOutputStream.write(manifestEntry.bytes)
            jarOutputStream.closeEntry()
        }
        artifact.jarEntries.forEach { jarEntryData: JarEntryData ->
            val updatedClassArtifact = classArtifactByEntryName[jarEntryData.name]
            val outputBytes = updatedClassArtifact?.bytes ?: jarEntryData.bytes
            writeJarEntry(jarOutputStream, jarEntryData.name, outputBytes)
        }
    }
}

private fun writeJarEntry(jarOutputStream: JarOutputStream, name: String, bytes: ByteArray) {
    val jarEntry = JarEntry(name)
    if (shouldStoreUncompressed(name, bytes)) {
        jarEntry.method = ZipEntry.STORED
        jarEntry.size = bytes.size.toLong()
        jarEntry.compressedSize = bytes.size.toLong()
        val crc = CRC32()
        crc.update(bytes)
        jarEntry.crc = crc.value
    }
    jarOutputStream.putNextEntry(jarEntry)
    jarOutputStream.write(bytes)
    jarOutputStream.closeEntry()
}

private fun shouldStoreUncompressed(name: String, bytes: ByteArray): Boolean {
    val lower = name.lowercase()
    if (lower.endsWith(".dll") || lower.endsWith(".so")) return true
    if ("/catalog/" in lower || lower.endsWith(".index")) return true
    if (bytes.size < 1024) return false
    return entropyBitsPerByte(bytes) >= 7.5
}

private fun entropyBitsPerByte(bytes: ByteArray): Double {
    val freq = IntArray(256)
    for (value in bytes) {
        freq[value.toInt() and 0xFF]++
    }
    var entropy = 0.0
    val n = bytes.size.toDouble()
    for (count in freq) {
        if (count == 0) continue
        val p = count / n
        entropy -= p * (kotlin.math.ln(p) / kotlin.math.ln(2.0))
    }
    return entropy
}

private fun inferredManifestEntry(artifact: BytecodeArtifact): JarEntryData? {
    if (artifact.jarEntries.any { it.name.equals("META-INF/MANIFEST.MF", ignoreCase = true) }) return null
    val mainClasses = artifact.classArtifacts.mapNotNull { classArtifact ->
        if (hasPublicStaticMain(classArtifact.bytes)) classArtifact.summary.internalName.replace('/', '.') else null
    }.distinct()
    if (mainClasses.size != 1) return null
    val manifest = Manifest().apply {
        mainAttributes.putValue("Manifest-Version", "1.0")
        mainAttributes.putValue("Main-Class", mainClasses.single())
    }
    val out = java.io.ByteArrayOutputStream()
    manifest.write(out)
    return JarEntryData("META-INF/MANIFEST.MF", out.toByteArray())
}

private fun hasPublicStaticMain(bytes: ByteArray): Boolean {
    var found = false
    ClassReader(bytes).accept(object : ClassVisitor(Opcodes.ASM9) {
        override fun visitMethod(
            access: Int,
            name: String?,
            descriptor: String?,
            signature: String?,
            exceptions: Array<out String>?,
        ): MethodVisitor? {
            if (
                name == "main" &&
                descriptor == "([Ljava/lang/String;)V" &&
                access and Opcodes.ACC_PUBLIC != 0 &&
                access and Opcodes.ACC_STATIC != 0
            ) {
                found = true
            }
            return null
        }
    }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
    return found
}
