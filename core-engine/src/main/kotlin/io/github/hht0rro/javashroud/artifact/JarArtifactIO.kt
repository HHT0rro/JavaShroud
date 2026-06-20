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
            val jarEntry = JarEntry(jarEntryData.name)
            jarOutputStream.putNextEntry(jarEntry)
            jarOutputStream.write(outputBytes)
            jarOutputStream.closeEntry()
        }
    }
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
