package io.github.hht0rro.javashroud

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarInputStream

internal data class MemberAccessSummary(
    val kind: String,
    val owner: String,
    val name: String,
    val descriptor: String,
    val access: Int,
)

internal data class ClassBytecodeAttributes(
    val internalName: String,
    val sourceFilePresent: Boolean = false,
    val sourceDebugPresent: Boolean = false,
    val lineCount: Int = 0,
    val hasInnerClasses: Boolean = false,
    val hasSignature: Boolean = false,
    val hasEnclosingMethod: Boolean = false,
    val hasOuterClass: Boolean = false,
    val hasExceptions: Boolean = false,
    val hasTryCatch: Boolean = false,
    val memberAccess: List<MemberAccessSummary> = emptyList(),
)

internal fun loadJarClassBytes(jarPath: Path): Map<String, ByteArray> {
    val entries = mutableMapOf<String, ByteArray>()
    JarInputStream(Files.newInputStream(jarPath)).use { jar ->
        while (true) {
            val entry: JarEntry = jar.nextJarEntry ?: break
            if (!entry.isDirectory && entry.name.endsWith(".class")) {
                val internalName = entry.name.removeSuffix(".class")
                entries[internalName] = jar.readBytes()
            }
            jar.closeEntry()
        }
    }
    return entries.toMap()
}

internal fun collectClassBytecodeAttributes(classBytes: ByteArray): ClassBytecodeAttributes {
    var internalName = ""
    var sourceFilePresent = false
    var sourceDebugPresent = false
    var lineCount = 0
    var hasInnerClasses = false
    var hasSignature = false
    var hasEnclosingMethod = false
    var hasOuterClass = false
    var hasExceptions = false
    var hasTryCatch = false
    val members = mutableListOf<MemberAccessSummary>()

    val reader = ClassReader(classBytes)
    reader.accept(
        object : ClassVisitor(Opcodes.ASM9) {
            override fun visit(
                version: Int,
                access: Int,
                name: String,
                signature: String?,
                superName: String?,
                interfaces: Array<out String>?,
            ) {
                internalName = name
                if (signature != null) {
                    hasSignature = true
                }
            }

            override fun visitSource(source: String?, debug: String?) {
                if (source != null) {
                    sourceFilePresent = true
                }
                if (debug != null) {
                    sourceDebugPresent = true
                }
            }

            override fun visitOuterClass(owner: String?, name: String?, descriptor: String?) {
                hasOuterClass = true
            }

            override fun visitInnerClass(name: String?, outerName: String?, innerName: String?, access: Int) {
                hasInnerClasses = true
            }

            override fun visitField(access: Int, name: String?, descriptor: String?, signature: String?, value: Any?): FieldVisitor? {
                if (name != null && descriptor != null) {
                    members += MemberAccessSummary(kind = "FIELD", owner = internalName, name = name, descriptor = descriptor, access = access)
                }
                if (signature != null) {
                    hasSignature = true
                }
                return super.visitField(access, name, descriptor, signature, value)
            }

            override fun visitMethod(
                access: Int,
                name: String?,
                descriptor: String?,
                signature: String?,
                exceptions: Array<out String>?,
            ): MethodVisitor {
                if (name != null && descriptor != null) {
                    members += MemberAccessSummary(kind = "METHOD", owner = internalName, name = name, descriptor = descriptor, access = access)
                }
                if (signature != null) {
                    hasSignature = true
                }
                if (!exceptions.isNullOrEmpty()) {
                    hasExceptions = true
                }

                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitLineNumber(line: Int, start: Label?) {
                        lineCount += 1
                    }

                    override fun visitTryCatchBlock(start: Label?, end: Label?, handler: Label?, type: String?) {
                        hasTryCatch = true
                    }
                }
            }
        },
        ClassReader.SKIP_FRAMES,
    )

    return ClassBytecodeAttributes(
        internalName = internalName,
        sourceFilePresent = sourceFilePresent,
        sourceDebugPresent = sourceDebugPresent,
        lineCount = lineCount,
        hasInnerClasses = hasInnerClasses,
        hasSignature = hasSignature,
        hasEnclosingMethod = hasEnclosingMethod,
        hasOuterClass = hasOuterClass,
        hasExceptions = hasExceptions,
        hasTryCatch = hasTryCatch,
        memberAccess = members,
    )
}

private fun InputStream.readBytes(): ByteArray {
    val buffer = ByteArrayOutputStream()
    val temp = ByteArray(4096)
    while (true) {
        val read = this.read(temp)
        if (read == -1) break
        buffer.write(temp, 0, read)
    }
    return buffer.toByteArray()
}

private class ByteArrayOutputStream {
    private var bytes = ByteArray(0)

    fun write(buffer: ByteArray, offset: Int, length: Int) {
        bytes += buffer.copyOfRange(offset, offset + length)
    }

    fun toByteArray(): ByteArray = bytes
}
