package io.github.hht0rro.javashroud

import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes
import java.io.BufferedOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream

internal fun buildDiverseFixtureJar(outputPath: Path): Path {
    outputPath.parent?.let { parent -> Files.createDirectories(parent) }

    JarOutputStream(BufferedOutputStream(Files.newOutputStream(outputPath))).use { jar ->
        writeManifestEntry(jar)
        writeClassEntry(jar, "e2e/Root.class", buildRootClassBytes())
        writeClassEntry(jar, innerClassName() + ".class", buildInnerClassBytes())
        writeClassEntry(jar, "e2e/Base.class", buildBaseClassBytes())
        writeClassEntry(jar, "e2e/Impl.class", buildImplClassBytes())
        writeClassEntry(jar, "e2e/Shape.class", buildInterfaceBytes())
        writeClassEntry(jar, "e2e/LambdaStyle.class", buildLambdaStyleClassBytes())
    }

    return outputPath
}

private fun innerClassName(): String = "e2e/Root" + "$" + "Inner"

private fun lambdaMethodName(): String = "lambda" + "$" + "run" + "$" + "0"

private fun writeManifestEntry(jar: JarOutputStream) {
    jar.putNextEntry(JarEntry("META-INF/MANIFEST.MF"))
    jar.write("Manifest-Version: 1.0\r\nMain-Class: e2e.Root\r\n\r\n".toByteArray())
    jar.closeEntry()
}

private fun writeClassEntry(jar: JarOutputStream, entryName: String, classBytes: ByteArray) {
    jar.putNextEntry(JarEntry(entryName))
    jar.write(classBytes)
    jar.closeEntry()
}

private fun ClassWriter.addMethodWithCode(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?, block: (mv: org.objectweb.asm.MethodVisitor) -> Unit) {
    val mv = visitMethod(access, name, descriptor, signature, exceptions)
    mv.visitCode()
    block(mv)
    mv.visitMaxs(2, if (access and Opcodes.ACC_STATIC != 0) 0 else 1)
    mv.visitEnd()
}

private fun buildRootClassBytes(): ByteArray {
    val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
    cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "e2e/Root", null, "java/lang/Object", arrayOf("e2e/Shape"))
    cw.visitSource("Root.java", "JSR45#/e2e/Root.java")
    cw.visitOuterClass("e2e/Outer", "outerCall", "()V")
    cw.visitInnerClass(innerClassName(), "e2e/Root", "Inner", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_ABSTRACT)

    val valueField = cw.visitField(Opcodes.ACC_PRIVATE, "value", "I", null, null)
    valueField.visitEnd()

    cw.addMethodWithCode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null) { mv ->
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        mv.visitInsn(Opcodes.RETURN)
    }

    cw.addMethodWithCode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "call", "()I", null, null) { mv ->
        val start = Label()
        val end = Label()
        val handler = Label()
        mv.visitLabel(start)
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/Root", "maybeFail", "()V", false)
        mv.visitLdcInsn("Hello from JavaShroud")
        mv.visitInsn(Opcodes.POP)
        mv.visitLdcInsn("SecretMessage123")
        mv.visitInsn(Opcodes.POP)
        mv.visitInsn(Opcodes.ICONST_1)
        mv.visitInsn(Opcodes.IRETURN)
        mv.visitLabel(handler)
        mv.visitInsn(Opcodes.POP)
        mv.visitInsn(Opcodes.ICONST_0)
        mv.visitInsn(Opcodes.IRETURN)
        mv.visitLabel(end)
        mv.visitTryCatchBlock(start, end, handler, "java/lang/RuntimeException")
    }

    // main method for runtime verification: calls call() and uses result as exit code
    // call() returns 1 normally, so exit code 1 = correct behavior preserved
    cw.addMethodWithCode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null) { mv ->
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/Root", "call", "()I", false)
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V", false)
        mv.visitInsn(Opcodes.RETURN)
    }

    cw.addMethodWithCode(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "maybeFail", "()V", null, arrayOf("java/lang/RuntimeException")) { mv ->
        val skip = Label()
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Math", "random", "()D", false)
        mv.visitInsn(Opcodes.DCONST_1)
        mv.visitInsn(Opcodes.DCMPL)
        mv.visitJumpInsn(Opcodes.IFNE, skip)
        mv.visitTypeInsn(Opcodes.NEW, "java/lang/RuntimeException")
        mv.visitInsn(Opcodes.DUP)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/RuntimeException", "<init>", "()V", false)
        mv.visitInsn(Opcodes.ATHROW)
        mv.visitLabel(skip)
        mv.visitInsn(Opcodes.RETURN)
    }

    cw.visitEnd()
    return cw.toByteArray()
}

private fun buildInnerClassBytes(): ByteArray {
    val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
    cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC or Opcodes.ACC_ABSTRACT, innerClassName(), null, "java/lang/Object", null)
    cw.visitSource("Root.java", null)
    cw.visitOuterClass("e2e/Root", "call", "()I")
    cw.visitEnd()
    return cw.toByteArray()
}

private fun buildBaseClassBytes(): ByteArray {
    val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
    cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_ABSTRACT, "e2e/Base", null, "java/lang/Object", null)
    cw.visitSource("Base.java", null)

    cw.addMethodWithCode(
        Opcodes.ACC_PUBLIC,
        "identity",
        "(Ljava/lang/Object;)Ljava/lang/Object;",
        "<T:Ljava/lang/Object;>(TT;)TT;",
        null,
    ) { mv ->
        mv.visitVarInsn(Opcodes.ALOAD, 1)
        mv.visitInsn(Opcodes.ARETURN)
    }

    cw.visitEnd()
    return cw.toByteArray()
}

private fun buildImplClassBytes(): ByteArray {
    val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
    cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "e2e/Impl", null, "e2e/Base", arrayOf("java/io/Serializable"))
    cw.visitSource("Impl.java", null)

    cw.addMethodWithCode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null) { mv ->
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "e2e/Base", "<init>", "()V", false)
        mv.visitInsn(Opcodes.RETURN)
    }

    cw.visitEnd()
    return cw.toByteArray()
}

private fun buildInterfaceBytes(): ByteArray {
    val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
    cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_INTERFACE or Opcodes.ACC_ABSTRACT, "e2e/Shape", null, "java/lang/Object", null)
    cw.visitSource("Shape.java", null)

    cw.addMethodWithCode(Opcodes.ACC_PUBLIC, "area", "()D", null, null) { mv ->
        mv.visitInsn(Opcodes.DCONST_0)
        mv.visitInsn(Opcodes.DRETURN)
    }

    cw.visitEnd()
    return cw.toByteArray()
}

private fun buildLambdaStyleClassBytes(): ByteArray {
    val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
    cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC, "e2e/LambdaStyle", null, "java/lang/Object", null)
    cw.visitSource("LambdaStyle.java", null)

    val handler = cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_SYNTHETIC, "handler", "Ljava/lang/Runnable;", null, null)
    handler.visitEnd()

    cw.addMethodWithCode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null) { mv ->
        mv.visitVarInsn(Opcodes.ALOAD, 0)
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        mv.visitInsn(Opcodes.RETURN)
    }

    cw.addMethodWithCode(Opcodes.ACC_PUBLIC, "run", "()V", null, null) { mv ->
        mv.visitLdcInsn("LambdaRunner")
        mv.visitInsn(Opcodes.POP)
        mv.visitInsn(Opcodes.RETURN)
    }

    cw.addMethodWithCode(Opcodes.ACC_PRIVATE or Opcodes.ACC_SYNTHETIC, lambdaMethodName(), "()V", null, null) { mv ->
        mv.visitInsn(Opcodes.RETURN)
    }

    cw.visitEnd()
    return cw.toByteArray()
}
