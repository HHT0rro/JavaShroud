package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.passes.executablePassRegistry
import org.junit.jupiter.api.io.TempDir
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.Attributes
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import java.util.jar.Manifest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class LegacyClassfileCompatibilityTest {

    @Test
    fun java8_classfile_safe_passes_do_not_raise_target_version_or_write_condy(@TempDir directory: Path) {
        val inputJar = buildLegacyJava8FixtureJar(directory.resolve("input.jar"))
        assertRuns(inputJar, "untransformed Java 8 fixture")
        for (passId in JAVA8_CLASSFILE_PRESERVING_PASSES) {
            assertJava8Output(runJava8Fixture(inputJar, passId), passId)
        }
    }

    @Test
    fun condy_indirection_keeps_java8_classfiles_without_constantdynamic(@TempDir directory: Path) {
        val inputJar = buildLegacyJava8FixtureJar(directory.resolve("input.jar"))
        val passId = "condy-constant-indirection"
        assertJava8Output(runJava8Fixture(inputJar, passId), passId)
    }

    @Test
    fun compatibility_matrix_covers_every_registered_pass() {
        val classified = JAVA8_CLASSFILE_PRESERVING_PASSES + JAVA8_FEATURE_GATED_PASSES + JAVA11_OR_NATIVE_BOUND_PASSES
        assertEquals(classified.size, classified.toSet().size, "Each executable pass must be classified exactly once")
        assertEquals(executablePassRegistry.keys, classified.toSet(), "Compatibility matrix must match executable pass registry")
    }

    private fun runJava8Fixture(inputJar: Path, passId: String): Path {
        val outputJar = inputJar.resolveSibling("$passId.jar")
        val configPath = inputJar.resolveSibling("$passId.toml")
        writeTestRunConfigToml(
            configPath = configPath,
            inputJar = inputJar,
            outputJar = outputJar,
            passIds = listOf(passId),
            allowIncomplete = false,
            allowOptInPasses = true,
        )
        // Exercise each pass's classfile output independently of release validation.
        Files.writeString(configPath, "protectionProfile = \"minimal\"\n" + Files.readString(configPath))
        val output = captureStdout {
            dispatchRequest(
                buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                EngineKernel(),
            )
        }
        val events = output.trim().lines().filter { it.isNotBlank() }.map(::parseEventType)
        assertTrue("done" in events, "Engine should finish for pass=$passId, events=$events")
        assertTrue(Files.exists(outputJar), "Output jar should exist for pass=$passId")
        return outputJar
    }

    private fun buildLegacyJava8FixtureJar(outputPath: Path): Path {
        val manifest = Manifest().apply {
            mainAttributes[Attributes.Name.MANIFEST_VERSION] = "1.0"
            mainAttributes[Attributes.Name.MAIN_CLASS] = "legacy.Main"
        }
        JarOutputStream(Files.newOutputStream(outputPath), manifest).use { jar ->
            jar.putNextEntry(JarEntry("legacy/Main.class"))
            jar.write(legacyMainClassBytes())
            jar.closeEntry()
        }
        return outputPath
    }

    private fun legacyMainClassBytes(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES)
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "legacy/Main", null, "java/lang/Object", null)
        cw.visitSource("Main.java", null)

        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "counter", "I", null, null).visitEnd()
        cw.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "MESSAGE", "Ljava/lang/String;", null, "legacy-secret").visitEnd()

        cw.method(Opcodes.ACC_PUBLIC, "<init>", "()V") { mv ->
            mv.visitVarInsn(Opcodes.ALOAD, 0)
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            mv.visitInsn(Opcodes.RETURN)
        }

        cw.method(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V") { mv ->
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "legacy/Main", "value", "()I", false)
            mv.visitIntInsn(Opcodes.BIPUSH, 20)
            val expected = Label()
            mv.visitJumpInsn(Opcodes.IF_ICMPEQ, expected)
            mv.visitTypeInsn(Opcodes.NEW, "java/lang/AssertionError")
            mv.visitInsn(Opcodes.DUP)
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/AssertionError", "<init>", "()V", false)
            mv.visitInsn(Opcodes.ATHROW)
            mv.visitLabel(expected)
            mv.visitInsn(Opcodes.RETURN)
        }

        cw.method(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()I") { mv ->
            val start = Label()
            val end = Label()
            val handler = Label()
            val done = Label()
            mv.visitTryCatchBlock(start, end, handler, "java/lang/RuntimeException")
            mv.visitLabel(start)
            mv.visitLineNumber(12, start)
            mv.visitLdcInsn("legacy-secret")
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "legacy/Main", "consume", "(Ljava/lang/String;)I", false)
            mv.visitIntInsn(Opcodes.BIPUSH, 7)
            mv.visitInsn(Opcodes.IADD)
            mv.visitFieldInsn(Opcodes.PUTSTATIC, "legacy/Main", "counter", "I")
            mv.visitLabel(end)
            mv.visitJumpInsn(Opcodes.GOTO, done)
            mv.visitLabel(handler)
            mv.visitInsn(Opcodes.POP)
            mv.visitInsn(Opcodes.ICONST_M1)
            mv.visitFieldInsn(Opcodes.PUTSTATIC, "legacy/Main", "counter", "I")
            mv.visitLabel(done)
            mv.visitFieldInsn(Opcodes.GETSTATIC, "legacy/Main", "counter", "I")
            mv.visitInsn(Opcodes.IRETURN)
        }

        cw.method(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "consume", "(Ljava/lang/String;)I") { mv ->
            mv.visitVarInsn(Opcodes.ALOAD, 0)
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false)
            mv.visitInsn(Opcodes.IRETURN)
        }

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun ClassWriter.method(access: Int, name: String, descriptor: String, body: (MethodVisitor) -> Unit) {
        val mv = visitMethod(access, name, descriptor, null, null)
        mv.visitCode()
        body(mv)
        mv.visitMaxs(0, 0)
        mv.visitEnd()
    }

    private fun assertAsmReadable(classBytes: ByteArray, context: String) {
        ClassReader(classBytes).accept(object : ClassVisitor(Opcodes.ASM9) {}, ClassReader.SKIP_FRAMES)
        assertTrue(classBytes.isNotEmpty(), "Class bytes should be non-empty: $context")
    }

    private fun assertJava8Output(outputJar: Path, passId: String) {
        val mainClass = JarFile(outputJar.toFile()).use { jar ->
            assertNotNull(jar.manifest.mainAttributes.getValue(Attributes.Name.MAIN_CLASS))
        }.replace('.', '/')
        val classes = loadJarClassBytes(outputJar)
        assertTrue(mainClass in classes, "Pass $passId must retain the application entry point")
        for ((name, classBytes) in classes) {
            assertAsmReadable(classBytes, "$passId:$name")
            assertEquals(Opcodes.V1_8, classfileMajor(classBytes), "Pass $passId must preserve Java 8 classfile version for $name")
            assertFalse(containsConstantDynamic(classBytes), "Pass $passId must not write CONSTANT_Dynamic into $name")
        }
        assertRuns(outputJar, passId)
    }

    private fun assertRuns(jar: Path, context: String) {
        val javaHome = System.getenv("JAVA8_HOME") ?: System.getProperty("java.home")
        val java = Path.of(javaHome, "bin", "java")
        val run = runJavaProcessWithTimeout(ProcessBuilder(java.toString(), "-Xverify:all", "-jar", jar.toString()))
        assertEquals(0, run.exitCode, "$context failed on $java: " + run.output)
    }

    private fun classfileMajor(classBytes: ByteArray): Int =
        ((classBytes[6].toInt() and 0xff) shl 8) or (classBytes[7].toInt() and 0xff)

    private fun containsConstantDynamic(classBytes: ByteArray): Boolean {
        val reader = ClassReader(classBytes)
        return (1 until reader.itemCount).any { index ->
            val item = reader.getItem(index)
            item != 0 && reader.readByte(item - 1) == 17 // CONSTANT_Dynamic tag
        }
    }

    private fun captureStdout(block: () -> Unit): String {
        val originalOut = System.out
        val buffer = ByteArrayOutputStream()
        System.setOut(PrintStream(buffer, true, Charsets.UTF_8))
        return try {
            block()
            buffer.toString(Charsets.UTF_8)
        } finally {
            System.setOut(originalOut)
        }
    }

    private fun parseEventType(line: String): String {
        val match = Regex("""type\s*=\s*"((?:\\.|[^"])*)"""").find(line)
        return match?.groupValues?.get(1) ?: error("Engine event line missing type: $line")
    }

    private companion object {
        val JAVA8_CLASSFILE_PRESERVING_PASSES = listOf(
            "strip-compile-debug-info",
            "member-shuffle",
            "rename-classes",
            "rename-packages",
            "rename-methods",
            "rename-fields",
            "field-string-encryption",
            "integer-constant-obfuscation",
            "static-init-perturbation",
            "anti-decompiler-structure",
            "invoke-dynamic-indirection",
            "control-flow-obfuscation",
            "reference-proxy",
            "control-flow-flattening",
            "member-hide",
        )

        val JAVA8_FEATURE_GATED_PASSES = listOf(
            "condy-constant-indirection",
        )

        val JAVA11_OR_NATIVE_BOUND_PASSES = listOf(
            "string-encryption",
            "method-virtualization",
            "callsite-rotation-protection",
            "exception-semantic-virtualization",
            "os-anti-debug",
            "os-anti-vm",
            "jni-microkernel-loader",
            "nativeshroud",
        )
    }
}
