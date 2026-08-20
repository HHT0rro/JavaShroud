package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.config.RuleSpec
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.jar.JarEntry
import java.util.jar.JarInputStream
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Fresh-JVM proof for the page-bound class-open chain:
 * encrypted stub <clinit> -> sealed ClassEncryptionLoaderHelper.loadAkenClass
 * -> per-class descriptor -> typed native ClassPage open -> defineClass.
 */
class NativeClassEncryptionRuntimeRegressionTest {
    private val objectMapper = ObjectMapper()

    @Test
    fun sealed_native_class_decrypt_runs_with_verifier_and_preserves_behavior() {
        val workDir = Files.createTempDirectory("javashroud-native-class-decrypt")
        val inputJar = buildFixtureJar(workDir.resolve("input.jar"))
        val outputJar = workDir.resolve("output.jar")
        val configPath = workDir.resolve("config.toml")
        val preservedArtifacts = System.getenv("JAVASHROUD_CASE_ARTIFACTS")
            ?.trim()
            ?.takeIf { it.isNotEmpty() }
            ?.let(Path::of)
        try {
            val baseline = runJar(inputJar, verify = true)
            assertTrue(!baseline.timedOut, "Baseline fixture must finish. Output: ${baseline.output.take(500)}")
            assertEquals(7, baseline.exitCode, "Baseline fixture must execute its encrypted-target candidate. Output: ${baseline.output.take(500)}")
            assertTrue(baseline.output.contains("CLASS_DECRYPT=ok"), "Baseline fixture must reach its business marker")

            writeTestRunConfigToml(
                configPath = configPath,
                inputJar = inputJar,
                outputJar = outputJar,
                passIds = listOf("class-encryption-loader", "jni-microkernel-loader"),
                rules = listOf(RuleSpec(target = "probe/EncryptedTarget", action = "class-encryption-loader")),
                passParams = mapOf(
                    "jni-microkernel-loader" to mapOf(
                        "targetPlatform" to objectMapper.valueToTree("auto"),
                        "nativePackingLevel" to objectMapper.valueToTree("max"),
                    ),
                ),
            )
            val engineEvents = captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
            }
            assertTrue(engineEvents.lines().any { it.contains("type = \"done\"") }, "Engine must finish the combined class/native transform: $engineEvents")
            assertTrue(Files.exists(outputJar), "Combined transform must produce an output JAR")
            assertEncryptedTargetStub(outputJar)

            val protectedRun = runJar(outputJar, verify = true)
            assertTrue(!protectedRun.timedOut, "Protected JAR must finish under -Xverify:all. Output: ${protectedRun.output.take(800)}")
            assertEquals(7, protectedRun.exitCode, "Protected JAR must preserve target return behavior. Output: ${protectedRun.output.take(800)}")
            assertTrue(
                protectedRun.output.contains("CLASS_DECRYPT=ok"),
                "Protected JAR must open the encrypted target through the bound native ClassPage bridge. Output: ${protectedRun.output.take(800)}",
            )
            assertFalse(
                protectedRun.output.contains("IllegalAccessError"),
                "Relocated helpers must not fail the public native decrypt bridge access check. Output: ${protectedRun.output.take(800)}",
            )
        } finally {
            if (preservedArtifacts != null) {
                Files.createDirectories(preservedArtifacts)
                listOf(inputJar, outputJar, configPath).forEach { source ->
                    if (Files.exists(source)) Files.copy(source, preservedArtifacts.resolve(source.fileName.toString()), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                }
            }
            Files.deleteIfExists(configPath)
            if (preservedArtifacts == null) workDir.toFile().deleteRecursively()
        }
    }

    private fun buildFixtureJar(target: Path): Path {
        JarOutputStream(Files.newOutputStream(target)).use { jar ->
            jar.putNextEntry(JarEntry("META-INF/MANIFEST.MF"))
            jar.write("Manifest-Version: 1.0\r\nMain-Class: probe.Main\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
            jar.closeEntry()
            writeClass(jar, "probe/Main.class", buildMainClass())
            writeClass(jar, "probe/EncryptedTarget.class", buildEncryptedTargetClass())
        }
        return target
    }

    private fun writeClass(jar: JarOutputStream, entry: String, bytes: ByteArray) {
        jar.putNextEntry(JarEntry(entry))
        jar.write(bytes)
        jar.closeEntry()
    }

    private fun buildMainClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, "probe/Main", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val main = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null)
        main.visitCode()
        // Reflective lookup keeps the target outside the manifest entrypoint's
        // static dependency closure while still forcing the encrypted stub's
        // <clinit> and native decrypt path in the real JVM.
        main.visitLdcInsn("probe.EncryptedTarget")
        main.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName", "(Ljava/lang/String;)Ljava/lang/Class;", false)
        main.visitLdcInsn("value")
        main.visitInsn(Opcodes.ICONST_0)
        main.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class")
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false)
        main.visitInsn(Opcodes.ACONST_NULL)
        main.visitInsn(Opcodes.ICONST_0)
        main.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object")
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false)
        main.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Integer")
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false)
        main.visitVarInsn(Opcodes.ISTORE, 1)
        main.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
        main.visitLdcInsn("CLASS_DECRYPT=ok")
        main.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
        main.visitVarInsn(Opcodes.ILOAD, 1)
        main.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V", false)
        main.visitInsn(Opcodes.RETURN)
        main.visitMaxs(4, 2)
        main.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun buildEncryptedTargetClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, "probe/EncryptedTarget", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val value = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()I", null, null)
        value.visitCode()
        value.visitIntInsn(Opcodes.BIPUSH, 7)
        value.visitInsn(Opcodes.IRETURN)
        value.visitMaxs(1, 0)
        value.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun assertEncryptedTargetStub(jarPath: Path) {
        val bytes = jarEntry(jarPath, "probe/EncryptedTarget.class")
            ?: error("Expected transformed encrypted-target stub")
        val node = ClassNode()
        ClassReader(bytes).accept(node, 0)
        val clinit = node.methods.firstOrNull { it.name == "<clinit>" }
            ?: error("Encrypted target stub must bootstrap its decrypting class loader")
        val calls = clinit.instructions.asSequence().filterIsInstance<MethodInsnNode>().toList()
        assertTrue(
            calls.any {
                it.desc == "(Ljava/lang/String;)Ljava/lang/Class;"
            },
            "Encrypted target stub must invoke the sealed typed class-page bridge. Calls: " +
                calls.joinToString { "${it.owner}.${it.name}${it.desc}" },
        )
    }

    private fun jarEntry(jarPath: Path, expectedName: String): ByteArray? {
        JarInputStream(Files.newInputStream(jarPath)).use { input ->
            while (true) {
                val entry = input.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name == expectedName) return input.readBytes()
                input.closeEntry()
            }
        }
        return null
    }

    private fun runJar(jar: Path, verify: Boolean): ProcessResult {
        val command = mutableListOf("java")
        if (verify) command += "-Xverify:all"
        command += listOf("-jar", jar.toAbsolutePath().toString())
        val builder = ProcessBuilder(command).redirectErrorStream(true)
        builder.environment().apply {
            keys.removeIf { key -> key.startsWith("JAVASHROUD_BOOT_SECRET") }
        }
        val process = builder.start()
        val finished = process.waitFor(90, TimeUnit.SECONDS)
        if (!finished) process.destroyForcibly()
        val output = process.inputStream.bufferedReader().readText()
        return ProcessResult(
            timedOut = !finished,
            exitCode = if (finished) process.exitValue() else -1,
            output = output,
        )
    }

    private fun captureStdout(block: () -> Unit): String {
        val original = System.out
        val buffer = ByteArrayOutputStream()
        System.setOut(PrintStream(buffer, true, StandardCharsets.UTF_8))
        return try {
            block()
            buffer.toString(StandardCharsets.UTF_8)
        } finally {
            System.setOut(original)
        }
    }

    private data class ProcessResult(val timedOut: Boolean, val exitCode: Int, val output: String)
}
