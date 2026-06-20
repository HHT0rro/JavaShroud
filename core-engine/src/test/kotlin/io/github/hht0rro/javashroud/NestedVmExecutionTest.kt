package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.jar.JarEntry
import java.util.jar.JarInputStream
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NestedVmExecutionTest {
    private val objectMapper = ObjectMapper()

    @Test
    fun high_value_nested_vm_method_preserves_runtime_result_in_transformed_jar() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val inputJar = buildHighValueFixtureJar(Files.createTempFile("javashroud-nested-vm-input", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJava(inputJar)
            assertEquals(0, baseline.exitCode, "Baseline high-value fixture must run. output=${baseline.output}")
            assertEquals("42", baseline.output.trim(), "Baseline fixture contract changed")

            outputJar = runEngine(
                inputJar,
                passParams = mapOf(
                    "method-virtualization" to mapOf(
                        "methodSelection" to "critical-plus",
                        "strictVirtualization" to true,
                        "maxInstructions" to 512,
                        "highValueMethods" to "verifyLicense",
                    ),
                    "jni-microkernel-loader" to mapOf(
                        "targetPlatform" to currentNativeTargetPlatform(),
                    ),
                ),
            )
            assertTrue(
                methodInvokesNativeVmDispatcher(outputJar, "e2e/NestedVmRoot", "verifyLicense", "()I"),
                "High-value verifyLicense() must be replaced by native VM dispatcher stub",
            )

            val transformed = runJava(outputJar)
            assertEquals(0, transformed.exitCode, "Nested VM transformed JAR must run. output=${transformed.output}")
            assertEquals(baseline.output.trim(), transformed.output.trim(), "Nested VM must preserve high-value method semantics")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    private fun runEngine(inputJar: Path, passParams: Map<String, Map<String, Any>>): Path {
        val outputJar = inputJar.resolveSibling("javashroud-nested-vm-output.jar")
        val configPath = inputJar.resolveSibling("javashroud-nested-vm-config.toml")
        writeTestRunConfigToml(
            configPath = configPath,
            inputJar = inputJar,
            outputJar = outputJar,
            passIds = listOf("method-virtualization", "jni-microkernel-loader"),
            passParams = passParams.mapValues { (_, params) ->
                params.mapValues { (_, value) -> objectMapper.valueToTree(value) }
            },
        )
        try {
            dispatchRequest(buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())), EngineKernel())
        } finally {
            Files.deleteIfExists(configPath)
        }
        return outputJar
    }

    private fun buildHighValueFixtureJar(target: Path): Path {
        val cw = org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_FRAMES or org.objectweb.asm.ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, "e2e/NestedVmRoot", null, "java/lang/Object", null)
        cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(1, 1)
            visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "verifyLicense", "()I", null, null).apply {
            visitCode()
            visitIntInsn(Opcodes.BIPUSH, 40)
            visitInsn(Opcodes.ICONST_2)
            visitInsn(Opcodes.IADD)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(2, 0)
            visitEnd()
        }
        cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null).apply {
            visitCode()
            visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
            visitMethodInsn(Opcodes.INVOKESTATIC, "e2e/NestedVmRoot", "verifyLicense", "()I", false)
            visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(I)V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(2, 1)
            visitEnd()
        }
        cw.visitEnd()
        Files.newOutputStream(target).use { out ->
            JarOutputStream(out).use { jar ->
                jar.putNextEntry(JarEntry("META-INF/MANIFEST.MF"))
                jar.write("Manifest-Version: 1.0\r\nMain-Class: e2e.NestedVmRoot\r\n\r\n".toByteArray())
                jar.closeEntry()
                jar.putNextEntry(JarEntry("e2e/NestedVmRoot.class"))
                jar.write(cw.toByteArray())
                jar.closeEntry()
            }
        }
        return target
    }

    private fun methodInvokesNativeVmDispatcher(jarPath: Path, className: String, targetName: String, targetDescriptor: String): Boolean {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name == "$className.class") {
                    var found = false
                    ClassReader(jar.readBytes()).accept(object : ClassVisitor(Opcodes.ASM9) {
                        override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?): MethodVisitor {
                            if (name != targetName || descriptor != targetDescriptor) return object : MethodVisitor(Opcodes.ASM9) {}
                            return object : MethodVisitor(Opcodes.ASM9) {
                                override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
                                    if (
                                        opcode == Opcodes.INVOKESTATIC &&
                                        (descriptor == "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;" ||
                                            descriptor == "(J[Ljava/lang/Object;)Ljava/lang/Object;" ||
                                            descriptor == "(J)V" ||
                                            descriptor == "(JI)V")
                                    ) {
                                        found = true
                                    }
                                }
                            }
                        }
                    }, ClassReader.SKIP_FRAMES)
                    return found
                }
                jar.closeEntry()
            }
        }
        return false
    }

    private fun runJava(jarPath: Path): ProcessResult {
        val process = ProcessBuilder("java", "-jar", jarPath.toAbsolutePath().normalize().toString())
            .redirectErrorStream(true)
            .start()
        val completed = process.waitFor(60, TimeUnit.SECONDS)
        val output = process.inputStream.bufferedReader().readText()
        if (!completed) {
            process.destroyForcibly()
            return ProcessResult(-1, output)
        }
        return ProcessResult(process.exitValue(), output)
    }

    private fun currentNativeTargetPlatform(): String {
        val os = System.getProperty("os.name").lowercase()
        val arch = System.getProperty("os.arch").lowercase()
        return when {
            os.contains("win") -> "windows-x64"
            os.contains("mac") && arch.contains("aarch64") -> "macos-arm64"
            os.contains("mac") -> "macos-x64"
            else -> "linux-x64"
        }
    }

    private data class ProcessResult(val exitCode: Int, val output: String)
}
