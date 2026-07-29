package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import java.util.jar.JarEntry
import java.util.jar.JarInputStream
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MonitorSemanticsTest {
    private val objectMapper = ObjectMapper()

    @Test
    fun virtualized_monitors_preserve_contention_reentrancy_and_failures() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return

        val workDir = Files.createTempDirectory("javashroud-monitor-semantics")
        val inputJar = buildFixtureJar(workDir.resolve("monitor-input.jar"))
        val outputJar = workDir.resolve("monitor-output.jar")
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
                timeoutSeconds = 60,
            )
            assertFalse(baseline.timedOut, "Baseline monitor fixture must terminate")
            assertEquals(0, baseline.exitCode, "Baseline monitor fixture failed: ${baseline.output}")
            assertEquals("MONITOR_OK", baseline.output.trim(), "Baseline monitor fixture contract changed")

            runEngine(inputJar, outputJar)
            val virtualizedMethods = listOf(
                "increment" to "()V",
                "reentrant" to "(Ljava/lang/Object;)I",
                "enterNull" to "()V",
                "illegalExit" to "(Ljava/lang/Object;)V",
            )
            for ((name, descriptor) in virtualizedMethods) {
                assertTrue(
                    methodInvokesNativeVmDispatcher(outputJar, name, descriptor),
                    "$name$descriptor must execute through the native VM",
                )
            }

            val transformed = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
                timeoutSeconds = 120,
            )
            assertFalse(transformed.timedOut, "Transformed monitor fixture must not deadlock")
            assertEquals(0, transformed.exitCode, "Transformed monitor fixture failed: ${transformed.output}")
            assertEquals("MONITOR_OK", transformed.output.trim(), "Native VM monitor semantics changed")
        } finally {
            deleteTree(workDir)
        }
    }

    private fun runEngine(inputJar: Path, outputJar: Path) {
        val configPath = outputJar.resolveSibling("monitor-config.toml")
        writeTestRunConfigToml(
            configPath = configPath,
            inputJar = inputJar,
            outputJar = outputJar,
            passIds = listOf("method-virtualization", "jni-microkernel-loader"),
            rules = listOf(
                RuleSpec("e2e/MonitorRoot#increment:()V", "method-virtualization"),
                RuleSpec("e2e/MonitorRoot#reentrant:(Ljava/lang/Object;)I", "method-virtualization"),
                RuleSpec("e2e/MonitorRoot#enterNull:()V", "method-virtualization"),
                RuleSpec("e2e/MonitorRoot#illegalExit:(Ljava/lang/Object;)V", "method-virtualization"),
            ),
            passParams = mapOf(
                "method-virtualization" to mapOf(
                    "strictVirtualization" to objectMapper.valueToTree(true),
                    "methodSelection" to objectMapper.valueToTree("all-compatible"),
                    "maxInstructions" to objectMapper.valueToTree(512),
                ),
                "jni-microkernel-loader" to mapOf(
                    "targetPlatform" to objectMapper.valueToTree(currentNativeTargetPlatform()),
                ),
            ),
        )
        try {
            withTestBootSecret {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
            }
        } finally {
            Files.deleteIfExists(configPath)
        }
    }

    private fun buildFixtureJar(target: Path): Path {
        Files.newOutputStream(target).use { output ->
            JarOutputStream(output).use { jar ->
                jar.putNextEntry(JarEntry("META-INF/MANIFEST.MF"))
                jar.write("Manifest-Version: 1.0\r\nMain-Class: e2e.MonitorRoot\r\n\r\n".toByteArray())
                jar.closeEntry()

                jar.putNextEntry(JarEntry("e2e/MonitorRoot.class"))
                jar.write(monitorRootClassBytes())
                jar.closeEntry()

                jar.putNextEntry(JarEntry("e2e/MonitorWorker.class"))
                jar.write(monitorWorkerClassBytes())
                jar.closeEntry()
            }
        }
        return target
    }

    private fun monitorRootClassBytes(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL or Opcodes.ACC_SUPER,
            ROOT_CLASS,
            null,
            "java/lang/Object",
            null,
        )
        writer.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_FINAL, "LOCK", "Ljava/lang/Object;", null, null).visitEnd()
        writer.visitField(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, "counter", "I", null, null).visitEnd()

        writer.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null).apply {
            visitCode()
            visitTypeInsn(Opcodes.NEW, "java/lang/Object")
            visitInsn(Opcodes.DUP)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitFieldInsn(Opcodes.PUTSTATIC, ROOT_CLASS, "LOCK", "Ljava/lang/Object;")
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PRIVATE, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }

        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "increment", "()V", null, null).apply {
            visitCode()
            visitFieldInsn(Opcodes.GETSTATIC, ROOT_CLASS, "LOCK", "Ljava/lang/Object;")
            visitInsn(Opcodes.DUP)
            visitVarInsn(Opcodes.ASTORE, 0)
            visitInsn(Opcodes.MONITORENTER)
            visitFieldInsn(Opcodes.GETSTATIC, ROOT_CLASS, "counter", "I")
            visitVarInsn(Opcodes.ISTORE, 1)
            visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "yield", "()V", false)
            visitVarInsn(Opcodes.ILOAD, 1)
            visitInsn(Opcodes.ICONST_1)
            visitInsn(Opcodes.IADD)
            visitFieldInsn(Opcodes.PUTSTATIC, ROOT_CLASS, "counter", "I")
            visitVarInsn(Opcodes.ALOAD, 0)
            visitInsn(Opcodes.MONITOREXIT)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "reentrant", "(Ljava/lang/Object;)I", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitInsn(Opcodes.MONITORENTER)
            visitVarInsn(Opcodes.ALOAD, 0)
            visitInsn(Opcodes.MONITORENTER)
            visitVarInsn(Opcodes.ALOAD, 0)
            visitInsn(Opcodes.MONITOREXIT)
            visitVarInsn(Opcodes.ALOAD, 0)
            visitInsn(Opcodes.MONITOREXIT)
            visitIntInsn(Opcodes.BIPUSH, 7)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "enterNull", "()V", null, null).apply {
            visitCode()
            visitInsn(Opcodes.ACONST_NULL)
            visitInsn(Opcodes.MONITORENTER)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "illegalExit", "(Ljava/lang/Object;)V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitInsn(Opcodes.MONITOREXIT)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        emitMainMethod(writer)
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun emitMainMethod(writer: ClassWriter) {
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null)
        val nullStart = Label()
        val nullEnd = Label()
        val nullHandler = Label()
        val nullDone = Label()
        val illegalStart = Label()
        val illegalEnd = Label()
        val illegalHandler = Label()
        val illegalDone = Label()
        method.visitTryCatchBlock(nullStart, nullEnd, nullHandler, "java/lang/NullPointerException")
        method.visitTryCatchBlock(illegalStart, illegalEnd, illegalHandler, "java/lang/IllegalMonitorStateException")
        method.visitCode()
        method.visitInsn(Opcodes.ICONST_0)
        method.visitFieldInsn(Opcodes.PUTSTATIC, ROOT_CLASS, "counter", "I")

        for (slot in 1..WORKER_COUNT) {
            method.visitTypeInsn(Opcodes.NEW, "java/lang/Thread")
            method.visitInsn(Opcodes.DUP)
            method.visitTypeInsn(Opcodes.NEW, WORKER_CLASS)
            method.visitInsn(Opcodes.DUP)
            method.visitMethodInsn(Opcodes.INVOKESPECIAL, WORKER_CLASS, "<init>", "()V", false)
            method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Thread", "<init>", "(Ljava/lang/Runnable;)V", false)
            method.visitVarInsn(Opcodes.ASTORE, slot)
        }
        for (slot in 1..WORKER_COUNT) {
            method.visitVarInsn(Opcodes.ALOAD, slot)
            method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "start", "()V", false)
        }
        for (slot in 1..WORKER_COUNT) {
            method.visitVarInsn(Opcodes.ALOAD, slot)
            method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "join", "()V", false)
        }

        val counterMatches = Label()
        method.visitFieldInsn(Opcodes.GETSTATIC, ROOT_CLASS, "counter", "I")
        method.visitIntInsn(Opcodes.SIPUSH, WORKER_COUNT * ITERATIONS)
        method.visitJumpInsn(Opcodes.IF_ICMPEQ, counterMatches)
        method.throwAssertionError()
        method.visitLabel(counterMatches)

        val reentrantMatches = Label()
        method.visitFieldInsn(Opcodes.GETSTATIC, ROOT_CLASS, "LOCK", "Ljava/lang/Object;")
        method.visitMethodInsn(Opcodes.INVOKESTATIC, ROOT_CLASS, "reentrant", "(Ljava/lang/Object;)I", false)
        method.visitIntInsn(Opcodes.BIPUSH, 7)
        method.visitJumpInsn(Opcodes.IF_ICMPEQ, reentrantMatches)
        method.throwAssertionError()
        method.visitLabel(reentrantMatches)

        method.visitInsn(Opcodes.ICONST_0)
        method.visitVarInsn(Opcodes.ISTORE, 5)
        method.visitLabel(nullStart)
        method.visitMethodInsn(Opcodes.INVOKESTATIC, ROOT_CLASS, "enterNull", "()V", false)
        method.visitLabel(nullEnd)
        method.visitJumpInsn(Opcodes.GOTO, nullDone)
        method.visitLabel(nullHandler)
        method.visitInsn(Opcodes.POP)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitVarInsn(Opcodes.ISTORE, 5)
        method.visitLabel(nullDone)
        val nullMatched = Label()
        method.visitVarInsn(Opcodes.ILOAD, 5)
        method.visitJumpInsn(Opcodes.IFNE, nullMatched)
        method.throwAssertionError()
        method.visitLabel(nullMatched)

        method.visitInsn(Opcodes.ICONST_0)
        method.visitVarInsn(Opcodes.ISTORE, 6)
        method.visitLabel(illegalStart)
        method.visitFieldInsn(Opcodes.GETSTATIC, ROOT_CLASS, "LOCK", "Ljava/lang/Object;")
        method.visitMethodInsn(Opcodes.INVOKESTATIC, ROOT_CLASS, "illegalExit", "(Ljava/lang/Object;)V", false)
        method.visitLabel(illegalEnd)
        method.visitJumpInsn(Opcodes.GOTO, illegalDone)
        method.visitLabel(illegalHandler)
        method.visitInsn(Opcodes.POP)
        method.visitInsn(Opcodes.ICONST_1)
        method.visitVarInsn(Opcodes.ISTORE, 6)
        method.visitLabel(illegalDone)
        val illegalMatched = Label()
        method.visitVarInsn(Opcodes.ILOAD, 6)
        method.visitJumpInsn(Opcodes.IFNE, illegalMatched)
        method.throwAssertionError()
        method.visitLabel(illegalMatched)

        method.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
        method.visitLdcInsn("MONITOR_OK")
        method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
        method.visitInsn(Opcodes.RETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()
    }

    private fun monitorWorkerClassBytes(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(
            Opcodes.V1_8,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL or Opcodes.ACC_SUPER,
            WORKER_CLASS,
            null,
            "java/lang/Object",
            arrayOf("java/lang/Runnable"),
        )
        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null).apply {
            val loop = Label()
            val done = Label()
            visitCode()
            visitInsn(Opcodes.ICONST_0)
            visitVarInsn(Opcodes.ISTORE, 1)
            visitLabel(loop)
            visitVarInsn(Opcodes.ILOAD, 1)
            visitIntInsn(Opcodes.SIPUSH, ITERATIONS)
            visitJumpInsn(Opcodes.IF_ICMPGE, done)
            visitMethodInsn(Opcodes.INVOKESTATIC, ROOT_CLASS, "increment", "()V", false)
            visitIincInsn(1, 1)
            visitJumpInsn(Opcodes.GOTO, loop)
            visitLabel(done)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun methodInvokesNativeVmDispatcher(jarPath: Path, targetName: String, targetDescriptor: String): Boolean {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name == "$ROOT_CLASS.class") {
                    var found = false
                    ClassReader(jar.readBytes()).accept(object : ClassVisitor(Opcodes.ASM9) {
                        override fun visitMethod(
                            access: Int,
                            name: String,
                            descriptor: String,
                            signature: String?,
                            exceptions: Array<String>?,
                        ): MethodVisitor? {
                            if (name != targetName || descriptor != targetDescriptor) return null
                            return object : MethodVisitor(Opcodes.ASM9) {
                                override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
                                    if (opcode == Opcodes.INVOKESTATIC && descriptor.startsWith("(J")) found = true
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

    private fun MethodVisitor.throwAssertionError() {
        visitTypeInsn(Opcodes.NEW, "java/lang/AssertionError")
        visitInsn(Opcodes.DUP)
        visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/AssertionError", "<init>", "()V", false)
        visitInsn(Opcodes.ATHROW)
    }

    private fun currentNativeTargetPlatform(): String {
        val os = System.getProperty("os.name").lowercase()
        val arch = System.getProperty("os.arch").lowercase()
        return when {
            os.startsWith("windows") -> "windows-x64"
            os.contains("mac") && (arch == "aarch64" || arch == "arm64") -> "macos-arm64"
            os.contains("mac") -> "macos-x64"
            else -> "linux-x64"
        }
    }

    private fun deleteTree(path: Path) {
        if (!Files.exists(path)) return
        Files.walk(path).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    private companion object {
        const val ROOT_CLASS = "e2e/MonitorRoot"
        const val WORKER_CLASS = "e2e/MonitorWorker"
        const val WORKER_COUNT = 4
        const val ITERATIONS = 2_000
    }
}
