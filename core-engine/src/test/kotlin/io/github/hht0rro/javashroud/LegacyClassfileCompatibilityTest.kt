package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.ConstantDynamic
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.Attributes
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import java.util.jar.Manifest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class LegacyClassfileCompatibilityTest {

    @Test
    fun java8_classfile_safe_passes_do_not_raise_target_version_or_write_condy() {
        for (passId in JAVA8_CLASSFILE_PRESERVING_PASSES) {
            val result = runLegacyFixture(passId)
            val classBytesByName = loadJarClassBytes(result.outputJar)

            assertTrue(result.events.any { it == "done" }, "Engine should finish for pass=$passId, events=${result.events}")
            assertTrue(classBytesByName.isNotEmpty(), "Output jar should contain classes for pass=$passId")

            for ((internalName, classBytes) in classBytesByName) {
                assertAsmReadable(classBytes, "$passId:$internalName")
                assertEquals(
                    Opcodes.V1_8,
                    classfileMajor(classBytes),
                    "Pass $passId must not raise Java 8 classfile major for $internalName",
                )
                assertFalse(
                    containsConstantDynamic(classBytes),
                    "Pass $passId must not write CONSTANT_Dynamic into Java 8 classfile $internalName",
                )
            }

            assertLoadable(result.outputJar, passId)
        }
    }

    @Test
    fun condy_indirection_keeps_java8_classfiles_without_constantdynamic() {
        val result = runLegacyFixture("condy-constant-indirection")
        val classBytesByName = loadJarClassBytes(result.outputJar)

        assertTrue(result.events.any { it == "done" }, "Engine should finish for condy Java 8 compatibility")
        assertTrue(classBytesByName.isNotEmpty(), "Output jar should contain classes for condy Java 8 compatibility")

        for ((internalName, classBytes) in classBytesByName) {
            assertAsmReadable(classBytes, "condy-constant-indirection:$internalName")
            assertEquals(
                Opcodes.V1_8,
                classfileMajor(classBytes),
                "condy-constant-indirection must not raise Java 8 classfile major for $internalName",
            )
            assertFalse(
                containsConstantDynamic(classBytes),
                "condy-constant-indirection must skip or fall back on Java 8 classfile $internalName",
            )
        }
    }

    @Test
    fun compatibility_matrix_covers_every_registered_pass() {
        val documentedPassIds = (JAVA8_CLASSFILE_PRESERVING_PASSES + JAVA8_FEATURE_GATED_PASSES + JAVA11_OR_NATIVE_BOUND_PASSES).toSet()
        assertEquals(23, documentedPassIds.size, "Compatibility matrix should document every executable pass exactly once")
        assertEquals(EXPECTED_EXECUTABLE_PASS_IDS, documentedPassIds, "Compatibility matrix must match executable pass registry")
    }

    private fun runLegacyFixture(passId: String): LegacyRunResult {
        val inputJar = Files.createTempFile("javashroud-legacy-$passId-input", ".jar")
        val outputJar = inputJar.resolveSibling("javashroud-legacy-$passId-output.jar")
        val configPath = inputJar.resolveSibling("javashroud-legacy-$passId-config.toml")
        buildLegacyJava8FixtureJar(inputJar)
        writeTestRunConfigToml(
            configPath = configPath,
            inputJar = inputJar,
            outputJar = outputJar,
            passIds = listOf(passId),
            allowIncomplete = false,
            allowOptInPasses = true,
        )

        val output = withTestBootSecret {
            captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
            }
        }
        assertTrue(Files.exists(outputJar), "Output jar should exist for pass=$passId")
        return LegacyRunResult(outputJar = outputJar, events = output.trim().lines().filter { it.isNotBlank() }.map(::parseEventType))
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
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
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
            mv.visitInsn(Opcodes.POP)
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

    private fun assertLoadable(outputJar: Path, passId: String) {
        URLClassLoader(arrayOf(outputJar.toUri().toURL()), null).use { loader ->
            val className = loadJarClassBytes(outputJar).keys.firstOrNull()?.replace('/', '.')
            assertNotNull(className, "Pass $passId should keep at least one loadable class entry")
            loader.loadClass(className)
        }
    }

    private fun classfileMajor(classBytes: ByteArray): Int =
        ((classBytes[6].toInt() and 0xff) shl 8) or (classBytes[7].toInt() and 0xff)

    private fun containsConstantDynamic(classBytes: ByteArray): Boolean {
        val node = ClassNode()
        ClassReader(classBytes).accept(node, 0)
        return node.methods.any { method ->
            method.instructions?.toArray()?.any { insn ->
                insn is LdcInsnNode && insn.cst is ConstantDynamic
            } == true
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

    private data class LegacyRunResult(val outputJar: Path, val events: List<String>)

    private companion object {
        val JAVA8_CLASSFILE_PRESERVING_PASSES = listOf(
            "strip-compile-debug-info",
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
        )

        val EXPECTED_EXECUTABLE_PASS_IDS = setOf(
            "strip-compile-debug-info",
            "member-shuffle",
            "rename-classes",
            "rename-packages",
            "rename-methods",
            "rename-fields",
            "string-encryption",
            "field-string-encryption",
            "integer-constant-obfuscation",
            "static-init-perturbation",
            "anti-decompiler-structure",
            "invoke-dynamic-indirection",
            "control-flow-obfuscation",
            "reference-proxy",
            "control-flow-flattening",
            "condy-constant-indirection",
            "member-hide",
            "method-virtualization",
            "callsite-rotation-protection",
            "exception-semantic-virtualization",
            "os-anti-debug",
            "os-anti-vm",
            "jni-microkernel-loader",
        )
    }
}
