package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JniMicrokernelHelperJava8CompatibilityTest {
    @Test
    fun resolve_vm_method_handle_has_no_direct_java9_lookup_reference() {
        val resource = "/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class"
        val helperBytes = JniMicrokernelHelper::class.java.getResourceAsStream(resource)?.use { it.readBytes() }
            ?: error("Missing compiled JniMicrokernelHelper class")
        val calls = mutableListOf<Pair<String, String>>()
        val reader = ClassReader(helperBytes)
        reader.accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? {
                if (name != "resolveVmMethodHandle") return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(
                        opcode: Int,
                        owner: String,
                        name: String,
                        descriptor: String,
                        isInterface: Boolean,
                    ) {
                        calls += owner to name
                    }
                }
            }
        }, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)

        assertEquals(Opcodes.V1_8, reader.readShort(6).toInt(), "Embedded helper must remain Java 8 classfile v52")
        assertFalse(
            calls.any { it.first == "java/lang/invoke/MethodHandles" && it.second == "privateLookupIn" },
            "Java 8 cannot link a direct MethodHandles.privateLookupIn reference",
        )
        assertTrue(
            calls.any {
                it.first == "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper" &&
                    it.second == "privateLookup"
            },
            "VM method-handle resolution must use the Java 8 compatibility shim",
        )
    }

    @Test
    fun resolve_vm_method_handle_executes_on_java8_when_runtime_is_configured() {
        val java8Home = java8Home()
        assumeTrue(java8Home != null, "Set JAVASHROUD_JAVA8_HOME or JAVA8_HOME to run the Java 8 compatibility fixture")
        val resolvedJava8Home = requireNotNull(java8Home)
        val executableSuffix = if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) ".exe" else ""
        val javac = resolvedJava8Home.resolve("bin/javac$executableSuffix")
        val java = resolvedJava8Home.resolve("bin/java$executableSuffix")
        assumeTrue(Files.isRegularFile(javac) && Files.isRegularFile(java), "Configured Java 8 home is incomplete: $resolvedJava8Home")
        val version = runJavaProcessWithTimeout(ProcessBuilder(java.toString(), "-version"))
        assertEquals(0, version.exitCode, "Configured Java 8 runtime did not start: ${version.output}")
        assertTrue(version.output.contains("version \"1.8"), "Configured runtime is not Java 8: ${version.output}")

        val tempDir = Files.createTempDirectory("javashroud-java8-lookup-")
        try {
            val sourceRoot = tempDir.resolve("src")
            val classesDir = tempDir.resolve("classes")
            val helperTarget = sourceRoot.resolve(
                "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java",
            )
            Files.createDirectories(helperTarget.parent)
            Files.copy(helperSource(), helperTarget)
            val harness = sourceRoot.resolve("Java8LookupHarness.java")
            Files.write(harness, java8HarnessSource().toByteArray(StandardCharsets.UTF_8))
            Files.createDirectories(classesDir)

            val compile = runJavaProcessWithTimeout(
                ProcessBuilder(
                    javac.toString(),
                    "-d",
                    classesDir.toString(),
                    helperTarget.toString(),
                    harness.toString(),
                ),
            )
            assertFalse(compile.timedOut, "Java 8 javac timed out: ${compile.output}")
            assertEquals(0, compile.exitCode, "JniMicrokernelHelper must compile against the Java 8 API: ${compile.output}")

            val run = runJavaProcessWithTimeout(
                ProcessBuilder(
                    java.toString(),
                    "-Xverify:all",
                    "-cp",
                    classesDir.toString(),
                    "Java8LookupHarness",
                ),
            )
            assertFalse(run.timedOut, "Java 8 lookup fixture timed out: ${run.output}")
            assertEquals(0, run.exitCode, "Java 8 must resolve and invoke a private static VM target: ${run.output}")
            assertTrue(run.output.contains("java8-private-lookup-ok"), "Unexpected Java 8 fixture output: ${run.output}")
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    private fun java8Home(): Path? {
        return sequenceOf(
            System.getProperty("javashroud.java8.home"),
            System.getenv("JAVASHROUD_JAVA8_HOME"),
            System.getenv("JAVA8_HOME"),
        ).filterNotNull()
            .map { Paths.get(it) }
            .firstOrNull { Files.isDirectory(it) }
    }

    private fun helperSource(): Path {
        val relative = Paths.get(
            "src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java",
        )
        val candidates = listOf(relative, Paths.get("core-engine").resolve(relative))
        return candidates.firstOrNull { Files.isRegularFile(it) }
            ?: error("Cannot locate JniMicrokernelHelper.java from ${Paths.get("").toAbsolutePath()}")
    }

    private fun java8HarnessSource(): String = """
        import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper;
        import java.lang.invoke.MethodHandle;

        public final class Java8LookupHarness {
            private static final class Target {
                private static String join(String prefix, int value) {
                    return prefix + value;
                }
            }

            public static void main(String[] args) throws Throwable {
                MethodHandle handle = JniMicrokernelHelper.resolveVmMethodHandle(
                    "handle|6|Java8LookupHarness${'$'}Target|join|(Ljava/lang/String;I)Ljava/lang/String;"
                );
                if (handle == null) throw new AssertionError("private lookup returned null");
                Object result = handle.invokeWithArguments("value=", Integer.valueOf(8));
                if (!"value=8".equals(result)) throw new AssertionError(String.valueOf(result));
                System.out.println("java8-private-lookup-ok");
            }
        }
    """.trimIndent()
}
