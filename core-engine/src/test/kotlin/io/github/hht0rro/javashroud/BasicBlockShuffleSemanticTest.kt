package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import io.github.hht0rro.javashroud.transforms.protection.vbc4CfgDecodeIndex
import io.github.hht0rro.javashroud.transforms.protection.vbc4CfgEncodeIndex
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
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
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class BasicBlockShuffleSemanticTest {
    @Test
    fun keyed_block_ids_preserve_if_loop_switch_and_exception_edges() {
        val seed = 0x5A17_3C29
        val instructionCount = 96
        val logicalEdges = listOf(
            3 to 19,   // if
            27 to 8,   // loop back-edge
            31 to 44,  // switch default
            31 to 52,  // switch case
            12 to 71,  // exception handler
        )
        val storedEdges = logicalEdges.map { (from, to) ->
            vbc4CfgEncodeIndex(seed, instructionCount, from) to vbc4CfgEncodeIndex(seed, instructionCount, to)
        }

        assertNotEquals(logicalEdges, storedEdges, "stored VBC4 CFG must not retain raw instruction ids")
        val reconstructed = storedEdges.map { (from, to) ->
            vbc4CfgDecodeIndex(seed, instructionCount, from) to vbc4CfgDecodeIndex(seed, instructionCount, to)
        }
        assertEquals(logicalEdges, reconstructed, "runtime reconstruction must preserve branch/switch/exception semantics")
    }

    @Test
    fun keyed_block_ids_cover_complete_u16_domain_without_collisions() {
        val seed = 0x31C0_55AA
        val instructionCount = 0xFFFF
        val encoded = IntArray(instructionCount + 1) { index ->
            vbc4CfgEncodeIndex(seed, instructionCount, index)
        }

        assertEquals(0x10000, encoded.toSet().size)
        assertTrue(encoded.all { it in 0..0xFFFF })
        for (index in encoded.indices) {
            assertEquals(index, vbc4CfgDecodeIndex(seed, instructionCount, encoded[index]))
        }
    }

    @Test
    fun serializer_rejects_vm_maxs_that_would_exceed_the_u16_cfg_limit() {
        val serializer = VmBytecodeSerializer(buildSeed = 0x41A7_29C3, buildContext = fixedVbc4Context())
        serializer.visitCode()
        repeat(0xFFFF) { serializer.visitInsn(Opcodes.NOP) }

        assertFailsWith<UnsupportedOperationException> {
            serializer.visitMaxs(1, 1)
        }
    }

    @Test
    fun native_vbc4_reconstruction_preserves_if_loops_switch_and_try_catch() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return

        val workDir = Files.createTempDirectory("javashroud-block-shuffle")
        val inputJar = workDir.resolve("block-shuffle-input.jar")
        val outputJar = workDir.resolve("block-shuffle-output.jar")
        try {
            buildFixtureJar(inputJar)
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
                timeoutSeconds = 30,
            )
            assertFalse(baseline.timedOut, "Baseline CFG fixture must terminate")
            assertEquals(0, baseline.exitCode, "Baseline CFG fixture failed: ${baseline.output}")

            runEngine(inputJar, outputJar)
            assertTrue(
                methodInvokesNativeVmDispatcher(outputJar, "compute", "(I)I"),
                "compute(I)I must execute through the native VBC4 dispatcher",
            )
            val transformed = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
                timeoutSeconds = 60,
            )
            assertFalse(transformed.timedOut, "Transformed CFG fixture must terminate")
            assertEquals(0, transformed.exitCode, "Transformed CFG fixture failed: ${transformed.output}")
            assertEquals(
                baseline.output.trim(),
                transformed.output.trim(),
                "Native VBC4 CFG reconstruction changed if/for/while/switch/try-catch semantics",
            )
        } finally {
            deleteTree(workDir)
        }
    }

    private fun runEngine(inputJar: Path, outputJar: Path) {
        val configPath = outputJar.resolveSibling("block-shuffle-config.toml")
        writeTestRunConfigToml(
            configPath = configPath,
            inputJar = inputJar,
            outputJar = outputJar,
            passIds = listOf("method-virtualization", "jni-microkernel-loader"),
            rules = listOf(RuleSpec("e2e/BlockShuffleRoot#compute:(I)I", "method-virtualization")),
            passParams = mapOf(
                "method-virtualization" to mapOf(
                    "strictVirtualization" to ObjectMapper().valueToTree(true),
                    "methodSelection" to ObjectMapper().valueToTree("all-compatible"),
                    "maxInstructions" to ObjectMapper().valueToTree(512),
                ),
                "jni-microkernel-loader" to mapOf(
                    "targetPlatform" to ObjectMapper().valueToTree(currentNativeTargetPlatform()),
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
        val workDir = Files.createTempDirectory("javashroud-block-shuffle-source")
        try {
            val sourceDir = workDir.resolve("e2e")
            val classesDir = workDir.resolve("classes")
            Files.createDirectories(sourceDir)
            Files.createDirectories(classesDir)
            val sourcePath = sourceDir.resolve("BlockShuffleRoot.java")
            Files.writeString(sourcePath, FIXTURE_SOURCE)
            val compiler = javax.tools.ToolProvider.getSystemJavaCompiler()
                ?: error("JDK compiler is required for native VBC4 CFG fixture")
            val compileExit = compiler.run(null, null, null, "-d", classesDir.toString(), sourcePath.toString())
            assertEquals(0, compileExit, "Native VBC4 CFG fixture source must compile")

            Files.newOutputStream(target).use { output ->
                JarOutputStream(output).use { jar ->
                    jar.putNextEntry(JarEntry("META-INF/MANIFEST.MF"))
                    jar.write("Manifest-Version: 1.0\r\nMain-Class: e2e.BlockShuffleRoot\r\n\r\n".toByteArray())
                    jar.closeEntry()
                    Files.walk(classesDir).use { paths ->
                        paths.filter { Files.isRegularFile(it) }.forEach { classFile ->
                            val entryName = classesDir.relativize(classFile).toString().replace('\\', '/')
                            jar.putNextEntry(JarEntry(entryName))
                            jar.write(Files.readAllBytes(classFile))
                            jar.closeEntry()
                        }
                    }
                }
            }
            return target
        } finally {
            deleteTree(workDir)
        }
    }

    private fun methodInvokesNativeVmDispatcher(jarPath: Path, targetName: String, targetDescriptor: String): Boolean {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name == "e2e/BlockShuffleRoot.class") {
                    var found = false
                    ClassReader(jar.readBytes()).accept(object : ClassVisitor(Opcodes.ASM9) {
                        override fun visitMethod(
                            access: Int,
                            name: String,
                            descriptor: String,
                            signature: String?,
                            exceptions: Array<String>?,
                        ): MethodVisitor {
                            if (name != targetName || descriptor != targetDescriptor) {
                                return object : MethodVisitor(Opcodes.ASM9) {}
                            }
                            return object : MethodVisitor(Opcodes.ASM9) {
                                override fun visitMethodInsn(
                                    opcode: Int,
                                    owner: String,
                                    name: String,
                                    descriptor: String,
                                    isInterface: Boolean,
                                ) {
                                    if (
                                        opcode == Opcodes.INVOKESTATIC &&
                                        (descriptor == "(J[Ljava/lang/Object;)Ljava/lang/Object;" || descriptor == "(JI)I")
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

    private fun deleteTree(root: Path) {
        if (!Files.exists(root)) return
        Files.walk(root).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    private fun fixedVbc4Context(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 19 + 7).toByte() },
        nativeSeed = 0x5642_4334L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 23 + 11).toByte() },
    )

    private companion object {
        val FIXTURE_SOURCE = """
            package e2e;

            public final class BlockShuffleRoot {
                private static int compute(int seed) {
                    int acc = seed < 0 ? -seed : seed + 3;
                    for (int i = 0; i < 7; i++) {
                        if ((i & 1) == 0) acc += i * 3;
                        else acc -= i;
                    }
                    int i = 0;
                    while (i < 5) {
                        acc ^= seed + i;
                        i++;
                    }
                    switch (seed & 3) {
                        case 0: acc += 11; break;
                        case 1: acc -= 7; break;
                        case 2: acc ^= 0x55; break;
                        default: acc += 23;
                    }
                    try {
                        acc += 120 / (seed - 2);
                    } catch (ArithmeticException expected) {
                        acc += 37;
                    }
                    return acc;
                }

                public static void main(String[] args) {
                    int[] seeds = {-17, -1, 0, 1, 2, 3, 7, 31};
                    StringBuilder result = new StringBuilder();
                    for (int seed : seeds) result.append(seed).append('=').append(compute(seed)).append(';');
                    System.out.println(result);
                }
            }
        """.trimIndent()
    }
}
