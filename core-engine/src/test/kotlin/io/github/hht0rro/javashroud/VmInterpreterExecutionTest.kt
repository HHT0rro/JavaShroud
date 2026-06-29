package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.Type
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import java.security.SecureRandom
import kotlin.test.assertTrue

/**
 * VBC4 VM lifecycle tests.
 *
 * The former Java interpreter roundtrip tests are intentionally removed in
 * VBC4-only mode. These tests verify compile-time serializer output and
 * runtime helper injection behavior for the native-only path.
 */
class VmInterpreterExecutionTest {
    private val objectMapper = ObjectMapper()

    @Test
    fun vbc4_serializer_returns_expected_header_and_section_markers() {
        val serializer = VmBytecodeSerializer(buildSeed = 0x2468_1357, buildContext = fixedVbc4Context())
        serializer.visitCode()
        serializer.visitInsn(Opcodes.ICONST_1)
        serializer.visitInsn(Opcodes.IRETURN)
        serializer.visitMaxs(8, 8)
        serializer.visitEnd()

        val bytes = serializer.serialize()

        assertEquals("VBC4", bytes.copyOfRange(0, 4).toString(Charsets.US_ASCII))
        assertEquals(4, readU2(bytes, 4), "VBC4 version must be 4")
        assertFalse(bytes.containsInt32BigEndian(0x2468_1357), "Build seed must not be stored in plaintext")
        assertEquals(16, bytes.copyOfRange(26, 42).size, "VBC4 header must carry a wrapped seed token")
        val flags = readU2(bytes, 42)
        assertTrue(flags and 0x0001 != 0, "Constant pool section must be encrypted")
        assertTrue(flags and 0x0002 != 0, "Instruction section must be block encrypted")
        assertTrue(flags and 0x0004 != 0, "Stream must contain MAC")
        assertTrue(flags and 0x0020 != 0, "Stream must carry authenticated encryption metadata")
        assertTrue(bytes.last().toInt() and 0xFF == 32, "MAC length tag must be 32")
    }

    @Test
    fun vbc4_multi_block_layout_splits_large_methods_into_several_blocks() {
        val serializer = VmBytecodeSerializer(buildSeed = 0x0BADF00D, buildContext = fixedVbc4Context())
        serializer.visitCode()
        repeat(60) { i ->
            serializer.visitLdcInsn(i)
            serializer.visitInsn(Opcodes.POP)
        }
        serializer.visitInsn(Opcodes.ICONST_1)
        serializer.visitInsn(Opcodes.IRETURN)
        serializer.visitMaxs(8, 8)
        serializer.visitEnd()

        val bytes = serializer.serialize()
        val blockCount = readU2(bytes, 44)
        assertTrue(blockCount > 1, "Large methods must lower into multiple VM blocks, got $blockCount")
        assertTrue(blockCount <= 12, "Multi-block layout must respect the block ceiling, got $blockCount")
    }

    @Test
    fun vbc4_multi_block_layout_uses_entropy_even_for_same_seed() {
        fun emit(seed: Int): Int {
            val serializer = VmBytecodeSerializer(buildSeed = seed, buildContext = fixedVbc4Context())
            serializer.visitCode()
            repeat(60) { i ->
                serializer.visitLdcInsn(i)
                serializer.visitInsn(Opcodes.POP)
            }
            serializer.visitInsn(Opcodes.ICONST_1)
            serializer.visitInsn(Opcodes.IRETURN)
            serializer.visitMaxs(8, 8)
            serializer.visitEnd()
            return readU2(serializer.serialize(), 44)
        }
        val repeated = (1..16).map { emit(0x13572468) }
        assertTrue(repeated.toSet().size > 1, "Block layout must vary even for a repeated fixed seed")
    }

    @Test
    fun vbc4_multi_block_storage_order_is_seed_randomized() {
        fun blockIds(seed: Int): List<Int> {
            val serializer = VmBytecodeSerializer(buildSeed = seed, buildContext = fixedVbc4Context())
            serializer.visitCode()
            repeat(96) { i ->
                serializer.visitLdcInsn(i)
                serializer.visitInsn(Opcodes.POP)
            }
            serializer.visitInsn(Opcodes.ICONST_1)
            serializer.visitInsn(Opcodes.IRETURN)
            serializer.visitMaxs(8, 8)
            serializer.visitEnd()
            val bytes = serializer.serialize()
            val blockCount = readU2(bytes, 44)
            return readBlockIndexEntries(bytes, blockCount).map { it.blockId }
        }

        val ids = blockIds(0x2468_1357)
        assertTrue(ids.size > 1, "Fixture must produce enough blocks to make storage order randomization observable")
        assertEquals(ids.sorted(), ids.indices.toList(), "Physical block index must contain each logical block id exactly once")
        assertTrue(ids != ids.indices.toList(), "Multi-block storage order must be shuffled independently of logical execution order")
        assertTrue((1..40).map { blockIds(0x2468_1357) }.any { it != ids }, "Physical block order must vary across repeated same-seed builds")
    }

    @Test
    fun vbc4_multi_block_index_carries_masked_dispatch_chain() {
        val seed = 0x2468_1357
        val serializer = VmBytecodeSerializer(
            buildSeed = seed,
            buildContext = fixedVbc4Context(),
            structureEntropy = fixedStructureEntropy(),
        )
        serializer.visitCode()
        repeat(96) { i ->
            serializer.visitLdcInsn(i)
            serializer.visitInsn(Opcodes.POP)
        }
        serializer.visitInsn(Opcodes.ICONST_1)
        serializer.visitInsn(Opcodes.IRETURN)
        serializer.visitMaxs(8, 8)
        serializer.visitEnd()

        val bytes = serializer.serialize()
        val flags = readU2(bytes, 42)
        val blockCount = readU2(bytes, 44)
        val entries = readBlockIndexEntries(bytes, blockCount)

        assertTrue(flags and 0x0800 != 0, "VBC4 must mark block-dispatch metadata as required")
        assertTrue(blockCount > 1, "Fixture must produce multiple blocks")
        assertTrue(entries.any { it.maskedNext != it.blockId + 1 }, "Dispatch edges must be masked rather than plaintext next ids")
        val dispatchSeed = effectiveBuildSeed(serializer)
        val nextByBlock = entries.associate { it.blockId to decodeBlockDispatchNext(dispatchSeed, it.blockId, blockCount, it.maskedNext) }
        val chain = generateSequence(0) { current ->
            val next = nextByBlock.getValue(current)
            if (next == blockCount) null else next
        }.take(blockCount + 1).toList()
        assertEquals((0 until blockCount).toList(), chain, "Masked block-dispatch chain must reconstruct logical execution order")
        assertEquals(blockCount, nextByBlock.getValue(blockCount - 1), "Last logical block must dispatch to the terminal sentinel")
    }

    @Test
    fun vbc4_same_program_has_high_structural_variance_across_build_seeds() {
        fun emit(seed: Int): Pair<ByteArray, List<Int>> {
            val serializer = VmBytecodeSerializer(buildSeed = seed, buildContext = fixedVbc4Context())
            serializer.visitCode()
            repeat(128) { i ->
                serializer.visitLdcInsn(i xor (i shl 3))
                serializer.visitInsn(Opcodes.POP)
                serializer.visitInsn(Opcodes.ICONST_1)
                serializer.visitInsn(Opcodes.ICONST_2)
                serializer.visitInsn(Opcodes.IADD)
                serializer.visitInsn(Opcodes.POP)
            }
            serializer.visitInsn(Opcodes.ICONST_1)
            serializer.visitInsn(Opcodes.IRETURN)
            serializer.visitMaxs(8, 8)
            serializer.visitEnd()
            val bytes = serializer.serialize()
            val blockCount = readU2(bytes, 44)
            val blockIds = readBlockIndexEntries(bytes, blockCount).map { it.blockId }
            return bytes to blockIds
        }

        val outputs = (1..16).map { emit(0x5A00_0000.toInt() + it) }
        val uniquePayloads = outputs.map { it.first.toList() }.toSet().size
        val uniqueBlockCounts = outputs.map { it.second.size }.toSet().size
        val uniqueStorageOrders = outputs.map { it.second }.toSet().size

        assertEquals(outputs.size, uniquePayloads, "Same source VM program should produce unique VBC4 payloads across sampled build seeds")
        assertTrue(uniqueBlockCounts >= 2, "Same source VM program should vary logical block counts across seeds")
        assertTrue(uniqueStorageOrders >= outputs.size / 2, "Same source VM program should vary physical block storage order across seeds")
    }

    @Test
    fun vbc4_extended_opcode_aliasing_covers_more_semantic_families() {
        val serializerSource = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        val nativeSource = Files.readString(Path.of("src/main/native/js_vm_core.c"))
        // Arithmetic/bitwise, load-store, array, field, and branch families must all carry aliases.
        for (canonical in listOf("VM_IMUL", "VM_IXOR", "VM_IAND", "VM_ISHL", "VM_ALOAD", "VM_ASTORE", "VM_IALOAD", "VM_GETFIELD", "VM_GOTO", "VM_IF_ICMPEQ")) {
            assertTrue(serializerSource.contains("VmOpcodes.$canonical to intArrayOf("), "Serializer must alias $canonical")
        }
        // Native must canonicalize every new alias back to its base handler.
        for (pair in listOf("JS_VM_IMUL_ALT: return JS_VM_IMUL", "JS_VM_GOTO_ALT: return JS_VM_GOTO", "JS_VM_GETFIELD_ALT: return JS_VM_GETFIELD", "JS_VM_IALOAD_ALT: return JS_VM_IALOAD")) {
            assertTrue(nativeSource.contains("case $pair;"), "Native parser must canonicalize $pair")
        }
    }

    @Test
    fun vbc4_domain_super_operator_operands_are_alias_diversified() {
        fun foldedSources(seed: Int): Pair<Int, Int> {
            val serializer = VmBytecodeSerializer(buildSeed = seed, buildContext = fixedVbc4Context())
            val domainOperand = VmBytecodeSerializer::class.java.getDeclaredMethod(
                "domainSuperOperandOpcode",
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
                Int::class.javaPrimitiveType,
            ).apply { isAccessible = true }
            val srcA = domainOperand.invoke(serializer, 0x02, 0, 0) as Int
            val srcB = domainOperand.invoke(serializer, 0x40, 0, 1) as Int
            return srcA to srcB
        }

        val variants = (1..12).map { foldedSources(0x7100_0000 + it) }.toSet()

        assertTrue(variants.size >= 2, "Semantic/domain super-operator embedded opcodes must use multiple alias encodings across seeds")
    }

    @Test
    fun vbc4_stack_instruction_opcodes_are_masked_per_build_seed() {
        val serializerA = VmBytecodeSerializer(buildSeed = 0x11111111, buildContext = fixedVbc4Context())
        serializerA.visitCode()
        serializerA.visitInsn(Opcodes.ICONST_1)
        serializerA.visitInsn(Opcodes.IRETURN)
        serializerA.visitMaxs(8, 8)
        serializerA.visitEnd()
        val bytesA = serializerA.serialize()

        val serializerB = VmBytecodeSerializer(buildSeed = 0x22222222, buildContext = fixedVbc4Context())
        serializerB.visitCode()
        serializerB.visitInsn(Opcodes.ICONST_1)
        serializerB.visitInsn(Opcodes.IRETURN)
        serializerB.visitMaxs(8, 8)
        serializerB.visitEnd()
        val bytesB = serializerB.serialize()

        // Different seeds should produce different binary output for the same program
        assertFalse(bytesA.contentEquals(bytesB), "Different build seeds must produce different VBC4 encodings")
        // MAC tag at EOF should differ too
        assertEquals(32, bytesA.last().toInt() and 0xFF)
        assertEquals(32, bytesB.last().toInt() and 0xFF)
        assertFalse(
            bytesA.copyOfRange(bytesA.size - 33, bytesA.size - 1).contentEquals(
                bytesB.copyOfRange(bytesB.size - 33, bytesB.size - 1)
            ),
            "Different build seeds must produce different MAC tags"
        )
    }

    @Test
    fun vbc4_state_bound_serializer_uses_runtime_binding_in_seed_derivation() {
        val serializerSource = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        val virtualizationSource = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/MethodVirtualizationTransforms.kt"))
        val nativeKernelSource = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeKernelTransforms.kt"))

        assertTrue(serializerSource.contains("private val stateBinding: String"), "VBC4 serializer must accept runtime state binding material.")
        assertTrue(serializerSource.contains("VBC4_FLAG_STATE_BOUND") && serializerSource.contains("vbc4WrappedSeed(cryptoSeed, nonce, stateBinding)"), "VBC4 serializer seed wrapping must always include binding material.")
        assertTrue(virtualizationSource.contains("VBC4_CLEAN_ENTRY_INTEGRITY_HEX") && virtualizationSource.contains("jarLayoutDigest"), "VM resource binding must include clean entry integrity and build layout digest material.")
        assertTrue(virtualizationSource.contains("vmStateBinding(entryToken, resourcePath)"), "VM resource serialization must bind the hashed runtime entry token and resource path.")
        assertTrue(nativeKernelSource.contains("stateBinding = vmStateBinding(entryToken, resourcePath)"), "Helper VBC4 resource serialization must also bind the hashed runtime entry token and resource path.")
    }

    @Test
    fun vbc4_serializer_and_native_parser_support_opcode_level_polymorphism() {
        val serializerSource = Files.readString(Path.of("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/VmBytecodeSerializer.kt"))
        val nativeSource = Files.readString(Path.of("src/main/native/js_vm_core.c"))

        assertTrue(serializerSource.contains("VM_OPCODE_ALIASES"), "Serializer must define equivalent opcode aliases.")
        assertTrue(serializerSource.contains("lowerToLogicalProgram(metadataCpIndex)"), "VBC4-only serialization must lower bytecode into the register program consumed by native dispatch.")
        assertTrue(serializerSource.contains("polymorphicOpcode(instruction.opcode"), "Register instruction serialization must choose polymorphic opcode aliases.")
        assertTrue(serializerSource.contains("domainSuperOperandOpcode") && serializerSource.contains("polymorphicOpcode(opcode"), "Semantic/domain super-operators must diversify their embedded source opcodes instead of exposing stable canonical operands.")
        assertTrue(nativeSource.contains("js_vm_canonical_opcode"), "Native parser must canonicalize polymorphic opcode aliases before dispatch.")
        assertTrue(nativeSource.contains("case JS_VM_IADD_ALT: return JS_VM_IADD;"), "Native parser must map arithmetic aliases to canonical handlers.")
        assertTrue(nativeSource.contains("case JS_VM_IRETURN_ALT: return JS_VM_IRETURN;"), "Native parser must map return aliases to canonical handlers.")
    }

    @Test
    fun jni_native_only_profile_rejects_execution_when_no_kernel_is_available() {
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-vm-jni-exec", ".jar"))
        try {
            if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) {
                val error = assertFailsWith<IllegalArgumentException> { runEngine(inputJar, passes) }
                assertTrue(error.message?.contains("requires a bundled sealed JNI VM kernel") == true, "Native-only mode should fail closed. Message=${error.message}")
                return
            }

            val outputJar = runEngine(inputJar, passes)
            val entries = loadJarEntryNames(outputJar)
            assertFalse(entries.any { it.contains("Vm" + "Interpreter" + "Helper") }, "JNI native-only mode must not embed the full Java VM interpreter helper")
            assertTrue(entries.any { it.startsWith("META-INF/") && !it.endsWith(".class") && !it.endsWith("/") }, "JNI VM mode should seal VM resources under META-INF for native consumption")
            assertTrue(methodInvokesNativeVmDispatcher(outputJar, "e2e/Root", "call", "()I"), "Native-compatible method should be replaced with the JNI VM dispatcher")
            assertFalse(classHasMethodNameContaining(outputJar, "e2e/Root", "js" + "$" + "orig"), "Native-compatible method bodies must not remain as synthetic original Java methods")
            Files.deleteIfExists(outputJar)
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun jni_native_only_profile_preserves_hot_loops_and_nested_catch_semantics() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildHotLoopExceptionFixtureJar(Files.createTempFile("javashroud-vm-hot-exception", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
                timeoutSeconds = 20,
            )
            assertEquals(0, baseline.exitCode, "Baseline hot-loop/exception fixture must exit cleanly. stdout=${baseline.output}")

            outputJar = runEngine(inputJar, passes)
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
                timeoutSeconds = 20,
            )
            assertEquals(0, result.exitCode, "Virtualized hot-loop/exception fixture must exit cleanly. stdout=${result.output}")
            assertEquals(
                baseline.output.trim(),
                result.output.trim(),
                "Native VBC4 must preserve long-running loops and nested virtualized ArithmeticException catch semantics",
            )
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }
    @Test
    fun jni_native_only_profile_preserves_bitwise_and_shift_super_operator_fusion() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildBitwiseShiftFixtureJar(Files.createTempFile("javashroud-vm-bitwise", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, baseline.exitCode, "Baseline bitwise/shift fixture must exit cleanly. stdout=${baseline.output}")

            outputJar = runEngine(inputJar, passes)
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, result.exitCode, "Virtualized bitwise/shift fixture must exit cleanly. stdout=${result.output}")
            assertEquals(
                baseline.output.trim(),
                result.output.trim(),
                "Native VBC4 must preserve const+bitwise/shift semantics through broadened super-operator fusion",
            )
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun jni_native_only_profile_preserves_semantic_predicate_super_operator_fusion() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildPredicateDomainFixtureJar(Files.createTempFile("javashroud-vm-predicate", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, baseline.exitCode, "Baseline predicate fixture must exit cleanly. stdout=${'$'}{baseline.output}")

            outputJar = runEngine(inputJar, passes)
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, result.exitCode, "Virtualized predicate fixture must exit cleanly. stdout=${'$'}{result.output}")
            assertEquals(
                baseline.output.trim(),
                result.output.trim(),
                "Native VBC4 must preserve compare-and-branch semantics through semantic predicate super-operator fusion",
            )
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    private fun buildRenamedMainBridgeFixtureJar(target: Path): Path = buildJavaSourceFixtureJar(
        target = target,
        mainClass = "e2e.RenamedMainRoot",
        sourceFile = "RenamedMainRoot.java",
        source = """
            package e2e;

            public final class RenamedMainRoot {
                public static void main(String[] args) {
                    String mode = (args.length > 0 && "--diagnostics-only".equals(args[0])) ? "diagnostics" : "ui";
                    System.out.println("renamed-main:" + mode);
                }
            }
        """.trimIndent(),
    )
    private fun buildPredicateDomainFixtureJar(target: Path): Path = buildJavaSourceFixtureJar(
        target = target,
        mainClass = "e2e.PredicateRoot",
        sourceFile = "PredicateRoot.java",
        source = """
            package e2e;

            public final class PredicateRoot {
                private static int compare(long a, long b, float f, double d) {
                    int score = 0;
                    if (a < b) score += 3;
                    if (a == b) score += 5;
                    if (f > 7.25f) score += 11;
                    if (d <= 12.5d) score += 17;
                    return score;
                }

                public static void main(String[] args) {
                    int acc = 0;
                    for (int i = 0; i < 80; i++) {
                        acc += compare(i * 3L, 120L - i, i / 3.0f, i / 2.0d);
                    }
                    System.out.println(acc);
                }
            }
        """.trimIndent(),
    )

    private fun buildHotLoopExceptionFixtureJar(target: Path): Path = buildJavaSourceFixtureJar(
        target = target,
        mainClass = "e2e.HotExceptionRoot",
        sourceFile = "HotExceptionRoot.java",
        source = """
            package e2e;

            public final class HotExceptionRoot {
                private static int risky(int seed, int i) {
                    if (i % 131 == 0) return seed / (i - i);
                    return (seed ^ i) + Integer.reverseBytes(i);
                }

                private static int catchLoop(int seed) {
                    int result = seed;
                    int caught = 0;
                    for (int i = 1; i <= 5000; i++) {
                        try {
                            result ^= risky(seed, i);
                        } catch (ArithmeticException expected) {
                            caught += 7;
                            result += expected.getClass().getSimpleName().hashCode();
                        }
                        result = Integer.rotateLeft(result, i & 7);
                    }
                    return result ^ caught;
                }

                private static int hotLoop(int seed) {
                    int value = seed;
                    long wide = seed * -7046029254386353131L;
                    for (int i = 0; i < 160000; i++) {
                        value ^= i * 73244475;
                        value = Integer.rotateLeft(value, (i & 15) + 1);
                        wide ^= ((long)value) * (i + 1099511628211L);
                        wide = Long.rotateLeft(wide, i & 31);
                    }
                    return value ^ (int)(wide ^ (wide >>> 32));
                }

                public static void main(String[] args) {
                    System.out.println("hot-ex:" + hotLoop(17) + ":" + catchLoop(31));
                }
            }
        """.trimIndent(),
    )
    private fun buildBitwiseShiftFixtureJar(target: Path): Path = buildJavaSourceFixtureJar(
        target = target,
        mainClass = "e2e.BitwiseRoot",
        sourceFile = "BitwiseRoot.java",
        source = """
            package e2e;

            public final class BitwiseRoot {
                // Many `const, <binop>` idioms across arithmetic, bitwise, and shift
                // families so the folded super-operator path is exercised for each.
                private static int mix(int x) {
                    int a = x ^ 0x5A5A5A5A;
                    a = a & 0x7FFFFFFF;
                    a = a | 0x01010101;
                    a = a << 3;
                    a = a >> 2;
                    a = a >>> 1;
                    a = a + 1234;
                    a = a - 567;
                    a = a * 31;
                    return a;
                }

                public static void main(String[] args) {
                    int acc = 0;
                    for (int i = 0; i < 64; i++) {
                        acc = (acc + mix(i)) ^ (i << 2);
                        acc = acc & 0x3FFFFFFF;
                    }
                    System.out.println("bw:" + acc);
                }
            }
        """.trimIndent(),
    )

    @Test
    fun jni_native_only_profile_preserves_recursive_static_call_and_static_field_updates() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildRecursiveCounterFixtureJar(Files.createTempFile("javashroud-vm-recursive", ".jar"))
        var outputJar: Path? = null
        try {
            outputJar = runEngine(inputJar, passes)
            val process = ProcessBuilder(
                "java",
                "-jar",
                outputJar.toAbsolutePath().normalize().toString(),
            ).redirectErrorStream(true).start()
            val stdout = process.inputStream.bufferedReader().readText()
            val exit = process.waitFor()
            assertEquals(0, exit, "Recursive static VM fixture must exit cleanly. stdout=$stdout")
            assertTrue(stdout.contains("ok:4"), "Recursive static VM fixture must preserve decrement recursion and static field updates. stdout=$stdout")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun jni_native_only_profile_preserves_instance_tail_recursion_without_reentry() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildInstanceRecursiveCounterFixtureJar(Files.createTempFile("javashroud-vm-instance-recursive", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()))
            assertEquals(0, baseline.exitCode, "Baseline instance recursive fixture must exit cleanly. stdout=${baseline.output}")
            outputJar = runEngine(inputJar, passes)
            val result = runJavaProcessWithTimeout(ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()), timeoutSeconds = 20)
            assertEquals(0, result.exitCode, "Virtualized instance recursive fixture must exit cleanly without native reentry blowup. stdout=${result.output}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Native VBC4 must preserve private instance tail recursion semantics")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun jni_native_only_profile_preserves_custom_class_loader_define_class_from_byte_slice() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildDefineClassFixtureJar(Files.createTempFile("javashroud-vm-define-class", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, baseline.exitCode, "Baseline defineClass fixture must exit cleanly. stdout=${baseline.output}")
            assertEquals("defined:42", baseline.output.trim(), "Baseline defineClass fixture contract changed")

            outputJar = runEngine(inputJar, passes)
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, result.exitCode, "Virtualized defineClass fixture must exit cleanly. stdout=${result.output}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Native VBC4 must preserve defineClass(byte[], offset, length) semantics")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun jni_native_only_profile_preserves_uninitialized_constructor_stack_shapes() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildConstructorStackFixtureJar(Files.createTempFile("javashroud-vm-ctor-stack", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, baseline.exitCode, "Baseline constructor-stack fixture must exit cleanly. stdout=${baseline.output}")
            assertEquals("ctor:classic:2:true", baseline.output.trim(), "Baseline constructor-stack fixture contract changed")

            outputJar = runEngine(inputJar, passes)
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, result.exitCode, "Virtualized constructor-stack fixture must exit cleanly. stdout=${result.output}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Native VBC4 must preserve uninitialized object duplication and multi-arg constructor semantics")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun jni_native_only_profile_preserves_option_parser_constructor_tail() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildOptionParserFixtureJar(Files.createTempFile("javashroud-vm-option-parser", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, baseline.exitCode, "Baseline option parser fixture must exit cleanly. stdout=${baseline.output}")
            assertEquals("default:2:classic:true;custom:5:night:false", baseline.output.trim(), "Baseline option parser fixture contract changed")

            outputJar = runEngine(inputJar, passes)
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, result.exitCode, "Virtualized option parser fixture must exit cleanly. stdout=${result.output}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Native VBC4 must preserve looped option parsing and constructor tail semantics")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun jni_native_only_profile_preserves_virtualized_method_annotation_metadata() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildAnnotationMetadataFixtureJar(Files.createTempFile("javashroud-vm-annotation", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, baseline.exitCode, "Baseline annotation fixture must exit cleanly. stdout=${baseline.output}")
            assertEquals("ann:method:7:param:OK", baseline.output.trim(), "Baseline annotation fixture contract changed")

            outputJar = runEngine(inputJar, passes)
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, result.exitCode, "Virtualized annotation fixture must exit cleanly. stdout=${result.output}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Native VBC4 must preserve method, default, and parameter annotation metadata")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun jni_native_only_profile_preserves_runnable_lambda_thread_pool_timing() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildThreadPoolLambdaFixtureJar(Files.createTempFile("javashroud-vm-thread-pool", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, baseline.exitCode, "Baseline thread-pool fixture must exit cleanly. stdout=${baseline.output}")
            assertEquals("pool:30", baseline.output.trim(), "Baseline thread-pool fixture contract changed")

            outputJar = runEngine(inputJar, passes)
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, result.exitCode, "Virtualized thread-pool fixture must exit cleanly. stdout=${result.output}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Native VBC4 must preserve Runnable lambda execution inside time-bounded executor flows")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    @Test
    fun jni_native_only_profile_preserves_renamed_manifest_main_bridge() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("rename-methods", "method-virtualization", "jni-microkernel-loader")
        val inputJar = buildRenamedMainBridgeFixtureJar(Files.createTempFile("javashroud-vm-renamed-main", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString(), "--diagnostics-only"),
            )
            assertEquals(0, baseline.exitCode, "Baseline renamed-main fixture must exit cleanly. stdout=${baseline.output}")
            assertEquals("renamed-main:diagnostics", baseline.output.trim(), "Baseline renamed-main fixture contract changed")

            outputJar = runEngine(
                inputJar,
                passes,
                mapOf(
                    "method-virtualization" to mapOf(
                        "methodSelection" to "all-compatible",
                        "strictVirtualization" to true,
                        "maxInstructions" to 99999,
                    ),
                ),
            )
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString(), "--diagnostics-only"),
            )
            assertEquals(0, result.exitCode, "Virtualized renamed-main fixture must exit cleanly. stdout=${result.output}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Synthetic main bridge created for method renaming must continue to invoke the renamed original entry logic")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }
    @Test
    fun strict_all_compatible_virtualization_accepts_thread_sleep_calls() {
        if (!EmbeddedHelperDeployment.hasLoadableNativeKernel()) return
        val passes = listOf("method-virtualization", "jni-microkernel-loader")
        val inputJar = buildThreadSleepFixtureJar(Files.createTempFile("javashroud-vm-thread-sleep", ".jar"))
        var outputJar: Path? = null
        try {
            val baseline = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", inputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, baseline.exitCode, "Baseline Thread.sleep fixture must exit cleanly. stdout=${baseline.output}")
            assertEquals("sleep:13", baseline.output.trim(), "Baseline Thread.sleep fixture contract changed")

            outputJar = runEngine(
                inputJar,
                passes,
                mapOf(
                    "method-virtualization" to mapOf(
                        "methodSelection" to "all-compatible",
                        "strictVirtualization" to true,
                        "maxInstructions" to 99999,
                    ),
                ),
            )
            assertTrue(methodInvokesNativeVmDispatcher(outputJar, "e2e/ThreadSleepRoot", "compute", "(I)I"), "Strict all-compatible mode must virtualize methods containing Thread.sleep")
            val result = runJavaProcessWithTimeout(
                ProcessBuilder("java", "-jar", outputJar.toAbsolutePath().normalize().toString()),
            )
            assertEquals(0, result.exitCode, "Virtualized Thread.sleep fixture must exit cleanly. stdout=${result.output}")
            assertEquals(baseline.output.trim(), result.output.trim(), "Native VBC4 must preserve Thread.sleep call semantics")
        } finally {
            outputJar?.let { Files.deleteIfExists(it) }
            Files.deleteIfExists(inputJar)
        }
    }

    private fun runEngine(inputJar: Path, passIds: List<String>, passParams: Map<String, Map<String, Any>> = emptyMap()): Path {
        val tag = safeTag(passIds.joinToString("-"), "javashroud-vm-exec-")
        val outputJar = inputJar.resolveSibling("javashroud-vm-out-$tag.jar")
        val configPath = inputJar.resolveSibling("javashroud-vm-cfg-$tag.toml")
        writeRunConfig(configPath, inputJar, outputJar, passIds, passParams)
        try {
            dispatchRequest(buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())), EngineKernel())
        } finally {
            Files.deleteIfExists(configPath)
        }
        return outputJar
    }

    private fun writeRunConfig(configPath: Path, inputJar: Path, outputJar: Path, passIds: List<String>, passParams: Map<String, Map<String, Any>>) {
        writeTestRunConfigToml(
            configPath = configPath,
            inputJar = inputJar,
            outputJar = outputJar,
            passIds = passIds,
            passParams = passParams.mapValues { (_, params) -> params.mapValues { (_, value) -> objectMapper.valueToTree(value) } },
        )
    }

    private fun loadJarEntryNames(jarPath: Path): List<String> {
        val entries = mutableListOf<String>()
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory) entries.add(entry.name)
                jar.closeEntry()
            }
        }
        return entries
    }

    private fun classHasMethodNameContaining(jarPath: Path, className: String, needle: String): Boolean {
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory && entry.name == "$className.class") {
                    var found = false
                    ClassReader(jar.readBytes()).accept(object : ClassVisitor(Opcodes.ASM9) {
                        override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<String>?): MethodVisitor {
                            if (name.contains(needle)) found = true
                            return object : MethodVisitor(Opcodes.ASM9) {}
                        }
                    }, ClassReader.SKIP_CODE)
                    return found
                }
                jar.closeEntry()
            }
        }
        return false
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
                                    ) found = true
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

    private fun safeTag(raw: String, prefix: String): String {
        val clean = raw.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val maxLen = 180 - prefix.length
        return if (clean.length > maxLen) clean.substring(0, maxLen) else clean
    }

    private fun fixedVbc4Context(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 29 + 3).toByte() },
        nativeSeed = 0x2468_1357L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 31 + 9).toByte() },
    )

    private fun fixedStructureEntropy(): ByteArray = ByteArray(32) { index -> (index * 23 + 11).toByte() }

    private fun readU2(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 8) or (bytes[offset + 1].toInt() and 0xFF)

    private fun readU4(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)

    private fun effectiveBuildSeed(serializer: VmBytecodeSerializer): Int =
        serializer.javaClass.getDeclaredField("effectiveBuildSeed").apply { isAccessible = true }.getInt(serializer)

    private data class BlockIndexEntry(val blockId: Int, val entryToken: Int, val maskedNext: Int)

    private fun readBlockIndexEntries(bytes: ByteArray, blockCount: Int): List<BlockIndexEntry> {
        val cpSectionSize = readU4(bytes, 50)
        var offset = 54 + cpSectionSize
        return (0 until blockCount).map {
            val entry = BlockIndexEntry(
                blockId = readU2(bytes, offset),
                entryToken = readU4(bytes, offset + 2),
                maskedNext = readU4(bytes, offset + 6),
            )
            offset += 10
            entry
        }
    }

    private fun decodeBlockDispatchNext(seed: Int, blockId: Int, blockCount: Int, token: Int): Int {
        val mask = seed.rotateLeft((blockId * 5 + 7) and 31) xor
            (blockId * 0x45D9F3B) xor
            (blockCount * 0x119DE1F3)
        val payload = token xor mask
        if (payload in 0..blockCount) return payload
        val nextBlockId = payload and 0xFFFF
        val state = (payload ushr 16) and 0xFFFF
        val mixed = seed.rotateLeft((blockId * 3 + 11) and 31) xor
            (blockId * 0x632BE59B) xor
            (nextBlockId * 0x85157AF5.toInt()) xor
            (blockCount * 0x9E3779B9.toInt())
        val expectedState = ((mixed xor (mixed ushr 16)) and 0xFFFF).let { if (it == 0) 1 else it }
        return if (nextBlockId <= blockCount && state == expectedState) nextBlockId else -1
    }

    private fun ByteArray.containsInt32BigEndian(value: Int): Boolean {
        if (size < 4) return false
        for (offset in 0..(size - 4)) {
            if (readU4(this, offset) == value) return true
        }
        return false
    }

    private fun buildInstanceRecursiveCounterFixtureJar(target: Path): Path = buildJavaSourceFixtureJar(
        target = target,
        mainClass = "e2e.InstanceRecursiveCounter",
        sourceFile = "InstanceRecursiveCounter.java",
        source = """
            package e2e;

            public final class InstanceRecursiveCounter {
                private int count;

                private void call(int i) {
                    if (i == 0) count++;
                    else call(i - 1);
                }

                private int run() {
                    for (int i = 0; i < 10000; i++) call(100);
                    return count;
                }

                public static void main(String[] args) {
                    System.out.println("ok:" + new InstanceRecursiveCounter().run());
                }
            }
        """.trimIndent(),
    )

    private fun buildRecursiveCounterFixtureJar(target: Path): Path {
        val cw = org.objectweb.asm.ClassWriter(0)
        cw.visit(org.objectweb.asm.Opcodes.V21, org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_FINAL, "e2e/RecursiveCounter", null, "java/lang/Object", null)
        cw.visitField(org.objectweb.asm.Opcodes.ACC_PRIVATE or org.objectweb.asm.Opcodes.ACC_STATIC, "count", "I", null, null).visitEnd()
        val init = cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
        init.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(org.objectweb.asm.Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val call = cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PRIVATE or org.objectweb.asm.Opcodes.ACC_STATIC, "call", "(I)V", null, null)
        call.visitCode()
        val recurse = org.objectweb.asm.Label()
        val done = org.objectweb.asm.Label()
        call.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0)
        call.visitJumpInsn(org.objectweb.asm.Opcodes.IFNE, recurse)
        call.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "e2e/RecursiveCounter", "count", "I")
        call.visitInsn(org.objectweb.asm.Opcodes.ICONST_1)
        call.visitInsn(org.objectweb.asm.Opcodes.IADD)
        call.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "e2e/RecursiveCounter", "count", "I")
        call.visitJumpInsn(org.objectweb.asm.Opcodes.GOTO, done)
        call.visitLabel(recurse)
        call.visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 0)
        call.visitInsn(org.objectweb.asm.Opcodes.ICONST_1)
        call.visitInsn(org.objectweb.asm.Opcodes.ISUB)
        call.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "e2e/RecursiveCounter", "call", "(I)V", false)
        call.visitLabel(done)
        call.visitInsn(org.objectweb.asm.Opcodes.RETURN)
        call.visitMaxs(2, 1)
        call.visitEnd()
        val main = cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null)
        main.visitCode()
        main.visitInsn(org.objectweb.asm.Opcodes.ICONST_3)
        main.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "e2e/RecursiveCounter", "call", "(I)V", false)
        main.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "e2e/RecursiveCounter", "count", "I")
        main.visitInsn(org.objectweb.asm.Opcodes.ICONST_3)
        main.visitInsn(org.objectweb.asm.Opcodes.IADD)
        main.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "e2e/RecursiveCounter", "count", "I")
        main.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
        main.visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "e2e/RecursiveCounter", "count", "I")
        main.visitInvokeDynamicInsn(
            "makeConcatWithConstants",
            "(I)Ljava/lang/String;",
            org.objectweb.asm.Handle(
                org.objectweb.asm.Opcodes.H_INVOKESTATIC,
                "java/lang/invoke/StringConcatFactory",
                "makeConcatWithConstants",
                "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
                false,
            ),
            "ok:",
        )
        main.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
        main.visitInsn(org.objectweb.asm.Opcodes.RETURN)
        main.visitMaxs(2, 1)
        main.visitEnd()
        val clinit = cw.visitMethod(org.objectweb.asm.Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        clinit.visitCode()
        clinit.visitInsn(org.objectweb.asm.Opcodes.ICONST_0)
        clinit.visitFieldInsn(org.objectweb.asm.Opcodes.PUTSTATIC, "e2e/RecursiveCounter", "count", "I")
        clinit.visitInsn(org.objectweb.asm.Opcodes.RETURN)
        clinit.visitMaxs(1, 0)
        clinit.visitEnd()
        cw.visitEnd()
        java.nio.file.Files.newOutputStream(target).use { out ->
            java.util.jar.JarOutputStream(out).use { jar ->
                jar.putNextEntry(java.util.jar.JarEntry("e2e/RecursiveCounter.class"))
                jar.write(cw.toByteArray())
                jar.closeEntry()
            }
        }
        return target
    }

    private fun buildConstructorStackFixtureJar(target: Path): Path {
        val root = buildConstructorStackRootBytes()
        java.nio.file.Files.newOutputStream(target).use { out ->
            java.util.jar.JarOutputStream(out).use { jar ->
                jar.putNextEntry(java.util.jar.JarEntry("META-INF/MANIFEST.MF"))
                jar.write("Manifest-Version: 1.0\r\nMain-Class: e2e.CtorStackRoot\r\n\r\n".toByteArray())
                jar.closeEntry()
                jar.putNextEntry(java.util.jar.JarEntry("e2e/CtorStackRoot.class"))
                jar.write(root)
                jar.closeEntry()
            }
        }
        return target
    }

    private fun buildConstructorStackRootBytes(): ByteArray {
        val cw = org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_MAXS or org.objectweb.asm.ClassWriter.COMPUTE_FRAMES)
        cw.visit(org.objectweb.asm.Opcodes.V21, org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_FINAL, "e2e/CtorStackRoot", null, "java/lang/Object", null)
        cw.visitField(org.objectweb.asm.Opcodes.ACC_PRIVATE or org.objectweb.asm.Opcodes.ACC_FINAL, "label", "Ljava/lang/String;", null, null).visitEnd()
        cw.visitField(org.objectweb.asm.Opcodes.ACC_PRIVATE or org.objectweb.asm.Opcodes.ACC_FINAL, "count", "I", null, null).visitEnd()
        cw.visitField(org.objectweb.asm.Opcodes.ACC_PRIVATE or org.objectweb.asm.Opcodes.ACC_FINAL, "enabled", "Z", null, null).visitEnd()

        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(org.objectweb.asm.Opcodes.RETURN)
            visitMaxs(1, 1)
            visitEnd()
        }

        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PRIVATE, "<init>", "(ZZILjava/lang/String;Z)V", null, null).apply {
            visitCode()
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 4)
            visitFieldInsn(org.objectweb.asm.Opcodes.PUTFIELD, "e2e/CtorStackRoot", "label", "Ljava/lang/String;")
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 3)
            visitFieldInsn(org.objectweb.asm.Opcodes.PUTFIELD, "e2e/CtorStackRoot", "count", "I")
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 1)
            visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 2)
            visitInsn(org.objectweb.asm.Opcodes.IOR)
            visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 5)
            visitInsn(org.objectweb.asm.Opcodes.IAND)
            visitFieldInsn(org.objectweb.asm.Opcodes.PUTFIELD, "e2e/CtorStackRoot", "enabled", "Z")
            visitInsn(org.objectweb.asm.Opcodes.RETURN)
            visitMaxs(3, 6)
            visitEnd()
        }

        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PRIVATE, "describe", "()Ljava/lang/String;", null, null).apply {
            visitCode()
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitFieldInsn(org.objectweb.asm.Opcodes.GETFIELD, "e2e/CtorStackRoot", "label", "Ljava/lang/String;")
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitFieldInsn(org.objectweb.asm.Opcodes.GETFIELD, "e2e/CtorStackRoot", "count", "I")
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitFieldInsn(org.objectweb.asm.Opcodes.GETFIELD, "e2e/CtorStackRoot", "enabled", "Z")
            visitInvokeDynamicInsn(
                "makeConcatWithConstants",
                "(Ljava/lang/String;IZ)Ljava/lang/String;",
                org.objectweb.asm.Handle(
                    org.objectweb.asm.Opcodes.H_INVOKESTATIC,
                    "java/lang/invoke/StringConcatFactory",
                    "makeConcatWithConstants",
                    "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
                    false,
                ),
                "ctor:\u0001:\u0001:\u0001",
            )
            visitInsn(org.objectweb.asm.Opcodes.ARETURN)
            visitMaxs(3, 1)
            visitEnd()
        }

        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PRIVATE or org.objectweb.asm.Opcodes.ACC_STATIC, "run", "()Ljava/lang/String;", null, null).apply {
            visitCode()
            visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 7)
            visitIntInsn(org.objectweb.asm.Opcodes.NEWARRAY, org.objectweb.asm.Opcodes.T_CHAR)
            "classic".forEachIndexed { index, char ->
                visitInsn(org.objectweb.asm.Opcodes.DUP)
                visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, index)
                visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, char.code)
                visitInsn(org.objectweb.asm.Opcodes.CASTORE)
            }
            visitTypeInsn(org.objectweb.asm.Opcodes.NEW, "java/lang/String")
            visitInsn(org.objectweb.asm.Opcodes.DUP_X1)
            visitInsn(org.objectweb.asm.Opcodes.SWAP)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false)
            visitVarInsn(org.objectweb.asm.Opcodes.ASTORE, 0)
            visitTypeInsn(org.objectweb.asm.Opcodes.NEW, "e2e/CtorStackRoot")
            visitInsn(org.objectweb.asm.Opcodes.DUP)
            visitInsn(org.objectweb.asm.Opcodes.ICONST_1)
            visitInsn(org.objectweb.asm.Opcodes.ICONST_0)
            visitInsn(org.objectweb.asm.Opcodes.ICONST_2)
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitInsn(org.objectweb.asm.Opcodes.ICONST_1)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "e2e/CtorStackRoot", "<init>", "(ZZILjava/lang/String;Z)V", false)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "e2e/CtorStackRoot", "describe", "()Ljava/lang/String;", false)
            visitInsn(org.objectweb.asm.Opcodes.ARETURN)
            visitMaxs(7, 1)
            visitEnd()
        }

        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null).apply {
            visitCode()
            visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "e2e/CtorStackRoot", "run", "()Ljava/lang/String;", false)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
            visitInsn(org.objectweb.asm.Opcodes.RETURN)
            visitMaxs(2, 1)
            visitEnd()
        }

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildAnnotationMetadataFixtureJar(target: Path): Path = buildJavaSourceFixtureJar(
        target = target,
        mainClass = "e2e.AnnotationRoot",
        sourceFile = "AnnotationRoot.java",
        source = """
            package e2e;

            import java.lang.annotation.ElementType;
            import java.lang.annotation.Retention;
            import java.lang.annotation.RetentionPolicy;
            import java.lang.annotation.Target;
            import java.lang.reflect.Method;
            import java.util.Locale;

            @Retention(RetentionPolicy.RUNTIME)
            @Target({ElementType.METHOD, ElementType.PARAMETER})
            @interface Marker {
                String value();
                int count() default 1;
            }

            public final class AnnotationRoot {
                @Marker(value = "method", count = 7)
                private static String target(@Marker("param") String value) {
                    return value.toUpperCase(Locale.ROOT);
                }

                public static void main(String[] args) throws Exception {
                    Method method = AnnotationRoot.class.getDeclaredMethod("target", String.class);
                    method.setAccessible(true);
                    Marker methodMarker = method.getAnnotation(Marker.class);
                    Marker paramMarker = (Marker) method.getParameterAnnotations()[0][0];
                    System.out.println("ann:" + methodMarker.value() + ":" + methodMarker.count() + ":" + paramMarker.value() + ":" + method.invoke(null, "ok"));
                }
            }
        """.trimIndent(),
    )

    private fun buildThreadPoolLambdaFixtureJar(target: Path): Path = buildJavaSourceFixtureJar(
        target = target,
        mainClass = "e2e.ThreadPoolRoot",
        sourceFile = "ThreadPoolRoot.java",
        source = """
            package e2e;

            import java.util.concurrent.LinkedBlockingQueue;
            import java.util.concurrent.RejectedExecutionException;
            import java.util.concurrent.ThreadPoolExecutor;
            import java.util.concurrent.TimeUnit;

            public final class ThreadPoolRoot {
                private static int value = 1;
                private static final ThreadPoolExecutor EXECUTOR = new ThreadPoolExecutor(0, 1, 1L, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>(1));

                private static final class Exec {
                    private final int delta;

                    Exec(int delta) {
                        this.delta = delta;
                    }

                    void doAdd() {
                        try {
                            Thread.sleep(200L);
                        } catch (InterruptedException ignored) {
                            Thread.currentThread().interrupt();
                        }
                        value += delta;
                    }
                }

                private static Runnable direct(Exec exec) {
                    return exec::doAdd;
                }

                private static Runnable snapshot(Exec exec) {
                    return () -> {
                        int before = value;
                        exec.doAdd();
                        value += before;
                    };
                }

                private static String run() throws Exception {
                    try {
                        EXECUTOR.submit(direct(new Exec(3)));
                        Thread.sleep(50L);
                        EXECUTOR.submit(snapshot(new Exec(2)));
                        Thread.sleep(50L);
                        try {
                            EXECUTOR.submit(direct(new Exec(100)));
                        } catch (RejectedExecutionException expected) {
                            value += 10;
                        }
                        Thread.sleep(800L);
                        return "pool:" + value;
                    } finally {
                        EXECUTOR.shutdownNow();
                    }
                }

                public static void main(String[] args) throws Exception {
                    System.out.println(run());
                }
            }
        """.trimIndent(),
    )

    private fun buildThreadSleepFixtureJar(target: Path): Path = buildJavaSourceFixtureJar(
        target = target,
        mainClass = "e2e.ThreadSleepRoot",
        sourceFile = "ThreadSleepRoot.java",
        source = """
            package e2e;

            public final class ThreadSleepRoot {
                public static int compute(int value) throws Exception {
                    Thread.sleep(1L);
                    return value + 11;
                }

                public static void main(String[] args) throws Exception {
                    System.out.println("sleep:" + compute(2));
                }
            }
        """.trimIndent(),
    )

    private fun buildJavaSourceFixtureJar(target: Path, mainClass: String, sourceFile: String, source: String): Path {
        val workDir = Files.createTempDirectory("javashroud-java-fixture-src")
        try {
            val srcDir = workDir.resolve("e2e")
            val classesDir = workDir.resolve("classes")
            Files.createDirectories(srcDir)
            Files.createDirectories(classesDir)
            val sourcePath = srcDir.resolve(sourceFile)
            Files.writeString(sourcePath, source)
            val compiler = javax.tools.ToolProvider.getSystemJavaCompiler() ?: error("JDK compiler is required for Java fixture")
            val compileExit = compiler.run(null, null, null, "-d", classesDir.toString(), sourcePath.toString())
            assertEquals(0, compileExit, "Java fixture source must compile: $sourceFile")
            Files.newOutputStream(target).use { out ->
                java.util.jar.JarOutputStream(out).use { jar ->
                    jar.putNextEntry(java.util.jar.JarEntry("META-INF/MANIFEST.MF"))
                    jar.write("Manifest-Version: 1.0\r\nMain-Class: $mainClass\r\n\r\n".toByteArray())
                    jar.closeEntry()
                    Files.walk(classesDir).use { paths ->
                        paths.filter { Files.isRegularFile(it) }.forEach { classFile ->
                            val entryName = classesDir.relativize(classFile).toString().replace('\\', '/')
                            jar.putNextEntry(java.util.jar.JarEntry(entryName))
                            jar.write(Files.readAllBytes(classFile))
                            jar.closeEntry()
                        }
                    }
                }
            }
            return target
        } finally {
            Files.walk(workDir).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }
    private fun buildOptionParserFixtureJar(target: Path): Path {
        val workDir = Files.createTempDirectory("javashroud-option-parser-src")
        try {
            val srcDir = workDir.resolve("e2e")
            val classesDir = workDir.resolve("classes")
            Files.createDirectories(srcDir)
            Files.createDirectories(classesDir)
            val source = srcDir.resolve("OptionParserRoot.java")
            Files.writeString(
                source,
                """
                package e2e;

                public final class OptionParserRoot {
                    private final int depth;
                    private final String theme;
                    private final boolean animation;

                    private OptionParserRoot(boolean diagnosticsOnly, boolean skipStartupDiagnostics, int depth, String theme, boolean animation) {
                        this.depth = depth;
                        this.theme = theme;
                        this.animation = animation && !diagnosticsOnly && !skipStartupDiagnostics;
                    }

                    public static OptionParserRoot parse(String[] args) {
                        boolean diagnosticsOnly = false;
                        boolean skipStartupDiagnostics = false;
                        boolean animationEnabled = true;
                        int aiDepth = 2;
                        String themeName = "classic";
                        for (String arg : args) {
                            if ("--diagnostics-only".equals(arg)) {
                                diagnosticsOnly = true;
                            } else if ("--skip-startup-diagnostics".equals(arg)) {
                                skipStartupDiagnostics = true;
                            } else if ("--no-animation".equals(arg)) {
                                animationEnabled = false;
                            } else if (arg != null && arg.startsWith("--ai-depth=")) {
                                try {
                                    aiDepth = Math.max(1, Math.min(5, Integer.parseInt(arg.substring("--ai-depth=".length()))));
                                } catch (NumberFormatException ignored) {
                                    aiDepth = 2;
                                }
                            } else if (arg != null && arg.startsWith("--theme=")) {
                                String candidate = arg.substring("--theme=".length()).toLowerCase();
                                if ("classic".equals(candidate) || "paper".equals(candidate) || "night".equals(candidate)) {
                                    themeName = candidate;
                                }
                            }
                        }
                        return new OptionParserRoot(diagnosticsOnly, skipStartupDiagnostics, aiDepth, themeName, animationEnabled);
                    }

                    private String describe(String prefix) {
                        return prefix + ":" + depth + ":" + theme + ":" + animation;
                    }

                    public static void main(String[] args) {
                        OptionParserRoot def = parse(new String[0]);
                        OptionParserRoot custom = parse(new String[] {"--ai-depth=9", "--theme=NIGHT", "--no-animation"});
                        System.out.println(def.describe("default") + ";" + custom.describe("custom"));
                    }
                }
                """.trimIndent(),
            )
            val compiler = javax.tools.ToolProvider.getSystemJavaCompiler() ?: error("JDK compiler is required for option parser fixture")
            val compileExit = compiler.run(null, null, null, "-d", classesDir.toString(), source.toString())
            assertEquals(0, compileExit, "Option parser fixture Java source must compile")
            Files.newOutputStream(target).use { out ->
                java.util.jar.JarOutputStream(out).use { jar ->
                    jar.putNextEntry(java.util.jar.JarEntry("META-INF/MANIFEST.MF"))
                    jar.write("Manifest-Version: 1.0\r\nMain-Class: e2e.OptionParserRoot\r\n\r\n".toByteArray())
                    jar.closeEntry()
                    Files.walk(classesDir).use { paths ->
                        paths.filter { Files.isRegularFile(it) }.forEach { classFile ->
                            val entryName = classesDir.relativize(classFile).toString().replace('\\', '/')
                            jar.putNextEntry(java.util.jar.JarEntry(entryName))
                            jar.write(Files.readAllBytes(classFile))
                            jar.closeEntry()
                        }
                    }
                }
            }
            return target
        } finally {
            Files.walk(workDir).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    private fun buildDefineClassFixtureJar(target: Path): Path {
        val payload = buildDefineClassPayloadBytes()
        val host = buildDefineClassHostBytes()
        java.nio.file.Files.newOutputStream(target).use { out ->
            java.util.jar.JarOutputStream(out).use { jar ->
                jar.putNextEntry(java.util.jar.JarEntry("META-INF/MANIFEST.MF"))
                jar.write("Manifest-Version: 1.0\r\nMain-Class: e2e.DefineClassHost\r\n\r\n".toByteArray())
                jar.closeEntry()
                jar.putNextEntry(java.util.jar.JarEntry("e2e/DefineClassHost.class"))
                jar.write(host)
                jar.closeEntry()
                jar.putNextEntry(java.util.jar.JarEntry("payload.bin"))
                jar.write(payload)
                jar.closeEntry()
            }
        }
        return target
    }

    private fun buildDefineClassHostBytes(): ByteArray {
        val cw = org.objectweb.asm.ClassWriter(org.objectweb.asm.ClassWriter.COMPUTE_MAXS or org.objectweb.asm.ClassWriter.COMPUTE_FRAMES)
        cw.visit(org.objectweb.asm.Opcodes.V21, org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_FINAL, "e2e/DefineClassHost", null, "java/lang/ClassLoader", null)

        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitLdcInsn(Type.getType("Le2e/DefineClassHost;"))
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getClassLoader", "()Ljava/lang/ClassLoader;", false)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "java/lang/ClassLoader", "<init>", "(Ljava/lang/ClassLoader;)V", false)
            visitInsn(org.objectweb.asm.Opcodes.RETURN)
            visitMaxs(2, 1)
            visitEnd()
        }

        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PRIVATE, "definePayload", "([B)Ljava/lang/Class;", "([B)Ljava/lang/Class<*>;", null).apply {
            visitCode()
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitLdcInsn("e2e.DynamicPayload")
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 1)
            visitInsn(org.objectweb.asm.Opcodes.ICONST_3)
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 1)
            visitInsn(org.objectweb.asm.Opcodes.ARRAYLENGTH)
            visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 10)
            visitInsn(org.objectweb.asm.Opcodes.ISUB)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "e2e/DefineClassHost", "defineClass", "(Ljava/lang/String;[BII)Ljava/lang/Class;", false)
            visitInsn(org.objectweb.asm.Opcodes.ARETURN)
            visitMaxs(5, 2)
            visitEnd()
        }

        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PRIVATE or org.objectweb.asm.Opcodes.ACC_STATIC, "loadPayload", "()[B", null, arrayOf("java/io/IOException")).apply {
            visitCode()
            visitLdcInsn(Type.getType("Le2e/DefineClassHost;"))
            visitLdcInsn("/payload.bin")
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getResourceAsStream", "(Ljava/lang/String;)Ljava/io/InputStream;", false)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/io/InputStream", "readAllBytes", "()[B", false)
            visitVarInsn(org.objectweb.asm.Opcodes.ASTORE, 0)
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitInsn(org.objectweb.asm.Opcodes.ARRAYLENGTH)
            visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 10)
            visitInsn(org.objectweb.asm.Opcodes.IADD)
            visitIntInsn(org.objectweb.asm.Opcodes.NEWARRAY, org.objectweb.asm.Opcodes.T_BYTE)
            visitVarInsn(org.objectweb.asm.Opcodes.ASTORE, 1)
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitInsn(org.objectweb.asm.Opcodes.ICONST_0)
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 1)
            visitInsn(org.objectweb.asm.Opcodes.ICONST_3)
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 0)
            visitInsn(org.objectweb.asm.Opcodes.ARRAYLENGTH)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "java/lang/System", "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V", false)
            visitVarInsn(org.objectweb.asm.Opcodes.ALOAD, 1)
            visitInsn(org.objectweb.asm.Opcodes.ARETURN)
            visitMaxs(5, 2)
            visitEnd()
        }

        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, arrayOf("java/lang/Exception")).apply {
            visitCode()
            visitTypeInsn(org.objectweb.asm.Opcodes.NEW, "e2e/DefineClassHost")
            visitInsn(org.objectweb.asm.Opcodes.DUP)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESPECIAL, "e2e/DefineClassHost", "<init>", "()V", false)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "e2e/DefineClassHost", "loadPayload", "()[B", false)
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "e2e/DefineClassHost", "definePayload", "([B)Ljava/lang/Class;", false)
            visitLdcInsn("value")
            visitInsn(org.objectweb.asm.Opcodes.ICONST_0)
            visitTypeInsn(org.objectweb.asm.Opcodes.ANEWARRAY, "java/lang/Class")
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false)
            visitInsn(org.objectweb.asm.Opcodes.ACONST_NULL)
            visitInsn(org.objectweb.asm.Opcodes.ICONST_0)
            visitTypeInsn(org.objectweb.asm.Opcodes.ANEWARRAY, "java/lang/Object")
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false)
            visitTypeInsn(org.objectweb.asm.Opcodes.CHECKCAST, "java/lang/Integer")
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/lang/Integer", "intValue", "()I", false)
            visitVarInsn(org.objectweb.asm.Opcodes.ISTORE, 1)
            visitFieldInsn(org.objectweb.asm.Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;")
            visitVarInsn(org.objectweb.asm.Opcodes.ILOAD, 1)
            visitInvokeDynamicInsn(
                "makeConcatWithConstants",
                "(I)Ljava/lang/String;",
                org.objectweb.asm.Handle(
                    org.objectweb.asm.Opcodes.H_INVOKESTATIC,
                    "java/lang/invoke/StringConcatFactory",
                    "makeConcatWithConstants",
                    "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;",
                    false,
                ),
                "defined:\u0001",
            )
            visitMethodInsn(org.objectweb.asm.Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false)
            visitInsn(org.objectweb.asm.Opcodes.RETURN)
            visitMaxs(4, 2)
            visitEnd()
        }

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildDefineClassPayloadBytes(): ByteArray {
        val cw = org.objectweb.asm.ClassWriter(0)
        cw.visit(org.objectweb.asm.Opcodes.V21, org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_FINAL, "e2e/DynamicPayload", null, "java/lang/Object", null)
        cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_STATIC, "value", "()I", null, null).apply {
            visitCode()
            visitIntInsn(org.objectweb.asm.Opcodes.BIPUSH, 42)
            visitInsn(org.objectweb.asm.Opcodes.IRETURN)
            visitMaxs(1, 0)
            visitEnd()
        }
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildDiverseFixtureJar(target: Path): Path {
        val cw = org.objectweb.asm.ClassWriter(0)
        cw.visit(org.objectweb.asm.Opcodes.V21, org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_FINAL, "e2e/Root", null, "java/lang/Object", null)
        val mv = cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_STATIC, "call", "()I", null, null)
        mv.visitCode()
        mv.visitInsn(org.objectweb.asm.Opcodes.ICONST_1)
        mv.visitInsn(org.objectweb.asm.Opcodes.IRETURN)
        mv.visitMaxs(1, 0)
        mv.visitEnd()
        val main = cw.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC or org.objectweb.asm.Opcodes.ACC_STATIC, "main", "([Ljava/lang/String;)V", null, null)
        main.visitCode()
        main.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "e2e/Root", "call", "()I", false)
        main.visitMethodInsn(org.objectweb.asm.Opcodes.INVOKESTATIC, "java/lang/System", "exit", "(I)V", false)
        main.visitInsn(org.objectweb.asm.Opcodes.RETURN)
        main.visitMaxs(1, 1)
        main.visitEnd()
        cw.visitEnd()
        java.nio.file.Files.newOutputStream(target).use { out ->
            java.util.jar.JarOutputStream(out).use { jar ->
                jar.putNextEntry(java.util.jar.JarEntry("e2e/Root.class"))
                jar.write(cw.toByteArray())
                jar.closeEntry()
            }
        }
        return target
    }
}
