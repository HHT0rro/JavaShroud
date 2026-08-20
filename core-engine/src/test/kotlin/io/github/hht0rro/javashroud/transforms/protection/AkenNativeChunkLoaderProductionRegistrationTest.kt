package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.testClassArtifact
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import java.util.Arrays
import java.util.Random

class AkenNativeChunkLoaderProductionRegistrationTest {
    @Test
    fun jni_loader_registers_one_bootstrap_native_chunk_and_materializes_it_before_native_compilation() {
        val internalName = "fixture/NativeChunkLoaderHost"
        val original = hostClass(internalName)
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 3).toByte() },
            nativeSeed = 0x414B_454E_4E43_484BL,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 5).toByte() },
        )
        var emittedHandle: ByteArray? = null
        var emittedProof: ByteArray? = null
        var candidateHandle: ByteArray? = null
        var candidateProof: ByteArray? = null
        var candidatePlaintext: ByteArray? = null
        try {
            withVbc4BuildContext(context) {
                val scoped = requireVbc4BuildContext()
                val result = applyJniMicrokernelLoader(
                    artifact = testAttachedArtifact(
                        classArtifacts = listOf(testClassArtifact(internalName = internalName, bytes = original)),
                    ),
                    ruleMatches = listOf(loaderRuleMatch(internalName)),
                    params = mapOf(
                        "kernelComponents" to "all",
                        "targetPlatform" to "windows-x64",
                        "diversifiedVirtualization" to false,
                    ),
                )

                val transformedBytes = result.artifact.classArtifactIndex.getValue(internalName).bytes
                val node = ClassNode()
                ClassReader(transformedBytes).accept(node, ClassReader.SKIP_FRAMES)
                val clinit = node.methods.single { method -> method.name == "<clinit>" && method.desc == "()V" }
                val instructions = clinit.instructions.toArray()
                val loadIndex = instructions.indexOfFirst { instruction ->
                    instruction is MethodInsnNode &&
                        instruction.owner.endsWith("/JniMicrokernelHelper") &&
                        instruction.name == "loadKernel"
                }
                val consumeIndex = instructions.indexOfFirst { instruction ->
                    instruction is MethodInsnNode &&
                        instruction.owner.endsWith("/JniMicrokernelHelper") &&
                        instruction.name == "consumeAkenNativeChunk" &&
                        instruction.desc == "([BI[B)V"
                }
                assertTrue(loadIndex >= 0, "bootstrap class must load the JNI kernel")
                assertTrue(consumeIndex > loadIndex, "native chunk consume must run after loadKernel")

                val emitted = decodeNativeChunkCallInputs(instructions, loadIndex + 1, consumeIndex)
                emittedHandle = emitted.handle
                emittedProof = emitted.proof
                assertEquals(0, emitted.pageIndex)

                scoped.withAkenNativeChunkCandidatesForBuild { candidates ->
                    assertEquals(1, candidates.size, "one real native loader handler candidate must be registered")
                    val candidate = candidates.single()
                    assertEquals(0, candidate.pageIndex)
                    assertTrue(candidate.logicalBindingPath.startsWith("META-INF/.logical/native/loader/"))
                    candidateHandle = candidate.copyEncodedHandleForBuild()
                    candidateProof = candidate.copyCallSiteProofForBuild()
                    candidatePlaintext = candidate.copyPlaintextForBuild()
                }
                assertContentEquals(checkNotNull(candidateHandle), checkNotNull(emittedHandle))
                assertContentEquals(checkNotNull(candidateProof), checkNotNull(emittedProof))
                assertTrue(checkNotNull(candidatePlaintext).isNotEmpty(), "native handler descriptor must have encrypted-page plaintext before materialization")

                assertTrue(
                    RuntimeArtifactSealing.reserveAkenNativeChunkPreSealRoutesIfNeeded(
                        artifact = result.artifact,
                        seed = scoped.nativeSeed,
                    ),
                )
                val materialized = RuntimeArtifactSealing.materializeAkenVbc4PagesForNativeCompilation(
                    artifact = result.artifact,
                    seed = scoped.nativeSeed,
                )
                assertEquals(
                    result.artifact.jarEntries.size + 1,
                    materialized.jarEntries.size,
                    "the registered handler must materialize as one encrypted AKEN page entry",
                )
                scoped.withAkenNativeLocatorRecordsForBuild { records ->
                    assertEquals(1, records.size, "native compiler input must contain exactly the bootstrap handler record")
                    assertTrue(records.single().isNotEmpty())
                }
                val nativeLocatorInclude = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(
                    vbc4BuildContext = scoped,
                    rng = Random(0x4E43_484BL),
                )
                assertTrue(nativeLocatorInclude.contains("#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_COUNT 1u"))
            }
        } finally {
            emittedHandle?.let { Arrays.fill(it, 0) }
            emittedProof?.let { Arrays.fill(it, 0) }
            candidateHandle?.let { Arrays.fill(it, 0) }
            candidateProof?.let { Arrays.fill(it, 0) }
            candidatePlaintext?.let { Arrays.fill(it, 0) }
            Arrays.fill(original, 0)
            context.wipe()
        }
    }

    @Test
    fun jni_loader_without_an_active_build_context_does_not_inject_an_unbound_native_chunk_callsite() {
        val internalName = "fixture/NativeChunkNoContextHost"
        val original = hostClass(internalName)
        try {
            val result = applyJniMicrokernelLoader(
                artifact = testAttachedArtifact(
                    classArtifacts = listOf(testClassArtifact(internalName = internalName, bytes = original)),
                ),
                ruleMatches = listOf(loaderRuleMatch(internalName)),
                params = mapOf(
                    "kernelComponents" to "loader",
                    "targetPlatform" to "windows-x64",
                    "diversifiedVirtualization" to false,
                ),
            )
            val node = ClassNode()
            ClassReader(result.artifact.classArtifactIndex.getValue(internalName).bytes).accept(node, ClassReader.SKIP_FRAMES)
            val clinit = node.methods.single { method -> method.name == "<clinit>" && method.desc == "()V" }
            assertFalse(
                clinit.instructions.toArray().any { instruction ->
                    instruction is MethodInsnNode && instruction.name == "consumeAkenNativeChunk"
                },
                "a direct transform without an AKEN build context must not emit an unbound native chunk call",
            )
        } finally {
            Arrays.fill(original, 0)
        }
    }

    private fun loaderRuleMatch(internalName: String): RuleMatch = RuleMatch(
        rule = RuleSpec(target = internalName, action = "jni-microkernel-loader"),
        selector = TargetSelector(internalName, null, null),
        matchedClassNames = listOf(internalName),
        matchedMembers = emptyList(),
    )

    private fun hostClass(internalName: String): ByteArray = ClassWriter(ClassWriter.COMPUTE_FRAMES).run {
        visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(1, 1)
            visitEnd()
        }
        visitEnd()
        toByteArray()
    }

    private fun decodeNativeChunkCallInputs(
        instructions: Array<AbstractInsnNode>,
        start: Int,
        callIndex: Int,
    ): NativeChunkCallInputs {
        val (handle, afterHandle) = readByteArray(instructions, start)
        val (pageIndex, afterPageIndex) = readInt(instructions, afterHandle)
        val (proof, afterProof) = readByteArray(instructions, afterPageIndex)
        assertEquals(callIndex, afterProof, "native chunk call arguments must be contiguous")
        return NativeChunkCallInputs(handle, pageIndex, proof)
    }

    private fun readByteArray(
        instructions: Array<AbstractInsnNode>,
        start: Int,
    ): Pair<ByteArray, Int> {
        val (size, afterSize) = readInt(instructions, start)
        require(size >= 0) { "negative emitted byte-array size" }
        val newArray = instructions[afterSize] as? IntInsnNode
            ?: error("missing emitted byte-array allocation")
        require(newArray.opcode == Opcodes.NEWARRAY && newArray.operand == Opcodes.T_BYTE) {
            "emitted native chunk argument is not a byte array"
        }
        val bytes = ByteArray(size)
        var cursor = afterSize + 1
        for (index in bytes.indices) {
            require(instructions[cursor].opcode == Opcodes.DUP) { "missing byte-array DUP at $index" }
            cursor++
            val (writtenIndex, afterIndex) = readInt(instructions, cursor)
            assertEquals(index, writtenIndex, "emitted byte-array index order must be exact")
            val (writtenValue, afterValue) = readInt(instructions, afterIndex)
            bytes[index] = writtenValue.toByte()
            require(instructions[afterValue].opcode == Opcodes.BASTORE) { "missing byte-array store at $index" }
            cursor = afterValue + 1
        }
        return bytes to cursor
    }

    private fun readInt(
        instructions: Array<AbstractInsnNode>,
        index: Int,
    ): Pair<Int, Int> {
        val instruction = instructions[index]
        val value = when (instruction) {
            is IntInsnNode -> instruction.operand
            is LdcInsnNode -> instruction.cst as? Int ?: error("non-int LDC in native chunk call")
            else -> when (instruction.opcode) {
                Opcodes.ICONST_M1 -> -1
                Opcodes.ICONST_0 -> 0
                Opcodes.ICONST_1 -> 1
                Opcodes.ICONST_2 -> 2
                Opcodes.ICONST_3 -> 3
                Opcodes.ICONST_4 -> 4
                Opcodes.ICONST_5 -> 5
                else -> error("unsupported integer instruction ${instruction.opcode}")
            }
        }
        return value to index + 1
    }

    private data class NativeChunkCallInputs(
        val handle: ByteArray,
        val pageIndex: Int,
        val proof: ByteArray,
    )
}
