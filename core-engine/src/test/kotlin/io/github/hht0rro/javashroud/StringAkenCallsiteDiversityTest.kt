package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.bytecode.StringEncryptionConfig
import io.github.hht0rro.javashroud.bytecode.encryptClassStrings
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.sealedRuntimeHelperInternalName
import io.github.hht0rro.javashroud.transforms.protection.sealedRuntimeHelperMethodName
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Handle
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.IntInsnNode
import org.objectweb.asm.tree.InvokeDynamicInsnNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode

class StringAkenCallsiteDiversityTest {
    @Test
    fun `typed StringPage callsites diversify lengths page indexes stores and terminal form`() {
        val context = defaultVbc4BuildContext()
        val literals = fixtureLiterals()
        try {
            val transformed = withVbc4BuildContext(context) {
                encryptClassStrings(
                    classBytes = fixtureClass(literals),
                    config = StringEncryptionConfig(seed = CALLSITE_SEED),
                )
            }
            val method = classNode(transformed).methods.single { it.name == FIXTURE_METHOD }
            val fills = byteArrayFills(method.instructions.toArray())
            val handles = fills.filter { it.length == HANDLE_LENGTH }
            val proofs = fills.filter { it.length == PROOF_LENGTH }

            assertEquals(LITERAL_COUNT, handles.size, "each literal must build one opaque handle")
            assertEquals(LITERAL_COUNT, proofs.size, "each literal must build one call-site proof")
            assertTrue(
                setOf(PushEncoding.Bipush, PushEncoding.Sipush, PushEncoding.Ldc)
                    .all { expected -> fills.any { it.length in setOf(HANDLE_LENGTH, PROOF_LENGTH) && it.lengthEncoding == expected } },
                "fixed handle/proof lengths must use multiple bytecode encodings",
            )
            assertEquals(
                setOf(StoreOrder.Ascending, StoreOrder.Descending),
                handles.mapTo(linkedSetOf()) { it.storeOrder },
                "opaque handle stores must not retain one fixed order",
            )
            assertEquals(
                setOf(StoreOrder.Ascending, StoreOrder.Descending),
                proofs.mapTo(linkedSetOf()) { it.storeOrder },
                "call-site proof stores must not retain one fixed order",
            )

            val pageIndexInstructions = handles.map { fill ->
                checkNotNull(fill.nextInstruction) { "missing emitted StringPage pageIndex" }
            }
            val pageIndexes = pageIndexInstructions.map { instruction ->
                checkNotNull(instruction.intConstant()) { "StringPage pageIndex is not an integer constant" }
            }
            assertTrue(pageIndexes.all { it in 1..32 }, "typed StringPages must emit bounded non-zero page indexes")
            assertTrue(pageIndexes.toSet().size > 1, "StringPage callsites must not share one fixed pageIndex")
            assertTrue(
                pageIndexInstructions.mapTo(linkedSetOf()) { it.pushEncoding() }.size > 1,
                "pageIndex constants must use more than one bytecode encoding",
            )

            val directCalls = method.instructions.toArray()
                .filterIsInstance<MethodInsnNode>()
                .filter { instruction ->
                    instruction.opcode == Opcodes.INVOKESTATIC &&
                        instruction.owner == STRING_HELPER_OWNER &&
                        instruction.name == STRING_TERMINAL_NAME &&
                        instruction.desc == STRING_TERMINAL_DESCRIPTOR
                }
            val indyCalls = method.instructions.toArray()
                .filterIsInstance<InvokeDynamicInsnNode>()
                .filter { it.desc == STRING_TERMINAL_DESCRIPTOR && it.bsm.owner == STRING_HELPER_OWNER }
            assertEquals(LITERAL_COUNT / 2, directCalls.size, "even callsites must use the direct terminal")
            assertEquals(LITERAL_COUNT / 2, indyCalls.size, "odd callsites must use invokedynamic")

            val bootstrapNames = indyCalls.mapTo(linkedSetOf()) { it.bsm.name }
            assertTrue(bootstrapNames.size > 1, "invokedynamic callsites must select multiple bootstrap aliases")
            assertTrue(bootstrapNames.all { it in STRING_BOOTSTRAP_ALIASES }, "an unknown StringPage bootstrap alias was emitted")
            indyCalls.forEach { callsite ->
                assertEquals(STRING_BOOTSTRAP_DESCRIPTOR, callsite.bsm.desc)
                val target = callsite.bsmArgs.single() as Handle
                assertEquals(STRING_HELPER_OWNER, target.owner)
                assertEquals(STRING_TERMINAL_NAME, target.name)
                assertEquals(STRING_TERMINAL_DESCRIPTOR, target.desc)
            }

            val transformedText = transformed.toString(Charsets.ISO_8859_1)
            assertFalse(
                literals.any(transformedText::contains),
                "the diversity fixture must not leave any protected literal in the transformed class",
            )
        } finally {
            context.wipe()
        }
    }

    @Test
    fun `runtime sealing remaps direct and indy StringPage terminals including bootstrap handles`() {
        val context = defaultVbc4BuildContext()
        try {
            val sealed = withVbc4BuildContext(context) {
                val transformed = encryptClassStrings(
                    classBytes = fixtureClass(fixtureLiterals()),
                    config = StringEncryptionConfig(seed = CALLSITE_SEED),
                )
                val application = classArtifact(FIXTURE_INTERNAL_NAME, transformed)
                val helperBytes = loadClassBytes(STRING_HELPER_RESOURCE)
                val helper = classArtifact(STRING_HELPER_OWNER, helperBytes)
                RuntimeArtifactSealing.seal(
                    artifact = testAttachedArtifact(
                        classArtifacts = listOf(application, helper),
                        jarEntries = listOf(
                            JarEntryData(application.entryName, application.bytes),
                            JarEntryData(helper.entryName, helper.bytes),
                        ),
                    ),
                    seed = SEALING_SEED,
                    rewritesVmRuntime = false,
                    typedOnlyRuntime = true,
                )
            }

            val sealedHelperOwner = sealedRuntimeHelperInternalName(STRING_HELPER_OWNER, SEALING_SEED)
            val sealedTerminalName = sealedRuntimeHelperMethodName(
                STRING_HELPER_OWNER,
                STRING_TERMINAL_NAME,
                STRING_TERMINAL_DESCRIPTOR,
                SEALING_SEED,
            )
            val sealedBootstrapNames = STRING_BOOTSTRAP_ALIASES.associateWith { original ->
                sealedRuntimeHelperMethodName(
                    STRING_HELPER_OWNER,
                    original,
                    STRING_BOOTSTRAP_DESCRIPTOR,
                    SEALING_SEED,
                )
            }

            val applicationNode = classNode(
                sealed.classArtifacts.single { it.summary.internalName == FIXTURE_INTERNAL_NAME }.bytes,
            )
            val method = applicationNode.methods.single { it.name == FIXTURE_METHOD }
            val directCalls = method.instructions.toArray()
                .filterIsInstance<MethodInsnNode>()
                .filter { it.desc == STRING_TERMINAL_DESCRIPTOR }
            val indyCalls = method.instructions.toArray()
                .filterIsInstance<InvokeDynamicInsnNode>()
                .filter { it.desc == STRING_TERMINAL_DESCRIPTOR }

            assertTrue(directCalls.isNotEmpty() && indyCalls.isNotEmpty(), "sealed output must preserve direct/indy diversity")
            directCalls.forEach { callsite ->
                assertEquals(sealedHelperOwner, callsite.owner)
                assertEquals(sealedTerminalName, callsite.name)
            }
            val actualSealedBootstrapNames = linkedSetOf<String>()
            indyCalls.forEach { callsite ->
                assertEquals(sealedHelperOwner, callsite.bsm.owner)
                assertTrue(callsite.bsm.name in sealedBootstrapNames.values)
                actualSealedBootstrapNames += callsite.bsm.name
                val target = callsite.bsmArgs.single() as Handle
                assertEquals(sealedHelperOwner, target.owner)
                assertEquals(sealedTerminalName, target.name)
                assertEquals(STRING_TERMINAL_DESCRIPTOR, target.desc)
            }
            assertTrue(actualSealedBootstrapNames.size > 1, "multiple bootstrap aliases must survive as distinct sealed names")

            val helperNode = classNode(
                sealed.classArtifacts.single { it.summary.internalName == sealedHelperOwner }.bytes,
            )
            assertFalse(
                helperNode.methods.any { methodNode ->
                    methodNode.name == STRING_TERMINAL_NAME || methodNode.name in STRING_BOOTSTRAP_ALIASES
                },
                "unsealed StringPage helper method names must not survive in the relocated helper",
            )
            assertTrue(
                helperNode.methods.any { it.name == sealedTerminalName && it.desc == STRING_TERMINAL_DESCRIPTOR },
                "the relocated helper must retain the sealed String terminal",
            )
            assertTrue(
                sealedBootstrapNames.values.all { sealedName ->
                    helperNode.methods.any { it.name == sealedName && it.desc == STRING_BOOTSTRAP_DESCRIPTOR }
                },
                "every bootstrap alias must be renamed in the relocated helper",
            )
        } finally {
            context.wipe()
        }
    }

    private fun byteArrayFills(instructions: Array<AbstractInsnNode>): List<ByteArrayFill> =
        instructions.asSequence()
            .filterIsInstance<IntInsnNode>()
            .filter { it.opcode == Opcodes.NEWARRAY && it.operand == Opcodes.T_BYTE }
            .map { newArray ->
                val lengthInstruction = checkNotNull(newArray.previousOpcode()) { "byte-array length instruction is missing" }
                val length = checkNotNull(lengthInstruction.intConstant()) { "byte-array length is not constant" }
                val indices = ArrayList<Int>(length)
                var cursor = newArray.nextOpcode()
                repeat(length) {
                    check(cursor?.opcode == Opcodes.DUP) { "byte-array fill is missing DUP" }
                    val indexInstruction = checkNotNull(cursor.nextOpcode()) { "byte-array index is missing" }
                    indices += checkNotNull(indexInstruction.intConstant()) { "byte-array index is not constant" }
                    val valueInstruction = checkNotNull(indexInstruction.nextOpcode()) { "byte-array value is missing" }
                    checkNotNull(valueInstruction.intConstant()) { "byte-array value is not constant" }
                    val storeInstruction = checkNotNull(valueInstruction.nextOpcode()) { "byte-array store is missing" }
                    check(storeInstruction.opcode == Opcodes.BASTORE) { "byte-array fill does not end in BASTORE" }
                    cursor = storeInstruction.nextOpcode()
                }
                ByteArrayFill(
                    length = length,
                    lengthEncoding = lengthInstruction.pushEncoding(),
                    storeOrder = when (indices) {
                        (0 until length).toList() -> StoreOrder.Ascending
                        (length - 1 downTo 0).toList() -> StoreOrder.Descending
                        else -> error("byte-array stores are neither ascending nor descending")
                    },
                    nextInstruction = cursor,
                )
            }
            .toList()

    private fun fixtureLiterals(): List<String> = List(LITERAL_COUNT) { index ->
        buildString {
            append("fixture-")
            append(index.toString(16).padStart(3, '0'))
            append('-')
            append((index * 0x45D9F3B).toUInt().toString(16))
        }
    }

    private fun fixtureClass(literals: List<String>): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, FIXTURE_INTERNAL_NAME, null, "java/lang/Object", null)
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, FIXTURE_METHOD, "()V", null, null).apply {
            visitCode()
            literals.forEach { literal ->
                visitLdcInsn(literal)
                visitInsn(Opcodes.POP)
            }
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun classArtifact(internalName: String, bytes: ByteArray): ClassArtifact = ClassArtifact(
        entryName = "$internalName.class",
        summary = analyzeClassBytes(bytes),
        bytes = bytes,
    )

    private fun classNode(bytes: ByteArray): ClassNode = ClassNode().also { node ->
        ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES)
    }

    private fun loadClassBytes(resource: String): ByteArray = checkNotNull(javaClass.classLoader.getResourceAsStream(resource)) {
        "missing test classpath resource"
    }.use { it.readBytes() }

    private fun AbstractInsnNode?.previousOpcode(): AbstractInsnNode? {
        var current = this?.previous
        while (current != null && current.opcode < 0) current = current.previous
        return current
    }

    private fun AbstractInsnNode?.nextOpcode(): AbstractInsnNode? {
        var current = this?.next
        while (current != null && current.opcode < 0) current = current.next
        return current
    }

    private fun AbstractInsnNode.intConstant(): Int? = when (this) {
        is InsnNode -> when (opcode) {
            Opcodes.ICONST_M1 -> -1
            Opcodes.ICONST_0 -> 0
            Opcodes.ICONST_1 -> 1
            Opcodes.ICONST_2 -> 2
            Opcodes.ICONST_3 -> 3
            Opcodes.ICONST_4 -> 4
            Opcodes.ICONST_5 -> 5
            else -> null
        }
        is IntInsnNode -> if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) operand else null
        is LdcInsnNode -> cst as? Int
        else -> null
    }

    private fun AbstractInsnNode.pushEncoding(): PushEncoding = when (opcode) {
        in Opcodes.ICONST_M1..Opcodes.ICONST_5 -> PushEncoding.Iconst
        Opcodes.BIPUSH -> PushEncoding.Bipush
        Opcodes.SIPUSH -> PushEncoding.Sipush
        Opcodes.LDC -> PushEncoding.Ldc
        else -> error("instruction is not an integer push")
    }

    private data class ByteArrayFill(
        val length: Int,
        val lengthEncoding: PushEncoding,
        val storeOrder: StoreOrder,
        val nextInstruction: AbstractInsnNode?,
    )

    private enum class PushEncoding { Iconst, Bipush, Sipush, Ldc }

    private enum class StoreOrder { Ascending, Descending }

    private companion object {
        const val FIXTURE_INTERNAL_NAME = "fixture/StringAkenDiversity"
        const val FIXTURE_METHOD = "run"
        const val LITERAL_COUNT = 96
        const val HANDLE_LENGTH = 24
        const val PROOF_LENGTH = 32
        const val CALLSITE_SEED = 0x6A53_5250L
        const val SEALING_SEED = 0x4A53_524CL
        const val STRING_HELPER_OWNER = "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper"
        const val STRING_HELPER_RESOURCE = "$STRING_HELPER_OWNER.class"
        const val STRING_TERMINAL_NAME = "invokeAkenStringTerminal"
        const val STRING_TERMINAL_DESCRIPTOR = "([BI[B)Ljava/lang/String;"
        const val STRING_BOOTSTRAP_DESCRIPTOR =
            "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
                "Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;"
        val STRING_BOOTSTRAP_ALIASES = setOf("q0", "m7", "x3", "v8")
    }
}
