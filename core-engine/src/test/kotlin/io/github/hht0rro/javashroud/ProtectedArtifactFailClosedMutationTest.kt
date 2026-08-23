package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.analysis.attachAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.applyMethodVirtualization
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.lang.reflect.InvocationTargetException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.MethodInsnNode

class ProtectedArtifactFailClosedMutationTest {
    @Test
    fun `production protection wrapper has one ordered fail closed native terminal`() {
        val helperBytes = checkNotNull(
            javaClass.classLoader.getResourceAsStream("$PROTECTION_HELPER_INTERNAL_NAME.class"),
        ) { "missing production protection helper class" }.use { it.readBytes() }
        val helper = ClassNode()
        ClassReader(helperBytes).accept(helper, ClassReader.SKIP_FRAMES)
        val wrapper = helper.methods.single { method ->
            method.name == DISPATCH_METHOD_NAME && method.desc == DISPATCH_DESCRIPTOR
        }
        val calls = wrapper.instructions.asSequence().filterIsInstance<MethodInsnNode>().toList()
        val requestCheck = calls.indexOfFirst { it.owner == PROTECTION_HELPER_INTERNAL_NAME && it.name == "requireAkenPageRequest" }
        val readinessCheck = calls.indexOfFirst { it.owner == PROTECTION_HELPER_INTERNAL_NAME && it.name == "ensureAkenNativeKernel" }
        val nativeTerminal = calls.indexOfFirst { it.owner == PROTECTION_HELPER_INTERNAL_NAME && it.name == "nativeExecuteAkenVmPage" }

        assertTrue(requestCheck >= 0, "the production wrapper must validate the typed page request")
        assertTrue(readinessCheck > requestCheck, "native readiness must follow request validation")
        assertTrue(nativeTerminal > readinessCheck, "the native VM terminal must follow both fail-closed gates")
        assertEquals(1, calls.count { it.owner == PROTECTION_HELPER_INTERNAL_NAME && it.name == "nativeExecuteAkenVmPage" })
        assertEquals(1, wrapper.tryCatchBlocks.size, "only the UnsatisfiedLinkError translation is permitted around native dispatch")
        assertEquals("java/lang/UnsatisfiedLinkError", wrapper.tryCatchBlocks.single().type)

        val opcodes = wrapper.instructions.asSequence().map { it.opcode }.filter { it >= 0 }.toList()
        assertFalse(
            opcodes.zipWithNext().any { (first, second) -> first == Opcodes.ACONST_NULL && second == Opcodes.ARETURN },
            "the production wrapper must not carry a legal null-return bypass",
        )
        assertTrue(Opcodes.ATHROW in opcodes, "native-linkage failure must terminate by throwing SecurityException")
    }

    @Test
    fun `VM stub and protection wrapper mutations cannot reach suite complete marker`() {
        val protectedClass = virtualizedFixtureClass()
        val helperClass = protectionHelperClass()

        val dispatcher = dispatcherMethod(protectedClass)
        val dispatchCalls = dispatcher.instructions.asSequence()
            .filterIsInstance<MethodInsnNode>()
            .filter { instruction ->
                instruction.opcode == Opcodes.INVOKESTATIC &&
                    instruction.owner == PROTECTION_HELPER_INTERNAL_NAME &&
                    instruction.name == DISPATCH_METHOD_NAME &&
                    instruction.desc == DISPATCH_DESCRIPTOR
            }
            .toList()
        assertEquals(1, dispatchCalls.size, "the production VM stub fixture must have one live typed protection terminal")
        assertTrue(dispatcher.tryCatchBlocks.isEmpty(), "the VM stub must not swallow protection-terminal failures")

        val baseline = runFixture(protectedClass, helperClass)
        assertNull(baseline.failure)
        assertEquals(SUITE_COMPLETE_MARKER, baseline.marker)
        assertEquals(1, baseline.dispatchCount, "the baseline marker must depend on the protection terminal")

        val defaultVmStub = runFixture(
            replaceMethodWithDefault(protectedClass, PROTECTED_METHOD_NAME, PROTECTED_METHOD_DESCRIPTOR, Opcodes.ICONST_0, Opcodes.IRETURN),
            helperClass,
        )
        assertFailClosed<SecurityException>("legal-default VM stub", defaultVmStub)
        assertEquals(0, defaultVmStub.dispatchCount, "a replaced VM stub must not be mistaken for successful native dispatch")

        val deletedVmStub = runFixture(
            removeMethod(protectedClass, PROTECTED_METHOD_NAME, PROTECTED_METHOD_DESCRIPTOR),
            helperClass,
        )
        assertFailClosed<NoSuchMethodError>("deleted VM stub", deletedVmStub)
        assertEquals(0, deletedVmStub.dispatchCount)

        val defaultProtectionWrapper = runFixture(
            protectedClass,
            replaceMethodWithDefault(helperClass, DISPATCH_METHOD_NAME, DISPATCH_DESCRIPTOR, Opcodes.ACONST_NULL, Opcodes.ARETURN),
        )
        assertFailClosed<NullPointerException>("legal-default protection wrapper", defaultProtectionWrapper)
        assertEquals(0, defaultProtectionWrapper.dispatchCount)

        val deletedProtectionWrapper = runFixture(
            protectedClass,
            removeMethod(helperClass, DISPATCH_METHOD_NAME, DISPATCH_DESCRIPTOR),
        )
        assertFailClosed<NoSuchMethodError>("deleted protection wrapper", deletedProtectionWrapper)
        assertEquals(0, deletedProtectionWrapper.dispatchCount)
    }

    private inline fun <reified T : Throwable> assertFailClosed(label: String, observation: RunObservation) {
        assertNull(observation.marker, "$label must not reach $SUITE_COMPLETE_MARKER")
        assertIs<T>(observation.failure, "$label must fail before publishing the suite-complete marker")
    }

    private fun virtualizedFixtureClass(): ByteArray {
        val original = suiteFixtureClass()
        val classArtifact = ClassArtifact(
            entryName = "$FIXTURE_INTERNAL_NAME.class",
            summary = analyzeClassBytes(original),
            bytes = original,
        )
        val ruleMatch = RuleMatch(
            rule = RuleSpec(
                target = "$FIXTURE_INTERNAL_NAME#$PROTECTED_METHOD_NAME:$PROTECTED_METHOD_DESCRIPTOR",
                action = "method-virtualization",
            ),
            selector = TargetSelector(
                classPattern = FIXTURE_INTERNAL_NAME,
                memberPattern = PROTECTED_METHOD_NAME,
                memberDescriptorPattern = PROTECTED_METHOD_DESCRIPTOR,
            ),
            matchedClassNames = listOf(FIXTURE_INTERNAL_NAME),
            matchedMembers = listOf(
                MatchedMember(
                    owner = FIXTURE_INTERNAL_NAME,
                    kind = MemberKind.METHOD,
                    name = PROTECTED_METHOD_NAME,
                    descriptor = PROTECTED_METHOD_DESCRIPTOR,
                ),
            ),
        )
        val context = defaultVbc4BuildContext()
        return try {
            val transformed = withVbc4BuildContext(context) {
                applyMethodVirtualization(
                    artifact = attachAnalysisSummary(
                        config = ObfuscationConfig(
                            inputJarPath = "fixture-input.jar",
                            outputJarPath = "fixture-output.jar",
                            passes = emptyList(),
                            ruleSet = RuleSet(emptyList()),
                        ),
                        jarEntries = listOf(JarEntryData(classArtifact.entryName, classArtifact.bytes)),
                        classArtifacts = listOf(classArtifact),
                        manifestPresent = false,
                    ),
                    ruleMatches = listOf(ruleMatch),
                    params = mapOf(
                        "maxInstructions" to 64,
                        "strictVirtualization" to true,
                        "seed" to 0x5A17,
                    ),
                ).artifact
            }
            transformed.classArtifacts.single { it.summary.internalName == FIXTURE_INTERNAL_NAME }.bytes
        } finally {
            context.wipe()
        }
    }

    private fun dispatcherMethod(bytes: ByteArray) = ClassNode().also { node ->
        ClassReader(bytes).accept(node, ClassReader.SKIP_FRAMES)
    }.methods.single { method -> method.name == PROTECTED_METHOD_NAME && method.desc == PROTECTED_METHOD_DESCRIPTOR }

    private fun runFixture(protectedClass: ByteArray, helperClass: ByteArray): RunObservation {
        val loader = FixtureClassLoader(
            javaClass.classLoader,
            mapOf(
                FIXTURE_BINARY_NAME to protectedClass,
                PROTECTION_HELPER_BINARY_NAME to helperClass,
            ),
        )
        val fixture = loader.loadClass(FIXTURE_BINARY_NAME)
        val failure = try {
            fixture.getDeclaredMethod(SUITE_METHOD_NAME).invoke(null)
            null
        } catch (error: InvocationTargetException) {
            error.targetException
        }
        val marker = fixture.getField(SUITE_MARKER_FIELD).get(null) as String?
        val helper = loader.loadClass(PROTECTION_HELPER_BINARY_NAME)
        val dispatchCount = helper.getField(DISPATCH_COUNT_FIELD).getInt(null)
        return RunObservation(marker, dispatchCount, failure)
    }

    private fun suiteFixtureClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, FIXTURE_INTERNAL_NAME, null, "java/lang/Object", null)
        writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, SUITE_MARKER_FIELD, "Ljava/lang/String;", null, null).visitEnd()

        writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).apply {
            visitCode()
            visitVarInsn(Opcodes.ALOAD, 0)
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC, PROTECTED_METHOD_NAME, PROTECTED_METHOD_DESCRIPTOR, null, null).apply {
            visitCode()
            visitIntInsn(Opcodes.BIPUSH, EXPECTED_VALUE)
            visitInsn(Opcodes.IRETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, SUITE_METHOD_NAME, "()V", null, null).apply {
            val accepted = org.objectweb.asm.Label()
            visitCode()
            visitMethodInsn(Opcodes.INVOKESTATIC, FIXTURE_INTERNAL_NAME, PROTECTED_METHOD_NAME, PROTECTED_METHOD_DESCRIPTOR, false)
            visitIntInsn(Opcodes.BIPUSH, EXPECTED_VALUE)
            visitJumpInsn(Opcodes.IF_ICMPEQ, accepted)
            visitTypeInsn(Opcodes.NEW, "java/lang/SecurityException")
            visitInsn(Opcodes.DUP)
            visitLdcInsn("protected VM result mismatch")
            visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/SecurityException", "<init>", "(Ljava/lang/String;)V", false)
            visitInsn(Opcodes.ATHROW)
            visitLabel(accepted)
            visitLdcInsn(SUITE_COMPLETE_MARKER)
            visitFieldInsn(Opcodes.PUTSTATIC, FIXTURE_INTERNAL_NAME, SUITE_MARKER_FIELD, "Ljava/lang/String;")
            visitInsn(Opcodes.RETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun protectionHelperClass(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_FINAL, PROTECTION_HELPER_INTERNAL_NAME, null, "java/lang/Object", null)
        writer.visitField(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, DISPATCH_COUNT_FIELD, "I", null, null).visitEnd()
        writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, DISPATCH_METHOD_NAME, DISPATCH_DESCRIPTOR, null, null).apply {
            visitCode()
            visitFieldInsn(Opcodes.GETSTATIC, PROTECTION_HELPER_INTERNAL_NAME, DISPATCH_COUNT_FIELD, "I")
            visitInsn(Opcodes.ICONST_1)
            visitInsn(Opcodes.IADD)
            visitFieldInsn(Opcodes.PUTSTATIC, PROTECTION_HELPER_INTERNAL_NAME, DISPATCH_COUNT_FIELD, "I")
            visitIntInsn(Opcodes.BIPUSH, EXPECTED_VALUE)
            visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false)
            visitInsn(Opcodes.ARETURN)
            visitMaxs(0, 0)
            visitEnd()
        }
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun replaceMethodWithDefault(
        bytes: ByteArray,
        methodName: String,
        descriptor: String,
        valueOpcode: Int,
        returnOpcode: Int,
    ): ByteArray {
        val node = ClassNode()
        ClassReader(bytes).accept(node, ClassReader.EXPAND_FRAMES)
        val method = node.methods.single { it.name == methodName && it.desc == descriptor }
        method.instructions.clear()
        method.tryCatchBlocks.clear()
        method.localVariables?.clear()
        method.instructions.add(InsnNode(valueOpcode))
        method.instructions.add(InsnNode(returnOpcode))
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        node.accept(writer)
        return writer.toByteArray()
    }

    private fun removeMethod(bytes: ByteArray, methodName: String, descriptor: String): ByteArray {
        val node = ClassNode()
        ClassReader(bytes).accept(node, ClassReader.EXPAND_FRAMES)
        assertTrue(node.methods.removeIf { it.name == methodName && it.desc == descriptor })
        assertFalse(node.methods.any { it.name == methodName && it.desc == descriptor })
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        node.accept(writer)
        return writer.toByteArray()
    }

    private data class RunObservation(
        val marker: String?,
        val dispatchCount: Int,
        val failure: Throwable?,
    )

    private class FixtureClassLoader(
        parent: ClassLoader,
        private val definitions: Map<String, ByteArray>,
    ) : ClassLoader(parent) {
        override fun loadClass(name: String, resolve: Boolean): Class<*> = synchronized(getClassLoadingLock(name)) {
            var loaded = findLoadedClass(name)
            if (loaded == null) {
                loaded = definitions[name]?.let { bytes -> defineClass(name, bytes, 0, bytes.size) } ?: super.loadClass(name, false)
            }
            if (resolve) resolveClass(loaded)
            loaded
        }
    }

    private companion object {
        const val FIXTURE_INTERNAL_NAME = "attack/ProtectedMutationFixture"
        const val FIXTURE_BINARY_NAME = "attack.ProtectedMutationFixture"
        const val PROTECTION_HELPER_INTERNAL_NAME = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        const val PROTECTION_HELPER_BINARY_NAME = "io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper"
        const val PROTECTED_METHOD_NAME = "protectedValue"
        const val PROTECTED_METHOD_DESCRIPTOR = "()I"
        const val SUITE_METHOD_NAME = "runSuite"
        const val SUITE_MARKER_FIELD = "SUITE_MARKER"
        const val SUITE_COMPLETE_MARKER = "SUITE_COMPLETE"
        const val DISPATCH_METHOD_NAME = "executeAkenVmPage"
        const val DISPATCH_DESCRIPTOR = "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;"
        const val DISPATCH_COUNT_FIELD = "dispatchCount"
        const val EXPECTED_VALUE = 73
    }
}
