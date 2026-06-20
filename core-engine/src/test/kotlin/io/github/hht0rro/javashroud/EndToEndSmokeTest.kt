package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.analysis.attachAnalysisSummary
import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.modules.buildModuleRegistry
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class EndToEndSmokeTest {

    @Test
    fun all_registered_modules_can_be_applied_to_test_artifact() {
        val registry = buildModuleRegistry()
        val artifact = buildTestArtifactWithStrings("Hello", "World")
        val emptyMatches = emptyList<RuleMatch>()

        // Every registered module should be callable without throwing
        val context = defaultVbc4BuildContext()
        for ((id, module) in registry) {
            val result = withVbc4BuildContext(context) {
                module.transform.apply(artifact, emptyMatches, emptyMap())
            }
            assertTrue(result.transformedClassCount >= 0, "Module $id should return non-negative classCount")
            assertTrue(result.transformedMemberCount >= 0, "Module $id should return non-negative memberCount")
        }
    }

    @Test
    fun string_encryption_transform_modifies_bytecode() {
        val artifact = buildTestArtifactWithStrings("SecretMessage")
        val registry = buildModuleRegistry()
        val module = registry["string-encryption"]!!

        val result = withVbc4BuildContext(defaultVbc4BuildContext()) {
            module.transform.apply(artifact, emptyList(), emptyMap())
        }

        assertTrue(result.transformedClassCount > 0, "Should transform at least one class")
        val originalBytes = artifact.classArtifacts.single().bytes
        val transformedBytes = result.artifact.classArtifacts.single().bytes
        assertNotEquals(
            originalBytes.contentHashCode(),
            transformedBytes.contentHashCode(),
            "Transformed bytes should differ from original",
        )
    }

    @Test
    fun integer_constant_obfuscation_modifies_bytecode() {
        val artifact = buildTestArtifactWithIntConstants()
        val registry = buildModuleRegistry()
        val module = registry["integer-constant-obfuscation"]!!

        val result = withVbc4BuildContext(defaultVbc4BuildContext()) {
            module.transform.apply(artifact, emptyList(), emptyMap())
        }

        assertTrue(result.transformedClassCount > 0, "Should transform at least one class")
        val originalBytes = artifact.classArtifacts.single().bytes
        val transformedBytes = result.artifact.classArtifacts.single().bytes
        assertNotEquals(
            originalBytes.contentHashCode(),
            transformedBytes.contentHashCode(),
            "Transformed bytes should differ from original",
        )
    }

    @Test
    fun schema_exposes_params_for_configurable_passes() {
        val schema = buildEngineSchemaPayload()
        val moduleIndex = schema.modules.associateBy { it.id }

        val stringModule = moduleIndex["string-encryption"]!!
        val stringParamKeys = stringModule.params.map { it.key }.toSet()
        assertTrue("scope" in stringParamKeys, "string-encryption should expose 'scope' param")
        assertTrue("lengthThreshold" in stringParamKeys, "string-encryption should expose 'lengthThreshold' param")
        assertTrue("seed" in stringParamKeys, "string-encryption should expose 'seed' param")
        assertTrue("algorithm" !in stringParamKeys, "string-encryption must not expose legacy XOR/algorithm selector")

        val controlFlowModule = moduleIndex["control-flow-obfuscation"]!!
        assertTrue(controlFlowModule.params.any { it.key == "density" }, "control-flow-obfuscation should expose 'density' param")
    }

    private fun buildTestArtifactWithStrings(vararg strings: String): BytecodeArtifact {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "TestClass", null, "java/lang/Object", null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "getStrings", "()V", null, null)
        mv.visitCode()
        for (s in strings) {
            mv.visitLdcInsn(s)
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/String", "valueOf", "(Ljava/lang/Object;)Ljava/lang/String;", false)
            mv.visitInsn(Opcodes.POP)
        }
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(1, 0)
        mv.visitEnd()
        cw.visitEnd()

        val classBytes = cw.toByteArray()
        val classArtifact = ClassArtifact(
            entryName = "TestClass.class",
            summary = io.github.hht0rro.javashroud.analysis.analyzeClassBytes(classBytes),
            bytes = classBytes,
        )
        return attachAnalysisSummary(
            config = testConfig(),
            jarEntries = listOf(JarEntryData("TestClass.class", classBytes)),
            classArtifacts = listOf(classArtifact),
            manifestPresent = false,
        )
    }

    private fun buildTestArtifactWithIntConstants(): BytecodeArtifact {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "TestIntClass", null, "java/lang/Object", null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val mv = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "getInts", "()V", null, null)
        mv.visitCode()
        mv.visitIntInsn(Opcodes.BIPUSH, 42)
        mv.visitInsn(Opcodes.POP)
        mv.visitIntInsn(Opcodes.SIPUSH, 1234)
        mv.visitInsn(Opcodes.POP)
        mv.visitLdcInsn(99999)
        mv.visitInsn(Opcodes.POP)
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(1, 0)
        mv.visitEnd()
        cw.visitEnd()

        val classBytes = cw.toByteArray()
        val classArtifact = ClassArtifact(
            entryName = "TestIntClass.class",
            summary = io.github.hht0rro.javashroud.analysis.analyzeClassBytes(classBytes),
            bytes = classBytes,
        )
        return attachAnalysisSummary(
            config = testConfig(),
            jarEntries = listOf(JarEntryData("TestIntClass.class", classBytes)),
            classArtifacts = listOf(classArtifact),
            manifestPresent = false,
        )
    }
}
