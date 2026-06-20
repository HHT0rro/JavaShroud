package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.applyCondyConstantIndirection
import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.RenamePlan
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.applyAntiDumpConstantPool
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.ConstantDynamic
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CondyVersionCompatibilityTest {
    @Test
    fun condy_indirection_skips_java8_classfiles() {
        val input = java8ClassWithStringConstant()

        val output = applyCondyConstantIndirection(input)

        assertTrue(output.contentEquals(input), "Java 8 classfiles must not receive CONSTANT_Dynamic entries")
        assertFalse(containsConstantDynamic(output), "Output must remain loadable by Java 8 classfile rules")
    }

    @Test
    fun anti_dump_constant_pool_falls_back_for_java8_classfiles() {
        val artifact = artifactFor(java8ClassWithStringConstant(), "example/Java8CondyGuard")
        val ruleMatches = ruleMatchesFor("condy-constant-indirection", "example/Java8CondyGuard")

        val result = applyAntiDumpConstantPool(artifact, ruleMatches, emptyMap())
        val output = result.artifact.classArtifacts.single().bytes

        assertTrue(result.transformedClassCount > 0, "Runtime-builder fallback should still protect strings")
        assertFalse(containsConstantDynamic(output), "Java 8 fallback must not write CONSTANT_Dynamic")
        ClassReader(output)
    }

    private fun java8ClassWithStringConstant(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "example/Java8CondyGuard", null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()Ljava/lang/String;", null, null)
        method.visitCode()
        method.visitLdcInsn("java8-sensitive-value")
        method.visitInsn(Opcodes.ARETURN)
        method.visitMaxs(1, 0)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun artifactFor(classBytes: ByteArray, internalName: String): BytecodeArtifact {
        val summary = ClassAnalysisSummary(
            internalName = internalName,
            superName = "java/lang/Object",
            interfaceNames = emptyList(),
            accessFlags = Opcodes.ACC_PUBLIC,
            fieldCount = 0,
            methodCount = 2,
            fieldSummaries = emptyList(),
            methodSummaries = emptyList(),
        )
        val classArtifact = ClassArtifact(
            entryName = "$internalName.class",
            summary = summary,
            bytes = classBytes,
        )
        val ruleMatches = ruleMatchesFor("condy-constant-indirection", internalName)
        return BytecodeArtifact(
            jarEntries = listOf(JarEntryData(classArtifact.entryName, classBytes)),
            classArtifacts = listOf(classArtifact),
            classArtifactIndex = mapOf(internalName to classArtifact),
            analysisSummary = JarAnalysisSummary(
                classCount = 1,
                resourceCount = 0,
                manifestPresent = false,
                classSummaries = listOf(summary),
                classNameIndex = mapOf(internalName to summary),
                ruleMatches = ruleMatches,
                renamePlan = RenamePlan(emptyList()),
            ),
        )
    }

    private fun ruleMatchesFor(action: String, internalName: String): List<RuleMatch> = listOf(
        RuleMatch(
            rule = RuleSpec(target = internalName, action = action),
            selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
            matchedClassNames = listOf(internalName),
            matchedMembers = emptyList(),
        ),
    )

    private fun containsConstantDynamic(classBytes: ByteArray): Boolean {
        val node = ClassNode()
        ClassReader(classBytes).accept(node, 0)
        return node.methods.any { method ->
            method.instructions?.toArray()?.any { insn ->
                insn is LdcInsnNode && insn.cst is ConstantDynamic
            } == true
        }
    }
}
