package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.MatchedMember
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.analysis.ClassAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.RenamePlan
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.applyMethodVirtualization
import io.github.hht0rro.javashroud.transforms.protection.currentQpBuildContextOrNull
import io.github.hht0rro.javashroud.transforms.protection.defaultQpBuildContext
import io.github.hht0rro.javashroud.transforms.protection.withQpBuildContext
import java.net.URLClassLoader
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode

class MethodVirtualizationConstantPoolPruneTest {
    @Test
    fun virtualization_strips_imports_exclusive_to_replaced_method_bodies() {
        val internalName = "example/CpPruneHost"
        val deadOwner = "example/DeadImportExclusive"
        val liveOwner = "example/LiveImportExclusive"
        val artifact = artifactFor(
            classBytes = hostClassBytes(internalName, deadOwner, liveOwner),
            internalName = internalName,
            methodSummaries = listOf(
                MemberSummary(MemberKind.METHOD, "secret", "(I)I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
                MemberSummary(MemberKind.METHOD, "keep", "(I)I", Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC),
            ),
        )
        assertTrue(utf8Present(artifact.classArtifactIndex.getValue(internalName).bytes, deadOwner))
        assertTrue(utf8Present(artifact.classArtifactIndex.getValue(internalName).bytes, liveOwner))

        val result = virtualize(
            artifact = artifact,
            ruleMatches = explicitMethodRule(internalName, "secret", "(I)I"),
            params = mapOf(
                "maxInstructions" to 100,
                "seed" to 42,
                "strictVirtualization" to true,
                "methodSelection" to "all-compatible",
                "maxBroadVirtualizedMethods" to 0,
            ),
        )

        assertEquals(1, result.transformedMemberCount)
        val transformed = result.artifact.classArtifactIndex.getValue(internalName).bytes
        assertFalse(hasMethod(transformed, "secret", "(I)I"), "Virtualized methods must drop the original JVM signature")
        assertTrue(hasOpaqueVmDispatcher(transformed), "The selected method must become an opaque Object[] native VM dispatcher")
        assertFalse(methodCallsVmDispatcher(transformed, "keep", "(I)I"), "Unselected method must stay on the JVM")
        assertFalse(utf8Present(transformed, deadOwner), "Imports exclusive to the virtualized body must leave the classfile constant pool")
        assertTrue(utf8Present(transformed, liveOwner), "Imports still referenced by leftover JVM methods must remain")

        val node = ClassNode()
        ClassReader(transformed).accept(node, ClassReader.SKIP_FRAMES)
        val keep = node.methods.single { it.name == "keep" && it.desc == "(I)I" }
        assertTrue(
            keep.instructions.toArray().filterIsInstance<MethodInsnNode>().any {
                it.owner == liveOwner && it.name == "touch"
            },
            "Unvirtualized method must still invoke its exclusive helper",
        )

        val outputDir = Files.createTempDirectory("vm-cp-prune-verify")
        try {
            val classFile = outputDir.resolve("$internalName.class")
            Files.createDirectories(classFile.parent)
            Files.write(classFile, transformed)
            URLClassLoader(arrayOf(outputDir.toUri().toURL()), null).use { loader ->
                loader.loadClass(internalName.replace('/', '.'))
            }
        } finally {
            outputDir.toFile().deleteRecursively()
        }
    }

    private fun virtualize(
        artifact: BytecodeArtifact,
        ruleMatches: List<RuleMatch>,
        params: Map<String, Any>,
    ) = if (currentQpBuildContextOrNull() != null) {
        applyMethodVirtualization(artifact = artifact, ruleMatches = ruleMatches, params = params)
    } else {
        withQpBuildContext(defaultQpBuildContext()) {
            applyMethodVirtualization(artifact = artifact, ruleMatches = ruleMatches, params = params)
        }
    }

    private fun hostClassBytes(internalName: String, deadOwner: String, liveOwner: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val secret = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "secret", "(I)I", null, null)
        secret.visitCode()
        secret.visitVarInsn(Opcodes.ILOAD, 0)
        secret.visitMethodInsn(Opcodes.INVOKESTATIC, deadOwner, "touch", "(I)I", false)
        secret.visitInsn(Opcodes.IRETURN)
        secret.visitMaxs(1, 1)
        secret.visitEnd()

        val keep = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "keep", "(I)I", null, null)
        keep.visitCode()
        keep.visitVarInsn(Opcodes.ILOAD, 0)
        keep.visitMethodInsn(Opcodes.INVOKESTATIC, liveOwner, "touch", "(I)I", false)
        keep.visitInsn(Opcodes.IRETURN)
        keep.visitMaxs(1, 1)
        keep.visitEnd()

        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun utf8Present(classBytes: ByteArray, token: String): Boolean =
        String(classBytes, Charsets.ISO_8859_1).contains(token)

    private fun hasMethod(classBytes: ByteArray, methodName: String, descriptor: String): Boolean {
        var found = false
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                desc: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? {
                if (name == methodName && desc == descriptor) found = true
                return null
            }
        }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        return found
    }

    private fun hasOpaqueVmDispatcher(classBytes: ByteArray): Boolean {
        var found = false
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                desc: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? {
                if (desc != "([Ljava/lang/Object;)Ljava/lang/Object;") return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(
                        opcode: Int,
                        owner: String,
                        name: String,
                        methodDescriptor: String,
                        isInterface: Boolean,
                    ) {
                        if (owner.endsWith("QpBridge") && name == "executeQpVmPage") found = true
                    }
                }
            }
        }, 0)
        return found
    }

    private fun methodCallsVmDispatcher(classBytes: ByteArray, methodName: String, descriptor: String): Boolean {
        var found = false
        ClassReader(classBytes).accept(object : org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                desc: String,
                signature: String?,
                exceptions: Array<String>?,
            ): MethodVisitor? {
                if (name != methodName || desc != descriptor) return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitMethodInsn(
                        opcode: Int,
                        owner: String,
                        name: String,
                        methodDescriptor: String,
                        isInterface: Boolean,
                    ) {
                        if (owner.endsWith("QpBridge") && name == "executeQpVmPage") found = true
                    }
                }
            }
        }, 0)
        return found
    }

    private fun explicitMethodRule(internalName: String, name: String, descriptor: String): List<RuleMatch> = listOf(
        RuleMatch(
            rule = RuleSpec(target = "$internalName#$name:$descriptor", action = "method-virtualization"),
            selector = TargetSelector(
                classPattern = internalName,
                memberPattern = name,
                memberDescriptorPattern = descriptor,
            ),
            matchedClassNames = listOf(internalName),
            matchedMembers = listOf(MatchedMember(internalName, MemberKind.METHOD, name, descriptor)),
        ),
    )

    private fun artifactFor(
        classBytes: ByteArray,
        internalName: String,
        methodSummaries: List<MemberSummary>,
    ): BytecodeArtifact {
        val summary = ClassAnalysisSummary(
            internalName = internalName,
            superName = "java/lang/Object",
            interfaceNames = emptyList(),
            accessFlags = Opcodes.ACC_PUBLIC,
            fieldCount = 0,
            methodCount = methodSummaries.size,
            fieldSummaries = emptyList(),
            methodSummaries = methodSummaries,
        )
        val classArtifact = ClassArtifact(
            entryName = "$internalName.class",
            summary = summary,
            bytes = classBytes,
        )
        val ruleMatches = explicitMethodRule(internalName, "secret", "(I)I")
        return BytecodeArtifact(
            jarEntries = listOf(JarEntryData(classArtifact.entryName, classArtifact.bytes)),
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
}
