package io.github.hht0rro.javashroud.hardening

import io.github.hht0rro.javashroud.artifact.writeBytecodeArtifact
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.testClassArtifact
import io.github.hht0rro.javashroud.transforms.protection.hardening.HardenedDefaultPipeline
import io.github.hht0rro.javashroud.transforms.protection.hardening.ProtectionFormat
import io.github.hht0rro.javashroud.transforms.protection.hardening.ReverseRegressionPipeline
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

class ReverseRegressionPipelineTest {
    @Test
    fun writes_stage_manifest_with_required_fields() {
        val classBytes = emptyClass("sample/PipelineHost")
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/PipelineHost", bytes = classBytes)),
        )
        val dir = Files.createTempDirectory("js-reverse-pipeline")
        try {
            val inputJar = dir.resolve("in.jar")
            val outputJar = dir.resolve("out.jar")
            writeBytecodeArtifact(inputJar, artifact)
            writeBytecodeArtifact(outputJar, artifact)
            val (manifest, path) = ReverseRegressionPipeline.run(
                outputJarPath = outputJar,
                artifact = artifact,
                profile = HardenedProtectionProfile.RELEASE_HARDENED,
                enabledPasses = HardenedDefaultPipeline.RELEASE_PASSES,
                inputJarPath = inputJar,
                inputJarBytes = Files.size(inputJar),
            )
            assertTrue(Files.exists(path))
            assertEquals(ProtectionFormat.CURRENT, manifest.protocolVersion)
            assertEquals(64, manifest.inputSha256.length)
            assertEquals(64, manifest.outputSha256.length)
            assertEquals(HardenedDefaultPipeline.RELEASE_PASSES, manifest.enabledPasses)
            assertEquals("absent", manifest.targetTriple)
            assertEquals("absent", manifest.nativeSha256)
            assertEquals("absent", manifest.abiDigest)
            assertEquals("absent", manifest.specializationDigest)
            assertTrue(manifest.jdk.isNotBlank())
            assertEquals(ProtectionFormat.CURRENT, manifest.toolVersion)
            assertTrue(manifest.cwd.isNotBlank())
            assertTrue(manifest.envSummary.contains("os="))
            assertTrue(manifest.envSummary.contains("locale="))
            assertEquals(ReverseRegressionPipeline.STAGE_NAMES, manifest.stages.map { it.name })
            assertTrue(manifest.stages.all { it.passed }, manifest.toText())
            assertTrue(manifest.passed)
            val text = Files.readString(path)
            listOf(
                "protocol=",
                "inputSha256=",
                "outputSha256=",
                "enabledPasses=",
                "targetTriple=",
                "nativeSha256=",
                "abiDigest=",
                "specializationDigest=",
                "methodCount=",
                "pageCount=",
                "instructionCount=",
                "constantCount=",
                "jdk=",
                "toolVersion=",
                "cwd=",
                "env=",
                "passed=",
            ).forEach { field ->
                assertTrue(text.contains(field), "missing $field")
            }
            ReverseRegressionPipeline.STAGE_NAMES.forEach { stage ->
                assertTrue(text.contains("[stage $stage]"), "missing stage $stage")
                assertTrue(text.contains("failClosed="), "missing failClosed")
            }
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    @Test
    fun clone_finding_fails_exception_stage() {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, "sample/ExcClone", null, "java/lang/Object", null)
        val original = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "add", "(II)I", null, null)
        original.visitCode()
        original.visitVarInsn(Opcodes.ILOAD, 0)
        original.visitVarInsn(Opcodes.ILOAD, 1)
        original.visitInsn(Opcodes.IADD)
        original.visitInsn(Opcodes.IRETURN)
        original.visitMaxs(2, 2)
        original.visitEnd()
        val clone = writer.visitMethod(
            Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
            "\$jsv\$add\$1",
            "(II)I",
            null,
            null,
        )
        clone.visitCode()
        clone.visitVarInsn(Opcodes.ILOAD, 0)
        clone.visitVarInsn(Opcodes.ILOAD, 1)
        clone.visitInsn(Opcodes.IADD)
        clone.visitInsn(Opcodes.IRETURN)
        clone.visitMaxs(2, 2)
        clone.visitEnd()
        writer.visitEnd()
        val classBytes = writer.toByteArray()
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = "sample/ExcClone", bytes = classBytes)),
        )
        val dir = Files.createTempDirectory("js-reverse-clone")
        try {
            val jar = dir.resolve("out.jar")
            writeBytecodeArtifact(jar, artifact)
            val (manifest, _) = ReverseRegressionPipeline.run(
                outputJarPath = jar,
                artifact = artifact,
                profile = HardenedProtectionProfile.RELEASE_HARDENED,
                enabledPasses = emptyList(),
            )
            val exceptionStage = manifest.stages.single { it.name == "exception-clone-detector" }
            assertTrue(!exceptionStage.passed)
            assertTrue(exceptionStage.failClosed.contains("exception-body-clone"))
            assertTrue(!manifest.passed)
        } finally {
            Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    private fun emptyClass(internalName: String): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null)
        writer.visitEnd()
        return writer.toByteArray()
    }
}
