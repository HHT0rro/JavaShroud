package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.analysis.JarReadEntry
import io.github.hht0rro.javashroud.analysis.JarReadResult
import io.github.hht0rro.javashroud.analysis.buildLoadedBytecodeArtifact
import io.github.hht0rro.javashroud.annotations.JAVA_SHROUD_OPTION_DESCRIPTOR
import io.github.hht0rro.javashroud.annotations.JAVA_SHROUD_PASS_DESCRIPTOR
import io.github.hht0rro.javashroud.annotations.applyAnnotationDirectives
import io.github.hht0rro.javashroud.annotations.collectAnnotationDirectives
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.objectweb.asm.AnnotationVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

class AnnotationDirectiveSupportTest {
    @Test
    fun annotation_passes_are_rejected_until_explicitly_allowed() {
        val inputJar = Files.createTempFile("javashroud-annotation", ".jar")
        val config = testConfig(
            inputJarPath = inputJar.toString(),
            passes = listOf(testPassSpec(id = "strip-compile-debug-info", enabled = false)),
            allowAnnotationPasses = false,
        )

        val error = assertFailsWith<IllegalArgumentException> {
            buildLoadedBytecodeArtifact(config, inputJar, jarReadResult(annotatedClassBytes(classPass = "strip-compile-debug-info")))
        }

        assertTrue(error.message.orEmpty().contains("allowAnnotationPasses is false"))
        Files.deleteIfExists(inputJar)
    }

    @Test
    fun class_method_and_field_annotations_merge_rules_and_enable_passes() {
        val inputJar = Files.createTempFile("javashroud-annotation", ".jar")
        val config = testConfig(
            inputJarPath = inputJar.toString(),
            passes = listOf(testPassSpec(id = "strip-compile-debug-info", enabled = false)),
            allowAnnotationPasses = true,
            allowOptInPasses = true,
        )

        val artifact = buildLoadedBytecodeArtifact(
            config,
            inputJar,
            jarReadResult(
                annotatedClassBytes(
                    classPass = "strip-compile-debug-info",
                    methodPass = "member-hide",
                    fieldPass = "rename-fields",
                ),
            ),
        )

        assertEquals(
            listOf("member-hide", "rename-fields", "strip-compile-debug-info"),
            artifact.analysisSummary.ruleMatches.map { it.rule.action }.sorted(),
        )
        assertTrue(artifact.analysisSummary.ruleMatches.any { it.rule.target == "sample/Annotated" })
        assertTrue(artifact.analysisSummary.ruleMatches.any { it.rule.target == "sample/Annotated#marked:()V" })
        assertTrue(artifact.analysisSummary.ruleMatches.any { it.rule.target == "sample/Annotated#secret:Ljava/lang/String;" })
        assertTrue(artifact.analysisSummary.ruleMatches.any { it.matchedMembers.any { member -> member.name == "marked" } })
        assertTrue(artifact.analysisSummary.ruleMatches.any { it.matchedMembers.any { member -> member.name == "secret" } })
        assertTrue(artifact.analysisSummary.classSummaries.single().internalName == "sample/Annotated")
        Files.deleteIfExists(inputJar)
    }

    @Test
    fun annotation_options_merge_into_annotation_enabled_pass() {
        val config = testConfig(
            passes = listOf(testPassSpec(id = "strip-compile-debug-info", enabled = true)),
            allowAnnotationPasses = true,
            allowOptInPasses = true,
        )

        val effective = applyAnnotationDirectives(
            config,
            collectAnnotationDirectives(
                annotatedClassBytes(
                    classPass = "string-encryption",
                    classOptions = mapOf("scope" to "annotated", "lengthThreshold" to "8"),
                ),
            ),
        )

        val pass = effective.passes.single { it.id == "string-encryption" }
        assertEquals("annotated", pass.params["scope"]?.asText())
        assertEquals(8, pass.params["lengthThreshold"]?.asInt())
    }

    @Test
    fun explicit_config_params_override_annotation_options() {
        val config = testConfig(
            passes = listOf(
                testPassSpec(
                    id = "string-encryption",
                    enabled = true,
                    params = mapOf("scope" to JsonNodeFactory.instance.textNode("all-strings")),
                ),
            ),
            allowAnnotationPasses = true,
            allowOptInPasses = true,
        )

        val effective = applyAnnotationDirectives(
            config,
            collectAnnotationDirectives(annotatedClassBytes(classPass = "string-encryption", classOptions = mapOf("scope" to "annotated"))),
        )

        assertEquals("all-strings", effective.passes.single().params["scope"]?.asText())
    }

    @Test
    fun invalid_pass_option_and_enum_values_are_rejected() {
        val inputJar = Files.createTempFile("javashroud-annotation", ".jar")
        val base = testConfig(
            inputJarPath = inputJar.toString(),
            passes = listOf(testPassSpec(id = "strip-compile-debug-info", enabled = true)),
            allowAnnotationPasses = true,
            allowOptInPasses = true,
        )

        assertTrue(assertFailsWith<IllegalArgumentException> {
            buildLoadedBytecodeArtifact(base, inputJar, jarReadResult(annotatedClassBytes(classPass = "missing-pass")))
        }.message.orEmpty().contains("unknown JavaShroud annotation pass id"))

        assertTrue(assertFailsWith<IllegalArgumentException> {
            buildLoadedBytecodeArtifact(base, inputJar, jarReadResult(annotatedClassBytes(classPass = "string-encryption", classOptions = mapOf("bad" to "x"))))
        }.message.orEmpty().contains("is not supported by pass"))

        assertTrue(assertFailsWith<IllegalArgumentException> {
            buildLoadedBytecodeArtifact(base, inputJar, jarReadResult(annotatedClassBytes(classPass = "string-encryption", classOptions = mapOf("scope" to "bad"))))
        }.message.orEmpty().contains("unsupported value"))

        Files.deleteIfExists(inputJar)
    }

    private fun jarReadResult(classBytes: ByteArray): JarReadResult = JarReadResult(
        manifestPresent = false,
        entries = listOf(JarReadEntry("sample/Annotated.class", classBytes)),
    )

    private fun annotatedClassBytes(
        classPass: String? = null,
        methodPass: String? = null,
        fieldPass: String? = null,
        classOptions: Map<String, String> = emptyMap(),
    ): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "sample/Annotated", null, "java/lang/Object", null)
        if (classPass != null) addPassAnnotation(cw.visitAnnotation(JAVA_SHROUD_PASS_DESCRIPTOR, false), classPass, classOptions)

        val field = cw.visitField(Opcodes.ACC_PUBLIC, "secret", "Ljava/lang/String;", null, null)
        if (fieldPass != null) addPassAnnotation(field.visitAnnotation(JAVA_SHROUD_PASS_DESCRIPTOR, false), fieldPass)
        field.visitEnd()

        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val method = cw.visitMethod(Opcodes.ACC_PUBLIC, "marked", "()V", null, null)
        if (methodPass != null) addPassAnnotation(method.visitAnnotation(JAVA_SHROUD_PASS_DESCRIPTOR, false), methodPass)
        method.visitCode()
        method.visitInsn(Opcodes.RETURN)
        method.visitMaxs(0, 1)
        method.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun addPassAnnotation(visitor: AnnotationVisitor, passId: String, options: Map<String, String> = emptyMap()) {
        visitor.visit("id", passId)
        visitor.visit("enabled", true)
        val optionArray = visitor.visitArray("options")
        for ((key, value) in options) {
            val option = optionArray.visitAnnotation(null, JAVA_SHROUD_OPTION_DESCRIPTOR)
            option.visit("key", key)
            option.visit("value", value)
            option.visitEnd()
        }
        optionArray.visitEnd()
        visitor.visitEnd()
    }
}