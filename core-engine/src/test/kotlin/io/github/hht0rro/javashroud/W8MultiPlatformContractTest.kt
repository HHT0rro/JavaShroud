package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.capabilities.buildEngineSchemaPayload
import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper
import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.applyJniMicrokernelLoader
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.LdcInsnNode
import org.objectweb.asm.tree.MethodInsnNode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class W8MultiPlatformContractTest {
    @Test
    fun target_platform_schema_accepts_auto_all_and_comma_lists() {
        val module = buildEngineSchemaPayload().modules.single { it.id == "jni-microkernel-loader" }
        val targetPlatform = module.params.single { it.key == "targetPlatform" }

        assertEquals("string", targetPlatform.type)
        assertEquals("auto", targetPlatform.defaultValue?.asText())
        assertNull(targetPlatform.options)
        assertTrue(targetPlatform.description.contains("all"))
        assertTrue(targetPlatform.description.contains("windows-x64,linux-x64"))
    }

    @Test
    fun compile_target_parser_supports_all_and_normalized_comma_lists() {
        assertEquals(
            NativeRecompilationTransforms.ZIG_TARGETS.keys.toList(),
            EmbeddedHelperDeployment.resolveNativeCompileTargetPlatforms("all"),
        )
        assertEquals(
            listOf("windows-x64", "linux-x64"),
            EmbeddedHelperDeployment.resolveNativeCompileTargetPlatforms(" windows-x64, linux-x64,windows-x64 "),
        )
        assertFailsWith<IllegalArgumentException> {
            EmbeddedHelperDeployment.resolveNativeCompileTargetPlatforms("windows-x64,unsupported-platform")
        }
    }

    @Test
    fun explicit_compile_targets_require_one_result_per_requested_platform() {
        val windows = recompiledNative("windows-x64", "js_kernel_windows-x64.dll")
        val linux = recompiledNative("linux-x64", "js_kernel_linux-x64.so")

        assertEquals(
            listOf(windows, linux),
            EmbeddedHelperDeployment.requireCompleteNativeCompileTargets(
                requestedPlatforms = listOf("windows-x64", "linux-x64"),
                results = listOf(linux, windows),
            ),
        )
        val missing = assertFailsWith<IllegalStateException> {
            EmbeddedHelperDeployment.requireCompleteNativeCompileTargets(
                requestedPlatforms = listOf("windows-x64", "linux-x64"),
                results = listOf(windows),
            )
        }
        assertTrue(missing.message.orEmpty().contains("missing=linux-x64"))
    }

    @Test
    fun multi_target_and_all_builds_preserve_the_requested_runtime_set() {
        assertEquals("all", injectedRuntimeTarget("all"))
        assertEquals("windows-x64,linux-x64", injectedRuntimeTarget("windows-x64,linux-x64"))
        assertEquals("linux-x64", injectedRuntimeTarget("linux-x64"))
    }

    @Test
    fun runtime_selector_accepts_current_member_and_rejects_unrequested_platform() {
        val selector = JniMicrokernelHelper::class.java.getDeclaredMethod(
            "targetPlatformAllowsCurrent",
            String::class.java,
            String::class.java,
        ).apply { isAccessible = true }

        assertTrue(selector.invoke(null, "auto", "linux-x64") as Boolean)
        assertTrue(selector.invoke(null, "all", "linux-x64") as Boolean)
        assertTrue(selector.invoke(null, "windows-x64, linux-x64", "linux-x64") as Boolean)
        assertFalse(selector.invoke(null, "windows-x64", "linux-x64") as Boolean)
    }

    private fun injectedRuntimeTarget(configuredTarget: String): String {
        val internalName = "sample/W8Host"
        val original = hostClass(internalName)
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = internalName, bytes = original)),
        )
        val result = applyJniMicrokernelLoader(
            artifact = artifact,
            ruleMatches = listOf(
                RuleMatch(
                    rule = RuleSpec(target = internalName, action = "jni-microkernel-loader"),
                    selector = TargetSelector(internalName, null, null),
                    matchedClassNames = listOf(internalName),
                    matchedMembers = emptyList(),
                ),
            ),
            params = mapOf(
                "kernelComponents" to "loader",
                "targetPlatform" to configuredTarget,
                "diversifiedVirtualization" to false,
            ),
        )
        val node = ClassNode()
        ClassReader(result.artifact.classArtifactIndex.getValue(internalName).bytes).accept(node, ClassReader.SKIP_FRAMES)
        val clinit = node.methods.single { it.name == "<clinit>" }
        val instructions = clinit.instructions.toArray()
        val callIndex = instructions.indexOfFirst { instruction ->
            instruction is MethodInsnNode && instruction.owner.endsWith("/JniMicrokernelHelper") && instruction.name == "loadKernel"
        }
        assertTrue(callIndex >= 3, "JNI loader call must have three string arguments")
        return (instructions[callIndex - 2] as LdcInsnNode).cst as String
    }

    private fun hostClass(internalName: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V11, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val init = writer.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(0, 0)
        init.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun recompiledNative(platform: String, libName: String) =
        NativeRecompilationTransforms.RecompiledNative(platform, libName, byteArrayOf(1))
}
