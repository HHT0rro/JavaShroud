package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.DefenseKernelRuntimeHelper
import io.github.hht0rro.javashroud.transforms.protection.applyOsAntiDebug
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.MethodInsnNode

class DefenseProtectedPathBindingTest {
    @Test
    fun authorize_protected_data_is_noop_before_initialize() {
        DefenseKernelRuntimeHelper.authorizeProtectedData()
    }

    @Test
    fun anti_debug_injection_arms_data_path_even_if_method_probes_are_stripped() {
        val original = hostClass()
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = HOST, bytes = original)),
        )
        val transformed = applyOsAntiDebug(artifact, emptyList(), emptyMap()).artifact
        val bytes = transformed.classArtifacts.single { it.summary.internalName == HOST }.bytes
        val node = classNode(bytes)
        val clinit = node.methods.single { it.name == "<clinit>" }
        val clinitCalls = methodCalls(clinit)
        assertTrue(clinitCalls.any { it.name == "expectDefenseForProtectedPath" })
        assertTrue(clinitCalls.any { it.name == "initialize" })

        val run = node.methods.single { it.name == "run" }
        assertTrue(methodCalls(run).any { it.name == "probe" })
        assertFalse(
            methodCalls(node.methods.single { it.name == "lambda\$run\$0" }).any { it.name == "probe" },
            "synthetic worker callbacks must not pay distributed defense-probe startup cost",
        )

        val stripped = stripProbes(bytes)
        val strippedNode = classNode(stripped)
        assertFalse(methodCalls(strippedNode.methods.single { it.name == "run" }).any { it.name == "probe" })
        assertTrue(
            methodCalls(strippedNode.methods.single { it.name == "<clinit>" }).any { it.name == "expectDefenseForProtectedPath" },
            "deleting method probes must not disarm the protected-data gate",
        )

        val helper = classNode(
            checkNotNull(javaClass.classLoader.getResourceAsStream("$JNI_HELPER.class")).use { it.readBytes() },
        )
        val requireDefense = helper.methods.single { it.name == "requireDefenseForProtectedPath" }
        assertTrue(
            methodCalls(requireDefense).any { it.owner == DEFENSE_HELPER && it.name == "authorizeProtectedData" },
            "page open must re-run armed probes before releasing protected data",
        )
    }

    private fun hostClass(): ByteArray {
        val writer = ClassWriter(0)
        writer.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, HOST, null, "java/lang/Object", null)
        val mv = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "run", "()I", null, null)
        mv.visitCode()
        mv.visitInsn(Opcodes.ICONST_1)
        mv.visitInsn(Opcodes.IRETURN)
        mv.visitMaxs(1, 0)
        mv.visitEnd()
        val synthetic = writer.visitMethod(Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC, "lambda\$run\$0", "()V", null, null)
        synthetic.visitCode()
        synthetic.visitInsn(Opcodes.RETURN)
        synthetic.visitMaxs(0, 0)
        synthetic.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }

    private fun stripProbes(bytes: ByteArray): ByteArray {
        val node = classNode(bytes)
        node.methods.orEmpty().forEach { method ->
            if (method.name == "<clinit>") return@forEach
            val insns = method.instructions ?: return@forEach
            insns.toArray().filterIsInstance<MethodInsnNode>().filter { it.name == "probe" }.forEach { call ->
                val previous = generateSequence(call.previous) { it.previous }.take(2).toList()
                previous.forEach(insns::remove)
                insns.remove(call)
            }
        }
        val writer = ClassWriter(0)
        node.accept(writer)
        return writer.toByteArray()
    }

    private fun classNode(bytes: ByteArray): ClassNode = ClassNode().also { node ->
        ClassReader(bytes).accept(node, 0)
    }

    private fun methodCalls(method: org.objectweb.asm.tree.MethodNode): List<MethodInsnNode> =
        method.instructions?.toArray()?.filterIsInstance<MethodInsnNode>().orEmpty()

    private companion object {
        const val HOST = "sample/DefenseHost"
        const val JNI_HELPER = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        const val DEFENSE_HELPER = "io/github/hht0rro/javashroud/transforms/protection/DefenseKernelRuntimeHelper"
    }
}
