package io.github.hht0rro.javashroud.transforms.protection

import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

class AkenVmDispatcherGenerationTest {
    @Test
    fun page_zero_dispatcher_uses_the_typed_aken_bridge_and_obfuscated_byte_arrays() {
        val classBytes = generatedAkenDispatcher()
        assertNotNull(DefiningClassLoader(javaClass.classLoader).define(classBytes))

        var typedAkenInvocation = false
        var legacyVmInvocation = false
        var byteArrayAllocations = 0
        var iconstZeroCount = 0
        ClassReader(classBytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<out String>?,
            ): MethodVisitor? {
                if (name != "invoke" || descriptor != "(I)I") return null
                return object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitInsn(opcode: Int) {
                        if (opcode == Opcodes.ICONST_0) iconstZeroCount++
                    }

                    override fun visitIntInsn(opcode: Int, operand: Int) {
                        if (opcode == Opcodes.NEWARRAY && operand == Opcodes.T_BYTE) byteArrayAllocations++
                    }

                    override fun visitMethodInsn(
                        opcode: Int,
                        owner: String,
                        methodName: String,
                        methodDescriptor: String,
                        isInterface: Boolean,
                    ) {
                        if (opcode != Opcodes.INVOKESTATIC || !owner.endsWith("JniMicrokernelHelper")) return
                        if (
                            methodName == "executeAkenVmPage" &&
                            methodDescriptor == "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;"
                        ) {
                            typedAkenInvocation = true
                        }
                        if (methodName.startsWith("executeVmResource")) legacyVmInvocation = true
                    }
                }
            }
        }, ClassReader.EXPAND_FRAMES)

        assertTrue(typedAkenInvocation, "expected the page-zero dispatcher to call executeAkenVmPage")
        assertFalse(legacyVmInvocation, "AKEN page-zero dispatcher must not use a legacy VM resource bridge")
        assertTrue(byteArrayAllocations >= 2, "expected independent byte-array construction for handle and proof")
        assertTrue(iconstZeroCount >= 1, "expected an explicit page-zero argument")
    }

    private fun generatedAkenDispatcher(): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        writer.visit(
            Opcodes.V17,
            Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER,
            "fixture/AkenVmDispatcher",
            null,
            "java/lang/Object",
            null,
        )
        val method = writer.visitMethod(
            Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            "invoke",
            "(I)I",
            null,
            null,
        )
        generateVmDispatcher(
            mv = method,
            className = "fixture/AkenVmDispatcher",
            methodName = "invoke",
            descriptor = "(I)I",
            access = Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC,
            opcodeMapping = emptyMap(),
            handlerOrder = emptyList(),
            dispatchLayout = "fixture-layout",
            random = SecureRandom(),
            resourcePath = "META-INF/ignored.vm",
            entryToken = 0x1020_3040_5060_7080L,
            dispatchMethod = "executeAkenVmPage",
            dispatchDescriptor = "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;",
            akenEncodedHandle = ByteArray(24) { index -> (index * 17 + 3).toByte() },
            akenCallSiteProof = ByteArray(32) { index -> (index * 29 + 7).toByte() },
        )
        writer.visitEnd()
        return writer.toByteArray()
    }

    private class DefiningClassLoader(parent: ClassLoader) : ClassLoader(parent) {
        fun define(bytes: ByteArray): Class<*> = defineClass(null, bytes, 0, bytes.size)
    }
}
