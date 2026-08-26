package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.encryptClassStrings
import io.github.hht0rro.javashroud.bytecode.poolClassStrings
import io.github.hht0rro.javashroud.bytecode.StringEncryptionConfig
import io.github.hht0rro.javashroud.model.schema.requiredPassIdsFor
import io.github.hht0rro.javashroud.modules.buildModuleRegistry
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class StringEncryptionSmokeTest {

    @Test
    fun encryptClassStrings_replaces_ldc_strings_with_native_aken_callsite() {
        val classBytes = buildTestClassWithStrings("Hello", "World")
        val context = defaultVbc4BuildContext()
        try {
            val encrypted = withVbc4BuildContext(context) {
                encryptClassStrings(classBytes).also {
                    requireVbc4BuildContext().withAkenStringPageCandidatesForBuild { candidates ->
                        assertEquals(2, candidates.size, "Each protected literal must register one StringPage candidate")
                        val identities = candidates.map { it.copyLogicalIdentityForBuild() }
                        val plaintexts = candidates.map { it.copyPlaintextForBuild() }
                        val handles = candidates.map { it.copyEncodedHandleForBuild() }
                        val proofs = candidates.map { it.copyCallSiteProofForBuild() }
                        try {
                            assertTrue(candidates.all { it.pageIndex > 0 })
                            assertTrue(identities.all { it.size == 32 })
                            assertFalse(identities[0].contentEquals(identities[1]), "StringPage identities must be page-local")
                            assertTrue(handles.all { it.size == 24 })
                            assertFalse(handles[0].contentEquals(handles[1]), "StringPage handles must be page-local")
                            assertTrue(proofs.all { it.size == 32 })
                            assertFalse(proofs[0].contentEquals(proofs[1]), "StringPage call-site proofs must be page-local")
                            assertEquals(setOf("Hello", "World"), plaintexts.map { plaintext -> plaintext.decodeToString() }.toSet())
                            assertEquals(2, candidates.map { candidate -> candidate.logicalBindingPath }.distinct().size)
                        } finally {
                            identities.forEach { identity -> Arrays.fill(identity, 0) }
                            plaintexts.forEach { plaintext -> Arrays.fill(plaintext, 0) }
                            handles.forEach { handle -> Arrays.fill(handle, 0) }
                            proofs.forEach { proof -> Arrays.fill(proof, 0) }
                        }
                    }
                }
            }

            assertTrue(classBytes.isNotEmpty())
            assertTrue(encrypted.contentEquals(classBytes).not(), "Expected encrypted bytes to differ from original")

            val encryptedText = String(encrypted, Charsets.ISO_8859_1)
            assertFalse(encryptedText.contains("a_dx"), "Legacy decrypt method names must not be injected")
            assertFalse(encryptedText.contains("AES/ECB"), "Legacy AES stub must not be injected")
            assertFalse(encryptedText.contains("PKCS8EncodedKeySpec"), "Legacy RSA private-key stub must not be injected")

            val reader = ClassReader(encrypted)
            var foundSyntheticStringArray = false
            var akenHelperInvokeCount = 0
            var akenHelperInvokeDynamicCount = 0
            val bootstrapNames = setOf("q0", "m7", "x3", "v8")
            var foundLegacyHelperInvoke = false
            var foundOriginalLiteral = false
            reader.accept(object : ClassVisitor(Opcodes.ASM9) {
                override fun visitField(access: Int, name: String, descriptor: String, signature: String?, value: Any?): org.objectweb.asm.FieldVisitor? {
                    if ((access and Opcodes.ACC_SYNTHETIC) != 0 && descriptor == "[Ljava/lang/String;") {
                        foundSyntheticStringArray = true
                    }
                    return super.visitField(access, name, descriptor, signature, value)
                }

                override fun visitMethod(access: Int, name: String, descriptor: String, signature: String?, exceptions: Array<out String>?): MethodVisitor {
                    return object : MethodVisitor(Opcodes.ASM9) {
                        override fun visitLdcInsn(value: Any?) {
                            if (value == "Hello" || value == "World") foundOriginalLiteral = true
                        }

                        override fun visitMethodInsn(opcode: Int, owner: String, name: String, descriptor: String, isInterface: Boolean) {
                            if (opcode != Opcodes.INVOKESTATIC || owner != "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper") return
                            if (name == "invokeAkenStringTerminal" && descriptor == "([B)Ljava/lang/String;") {
                                akenHelperInvokeCount++
                            }
                            if (name == "cachedDecodeString" || descriptor == "([BIIJJ)Ljava/lang/String;") {
                                foundLegacyHelperInvoke = true
                            }
                        }

                        override fun visitInvokeDynamicInsn(
                            name: String,
                            descriptor: String,
                            bootstrapMethodHandle: org.objectweb.asm.Handle,
                            vararg bootstrapMethodArguments: Any,
                        ) {
                            if (
                                descriptor == "([B)Ljava/lang/String;" &&
                                bootstrapMethodHandle.owner == "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper" &&
                                bootstrapMethodHandle.desc ==
                                    "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
                                        "Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;"
                            ) {
                                assertTrue(bootstrapNames.contains(bootstrapMethodHandle.name))
                                assertEquals(1, bootstrapMethodArguments.size)
                                assertTrue(bootstrapMethodArguments[0] is org.objectweb.asm.Handle)
                                val target = bootstrapMethodArguments[0] as org.objectweb.asm.Handle
                                assertEquals("invokeAkenStringTerminal", target.name)
                                assertEquals("([B)Ljava/lang/String;", target.desc)
                                akenHelperInvokeDynamicCount++
                            }
                        }
                    }
                }
            }, 0)
            assertFalse(foundSyntheticStringArray, "String encryption must not add reflection-visible fields to business classes")
            assertEquals(1, akenHelperInvokeCount, "One literal should use the direct typed AKEN StringPage helper")
            assertEquals(1, akenHelperInvokeDynamicCount, "One literal should use the indy typed AKEN StringPage helper")
            assertFalse(foundLegacyHelperInvoke, "Production call sites must not use the legacy inline string payload decoder")
            assertFalse(foundOriginalLiteral, "Original literals should be removed from LDC sites")
        } finally {
            context.wipe()
        }
    }

    @Test
    fun encryptClassStrings_preserves_reflection_member_names_for_member_rename_stage() {
        val context = defaultVbc4BuildContext()
        try {
            val encrypted = withVbc4BuildContext(context) {
                encryptClassStrings(buildReflectiveLookupClassWithExtraLiteral())
            }
            val constants = linkedSetOf<String>()
            val node = org.objectweb.asm.tree.ClassNode()
            ClassReader(encrypted).accept(node, 0)
            node.methods.orEmpty().forEach { method ->
                method.instructions?.forEach { instruction ->
                    val value = (instruction as? org.objectweb.asm.tree.LdcInsnNode)?.cst as? String
                    if (value != null) constants += value
                }
            }
            assertTrue("add" in constants, "Reflection member name must remain an LDC for rename-methods")
            assertFalse("protected-literal" in constants, "Ordinary literals should still be encrypted")
        } finally {
            context.wipe()
        }
    }

    @Test
    fun encryptClassStrings_lazily_hoists_loop_invariant_pages_into_method_locals() {
        val context = defaultVbc4BuildContext()
        try {
            val encrypted = withVbc4BuildContext(context) {
                encryptClassStrings(buildLoopStringClass()).also {
                    requireVbc4BuildContext().withAkenStringPageCandidatesForBuild { candidates ->
                        assertEquals(1, candidates.size)
                    }
                }
            }

            var originalLiteralPresent = false
            var guardedLoadCount = 0
            var localStoreCount = 0
            var terminalCount = 0
            ClassReader(encrypted).accept(object : ClassVisitor(Opcodes.ASM9) {
                override fun visitMethod(
                    access: Int,
                    name: String,
                    descriptor: String,
                    signature: String?,
                    exceptions: Array<out String>?,
                ): MethodVisitor = object : MethodVisitor(Opcodes.ASM9) {
                    override fun visitLdcInsn(value: Any?) {
                        if (value == "loop-value") originalLiteralPresent = true
                    }

                    override fun visitJumpInsn(opcode: Int, label: org.objectweb.asm.Label) {
                        if (opcode == Opcodes.IFNONNULL) guardedLoadCount++
                    }

                    override fun visitVarInsn(opcode: Int, variable: Int) {
                        if (opcode == Opcodes.ASTORE && variable > 0) localStoreCount++
                    }

                    override fun visitMethodInsn(
                        opcode: Int,
                        owner: String,
                        name: String,
                        descriptor: String,
                        isInterface: Boolean,
                    ) {
                        if (
                            opcode == Opcodes.INVOKESTATIC &&
                            owner == "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper" &&
                            name == "invokeAkenStringTerminal"
                        ) {
                            terminalCount++
                        }
                    }

                    override fun visitInvokeDynamicInsn(
                        name: String,
                        descriptor: String,
                        bootstrapMethodHandle: org.objectweb.asm.Handle,
                        vararg bootstrapMethodArguments: Any,
                    ) {
                        if (
                            descriptor == "([BI[B)Ljava/lang/String;" &&
                            bootstrapMethodHandle.owner ==
                                "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper"
                        ) {
                            terminalCount++
                        }
                    }
                }
            }, 0)

            assertFalse(originalLiteralPresent)
            assertEquals(1, terminalCount, "The page terminal remains authenticated and unique")
            assertEquals(1, guardedLoadCount, "The loop page must be decoded lazily once per invocation")
            assertTrue(localStoreCount >= 2, "The local must be initialized and populated after authentication")
        } finally {
            context.wipe()
        }
    }

    @Test
    fun encryptClassStrings_preserves_class_structure() {
        val classBytes = buildTestClassWithStrings("TestString")
        val encrypted = withVbc4BuildContext(defaultVbc4BuildContext()) {
            encryptClassStrings(classBytes)
        }

        val reader = ClassReader(encrypted)
        var className = ""
        reader.accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visit(version: Int, access: Int, name: String, signature: String?, superName: String?, interfaces: Array<out String>?) {
                className = name
                super.visit(version, access, name, signature, superName, interfaces)
            }
        }, 0)
        assertTrue(className.isNotEmpty(), "Class name should be preserved")
    }

    @Test
    fun string_array_pool_does_not_rewrite_classes_with_typed_aken_string_pages() {
        val context = defaultVbc4BuildContext()
        try {
            val encrypted = withVbc4BuildContext(context) {
                encryptClassStrings(
                    buildTestClassWithStrings("protected-value", "x"),
                    StringEncryptionConfig(lengthThreshold = 3),
                )
            }

            val pooled = poolClassStrings(encrypted)
            assertTrue(
                pooled.contentEquals(encrypted),
                "String array pooling must leave a class with a typed AKEN page callsite unchanged.",
            )
        } finally {
            context.wipe()
        }
    }

    @Test
    fun string_encryption_pass_is_registered_in_module_registry() {
        val registry = buildModuleRegistry()
        assertTrue(registry.containsKey("string-encryption"), "string-encryption should be in module registry")
        val module = registry["string-encryption"]!!
        assertTrue(module.definition.tagIds.contains("encryption"), "Should have encryption tag")
        assertTrue(
            module.definition.requiredPassIdsFor(emptyMap()).contains("jni-microkernel-loader"),
            "Should require JNI microkernel loader for the default native-kernel decoder backend",
        )
    }

    private fun buildReflectiveLookupClassWithExtraLiteral(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "ReflectiveLookup", null, "java/lang/Object", null)

        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()

        val lookup = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "lookup", "()Ljava/lang/reflect/Method;", null, null)
        lookup.visitCode()
        lookup.visitLdcInsn(org.objectweb.asm.Type.getObjectType("ReflectiveLookup"))
        lookup.visitLdcInsn("add")
        lookup.visitInsn(Opcodes.ICONST_0)
        lookup.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class")
        lookup.visitMethodInsn(
            Opcodes.INVOKEVIRTUAL,
            "java/lang/Class",
            "getDeclaredMethod",
            "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;",
            false,
        )
        lookup.visitInsn(Opcodes.ARETURN)
        lookup.visitMaxs(3, 0)
        lookup.visitEnd()

        val literal = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "literal", "()V", null, null)
        literal.visitCode()
        literal.visitLdcInsn("protected-literal")
        literal.visitInsn(Opcodes.POP)
        literal.visitInsn(Opcodes.RETURN)
        literal.visitMaxs(1, 0)
        literal.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildLoopStringClass(): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_FRAMES or ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "LoopStringClass", null, "java/lang/Object", null)

        val method = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "runLoop", "()V", null, null)
        val loop = org.objectweb.asm.Label()
        val done = org.objectweb.asm.Label()
        method.visitCode()
        method.visitInsn(Opcodes.ICONST_0)
        method.visitVarInsn(Opcodes.ISTORE, 0)
        method.visitLabel(loop)
        method.visitVarInsn(Opcodes.ILOAD, 0)
        method.visitInsn(Opcodes.ICONST_3)
        method.visitJumpInsn(Opcodes.IF_ICMPGE, done)
        method.visitLdcInsn("loop-value")
        method.visitInsn(Opcodes.POP)
        method.visitIincInsn(0, 1)
        method.visitJumpInsn(Opcodes.GOTO, loop)
        method.visitLabel(done)
        method.visitInsn(Opcodes.RETURN)
        method.visitMaxs(0, 0)
        method.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun buildTestClassWithStrings(vararg strings: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, "TestStringClass", null, "java/lang/Object", null)

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
            mv.visitInsn(Opcodes.POP)
        }
        mv.visitInsn(Opcodes.RETURN)
        mv.visitMaxs(1, 0)
        mv.visitEnd()

        cw.visitEnd()
        return cw.toByteArray()
    }
}
