package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.encryptClassStrings
import io.github.hht0rro.javashroud.modules.buildModuleRegistry
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class StringEncryptionSmokeTest {

    @Test
    fun encryptClassStrings_replaces_ldc_strings_with_native_cached_callsite() {
        val classBytes = buildTestClassWithStrings("Hello", "World")
        val encrypted = withVbc4BuildContext(defaultVbc4BuildContext()) {
            encryptClassStrings(classBytes)
        }

        assertTrue(classBytes.size > 0)
        assertTrue(encrypted.contentEquals(classBytes).not(), "Expected encrypted bytes to differ from original")

        val encryptedText = String(encrypted, Charsets.ISO_8859_1)
        assertFalse(encryptedText.contains("a_dx"), "Legacy decrypt method names must not be injected")
        assertFalse(encryptedText.contains("AES/ECB"), "Legacy AES stub must not be injected")
        assertFalse(encryptedText.contains("PKCS8EncodedKeySpec"), "Legacy RSA private-key stub must not be injected")

        val reader = ClassReader(encrypted)
        var foundSyntheticStringArray = false
        var foundHelperInvoke = false
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
                        if (opcode == Opcodes.INVOKESTATIC && owner == "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper" && name == "nativeDecodeString") {
                            foundHelperInvoke = true
                        }
                    }
                }
            }
        }, 0)
        assertFalse(foundSyntheticStringArray, "String encryption must not add reflection-visible fields to business classes")
        assertTrue(foundHelperInvoke, "Should invoke StringEncryptionHelper.nativeDecodeString directly")
        assertFalse(foundOriginalLiteral, "Original literals should be removed from LDC sites")
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
    fun string_encryption_pass_is_registered_in_module_registry() {
        val registry = buildModuleRegistry()
        assertTrue(registry.containsKey("string-encryption"), "string-encryption should be in module registry")
        val module = registry["string-encryption"]!!
        assertTrue(module.definition.tagIds.contains("encryption"), "Should have encryption tag")
        assertTrue(module.definition.requiredPassIds.contains("jni-microkernel-loader"), "Should require JNI microkernel loader")
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
