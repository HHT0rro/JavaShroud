package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.*
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Field string encryption transform (fusion from jar-obfuscator).
 *
 * Encrypts static final String field constant values and injects
 * clinit initialization that decrypts them at class load time.
 * Uses Tree API to properly handle classes with existing clinit methods.
 */
fun encryptFieldStrings(classBytes: ByteArray, aesKey: ByteArray? = null): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if ((classNode.access and Opcodes.ACC_INTERFACE) != 0) {
        return classBytes
    }

    val key = aesKey ?: ByteArray(16).also { SecureRandom().nextBytes(it) }
    val encryptedFields = mutableListOf<Triple<FieldNode, String, ByteArray>>() // field, encryptedValue, AES key

    // Find static final String fields with constant values
    for (field in classNode.fields) {
        if (field.value is String &&
            (field.access and Opcodes.ACC_STATIC) != 0 &&
            (field.access and Opcodes.ACC_FINAL) != 0
        ) {
            val encrypted = aesEncryptFieldString(field.value as String, key)
            encryptedFields.add(Triple(field, encrypted, key))
            field.value = null // Remove constant value
        }
    }

    if (encryptedFields.isEmpty()) {
        return classBytes
    }

    // Inject decrypt helper method
    classNode.methods.add(createFieldDecryptHelper())

    // Inject field initialization into clinit
    val existingClinit = classNode.methods.find { it.name == "<clinit>" }
    if (existingClinit != null) {
        // Prepend field decrypt calls to existing clinit
        val initInsns = InsnList()
        for ((field, encrypted, k) in encryptedFields) {
            initInsns.add(LdcInsnNode(encrypted))
            initInsns.add(LdcInsnNode(Base64.getEncoder().encodeToString(k)))
            initInsns.add(MethodInsnNode(
                Opcodes.INVOKESTATIC, classNode.name,
                "a_fd", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false
            ))
            initInsns.add(FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, field.name, field.desc))
        }
        // Find the first real instruction in clinit to insert before
        val firstReal = existingClinit.instructions.firstOrNull { it.opcode != -1 }
        if (firstReal != null) {
            existingClinit.instructions.insertBefore(firstReal, initInsns)
        } else {
            // Empty clinit, insert before RETURN
            existingClinit.instructions.insert(initInsns)
        }
    } else {
        // Create new clinit
        val clinit = MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null)
        val insns = InsnList()
        for ((field, encrypted, k) in encryptedFields) {
            insns.add(LdcInsnNode(encrypted))
            insns.add(LdcInsnNode(Base64.getEncoder().encodeToString(k)))
            insns.add(MethodInsnNode(
                Opcodes.INVOKESTATIC, classNode.name,
                "a_fd", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false
            ))
            insns.add(FieldInsnNode(Opcodes.PUTSTATIC, classNode.name, field.name, field.desc))
        }
        insns.add(InsnNode(Opcodes.RETURN))
        clinit.instructions = insns
        clinit.maxStack = 2
        clinit.maxLocals = 0
        classNode.methods.add(clinit)
    }

    val writer = computeFramesWriter(reader)
    classNode.accept(writer)
    return writer.toByteArray()
}

private fun createFieldDecryptHelper(): MethodNode {
    val method = MethodNode(
        Opcodes.ACC_PRIVATE or Opcodes.ACC_STATIC or Opcodes.ACC_SYNTHETIC,
        "a_fd",
        "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
        null, null,
    )
    method.visitCode()

    val nonNull = org.objectweb.asm.Label()
    method.visitVarInsn(Opcodes.ALOAD, 0)
    method.visitJumpInsn(Opcodes.IFNONNULL, nonNull)
    method.visitInsn(Opcodes.ACONST_NULL)
    method.visitInsn(Opcodes.ARETURN)
    method.visitLabel(nonNull)

    val tryStart = org.objectweb.asm.Label()
    val tryEnd = org.objectweb.asm.Label()
    val catchHandler = org.objectweb.asm.Label()
    method.visitTryCatchBlock(tryStart, tryEnd, catchHandler, "java/lang/Exception")
    method.visitLabel(tryStart)

    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder", "()Ljava/util/Base64${"$"}Decoder;", false)
    method.visitVarInsn(Opcodes.ALOAD, 0)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Base64${"$"}Decoder", "decode", "(Ljava/lang/String;)[B", false)
    method.visitVarInsn(Opcodes.ASTORE, 2)

    method.visitIntInsn(Opcodes.BIPUSH, 16)
    method.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
    method.visitVarInsn(Opcodes.ASTORE, 3)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitIntInsn(Opcodes.BIPUSH, 16)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V", false)

    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitInsn(Opcodes.ARRAYLENGTH)
    method.visitIntInsn(Opcodes.BIPUSH, 16)
    method.visitInsn(Opcodes.ISUB)
    method.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE)
    method.visitVarInsn(Opcodes.ASTORE, 4)
    method.visitVarInsn(Opcodes.ALOAD, 2)
    method.visitIntInsn(Opcodes.BIPUSH, 16)
    method.visitVarInsn(Opcodes.ALOAD, 4)
    method.visitInsn(Opcodes.ICONST_0)
    method.visitVarInsn(Opcodes.ALOAD, 4)
    method.visitInsn(Opcodes.ARRAYLENGTH)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/System", "arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V", false)

    method.visitTypeInsn(Opcodes.NEW, "javax/crypto/spec/SecretKeySpec")
    method.visitInsn(Opcodes.DUP)
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder", "()Ljava/util/Base64${"$"}Decoder;", false)
    method.visitVarInsn(Opcodes.ALOAD, 1)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Base64${"$"}Decoder", "decode", "(Ljava/lang/String;)[B", false)
    method.visitLdcInsn("AES")
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "javax/crypto/spec/SecretKeySpec", "<init>", "([BLjava/lang/String;)V", false)
    method.visitVarInsn(Opcodes.ASTORE, 5)

    method.visitLdcInsn("AES/CBC/PKCS5Padding")
    method.visitMethodInsn(Opcodes.INVOKESTATIC, "javax/crypto/Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", false)
    method.visitVarInsn(Opcodes.ASTORE, 6)
    method.visitVarInsn(Opcodes.ALOAD, 6)
    method.visitInsn(Opcodes.ICONST_2)
    method.visitVarInsn(Opcodes.ALOAD, 5)
    method.visitTypeInsn(Opcodes.NEW, "javax/crypto/spec/IvParameterSpec")
    method.visitInsn(Opcodes.DUP)
    method.visitVarInsn(Opcodes.ALOAD, 3)
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "javax/crypto/spec/IvParameterSpec", "<init>", "([B)V", false)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "javax/crypto/Cipher", "init", "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V", false)

    method.visitTypeInsn(Opcodes.NEW, "java/lang/String")
    method.visitInsn(Opcodes.DUP)
    method.visitVarInsn(Opcodes.ALOAD, 6)
    method.visitVarInsn(Opcodes.ALOAD, 4)
    method.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "javax/crypto/Cipher", "doFinal", "([B)[B", false)
    method.visitLdcInsn("UTF-8")
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([BLjava/lang/String;)V", false)
    method.visitLabel(tryEnd)
    method.visitInsn(Opcodes.ARETURN)

    method.visitLabel(catchHandler)
    method.visitInsn(Opcodes.POP)
    method.visitTypeInsn(Opcodes.NEW, "java/lang/IllegalStateException")
    method.visitInsn(Opcodes.DUP)
    method.visitLdcInsn("Encrypted field string decode failed")
    method.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/IllegalStateException", "<init>", "(Ljava/lang/String;)V", false)
    method.visitInsn(Opcodes.ATHROW)

    method.visitMaxs(7, 7)
    method.visitEnd()
    return method
}

internal fun aesEncryptFieldString(input: String, key: ByteArray): String {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    return Base64.getEncoder().encodeToString(iv + cipher.doFinal(input.toByteArray(Charsets.UTF_8)))
}
