package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.applyClassEncryptionLoader
import io.github.hht0rro.javashroud.transforms.protection.deriveClassEncryptionKey
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes

/**
 * Phase 0 / REQ-001 gate: the class-encryption artifact must NOT carry any
 * directly reusable symmetric key. The manifest stores only non-secret
 * metadata (strategy:keyId:salt:iv); the real AES key is HKDF-derived from the
 * per-build root key and recomputed at runtime, never persisted.
 */
class KerckhoffsLeakageTest {

    private fun freshContext(): Vbc4BuildContext {
        val random = SecureRandom()
        val master = ByteArray(32).also { random.nextBytes(it) }
        val layout = ByteArray(32).also { random.nextBytes(it) }
        return Vbc4BuildContext(masterKey = master, nativeSeed = 0x5151_2626L, jarLayoutDigest = layout)
    }

    @Test
    fun encrypted_class_manifest_contains_no_reusable_symmetric_key() {
        val internalName = "leak/Target"
        val classBytes = buildSimpleClass(internalName)
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = internalName, bytes = classBytes)),
        )
        val context = freshContext()

        val result = withVbc4BuildContext(context) {
            applyClassEncryptionLoader(
                artifact = artifact,
                ruleMatches = listOf(ruleMatchFor(internalName)),
                params = mapOf("encryptionStrategy" to "aes-256", "keyMode" to "per-class"),
            )
        }

        val manifest = result.artifact.jarEntries.firstOrNull { it.name == "__jse/index.tab" }
        assertNotNull(manifest, "Encryption manifest must be present")
        val resourceEntry = result.artifact.jarEntries.firstOrNull { it.name == "__jse/$internalName.enc" }
        assertNotNull(resourceEntry, "Encrypted class resource must be present")

        val lines = String(manifest.bytes, Charsets.UTF_8).lines().filter { it.isNotBlank() }
        assertEquals(1, lines.size, "One manifest entry expected")
        val cols = lines[0].split('\t')
        val keyMetadata = cols[2]
        val parts = keyMetadata.split(':')
        assertEquals(4, parts.size, "Metadata must be strategy:keyId:salt:iv (4 parts, no raw key)")
        assertEquals("aes-256", parts[0])

        val keyId = Base64.getDecoder().decode(parts[1])
        val salt = Base64.getDecoder().decode(parts[2])
        val iv = Base64.getDecoder().decode(parts[3])
        assertEquals(8, keyId.size, "keyId is an 8-byte non-secret id")
        assertEquals(16, salt.size, "salt is 16 bytes")
        assertEquals(16, iv.size, "iv is 16 bytes")

        // Re-derive the real AES key the same way the runtime would.
        val derivedKey = deriveClassEncryptionKey(context, "aes-256", keyId, salt)
        assertEquals(32, derivedKey.size)

        // RED-LINE: none of the Base64 fields in the manifest may equal the real
        // key, i.e. the key must not be extractable from the artifact alone.
        val derivedB64 = Base64.getEncoder().encodeToString(derivedKey)
        for (field in parts.drop(1)) {
            assertTrue(field != derivedB64, "Manifest field must not equal the real AES key")
        }
        // The raw key bytes must not appear anywhere in the manifest bytes.
        assertFalse(containsSubsequence(manifest.bytes, derivedKey), "Raw AES key bytes must not be present in manifest")

        // Round-trip: the metadata + per-build root recompute the key and decrypt
        // the resource back to valid class bytecode (0xCAFEBABE).
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(derivedKey, "AES"), IvParameterSpec(iv))
        val decrypted = cipher.doFinal(resourceEntry.bytes)
        assertEquals(0xCAFEBABE.toInt(), readInt(decrypted, 0), "Decrypted resource must be valid class bytecode")
    }

    private fun readInt(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)

    private fun containsSubsequence(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        outer@ for (start in 0..haystack.size - needle.size) {
            for (i in needle.indices) {
                if (haystack[start + i] != needle[i]) continue@outer
            }
            return true
        }
        return false
    }

    private fun buildSimpleClass(internalName: String): ByteArray {
        val cw = ClassWriter(ClassWriter.COMPUTE_MAXS)
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, internalName, null, "java/lang/Object", null)
        val init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null)
        init.visitCode()
        init.visitVarInsn(Opcodes.ALOAD, 0)
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false)
        init.visitInsn(Opcodes.RETURN)
        init.visitMaxs(1, 1)
        init.visitEnd()
        val m = cw.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "answer", "()I", null, null)
        m.visitCode()
        m.visitIntInsn(Opcodes.BIPUSH, 42)
        m.visitInsn(Opcodes.IRETURN)
        m.visitMaxs(1, 0)
        m.visitEnd()
        cw.visitEnd()
        return cw.toByteArray()
    }

    private fun ruleMatchFor(internalName: String): RuleMatch = RuleMatch(
        rule = RuleSpec(target = internalName, action = "class-encryption-loader"),
        selector = TargetSelector(classPattern = internalName, memberPattern = null, memberDescriptorPattern = null),
        matchedClassNames = listOf(internalName),
        matchedMembers = emptyList(),
    )
}
