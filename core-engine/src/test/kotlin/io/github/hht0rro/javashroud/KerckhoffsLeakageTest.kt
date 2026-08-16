package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.model.analysis.RuleMatch
import io.github.hht0rro.javashroud.model.analysis.TargetSelector
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.RuntimeArtifactSealing
import io.github.hht0rro.javashroud.transforms.protection.applyClassEncryptionLoader
import io.github.hht0rro.javashroud.transforms.protection.deriveClassEncryptionKey
import io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
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
 * v2 metadata (strategy/keyId/salt/nonce/AAD hash); the real AES-GCM key is
 * HKDF-derived from the per-build root key and recomputed at runtime, never persisted.
 */
class KerckhoffsLeakageTest {

    private fun freshContext(): Vbc4BuildContext {
        val random = SecureRandom()
        val master = ByteArray(32).also { random.nextBytes(it) }
        val layout = ByteArray(32).also { random.nextBytes(it) }
        return Vbc4BuildContext(masterKey = master, nativeSeed = 0x5151_2626L, jarLayoutDigest = layout)
    }

    @Test
    fun encrypted_class_pages_have_no_legacy_manifest_or_reusable_build_root() {
        val internalName = "leak/Target"
        val classBytes = buildSimpleClass(internalName)
        val artifact = testAttachedArtifact(
            classArtifacts = listOf(testClassArtifact(internalName = internalName, bytes = classBytes)),
        )
        val context = freshContext()
        try {
            withVbc4BuildContext(context) {
                val transformed = applyClassEncryptionLoader(
                    artifact = artifact,
                    ruleMatches = listOf(ruleMatchFor(internalName)),
                    params = mapOf("encryptionStrategy" to "aes-256", "keyMode" to "per-class"),
                )
                assertTrue(
                    transformed.artifact.jarEntries.none { entry -> entry.name.startsWith("__jse/") },
                    "AKEN transform must not emit the retired class manifest/resource namespace",
                )

                val scoped = requireVbc4BuildContext()
                assertTrue(scoped.hasAkenClassPageDescriptorSources())
                assertTrue(
                    RuntimeArtifactSealing.reserveAkenClassPagePreSealRoutesIfNeeded(
                        artifact = transformed.artifact,
                        seed = scoped.nativeSeed,
                    ),
                )
                val materialized = RuntimeArtifactSealing.materializeAkenVbc4PagesForNativeCompilation(
                    artifact = transformed.artifact,
                    seed = scoped.nativeSeed,
                )
                assertTrue(
                    materialized.jarEntries.any { entry ->
                        entry.name.startsWith("META-INF/.a4/") ||
                            entry.name.startsWith("META-INF/.r4/") ||
                            entry.name.startsWith("assets/.a4/") ||
                            entry.name.startsWith("META-INF/.j4/")
                    },
                    "AKEN materialization must emit page-local resources",
                )
                assertFalse(
                    materialized.jarEntries.any { entry -> entry.name.startsWith("__jse/") },
                    "AKEN materialization must not recreate the legacy manifest/resource namespace",
                )

                val descriptorPath =
                    io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptor
                        .resourcePathForInternalNameForBuild(internalName)
                val descriptorEntry = materialized.jarEntries.singleOrNull { entry -> entry.name == descriptorPath }
                assertNotNull(descriptorEntry, "One class-local descriptor must be emitted")
                val descriptorBytes = descriptorEntry.bytes.copyOf()
                var descriptor: io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptor? = null
                try {
                    descriptor =
                        io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptor
                            .decodeForBuild(descriptorBytes)
                    assertEquals(internalName, descriptor.internalName)
                    assertEquals(1, descriptor.pageCount)
                } finally {
                    descriptor?.wipe()
                    java.util.Arrays.fill(descriptorBytes, 0)
                }

                val allArtifactBytes = materialized.jarEntries.map { entry -> entry.bytes } +
                    materialized.classArtifacts.map { classArtifact -> classArtifact.bytes }
                val rootCopy = scoped.masterKey.copyOf()
                try {
                    assertFalse(
                        allArtifactBytes.any { bytes -> containsSubsequence(bytes, rootCopy) },
                        "Build authority must not be copied into class/page artifact bytes",
                    )
                } finally {
                    java.util.Arrays.fill(rootCopy, 0)
                }

                val layout = scoped.requireAkenVbc4FinalizationLayout()
                assertTrue(
                    layout.verifyWriterEquivalentArtifactForBuild(
                        layout.entriesForBuild().map { entry ->
                            val bytes = entry.copyBytesForBuild()
                            try {
                                io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry(
                                    entry.name,
                                    bytes,
                                )
                            } finally {
                                java.util.Arrays.fill(bytes, 0)
                            }
                        },
                    ),
                )
            }
        } finally {
            context.wipe()
        }
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
