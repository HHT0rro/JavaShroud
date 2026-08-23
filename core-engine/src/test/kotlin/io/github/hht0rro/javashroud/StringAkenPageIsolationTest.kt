package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.StringEncryptionConfig
import io.github.hht0rro.javashroud.bytecode.encryptClassStrings
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class StringAkenPageIsolationTest {
    @Test
    fun identical_literals_in_different_classes_register_independent_string_pages() {
        val context = defaultVbc4BuildContext()
        try {
            withVbc4BuildContext(context) {
                val config = StringEncryptionConfig(seed = 0x1357_2468L)
                encryptClassStrings(buildFixture("example/First", "domain-separated"), config)
                encryptClassStrings(buildFixture("example/Second", "domain-separated"), config)

                requireVbc4BuildContext().withAkenStringPageCandidatesForBuild { candidates ->
                    assertEquals(2, candidates.size)
                    val identities = candidates.map { candidate -> candidate.copyLogicalIdentityForBuild() }
                    val plaintexts = candidates.map { candidate -> candidate.copyPlaintextForBuild() }
                    val handles = candidates.map { candidate -> candidate.copyEncodedHandleForBuild() }
                    val proofs = candidates.map { candidate -> candidate.copyCallSiteProofForBuild() }
                    try {
                        assertTrue(candidates.all { candidate -> candidate.pageIndex > 0 })
                        assertTrue(identities.all { identity -> identity.size == 32 })
                        assertFalse(identities[0].contentEquals(identities[1]))
                        assertFalse(handles[0].contentEquals(handles[1]))
                        assertFalse(proofs[0].contentEquals(proofs[1]))
                        assertEquals(listOf("domain-separated", "domain-separated"), plaintexts.map { it.decodeToString() })
                        assertEquals(2, candidates.map { candidate -> candidate.identityPageKeyForBuild() }.distinct().size)
                        assertEquals(2, candidates.map { candidate -> candidate.logicalBindingPath }.distinct().size)
                    } finally {
                        identities.forEach { identity -> Arrays.fill(identity, 0) }
                        plaintexts.forEach { plaintext -> Arrays.fill(plaintext, 0) }
                        handles.forEach { handle -> Arrays.fill(handle, 0) }
                        proofs.forEach { proof -> Arrays.fill(proof, 0) }
                    }
                }
            }
        } finally {
            context.wipe()
        }
    }

    private fun buildFixture(classInternalName: String, literal: String): ByteArray {
        val writer = ClassWriter(ClassWriter.COMPUTE_MAXS)
        writer.visit(Opcodes.V21, Opcodes.ACC_PUBLIC or Opcodes.ACC_SUPER, classInternalName, null, "java/lang/Object", null)
        val method = writer.visitMethod(Opcodes.ACC_PUBLIC or Opcodes.ACC_STATIC, "value", "()V", null, null)
        method.visitCode()
        method.visitLdcInsn(literal)
        method.visitInsn(Opcodes.POP)
        method.visitInsn(Opcodes.RETURN)
        method.visitMaxs(1, 0)
        method.visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }
}
