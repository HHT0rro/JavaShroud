package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4LogicalMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4MethodCandidate
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AkenVbc4MethodCandidateRegistryTest {
    @Test
    fun candidate_registry_is_build_only_defensive_and_wiped_at_each_scope_boundary() {
        val masterKey = ByteArray(32) { index -> (index * 3 + 1).toByte() }
        val layoutDigest = ByteArray(32) { index -> (index * 5 + 7).toByte() }
        val suppliedIdentity = ByteArray(32) { index -> (index * 11 + 9).toByte() }
        val suppliedProgram = ByteArray(96) { index -> (index * 13 + 4).toByte() }
        val expectedIdentity = suppliedIdentity.copyOf()
        val expectedProgram = suppliedProgram.copyOf()
        val logicalMethod = AkenVbc4LogicalMethodIdentity.create(
            dispatchClassToken = "class-token",
            dispatchMethodToken = "method-token",
            descriptor = "(I)I",
            logicalVmResourcePath = "META-INF/vbc4/logical-method.bin",
        )
        val sourceCandidate = AkenVbc4MethodCandidate.create(
            entryToken = 0x1122_3344_5566_7788L,
            logicalMethod = logicalMethod,
            logicalIdentity = suppliedIdentity,
            serializedProgram = suppliedProgram,
        )
        val context = Vbc4BuildContext(
            masterKey = masterKey,
            nativeSeed = 0x2A17C0DEL,
            jarLayoutDigest = layoutDigest,
        )
        var escapedSnapshot: AkenVbc4MethodCandidate? = null
        try {
            context.registerAkenVbc4MethodCandidates(listOf(sourceCandidate))
            sourceCandidate.wipe()
            Arrays.fill(suppliedIdentity, 0)
            Arrays.fill(suppliedProgram, 0)

            context.withAkenVbc4MethodCandidatesForBuild { candidates ->
                assertEquals(1, candidates.size)
                val candidate = candidates.single()
                escapedSnapshot = candidate
                assertEquals(logicalMethod, candidate.logicalMethod)
                assertContentEquals(expectedIdentity, candidate.copyLogicalIdentityForBuild())
                val programCopy = candidate.copySerializedProgramForBuild()
                try {
                    assertContentEquals(expectedProgram, programCopy)
                    programCopy[0] = (programCopy[0].toInt() xor 0x5A).toByte()
                } finally {
                    Arrays.fill(programCopy, 0)
                }
            }

            assertTrue(checkNotNull(escapedSnapshot).isWiped)
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedSnapshot).copySerializedProgramForBuild()
            }

            context.withAkenVbc4MethodCandidatesForBuild { candidates ->
                val freshProgramCopy = candidates.single().copySerializedProgramForBuild()
                try {
                    assertContentEquals(expectedProgram, freshProgramCopy)
                } finally {
                    Arrays.fill(freshProgramCopy, 0)
                }
            }

            val duplicate = AkenVbc4MethodCandidate.create(
                entryToken = 0x1122_3344_5566_7788L,
                logicalMethod = AkenVbc4LogicalMethodIdentity.create(
                    dispatchClassToken = "other-class-token",
                    dispatchMethodToken = "other-method-token",
                    descriptor = "()V",
                    logicalVmResourcePath = "META-INF/vbc4/other-method.bin",
                ),
                logicalIdentity = expectedIdentity,
                serializedProgram = expectedProgram,
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    context.registerAkenVbc4MethodCandidates(listOf(duplicate))
                }
            } finally {
                duplicate.wipe()
            }

            assertTrue(context.akenVbc4FinalizationLayoutOrNull() == null)
            assertFailsWith<IllegalStateException> {
                context.withAkenNativeLocatorRecordsForBuild { error("unexpected native locator record callback") }
            }

            val scopedCopy = context.scopedCopy()
            try {
                assertFailsWith<IllegalStateException> {
                    scopedCopy.withAkenVbc4MethodCandidatesForBuild { error("scoped copy must not contain plaintext candidates") }
                }
            } finally {
                scopedCopy.wipe()
            }
        } finally {
            context.wipe()
            Arrays.fill(expectedIdentity, 0)
            Arrays.fill(expectedProgram, 0)
        }

        assertFailsWith<IllegalStateException> {
            context.withAkenVbc4MethodCandidatesForBuild { error("wiped context must not expose candidates") }
        }
    }
}
