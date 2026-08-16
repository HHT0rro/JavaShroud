package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptorSource
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenClassPageDescriptorSourceRegistryTest {
    @Test
    fun class_local_descriptor_sources_are_scoped_contiguous_and_wiped() {
        val masterKey = ByteArray(32) { index -> (index * 5 + 1).toByte() }
        val layoutDigest = ByteArray(32) { index -> (index * 7 + 3).toByte() }
        val identityZero = ByteArray(32) { index -> (index * 11 + 9).toByte() }
        val identityOne = ByteArray(32) { index -> (index * 13 + 5).toByte() }
        val plaintextZero = "context-owned ClassPage zero".encodeToByteArray()
        val plaintextOne = "context-owned ClassPage one".encodeToByteArray()
        val proofZero = ByteArray(53) { index -> (index * 17 + 5).toByte() }
        val proofOne = ByteArray(57) { index -> (index * 19 + 7).toByte() }
        val handleZero = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 23 + 3).toByte() }
        val handleOne = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 29 + 11).toByte() }
        val expectedIdentityZero = identityZero.copyOf()
        val expectedIdentityOne = identityOne.copyOf()
        val internalName = "fixture/DescriptorSourceOwner"
        val candidateZero = AkenClassPageCandidate.create(
            logicalIdentity = identityZero,
            plaintext = plaintextZero,
            pageIndex = 0,
            callSiteProof = proofZero,
            encodedHandle = handleZero,
            logicalBindingPath = "META-INF/.logical/class/source-owner-0.bin",
            targetPageSize = 512,
        )
        val candidateOne = AkenClassPageCandidate.create(
            logicalIdentity = identityOne,
            plaintext = plaintextOne,
            pageIndex = 1,
            callSiteProof = proofOne,
            encodedHandle = handleOne,
            logicalBindingPath = "META-INF/.logical/class/source-owner-1.bin",
            targetPageSize = 1024,
        )
        val expectedIdentityKeys = listOf(
            candidateZero.identityPageKeyForBuild(),
            candidateOne.identityPageKeyForBuild(),
        )
        val context = Vbc4BuildContext(
            masterKey = masterKey,
            nativeSeed = 0x414B_454E_0000_3101L,
            jarLayoutDigest = layoutDigest,
        )
        var escapedSources: List<AkenClassPageDescriptorSource> = emptyList()
        try {
            context.registerAkenClassPageCandidatesForClass(
                internalName = internalName,
                candidates = listOf(candidateOne, candidateZero),
            )
            candidateZero.wipe()
            candidateOne.wipe()
            Arrays.fill(identityZero, 0)
            Arrays.fill(identityOne, 0)
            Arrays.fill(plaintextZero, 0)
            Arrays.fill(plaintextOne, 0)
            Arrays.fill(proofZero, 0)
            Arrays.fill(proofOne, 0)
            Arrays.fill(handleZero, 0)
            Arrays.fill(handleOne, 0)

            assertTrue(context.hasAkenClassPageCandidates())
            assertTrue(context.hasAkenClassPageDescriptorSources())
            context.withAkenClassPageDescriptorSourcesForBuild { sources ->
                assertEquals(2, sources.size)
                assertEquals(listOf(0, 1), sources.map { source -> source.pageIndex })
                assertEquals(setOf(internalName), sources.mapTo(linkedSetOf()) { source -> source.internalName })
                assertEquals(expectedIdentityKeys.toSet(), sources.mapTo(linkedSetOf()) { source -> source.identityPageKeyForBuild() })
                escapedSources = sources.toList()

                val copiedZero = sources[0].copyLogicalIdentityForBuild()
                val copiedOne = sources[1].copyLogicalIdentityForBuild()
                try {
                    assertContentEquals(expectedIdentityZero, copiedZero)
                    assertContentEquals(expectedIdentityOne, copiedOne)
                } finally {
                    Arrays.fill(copiedZero, 0)
                    Arrays.fill(copiedOne, 0)
                }
            }
            assertTrue(escapedSources.all { source -> source.isWiped })
            assertFailsWith<IllegalStateException> {
                escapedSources.first().copyLogicalIdentityForBuild()
            }

            val duplicateIdentity = ByteArray(32) { index -> (index * 31 + 13).toByte() }
            val duplicatePlaintext = "duplicate class-local source".encodeToByteArray()
            val duplicateProof = ByteArray(41) { index -> (index * 37 + 17).toByte() }
            val duplicateHandle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 41 + 19).toByte() }
            val duplicate = AkenClassPageCandidate.create(
                logicalIdentity = duplicateIdentity,
                plaintext = duplicatePlaintext,
                pageIndex = 0,
                callSiteProof = duplicateProof,
                encodedHandle = duplicateHandle,
                logicalBindingPath = "META-INF/.logical/class/duplicate-source.bin",
                targetPageSize = 512,
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    context.registerAkenClassPageCandidatesForClass(
                        internalName = internalName,
                        candidates = listOf(duplicate),
                    )
                }
            } finally {
                duplicate.wipe()
                Arrays.fill(duplicateIdentity, 0)
                Arrays.fill(duplicatePlaintext, 0)
                Arrays.fill(duplicateProof, 0)
                Arrays.fill(duplicateHandle, 0)
            }

            val scopedCopy = context.scopedCopy()
            try {
                assertFalse(scopedCopy.hasAkenClassPageDescriptorSources())
                assertFailsWith<IllegalStateException> {
                    scopedCopy.withAkenClassPageDescriptorSourcesForBuild {
                        error("scoped runtime copy must not contain ClassPage descriptor sources")
                    }
                }
            } finally {
                scopedCopy.wipe()
            }
        } finally {
            context.wipe()
            candidateZero.wipe()
            candidateOne.wipe()
            Arrays.fill(masterKey, 0)
            Arrays.fill(layoutDigest, 0)
            Arrays.fill(identityZero, 0)
            Arrays.fill(identityOne, 0)
            Arrays.fill(plaintextZero, 0)
            Arrays.fill(plaintextOne, 0)
            Arrays.fill(proofZero, 0)
            Arrays.fill(proofOne, 0)
            Arrays.fill(handleZero, 0)
            Arrays.fill(handleOne, 0)
            Arrays.fill(expectedIdentityZero, 0)
            Arrays.fill(expectedIdentityOne, 0)
        }

        assertFailsWith<IllegalStateException> {
            context.withAkenClassPageDescriptorSourcesForBuild {
                error("wiped context must not expose ClassPage descriptor sources")
            }
        }
    }
}
