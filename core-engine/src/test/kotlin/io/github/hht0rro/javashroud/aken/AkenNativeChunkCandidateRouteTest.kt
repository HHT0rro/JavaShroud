package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPendingNativeChunk
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkPreSealRoute
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkPreSealRouteAllocator
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkPreSealRouteReservation
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkRouteCandidateRef
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AkenNativeChunkCandidateRouteTest {
    @Test
    fun candidate_defensively_owns_native_chunk_inputs_and_binds_only_a_matching_preseal_route() {
        val identity = ByteArray(32) { index -> (index * 7 + 3).toByte() }
        val plaintext = "candidate-owned native chunk".encodeToByteArray()
        val proof = ByteArray(37) { index -> (index * 19 + 5).toByte() }
        val handle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 11 + 9).toByte() }
        val expectedIdentity = identity.copyOf()
        val expectedPlaintext = plaintext.copyOf()
        val expectedProof = proof.copyOf()
        val expectedHandle = handle.copyOf()
        val bindingPath = "META-INF/.logical/native/candidate.bin"
        var candidate: AkenNativeChunkCandidate? = null
        var candidateCopy: AkenNativeChunkCandidate? = null
        var route: AkenNativeChunkPreSealRoute? = null
        var pending: AkenPendingNativeChunk? = null
        try {
            candidate = AkenNativeChunkCandidate.create(
                logicalIdentity = identity,
                plaintext = plaintext,
                pageIndex = 4,
                callSiteProof = proof,
                encodedHandle = handle,
                logicalBindingPath = bindingPath,
                targetPageSize = 1024,
            )
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(handle, 0)

            candidateCopy = candidate.copyForBuild()
            assertEquals(candidate.identityPageKeyForBuild(), candidateCopy.identityPageKeyForBuild())

            route = AkenNativeChunkPreSealRoute.create(
                identityPageKey = candidate.identityPageKeyForBuild(),
                logicalBindingPath = bindingPath,
                futureResourcePath = "META-INF/.aken/native/candidate-final.bin",
            )
            pending = candidate.toPendingPage(route)

            val pendingIdentity = pending.copyLogicalIdentityForBuild()
            val pendingPlaintext = pending.copyPlaintextForBuild()
            val pendingProof = pending.copyCallSiteProofForBuild()
            val pendingHandle = pending.copyEncodedHandleForBuild()
            try {
                assertEquals(4, pending.pageIndex)
                assertEquals(1024, pending.targetPageSize)
                assertEquals(route.futureResourcePath, pending.resourcePath)
                assertEquals(bindingPath, pending.logicalBindingPath)
                assertContentEquals(expectedIdentity, pendingIdentity)
                assertContentEquals(expectedPlaintext, pendingPlaintext)
                assertContentEquals(expectedProof, pendingProof)
                assertContentEquals(expectedHandle, pendingHandle)
            } finally {
                Arrays.fill(pendingIdentity, 0)
                Arrays.fill(pendingPlaintext, 0)
                Arrays.fill(pendingProof, 0)
                Arrays.fill(pendingHandle, 0)
            }

            val mismatchedRoute = AkenNativeChunkPreSealRoute.create(
                identityPageKey = candidate.identityPageKeyForBuild(),
                logicalBindingPath = "META-INF/.logical/native/other.bin",
                futureResourcePath = "META-INF/.aken/native/other-final.bin",
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    candidate.toPendingPage(mismatchedRoute)
                }
            } finally {
                mismatchedRoute.wipe()
            }

            candidate.wipe()
            assertTrue(candidate.isWiped)
            val retainedCopy = candidateCopy.copyPlaintextForBuild()
            try {
                assertContentEquals(expectedPlaintext, retainedCopy)
            } finally {
                Arrays.fill(retainedCopy, 0)
            }
        } finally {
            pending?.wipe()
            route?.wipe()
            candidateCopy?.wipe()
            candidate?.wipe()
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(handle, 0)
            Arrays.fill(expectedIdentity, 0)
            Arrays.fill(expectedPlaintext, 0)
            Arrays.fill(expectedProof, 0)
            Arrays.fill(expectedHandle, 0)
        }
    }

    @Test
    fun preseal_route_reservation_is_scoped_deterministic_and_collision_checked() {
        val later = AkenNativeChunkRouteCandidateRef.create(
            identityPageKey = "page_z",
            logicalBindingPath = "META-INF/.logical/native/z.bin",
        )
        val earlier = AkenNativeChunkRouteCandidateRef.create(
            identityPageKey = "page_a",
            logicalBindingPath = "META-INF/.logical/native/a.bin",
        )
        val allocationTrace = mutableListOf<String>()
        var escapedRoute: AkenNativeChunkPreSealRoute? = null
        var reservation: AkenNativeChunkPreSealRouteReservation? = null
        try {
            reservation = AkenNativeChunkPreSealRouteReservation.reserve(
                candidateRefs = listOf(later, earlier),
                occupiedEntryPaths = linkedSetOf("META-INF/existing.bin"),
                allocator = AkenNativeChunkPreSealRouteAllocator { candidate, ordinal, reservedEntryPaths ->
                    @Suppress("UNCHECKED_CAST")
                    assertFailsWith<UnsupportedOperationException> {
                        (reservedEntryPaths as MutableSet<String>).add("META-INF/mutated.bin")
                    }
                    allocationTrace += "${candidate.identityPageKey}:$ordinal"
                    "META-INF/.aken/native/reserved-$ordinal.bin"
                },
            )

            assertEquals(
                listOf("page_a:0", "page_z:1", "page_a:0", "page_z:1"),
                allocationTrace,
            )
            reservation.withRoutesForBuild { routes ->
                assertEquals(listOf("page_a", "page_z"), routes.map { it.identityPageKey })
                assertEquals(
                    listOf(
                        "META-INF/.aken/native/reserved-0.bin",
                        "META-INF/.aken/native/reserved-1.bin",
                    ),
                    routes.map { it.futureResourcePath },
                )
                escapedRoute = routes.first()
            }
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedRoute).futureResourcePath
            }

            val collision = AkenNativeChunkRouteCandidateRef.create(
                identityPageKey = "page_c",
                logicalBindingPath = "META-INF/.logical/native/c.bin",
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    AkenNativeChunkPreSealRouteReservation.reserve(
                        candidateRefs = listOf(collision),
                        occupiedEntryPaths = setOf("META-INF/occupied.bin"),
                        allocator = AkenNativeChunkPreSealRouteAllocator { _, _, _ -> "META-INF/occupied.bin" },
                    )
                }
            } finally {
                collision.wipe()
            }

            val duplicate = AkenNativeChunkRouteCandidateRef.create(
                identityPageKey = "page_a",
                logicalBindingPath = "META-INF/.logical/native/duplicate.bin",
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    AkenNativeChunkPreSealRouteReservation.reserve(
                        candidateRefs = listOf(earlier, duplicate),
                        occupiedEntryPaths = emptySet(),
                        allocator = AkenNativeChunkPreSealRouteAllocator { _, ordinal, _ ->
                            "META-INF/.aken/native/duplicate-$ordinal.bin"
                        },
                    )
                }
            } finally {
                duplicate.wipe()
            }
        } finally {
            reservation?.wipe()
            later.wipe()
            earlier.wipe()
        }
    }
}
