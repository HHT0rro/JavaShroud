package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingNativeSegment
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeSegmentCandidate
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeRoute
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeRouteAllocator
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeRouteReservation
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNativeRouteCandidateRef
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class QpNativeSegmentCandidateRouteTest {
    @Test
    fun candidate_defensively_owns_native_chunk_inputs_and_binds_only_a_matching_preseal_route() {
        val identity = ByteArray(32) { index -> (index * 7 + 3).toByte() }
        val plaintext = "candidate-owned native chunk".encodeToByteArray()
        val proof = ByteArray(37) { index -> (index * 19 + 5).toByte() }
        val handle = ByteArray(QpHandle.ENCODED_HANDLE_SIZE) { index -> (index * 11 + 9).toByte() }
        val expectedIdentity = identity.copyOf()
        val expectedPlaintext = plaintext.copyOf()
        val expectedProof = proof.copyOf()
        val expectedHandle = handle.copyOf()
        val bindingPath = "META-INF/.logical/native/candidate.bin"
        var candidate: QpNativeSegmentCandidate? = null
        var candidateCopy: QpNativeSegmentCandidate? = null
        var route: QpNativeRoute? = null
        var pending: QpPendingNativeSegment? = null
        try {
            candidate = QpNativeSegmentCandidate.create(
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

            route = QpNativeRoute.create(
                identityPageKey = candidate.identityPageKeyForBuild(),
                logicalBindingPath = bindingPath,
                futureResourcePath = "META-INF/.qp/native/candidate-final.bin",
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

            val mismatchedRoute = QpNativeRoute.create(
                identityPageKey = candidate.identityPageKeyForBuild(),
                logicalBindingPath = "META-INF/.logical/native/other.bin",
                futureResourcePath = "META-INF/.qp/native/other-final.bin",
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
        val later = QpNativeRouteCandidateRef.create(
            identityPageKey = "page_z",
            logicalBindingPath = "META-INF/.logical/native/z.bin",
        )
        val earlier = QpNativeRouteCandidateRef.create(
            identityPageKey = "page_a",
            logicalBindingPath = "META-INF/.logical/native/a.bin",
        )
        val allocationTrace = mutableListOf<String>()
        var escapedRoute: QpNativeRoute? = null
        var reservation: QpNativeRouteReservation? = null
        try {
            reservation = QpNativeRouteReservation.reserve(
                candidateRefs = listOf(later, earlier),
                occupiedEntryPaths = linkedSetOf("META-INF/existing.bin"),
                allocator = QpNativeRouteAllocator { candidate, ordinal, reservedEntryPaths ->
                    @Suppress("UNCHECKED_CAST")
                    assertFailsWith<UnsupportedOperationException> {
                        (reservedEntryPaths as MutableSet<String>).add("META-INF/mutated.bin")
                    }
                    allocationTrace += "${candidate.identityPageKey}:$ordinal"
                    "META-INF/.qp/native/reserved-$ordinal.bin"
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
                        "META-INF/.qp/native/reserved-0.bin",
                        "META-INF/.qp/native/reserved-1.bin",
                    ),
                    routes.map { it.futureResourcePath },
                )
                escapedRoute = routes.first()
            }
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedRoute).futureResourcePath
            }

            val collision = QpNativeRouteCandidateRef.create(
                identityPageKey = "page_c",
                logicalBindingPath = "META-INF/.logical/native/c.bin",
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    QpNativeRouteReservation.reserve(
                        candidateRefs = listOf(collision),
                        occupiedEntryPaths = setOf("META-INF/occupied.bin"),
                        allocator = QpNativeRouteAllocator { _, _, _ -> "META-INF/occupied.bin" },
                    )
                }
            } finally {
                collision.wipe()
            }

            val duplicate = QpNativeRouteCandidateRef.create(
                identityPageKey = "page_a",
                logicalBindingPath = "META-INF/.logical/native/duplicate.bin",
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    QpNativeRouteReservation.reserve(
                        candidateRefs = listOf(earlier, duplicate),
                        occupiedEntryPaths = emptySet(),
                        allocator = QpNativeRouteAllocator { _, ordinal, _ ->
                            "META-INF/.qp/native/duplicate-$ordinal.bin"
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
