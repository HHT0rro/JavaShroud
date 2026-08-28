package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingClassPage
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassPageCandidate
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassRoute
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassRouteAllocator
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassRouteReservation
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassRouteCandidateRef
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class QpClassPageCandidateRouteTest {
    @Test
    fun candidate_defensively_owns_class_page_inputs_and_binds_only_a_matching_preseal_route() {
        val identity = ByteArray(32) { index -> (index * 7 + 3).toByte() }
        val plaintext = "candidate-owned UTF-8 page".encodeToByteArray()
        val proof = ByteArray(37) { index -> (index * 19 + 5).toByte() }
        val handle = ByteArray(QpHandle.ENCODED_HANDLE_SIZE) { index -> (index * 11 + 9).toByte() }
        val expectedIdentity = identity.copyOf()
        val expectedPlaintext = plaintext.copyOf()
        val expectedProof = proof.copyOf()
        val expectedHandle = handle.copyOf()
        val bindingPath = "META-INF/.logical/class/candidate.bin"
        var candidate: QpClassPageCandidate? = null
        var candidateCopy: QpClassPageCandidate? = null
        var route: QpClassRoute? = null
        var pending: QpPendingClassPage? = null
        try {
            candidate = QpClassPageCandidate.create(
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

            route = QpClassRoute.create(
                identityPageKey = candidate.identityPageKeyForBuild(),
                logicalBindingPath = bindingPath,
                futureResourcePath = "META-INF/.qp/class/candidate-final.bin",
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

            val mismatchedRoute = QpClassRoute.create(
                identityPageKey = candidate.identityPageKeyForBuild(),
                logicalBindingPath = "META-INF/.logical/class/other.bin",
                futureResourcePath = "META-INF/.qp/class/other-final.bin",
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
        val later = QpClassRouteCandidateRef.create(
            identityPageKey = "page_z",
            logicalBindingPath = "META-INF/.logical/class/z.bin",
        )
        val earlier = QpClassRouteCandidateRef.create(
            identityPageKey = "page_a",
            logicalBindingPath = "META-INF/.logical/class/a.bin",
        )
        val allocationTrace = mutableListOf<String>()
        var escapedRoute: QpClassRoute? = null
        var reservation: QpClassRouteReservation? = null
        try {
            reservation = QpClassRouteReservation.reserve(
                candidateRefs = listOf(later, earlier),
                occupiedEntryPaths = linkedSetOf("META-INF/existing.bin"),
                allocator = QpClassRouteAllocator { candidate, ordinal, reservedEntryPaths ->
                    @Suppress("UNCHECKED_CAST")
                    assertFailsWith<UnsupportedOperationException> {
                        (reservedEntryPaths as MutableSet<String>).add("META-INF/mutated.bin")
                    }
                    allocationTrace += "${candidate.identityPageKey}:$ordinal"
                    "META-INF/.qp/class/reserved-$ordinal.bin"
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
                        "META-INF/.qp/class/reserved-0.bin",
                        "META-INF/.qp/class/reserved-1.bin",
                    ),
                    routes.map { it.futureResourcePath },
                )
                escapedRoute = routes.first()
            }
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedRoute).futureResourcePath
            }

            val collision = QpClassRouteCandidateRef.create(
                identityPageKey = "page_c",
                logicalBindingPath = "META-INF/.logical/class/c.bin",
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    QpClassRouteReservation.reserve(
                        candidateRefs = listOf(collision),
                        occupiedEntryPaths = setOf("META-INF/occupied.bin"),
                        allocator = QpClassRouteAllocator { _, _, _ -> "META-INF/occupied.bin" },
                    )
                }
            } finally {
                collision.wipe()
            }

            val duplicate = QpClassRouteCandidateRef.create(
                identityPageKey = "page_a",
                logicalBindingPath = "META-INF/.logical/class/duplicate.bin",
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    QpClassRouteReservation.reserve(
                        candidateRefs = listOf(earlier, duplicate),
                        occupiedEntryPaths = emptySet(),
                        allocator = QpClassRouteAllocator { _, ordinal, _ ->
                            "META-INF/.qp/class/duplicate-$ordinal.bin"
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
