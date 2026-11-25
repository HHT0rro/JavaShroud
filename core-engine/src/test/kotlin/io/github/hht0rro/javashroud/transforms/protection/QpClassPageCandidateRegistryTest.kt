package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
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
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class QpClassPageCandidateRegistryTest {
    @Test
    fun class_page_candidate_registry_and_preseal_routes_are_defensive_scoped_and_wiped() {
        val masterKey = ByteArray(32) { index -> (index * 5 + 1).toByte() }
        val layoutDigest = ByteArray(32) { index -> (index * 7 + 3).toByte() }
        val logicalIdentity = ByteArray(32) { index -> (index * 11 + 9).toByte() }
        val plaintext = "context-owned ClassPage".encodeToByteArray()
        val proof = ByteArray(53) { index -> (index * 17 + 5).toByte() }
        val handle = ByteArray(QpHandle.ENCODED_HANDLE_SIZE) { index -> (index * 13 + 7).toByte() }
        val expectedIdentity = logicalIdentity.copyOf()
        val expectedPlaintext = plaintext.copyOf()
        val expectedProof = proof.copyOf()
        val expectedHandle = handle.copyOf()
        val logicalBindingPath = "META-INF/.logical/class/context-page.bin"
        val sourceCandidate = QpClassPageCandidate.create(
            logicalIdentity = logicalIdentity,
            plaintext = plaintext,
            pageIndex = 0,
            callSiteProof = proof,
            encodedHandle = handle,
            logicalBindingPath = logicalBindingPath,
            targetPageSize = 512,
        )
        val expectedIdentityPageKey = sourceCandidate.identityPageKeyForBuild()
        val context = QpBuildContext(
            masterKey = masterKey,
            nativeSeed = 0x414B_454E_0000_0031L,
            jarLayoutDigest = layoutDigest,
        )
        var escapedCandidate: QpClassPageCandidate? = null
        var escapedRef: QpClassRouteCandidateRef? = null
        var escapedRoute: QpClassRoute? = null
        var reservation: QpClassRouteReservation? = null
        try {
            context.registerQpClassPageCandidates(listOf(sourceCandidate))
            sourceCandidate.wipe()
            Arrays.fill(logicalIdentity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(handle, 0)
            assertTrue(context.hasQpClassPageCandidates())

            context.withQpClassPageCandidatesForBuild { candidates ->
                assertEquals(1, candidates.size)
                val candidate = candidates.single()
                escapedCandidate = candidate
                assertEquals(expectedIdentityPageKey, candidate.identityPageKeyForBuild())
                val copiedIdentity = candidate.copyLogicalIdentityForBuild()
                val copiedPlaintext = candidate.copyPlaintextForBuild()
                val copiedProof = candidate.copyCallSiteProofForBuild()
                val copiedHandle = candidate.copyEncodedHandleForBuild()
                try {
                    assertContentEquals(expectedIdentity, copiedIdentity)
                    assertContentEquals(expectedPlaintext, copiedPlaintext)
                    assertContentEquals(expectedProof, copiedProof)
                    assertContentEquals(expectedHandle, copiedHandle)
                } finally {
                    Arrays.fill(copiedIdentity, 0)
                    Arrays.fill(copiedPlaintext, 0)
                    Arrays.fill(copiedProof, 0)
                    Arrays.fill(copiedHandle, 0)
                }
            }
            assertTrue(checkNotNull(escapedCandidate).isWiped)
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedCandidate).copyPlaintextForBuild()
            }

            context.withQpClassRouteCandidateRefsForBuild { refs ->
                assertEquals(1, refs.size)
                val ref = refs.single()
                escapedRef = ref
                assertEquals(expectedIdentityPageKey, ref.identityPageKey)
                assertEquals(logicalBindingPath, ref.logicalBindingPath)
            }
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedRef).logicalBindingPath
            }

            reservation = context.reserveQpClassRoutes(
                occupiedEntryPaths = setOf("META-INF/existing.bin"),
                allocator = QpClassRouteAllocator { candidate, ordinal, reservedEntryPaths ->
                    assertEquals(expectedIdentityPageKey, candidate.identityPageKey)
                    assertFalse("META-INF/.qp/class/context-$ordinal.bin" in reservedEntryPaths)
                    "META-INF/.qp/class/context-$ordinal.bin"
                },
            )
            assertEquals(reservation, context.requireQpClassRouteReservation())
            reservation.withRoutesForBuild { routes ->
                assertEquals(1, routes.size)
                val route = routes.single()
                escapedRoute = route
                assertEquals(expectedIdentityPageKey, route.identityPageKey)
                assertEquals(logicalBindingPath, route.logicalBindingPath)
                assertEquals("META-INF/.qp/class/context-0.bin", route.futureResourcePath)
            }
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedRoute).futureResourcePath
            }

            val duplicate = QpClassPageCandidate.create(
                logicalIdentity = expectedIdentity,
                plaintext = expectedPlaintext,
                pageIndex = 0,
                callSiteProof = expectedProof,
                encodedHandle = expectedHandle,
                logicalBindingPath = "META-INF/.logical/class/duplicate.bin",
                targetPageSize = 512,
            )
            try {
                assertFailsWith<IllegalArgumentException> {
                    context.registerQpClassPageCandidates(listOf(duplicate))
                }
            } finally {
                duplicate.wipe()
            }

            val scopedCopy = context.scopedCopy()
            try {
                assertFalse(scopedCopy.hasQpClassPageCandidates())
                assertNull(scopedCopy.qpClassRouteReservationOrNull())
                assertFailsWith<IllegalStateException> {
                    scopedCopy.withQpClassPageCandidatesForBuild {
                        error("scoped copy must not contain ClassPage plaintext candidates")
                    }
                }
            } finally {
                scopedCopy.wipe()
            }
        } finally {
            context.wipe()
            sourceCandidate.wipe()
            Arrays.fill(masterKey, 0)
            Arrays.fill(layoutDigest, 0)
            Arrays.fill(logicalIdentity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(handle, 0)
            Arrays.fill(expectedIdentity, 0)
            Arrays.fill(expectedPlaintext, 0)
            Arrays.fill(expectedProof, 0)
            Arrays.fill(expectedHandle, 0)
        }

        assertFailsWith<IllegalStateException> {
            context.withQpClassPageCandidatesForBuild {
                error("wiped context must not expose ClassPage candidates")
            }
        }
    }
}
