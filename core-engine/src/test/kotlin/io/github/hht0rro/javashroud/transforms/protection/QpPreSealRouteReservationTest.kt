package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.qp.QpMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.qp.QpMethodCandidate
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPreSealRouteAllocator
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPreSealRouteReservation
import io.github.hht0rro.javashroud.transforms.protection.qp.QpRouteCandidateRef
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class QpPreSealRouteReservationTest {
    @Test
    fun production_sealing_stage_reserves_scoped_aken_page_container_routes() {
        val context = QpBuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 3).toByte() },
            nativeSeed = 0x4A4B_454E_0000_0011L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 5).toByte() },
        )
        val logicalPath = "META-INF/qp/production-route.bin"
        val program = ByteArray(96) { index -> (index * 13 + 7).toByte() }
        val identity = ByteArray(32) { index -> (index * 17 + 9).toByte() }
        val candidate = candidate(
            entryToken = 0x414B_454E_0000_0011L,
            logicalVmResourcePath = logicalPath,
            logicalIdentity = identity,
            serializedProgram = program,
        )
        try {
            withQpBuildContext(context) {
                val scoped = requireQpBuildContext()
                scoped.registerQpMethodCandidates(listOf(candidate))
                candidate.wipe()

                val artifact = testAttachedArtifact(
                    classArtifacts = emptyList(),
                    jarEntries = listOf(JarEntryData("META-INF/existing.bin", byteArrayOf(1, 2, 3))),
                )
                assertTrue(RuntimeArtifactSealing.reserveQpPreSealRoutesIfNeeded(artifact, scoped.nativeSeed))
                assertTrue(RuntimeArtifactSealing.reserveQpPreSealRoutesIfNeeded(artifact, scoped.nativeSeed))

                scoped.requireQpPreSealRouteReservation().withRoutesForBuild { routes ->
                    assertEquals(1, routes.size)
                    assertEquals(0x414B_454E_0000_0011L, routes.single().entryToken)
                    assertEquals(logicalPath, routes.single().logicalVmResourcePath)
                    assertFalse(routes.single().futureContainerPath.isBlank())
                    assertFalse(routes.single().futureContainerPath == "META-INF/existing.bin")
                }
            }
        } finally {
            candidate.wipe()
            context.wipe()
            java.util.Arrays.fill(identity, 0)
            java.util.Arrays.fill(program, 0)
        }
    }

    @Test
    fun route_reservation_uses_only_scoped_candidate_refs_and_wipes_every_snapshot() {
        val masterKey = ByteArray(32) { index -> (index * 7 + 3).toByte() }
        val layoutDigest = ByteArray(32) { index -> (index * 11 + 5).toByte() }
        val identity0 = ByteArray(32) { index -> (index * 13 + 7).toByte() }
        val identity1 = ByteArray(32) { index -> (index * 17 + 9).toByte() }
        val program0 = ByteArray(96) { index -> (index * 19 + 11).toByte() }
        val program1 = ByteArray(112) { index -> (index * 23 + 13).toByte() }
        val candidate0 = candidate(
            entryToken = 0x414B_454E_0000_0002L,
            logicalVmResourcePath = "META-INF/qp/logical-two.bin",
            logicalIdentity = identity0,
            serializedProgram = program0,
        )
        val candidate1 = candidate(
            entryToken = 0x414B_454E_0000_0001L,
            logicalVmResourcePath = "META-INF/qp/logical-one.bin",
            logicalIdentity = identity1,
            serializedProgram = program1,
        )
        val context = QpBuildContext(
            masterKey = masterKey,
            nativeSeed = 0x5A17C0DEL,
            jarLayoutDigest = layoutDigest,
        )
        var escapedCandidateRef: QpRouteCandidateRef? = null
        var escapedRoute: io.github.hht0rro.javashroud.transforms.protection.qp.QpPreSealRoute? = null
        var reservation: QpPreSealRouteReservation? = null
        try {
            context.registerQpMethodCandidates(listOf(candidate0, candidate1))
            candidate0.wipe()
            candidate1.wipe()
            Arrays.fill(identity0, 0)
            Arrays.fill(identity1, 0)
            Arrays.fill(program0, 0)
            Arrays.fill(program1, 0)

            context.withQpRouteCandidateRefsForBuild { refs ->
                assertEquals(
                    listOf(0x414B_454E_0000_0001L, 0x414B_454E_0000_0002L),
                    refs.map { it.entryToken },
                )
                assertEquals(
                    listOf("META-INF/qp/logical-one.bin", "META-INF/qp/logical-two.bin"),
                    refs.map { it.logicalVmResourcePath },
                )
                escapedCandidateRef = refs.first()
                reservation = QpPreSealRouteReservation.reserve(
                    candidateRefs = refs,
                    occupiedEntryPaths = setOf("META-INF/existing/resource.bin"),
                    allocator = QpPreSealRouteAllocator { candidate, ordinal, reserved ->
                        assertEquals(ordinal, reserved.count { it.startsWith("META-INF/.qp/future/") })
                        "META-INF/.qp/future/${candidate.entryToken.toULong().toString(16)}-$ordinal.bin"
                    },
                )
            }

            assertFailsWith<IllegalStateException> { checkNotNull(escapedCandidateRef).entryToken }

            checkNotNull(reservation).withRoutesForBuild { routes ->
                assertEquals(2, routes.size)
                assertEquals(0x414B_454E_0000_0001L, routes[0].entryToken)
                assertEquals("META-INF/qp/logical-one.bin", routes[0].logicalVmResourcePath)
                assertEquals("META-INF/.qp/future/414b454e00000001-0.bin", routes[0].futureContainerPath)
                assertEquals(0x414B_454E_0000_0002L, routes[1].entryToken)
                assertEquals("META-INF/qp/logical-two.bin", routes[1].logicalVmResourcePath)
                assertEquals("META-INF/.qp/future/414b454e00000002-1.bin", routes[1].futureContainerPath)
                escapedRoute = routes.first()
            }
            assertFailsWith<IllegalStateException> { checkNotNull(escapedRoute).futureContainerPath }

            val scopedCopy = context.scopedCopy()
            try {
                assertFailsWith<IllegalStateException> {
                    scopedCopy.withQpRouteCandidateRefsForBuild { error("scoped copy must not inherit candidate refs") }
                }
            } finally {
                scopedCopy.wipe()
            }

            checkNotNull(reservation).wipe()
            assertFailsWith<IllegalStateException> {
                checkNotNull(reservation).withRoutesForBuild { error("wiped reservation must not expose routes") }
            }
        } finally {
            reservation?.wipe()
            context.wipe()
        }

        assertFailsWith<IllegalStateException> {
            context.withQpRouteCandidateRefsForBuild { error("wiped context must not expose candidate refs") }
        }
    }

    @Test
    fun reservation_rejects_nondeterminism_invalid_output_and_duplicate_candidate_identity() {
        val ref0 = QpRouteCandidateRef.create(7L, "META-INF/qp/a.bin")
        val ref1 = QpRouteCandidateRef.create(8L, "META-INF/qp/b.bin")
        var calls = 0
        try {
            assertFailsWith<IllegalArgumentException> {
                QpPreSealRouteReservation.reserve(
                    candidateRefs = listOf(ref0, ref1),
                    occupiedEntryPaths = emptySet(),
                    allocator = QpPreSealRouteAllocator { _, ordinal, _ ->
                        "META-INF/.qp/nondeterministic/${ordinal}-${calls++}.bin"
                    },
                )
            }

            assertFailsWith<IllegalArgumentException> {
                QpPreSealRouteReservation.reserve(
                    candidateRefs = listOf(ref0),
                    occupiedEntryPaths = setOf("META-INF/existing.bin"),
                    allocator = QpPreSealRouteAllocator { _, _, _ -> "META-INF/existing.bin" },
                )
            }

            assertFailsWith<IllegalArgumentException> {
                QpPreSealRouteReservation.reserve(
                    candidateRefs = listOf(ref0),
                    occupiedEntryPaths = emptySet(),
                    allocator = QpPreSealRouteAllocator { _, _, _ -> "/invalid.bin" },
                )
            }

            val duplicateToken = QpRouteCandidateRef.create(7L, "META-INF/qp/other.bin")
            try {
                assertFailsWith<IllegalArgumentException> {
                    QpPreSealRouteReservation.reserve(
                        candidateRefs = listOf(ref0, duplicateToken),
                        occupiedEntryPaths = emptySet(),
                        allocator = QpPreSealRouteAllocator { candidate, _, _ ->
                            "META-INF/.qp/future/${candidate.entryToken}.bin"
                        },
                    )
                }
            } finally {
                duplicateToken.wipe()
            }
        } finally {
            ref0.wipe()
            ref1.wipe()
        }

    }

    private fun candidate(
        entryToken: Long,
        logicalVmResourcePath: String,
        logicalIdentity: ByteArray,
        serializedProgram: ByteArray,
    ): QpMethodCandidate = QpMethodCandidate.create(
        entryToken = entryToken,
        logicalMethod = QpMethodIdentity.create(
            dispatchClassToken = "route-class-$entryToken",
            dispatchMethodToken = "route-method-$entryToken",
            descriptor = "()V",
            logicalVmResourcePath = logicalVmResourcePath,
        ),
        logicalIdentity = logicalIdentity,
        serializedProgram = serializedProgram,
    )
}
