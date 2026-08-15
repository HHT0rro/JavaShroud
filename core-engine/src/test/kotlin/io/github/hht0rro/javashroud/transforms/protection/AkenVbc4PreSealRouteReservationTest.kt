package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4LogicalMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4MethodCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PreSealRouteAllocator
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PreSealRouteReservation
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4RouteCandidateRef
import io.github.hht0rro.javashroud.transforms.protection.requireVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AkenVbc4PreSealRouteReservationTest {
    @Test
    fun production_sealing_stage_reserves_scoped_aken_page_container_routes() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 3).toByte() },
            nativeSeed = 0x4A4B_454E_0000_0011L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 5).toByte() },
        )
        val logicalPath = "META-INF/vbc4/production-route.bin"
        val program = ByteArray(96) { index -> (index * 13 + 7).toByte() }
        val identity = ByteArray(32) { index -> (index * 17 + 9).toByte() }
        val candidate = candidate(
            entryToken = 0x414B_454E_0000_0011L,
            logicalVmResourcePath = logicalPath,
            logicalIdentity = identity,
            serializedProgram = program,
        )
        try {
            withVbc4BuildContext(context) {
                val scoped = requireVbc4BuildContext()
                scoped.registerAkenVbc4MethodCandidates(listOf(candidate))
                candidate.wipe()

                val artifact = testAttachedArtifact(
                    classArtifacts = emptyList(),
                    jarEntries = listOf(JarEntryData("META-INF/existing.bin", byteArrayOf(1, 2, 3))),
                )
                assertTrue(RuntimeArtifactSealing.reserveAkenVbc4PreSealRoutesIfNeeded(artifact, scoped.nativeSeed))
                assertTrue(RuntimeArtifactSealing.reserveAkenVbc4PreSealRoutesIfNeeded(artifact, scoped.nativeSeed))

                scoped.requireAkenVbc4PreSealRouteReservation().withRoutesForBuild { routes ->
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
            logicalVmResourcePath = "META-INF/vbc4/logical-two.bin",
            logicalIdentity = identity0,
            serializedProgram = program0,
        )
        val candidate1 = candidate(
            entryToken = 0x414B_454E_0000_0001L,
            logicalVmResourcePath = "META-INF/vbc4/logical-one.bin",
            logicalIdentity = identity1,
            serializedProgram = program1,
        )
        val context = Vbc4BuildContext(
            masterKey = masterKey,
            nativeSeed = 0x5A17C0DEL,
            jarLayoutDigest = layoutDigest,
        )
        var escapedCandidateRef: AkenVbc4RouteCandidateRef? = null
        var escapedRoute: io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PreSealRoute? = null
        var reservation: AkenVbc4PreSealRouteReservation? = null
        try {
            context.registerAkenVbc4MethodCandidates(listOf(candidate0, candidate1))
            candidate0.wipe()
            candidate1.wipe()
            Arrays.fill(identity0, 0)
            Arrays.fill(identity1, 0)
            Arrays.fill(program0, 0)
            Arrays.fill(program1, 0)

            context.withAkenVbc4RouteCandidateRefsForBuild { refs ->
                assertEquals(
                    listOf(0x414B_454E_0000_0001L, 0x414B_454E_0000_0002L),
                    refs.map { it.entryToken },
                )
                assertEquals(
                    listOf("META-INF/vbc4/logical-one.bin", "META-INF/vbc4/logical-two.bin"),
                    refs.map { it.logicalVmResourcePath },
                )
                escapedCandidateRef = refs.first()
                reservation = AkenVbc4PreSealRouteReservation.reserve(
                    candidateRefs = refs,
                    occupiedEntryPaths = setOf("META-INF/existing/resource.bin"),
                    allocator = AkenVbc4PreSealRouteAllocator { candidate, ordinal, reserved ->
                        assertEquals(ordinal, reserved.count { it.startsWith("META-INF/.aken/future/") })
                        "META-INF/.aken/future/${candidate.entryToken.toULong().toString(16)}-$ordinal.bin"
                    },
                )
            }

            assertFailsWith<IllegalStateException> { checkNotNull(escapedCandidateRef).entryToken }

            checkNotNull(reservation).withRoutesForBuild { routes ->
                assertEquals(2, routes.size)
                assertEquals(0x414B_454E_0000_0001L, routes[0].entryToken)
                assertEquals("META-INF/vbc4/logical-one.bin", routes[0].logicalVmResourcePath)
                assertEquals("META-INF/.aken/future/414b454e00000001-0.bin", routes[0].futureContainerPath)
                assertEquals(0x414B_454E_0000_0002L, routes[1].entryToken)
                assertEquals("META-INF/vbc4/logical-two.bin", routes[1].logicalVmResourcePath)
                assertEquals("META-INF/.aken/future/414b454e00000002-1.bin", routes[1].futureContainerPath)
                escapedRoute = routes.first()
            }
            assertFailsWith<IllegalStateException> { checkNotNull(escapedRoute).futureContainerPath }

            val scopedCopy = context.scopedCopy()
            try {
                assertFailsWith<IllegalStateException> {
                    scopedCopy.withAkenVbc4RouteCandidateRefsForBuild { error("scoped copy must not inherit candidate refs") }
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
            context.withAkenVbc4RouteCandidateRefsForBuild { error("wiped context must not expose candidate refs") }
        }
    }

    @Test
    fun reservation_rejects_nondeterminism_invalid_output_and_duplicate_candidate_identity() {
        val ref0 = AkenVbc4RouteCandidateRef.create(7L, "META-INF/vbc4/a.bin")
        val ref1 = AkenVbc4RouteCandidateRef.create(8L, "META-INF/vbc4/b.bin")
        var calls = 0
        try {
            assertFailsWith<IllegalArgumentException> {
                AkenVbc4PreSealRouteReservation.reserve(
                    candidateRefs = listOf(ref0, ref1),
                    occupiedEntryPaths = emptySet(),
                    allocator = AkenVbc4PreSealRouteAllocator { _, ordinal, _ ->
                        "META-INF/.aken/nondeterministic/${ordinal}-${calls++}.bin"
                    },
                )
            }

            assertFailsWith<IllegalArgumentException> {
                AkenVbc4PreSealRouteReservation.reserve(
                    candidateRefs = listOf(ref0),
                    occupiedEntryPaths = setOf("META-INF/existing.bin"),
                    allocator = AkenVbc4PreSealRouteAllocator { _, _, _ -> "META-INF/existing.bin" },
                )
            }

            assertFailsWith<IllegalArgumentException> {
                AkenVbc4PreSealRouteReservation.reserve(
                    candidateRefs = listOf(ref0),
                    occupiedEntryPaths = emptySet(),
                    allocator = AkenVbc4PreSealRouteAllocator { _, _, _ -> "/invalid.bin" },
                )
            }

            val duplicateToken = AkenVbc4RouteCandidateRef.create(7L, "META-INF/vbc4/other.bin")
            try {
                assertFailsWith<IllegalArgumentException> {
                    AkenVbc4PreSealRouteReservation.reserve(
                        candidateRefs = listOf(ref0, duplicateToken),
                        occupiedEntryPaths = emptySet(),
                        allocator = AkenVbc4PreSealRouteAllocator { candidate, _, _ ->
                            "META-INF/.aken/future/${candidate.entryToken}.bin"
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
    ): AkenVbc4MethodCandidate = AkenVbc4MethodCandidate.create(
        entryToken = entryToken,
        logicalMethod = AkenVbc4LogicalMethodIdentity.create(
            dispatchClassToken = "route-class-$entryToken",
            dispatchMethodToken = "route-method-$entryToken",
            descriptor = "()V",
            logicalVmResourcePath = logicalVmResourcePath,
        ),
        logicalIdentity = logicalIdentity,
        serializedProgram = serializedProgram,
    )
}
