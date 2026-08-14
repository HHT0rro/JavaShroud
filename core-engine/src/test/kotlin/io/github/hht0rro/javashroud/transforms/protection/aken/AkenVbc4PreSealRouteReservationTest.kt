package io.github.hht0rro.javashroud.transforms.protection.aken

import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AkenVbc4PreSealRouteReservationTest {
    @Test
    fun pre_seal_routes_are_scoped_deterministic_and_collision_checked() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { index -> (index * 5 + 1).toByte() },
            nativeSeed = 0x5EAL,
            jarLayoutDigest = ByteArray(32) { index -> (index * 7 + 3).toByte() },
        )
        val laterCandidate = candidate(
            entryToken = 20L,
            logicalVmResourcePath = "META-INF/vbc4/logical-z.bin",
        )
        val earlierCandidate = candidate(
            entryToken = 10L,
            logicalVmResourcePath = "META-INF/vbc4/logical-a.bin",
        )
        var escapedContextRef: AkenVbc4RouteCandidateRef? = null
        var escapedAllocatorRef: AkenVbc4RouteCandidateRef? = null
        var escapedRoute: AkenVbc4PreSealRoute? = null
        var reservation: AkenVbc4PreSealRouteReservation? = null
        try {
            context.registerAkenVbc4MethodCandidates(listOf(laterCandidate, earlierCandidate))
            laterCandidate.wipe()
            earlierCandidate.wipe()

            val allocationTrace = mutableListOf<String>()
            context.withAkenVbc4RouteCandidateRefsForBuild { candidateRefs ->
                assertEquals(listOf(10L, 20L), candidateRefs.map { candidate -> candidate.entryToken })
                assertEquals(
                    listOf("META-INF/vbc4/logical-a.bin", "META-INF/vbc4/logical-z.bin"),
                    candidateRefs.map { candidate -> candidate.logicalVmResourcePath },
                )
                escapedContextRef = candidateRefs.first()

                reservation = AkenVbc4PreSealRouteReservation.reserve(
                    candidateRefs = candidateRefs,
                    occupiedEntryPaths = linkedSetOf("META-INF/already-reserved.bin"),
                    allocator = AkenVbc4PreSealRouteAllocator { candidate, ordinal, reservedEntryPaths ->
                        @Suppress("UNCHECKED_CAST")
                        assertFailsWith<UnsupportedOperationException> {
                            (reservedEntryPaths as MutableSet<String>) += "META-INF/mutated.bin"
                        }
                        escapedAllocatorRef = candidate
                        allocationTrace += listOf(
                            ordinal,
                            candidate.entryToken,
                            candidate.logicalVmResourcePath,
                            reservedEntryPaths.toList().sorted().joinToString(","),
                        ).joinToString("|")
                        "META-INF/future-aken/vbc4-$ordinal-${candidate.entryToken}.bin"
                    },
                )
            }

            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedContextRef).logicalVmResourcePath
            }
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedAllocatorRef).entryToken
            }
            assertEquals(
                listOf(
                    "0|10|META-INF/vbc4/logical-a.bin|META-INF/already-reserved.bin",
                    "1|20|META-INF/vbc4/logical-z.bin|META-INF/already-reserved.bin,META-INF/future-aken/vbc4-0-10.bin",
                    "0|10|META-INF/vbc4/logical-a.bin|META-INF/already-reserved.bin",
                    "1|20|META-INF/vbc4/logical-z.bin|META-INF/already-reserved.bin,META-INF/future-aken/vbc4-0-10.bin",
                ),
                allocationTrace,
            )

            checkNotNull(reservation).withRoutesForBuild { routes ->
                assertEquals(listOf(10L, 20L), routes.map { route -> route.entryToken })
                assertEquals(
                    listOf("META-INF/vbc4/logical-a.bin", "META-INF/vbc4/logical-z.bin"),
                    routes.map { route -> route.logicalVmResourcePath },
                )
                assertEquals(
                    listOf(
                        "META-INF/future-aken/vbc4-0-10.bin",
                        "META-INF/future-aken/vbc4-1-20.bin",
                    ),
                    routes.map { route -> route.futureContainerPath },
                )
                escapedRoute = routes.first()
            }
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedRoute).logicalVmResourcePath
            }
            checkNotNull(reservation).withRoutesForBuild { routes ->
                assertEquals("META-INF/future-aken/vbc4-0-10.bin", routes.first().futureContainerPath)
            }

            context.withAkenVbc4RouteCandidateRefsForBuild { candidateRefs ->
                assertFailsWith<IllegalArgumentException> {
                    AkenVbc4PreSealRouteReservation.reserve(
                        candidateRefs = candidateRefs,
                        occupiedEntryPaths = setOf("META-INF/future-aken/collision.bin"),
                        allocator = AkenVbc4PreSealRouteAllocator { _, _, _ ->
                            "META-INF/future-aken/collision.bin"
                        },
                    )
                }

                assertFailsWith<IllegalArgumentException> {
                    AkenVbc4PreSealRouteReservation.reserve(
                        candidateRefs = candidateRefs,
                        occupiedEntryPaths = emptySet(),
                        allocator = AkenVbc4PreSealRouteAllocator { _, _, _ ->
                            "META-INF/future-aken/duplicate-output.bin"
                        },
                    )
                }

                var allocationAttempt = 0
                assertFailsWith<IllegalArgumentException> {
                    AkenVbc4PreSealRouteReservation.reserve(
                        candidateRefs = candidateRefs,
                        occupiedEntryPaths = emptySet(),
                        allocator = AkenVbc4PreSealRouteAllocator { candidate, _, _ ->
                            "META-INF/future-aken/non-deterministic-${candidate.entryToken}-${allocationAttempt++}.bin"
                        },
                    )
                }

                assertFailsWith<IllegalArgumentException> {
                    AkenVbc4PreSealRouteReservation.reserve(
                        candidateRefs = candidateRefs,
                        occupiedEntryPaths = emptySet(),
                        allocator = AkenVbc4PreSealRouteAllocator { _, _, _ -> "../invalid.bin" },
                    )
                }
            }

            assertDuplicateCandidateInputsAreRejected()
        } finally {
            reservation?.wipe()
            context.wipe()
        }

        assertFailsWith<IllegalStateException> {
            context.withAkenVbc4RouteCandidateRefsForBuild { error("wiped context exposed route candidate refs") }
        }
        assertFailsWith<IllegalStateException> {
            checkNotNull(reservation).withRoutesForBuild { error("wiped reservation exposed routes") }
        }
    }

    private fun assertDuplicateCandidateInputsAreRejected() {
        val firstToken = AkenVbc4RouteCandidateRef.create(1L, "META-INF/vbc4/one.bin")
        val duplicateToken = AkenVbc4RouteCandidateRef.create(1L, "META-INF/vbc4/two.bin")
        val firstPath = AkenVbc4RouteCandidateRef.create(2L, "META-INF/vbc4/shared.bin")
        val duplicatePath = AkenVbc4RouteCandidateRef.create(3L, "META-INF/vbc4/shared.bin")
        try {
            assertFailsWith<IllegalArgumentException> {
                AkenVbc4PreSealRouteReservation.reserve(
                    candidateRefs = listOf(firstToken, duplicateToken),
                    occupiedEntryPaths = emptySet(),
                    allocator = deterministicAllocator(),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                AkenVbc4PreSealRouteReservation.reserve(
                    candidateRefs = listOf(firstPath, duplicatePath),
                    occupiedEntryPaths = emptySet(),
                    allocator = deterministicAllocator(),
                )
            }
        } finally {
            firstToken.wipe()
            duplicateToken.wipe()
            firstPath.wipe()
            duplicatePath.wipe()
        }
    }

    private fun deterministicAllocator(): AkenVbc4PreSealRouteAllocator =
        AkenVbc4PreSealRouteAllocator { candidate, ordinal, _ ->
            "META-INF/future-aken/route-$ordinal-${candidate.entryToken}.bin"
        }

    private fun candidate(
        entryToken: Long,
        logicalVmResourcePath: String,
    ): AkenVbc4MethodCandidate {
        val logicalIdentity = ByteArray(32) { index -> (entryToken + index).toByte() }
        val serializedProgram = ByteArray(96) { index -> (entryToken * 3 + index).toByte() }
        return try {
            AkenVbc4MethodCandidate.create(
                entryToken = entryToken,
                logicalMethod = AkenVbc4LogicalMethodIdentity.create(
                    dispatchClassToken = "class-$entryToken",
                    dispatchMethodToken = "method-$entryToken",
                    descriptor = "()V",
                    logicalVmResourcePath = logicalVmResourcePath,
                ),
                logicalIdentity = logicalIdentity,
                serializedProgram = serializedProgram,
            )
        } finally {
            Arrays.fill(logicalIdentity, 0)
            Arrays.fill(serializedProgram, 0)
        }
    }
}
