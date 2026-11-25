package io.github.hht0rro.javashroud.transforms.protection.qp

import io.github.hht0rro.javashroud.transforms.protection.QpBuildContext
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class QpPreSealRouteReservationTest {
    @Test
    fun pre_seal_routes_are_scoped_deterministic_and_collision_checked() {
        val context = QpBuildContext(
            masterKey = ByteArray(32) { index -> (index * 5 + 1).toByte() },
            nativeSeed = 0x5EAL,
            jarLayoutDigest = ByteArray(32) { index -> (index * 7 + 3).toByte() },
        )
        val laterCandidate = candidate(
            entryToken = 20L,
            logicalVmResourcePath = "META-INF/qp/logical-z.bin",
        )
        val earlierCandidate = candidate(
            entryToken = 10L,
            logicalVmResourcePath = "META-INF/qp/logical-a.bin",
        )
        var escapedContextRef: QpRouteCandidateRef? = null
        var escapedAllocatorRef: QpRouteCandidateRef? = null
        var escapedRoute: QpPreSealRoute? = null
        var reservation: QpPreSealRouteReservation? = null
        try {
            context.registerQpMethodCandidates(listOf(laterCandidate, earlierCandidate))
            laterCandidate.wipe()
            earlierCandidate.wipe()

            val allocationTrace = mutableListOf<String>()
            context.withQpRouteCandidateRefsForBuild { candidateRefs ->
                assertEquals(listOf(10L, 20L), candidateRefs.map { candidate -> candidate.entryToken })
                assertEquals(
                    listOf("META-INF/qp/logical-a.bin", "META-INF/qp/logical-z.bin"),
                    candidateRefs.map { candidate -> candidate.logicalVmResourcePath },
                )
                escapedContextRef = candidateRefs.first()

                reservation = QpPreSealRouteReservation.reserve(
                    candidateRefs = candidateRefs,
                    occupiedEntryPaths = linkedSetOf("META-INF/already-reserved.bin"),
                    allocator = QpPreSealRouteAllocator { candidate, ordinal, reservedEntryPaths ->
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
                        "META-INF/future-qp/qp-$ordinal-${candidate.entryToken}.bin"
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
                    "0|10|META-INF/qp/logical-a.bin|META-INF/already-reserved.bin",
                    "1|20|META-INF/qp/logical-z.bin|META-INF/already-reserved.bin,META-INF/future-qp/qp-0-10.bin",
                    "0|10|META-INF/qp/logical-a.bin|META-INF/already-reserved.bin",
                    "1|20|META-INF/qp/logical-z.bin|META-INF/already-reserved.bin,META-INF/future-qp/qp-0-10.bin",
                ),
                allocationTrace,
            )

            checkNotNull(reservation).withRoutesForBuild { routes ->
                assertEquals(listOf(10L, 20L), routes.map { route -> route.entryToken })
                assertEquals(
                    listOf("META-INF/qp/logical-a.bin", "META-INF/qp/logical-z.bin"),
                    routes.map { route -> route.logicalVmResourcePath },
                )
                assertEquals(
                    listOf(
                        "META-INF/future-qp/qp-0-10.bin",
                        "META-INF/future-qp/qp-1-20.bin",
                    ),
                    routes.map { route -> route.futureContainerPath },
                )
                escapedRoute = routes.first()
            }
            assertFailsWith<IllegalStateException> {
                checkNotNull(escapedRoute).logicalVmResourcePath
            }
            checkNotNull(reservation).withRoutesForBuild { routes ->
                assertEquals("META-INF/future-qp/qp-0-10.bin", routes.first().futureContainerPath)
            }

            context.withQpRouteCandidateRefsForBuild { candidateRefs ->
                assertFailsWith<IllegalArgumentException> {
                    QpPreSealRouteReservation.reserve(
                        candidateRefs = candidateRefs,
                        occupiedEntryPaths = setOf("META-INF/future-qp/collision.bin"),
                        allocator = QpPreSealRouteAllocator { _, _, _ ->
                            "META-INF/future-qp/collision.bin"
                        },
                    )
                }

                assertFailsWith<IllegalArgumentException> {
                    QpPreSealRouteReservation.reserve(
                        candidateRefs = candidateRefs,
                        occupiedEntryPaths = emptySet(),
                        allocator = QpPreSealRouteAllocator { _, _, _ ->
                            "META-INF/future-qp/duplicate-output.bin"
                        },
                    )
                }

                var allocationAttempt = 0
                assertFailsWith<IllegalArgumentException> {
                    QpPreSealRouteReservation.reserve(
                        candidateRefs = candidateRefs,
                        occupiedEntryPaths = emptySet(),
                        allocator = QpPreSealRouteAllocator { candidate, _, _ ->
                            "META-INF/future-qp/non-deterministic-${candidate.entryToken}-${allocationAttempt++}.bin"
                        },
                    )
                }

                assertFailsWith<IllegalArgumentException> {
                    QpPreSealRouteReservation.reserve(
                        candidateRefs = candidateRefs,
                        occupiedEntryPaths = emptySet(),
                        allocator = QpPreSealRouteAllocator { _, _, _ -> "../invalid.bin" },
                    )
                }
            }

            assertDuplicateCandidateInputsAreRejected()
        } finally {
            reservation?.wipe()
            context.wipe()
        }

        assertFailsWith<IllegalStateException> {
            context.withQpRouteCandidateRefsForBuild { error("wiped context exposed route candidate refs") }
        }
        assertFailsWith<IllegalStateException> {
            checkNotNull(reservation).withRoutesForBuild { error("wiped reservation exposed routes") }
        }
    }

    private fun assertDuplicateCandidateInputsAreRejected() {
        val firstToken = QpRouteCandidateRef.create(1L, "META-INF/qp/one.bin")
        val duplicateToken = QpRouteCandidateRef.create(1L, "META-INF/qp/two.bin")
        val firstPath = QpRouteCandidateRef.create(2L, "META-INF/qp/shared.bin")
        val duplicatePath = QpRouteCandidateRef.create(3L, "META-INF/qp/shared.bin")
        try {
            assertFailsWith<IllegalArgumentException> {
                QpPreSealRouteReservation.reserve(
                    candidateRefs = listOf(firstToken, duplicateToken),
                    occupiedEntryPaths = emptySet(),
                    allocator = deterministicAllocator(),
                )
            }
            assertFailsWith<IllegalArgumentException> {
                QpPreSealRouteReservation.reserve(
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

    private fun deterministicAllocator(): QpPreSealRouteAllocator =
        QpPreSealRouteAllocator { candidate, ordinal, _ ->
            "META-INF/future-qp/route-$ordinal-${candidate.entryToken}.bin"
        }

    private fun candidate(
        entryToken: Long,
        logicalVmResourcePath: String,
    ): QpMethodCandidate {
        val logicalIdentity = ByteArray(32) { index -> (entryToken + index).toByte() }
        val serializedProgram = ByteArray(96) { index -> (entryToken * 3 + index).toByte() }
        return try {
            QpMethodCandidate.create(
                entryToken = entryToken,
                logicalMethod = QpMethodIdentity.create(
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
