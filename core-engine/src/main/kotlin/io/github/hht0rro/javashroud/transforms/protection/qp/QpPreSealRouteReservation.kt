package io.github.hht0rro.javashroud.transforms.protection.qp

import java.util.Collections
import java.util.LinkedHashSet

/**
 * Minimal build-only projection used while reserving future Qp VM page-container
 * routes before sealing assigns the artifact namespace.
 *
 * The projection intentionally carries only the dispatcher entry token and the
 * logical Qp VM resource identity. It is scoped and invalidated after use so a
 * routing allocator never receives a serialized method program or page state.
 */
internal class QpRouteCandidateRef private constructor(
    private var entryTokenValue: Long,
    private var logicalVmResourcePathValue: String,
) : AutoCloseable {
    @Volatile
    private var wiped: Boolean = false

    val entryToken: Long
        get() {
            requireLive()
            return entryTokenValue
        }

    val logicalVmResourcePath: String
        get() {
            requireLive()
            return logicalVmResourcePathValue
        }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        entryTokenValue = 0L
        logicalVmResourcePathValue = ""
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "Qp current-format route candidate ref has been wiped" }
    }

    companion object {
        internal fun create(
            entryToken: Long,
            logicalVmResourcePath: String,
        ): QpRouteCandidateRef {
            requireValidArtifactEntryPath(
                value = logicalVmResourcePath,
                label = "Qp current-format route candidate logical resource path",
            )
            return QpRouteCandidateRef(
                entryTokenValue = entryToken,
                logicalVmResourcePathValue = logicalVmResourcePath,
            )
        }

        internal fun requireValidArtifactEntryPath(value: String, label: String) {
            require(isValidArtifactEntryPath(value)) { "$label is invalid" }
        }

        private fun isValidArtifactEntryPath(value: String): Boolean =
            value.isNotBlank() &&
                value == value.trim() &&
                !value.startsWith('/') &&
                !value.endsWith('/') &&
                !value.contains('\\') &&
                !value.contains('\u0000') &&
                value.split('/').all { segment ->
                    segment.isNotBlank() && segment != "." && segment != ".."
                }
    }
}

/**
 * Sealing-owned route allocator used by [QpPreSealRouteReservation].
 *
 * The allocator owns its resource-name grammar and collision strategy. This
 * contract only supplies a stable candidate order and an immutable view of the
 * namespace already reserved for the current allocation pass.
 */
internal fun interface QpPreSealRouteAllocator {
    fun allocate(
        candidate: QpRouteCandidateRef,
        ordinal: Int,
        reservedEntryPaths: Set<String>,
    ): String
}

/**
 * One sealed-name reservation for a Qp VM method entry.
 *
 * The result retains the entry token and logical resource identity so a later
 * sealing pass can re-check the binding before it consumes the future
 * page-container path. It deliberately omits every method-program and
 * page-level detail.
 */
internal class QpPreSealRoute private constructor(
    private var entryTokenValue: Long,
    private var logicalVmResourcePathValue: String,
    private var futureContainerPathValue: String,
) : AutoCloseable {
    @Volatile
    private var wiped: Boolean = false

    val entryToken: Long
        get() {
            requireLive()
            return entryTokenValue
        }

    val logicalVmResourcePath: String
        get() {
            requireLive()
            return logicalVmResourcePathValue
        }

    val futureContainerPath: String
        get() {
            requireLive()
            return futureContainerPathValue
        }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        entryTokenValue = 0L
        logicalVmResourcePathValue = ""
        futureContainerPathValue = ""
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "Qp current-format pre-seal route has been wiped" }
    }

    companion object {
        internal fun create(
            entryToken: Long,
            logicalVmResourcePath: String,
            futureContainerPath: String,
        ): QpPreSealRoute =
            QpPreSealRoute(
                entryTokenValue = entryToken,
                logicalVmResourcePathValue = logicalVmResourcePath,
                futureContainerPathValue = futureContainerPath,
            )
    }
}

/**
 * Pure pre-seal reservation of future Qp VM page-container paths.
 *
 * This object is build-only. It validates the supplied candidate projection,
 * invokes the sealing-owned allocator in a canonical order, validates the
 * returned namespace additions, and repeats the pass to reject stateful or
 * nondeterministic allocator output. No artifact entry is emitted here.
 */
internal class QpPreSealRouteReservation private constructor(
    routes: List<RouteAllocation>,
) : AutoCloseable {
    private var routesValue: List<RouteAllocation> = routes

    @Volatile
    private var wiped: Boolean = false

    internal val isWiped: Boolean
        get() = wiped

    /**
     * Gives the sealing stage fresh route copies. They are invalidated directly
     * after [block] returns, preventing a route snapshot from living beyond its
     * narrow build scope.
     */
    fun <T> withRoutesForBuild(block: (List<QpPreSealRoute>) -> T): T {
        val snapshots = synchronized(this) {
            requireLive()
            routesValue.map { route ->
                QpPreSealRoute.create(
                    entryToken = route.entryToken,
                    logicalVmResourcePath = route.logicalVmResourcePath,
                    futureContainerPath = route.futureContainerPath,
                )
            }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { route -> route.wipe() }
        }
    }

    override fun close() = wipe()

    @Synchronized
    fun wipe() {
        if (wiped) return
        routesValue = emptyList()
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "Qp current-format pre-seal route reservation has been wiped" }
    }

    private data class RouteAllocation(
        val entryToken: Long,
        val logicalVmResourcePath: String,
        val futureContainerPath: String,
    )

    companion object {
        /**
         * Reserve one future container path per unique Qp VM entry token.
         *
         * [allocator] is intentionally injected by the sealing layer. It must
         * be pure for a candidate, ordinal, and reserved namespace; this method
         * performs a second pass with the same inputs to enforce that contract.
         */
        fun reserve(
            candidateRefs: Iterable<QpRouteCandidateRef>,
            occupiedEntryPaths: Set<String>,
            allocator: QpPreSealRouteAllocator,
        ): QpPreSealRouteReservation {
            val candidates = snapshotCandidates(candidateRefs)
            val initialNamespace = snapshotNamespace(occupiedEntryPaths)
            val firstPass = allocatePass(candidates, initialNamespace, allocator)
            val verificationPass = allocatePass(candidates, initialNamespace, allocator)
            require(firstPass == verificationPass) {
                "Qp current-format pre-seal route allocator must return deterministic paths"
            }
            return QpPreSealRouteReservation(
                routes = firstPass,
            )
        }

        private fun snapshotCandidates(
            candidateRefs: Iterable<QpRouteCandidateRef>,
        ): List<CandidateInput> {
            val candidates = candidateRefs.map { candidate ->
                CandidateInput(
                    entryToken = candidate.entryToken,
                    logicalVmResourcePath = candidate.logicalVmResourcePath,
                )
            }
            require(candidates.isNotEmpty()) { "Qp current-format pre-seal route candidates are not initialized" }
            require(candidates.map { candidate -> candidate.entryToken }.distinct().size == candidates.size) {
                "Qp current-format pre-seal route candidates contain duplicate entry tokens"
            }
            require(candidates.map { candidate -> candidate.logicalVmResourcePath }.distinct().size == candidates.size) {
                "Qp current-format pre-seal route candidates contain duplicate logical resource paths"
            }
            candidates.forEach { candidate ->
                QpRouteCandidateRef.requireValidArtifactEntryPath(
                    value = candidate.logicalVmResourcePath,
                    label = "Qp current-format pre-seal route candidate logical resource path",
                )
            }
            return candidates.sortedWith(
                compareBy<CandidateInput> { candidate -> candidate.entryToken }
                    .thenBy { candidate -> candidate.logicalVmResourcePath },
            )
        }

        private fun snapshotNamespace(occupiedEntryPaths: Set<String>): Set<String> {
            val namespace = LinkedHashSet<String>(occupiedEntryPaths.size)
            occupiedEntryPaths.forEach { path ->
                QpRouteCandidateRef.requireValidArtifactEntryPath(
                    value = path,
                    label = "Qp current-format pre-seal occupied resource path",
                )
                namespace += path
            }
            return Collections.unmodifiableSet(namespace)
        }

        private fun allocatePass(
            candidates: List<CandidateInput>,
            initialNamespace: Set<String>,
            allocator: QpPreSealRouteAllocator,
        ): List<RouteAllocation> {
            val namespace = LinkedHashSet(initialNamespace)
            val allocations = ArrayList<RouteAllocation>(candidates.size)
            candidates.forEachIndexed { ordinal, candidate ->
                val allocatorCandidate = QpRouteCandidateRef.create(
                    entryToken = candidate.entryToken,
                    logicalVmResourcePath = candidate.logicalVmResourcePath,
                )
                val futureContainerPath = try {
                    allocator.allocate(
                        candidate = allocatorCandidate,
                        ordinal = ordinal,
                        reservedEntryPaths = Collections.unmodifiableSet(LinkedHashSet(namespace)),
                    )
                } finally {
                    allocatorCandidate.wipe()
                }
                QpRouteCandidateRef.requireValidArtifactEntryPath(
                    value = futureContainerPath,
                    label = "Qp current-format pre-seal allocator output path",
                )
                require(futureContainerPath !in namespace) {
                    "Qp current-format pre-seal allocator output collides with an occupied resource path"
                }
                namespace += futureContainerPath
                allocations += RouteAllocation(
                    entryToken = candidate.entryToken,
                    logicalVmResourcePath = candidate.logicalVmResourcePath,
                    futureContainerPath = futureContainerPath,
                )
            }
            return allocations
        }

        private data class CandidateInput(
            val entryToken: Long,
            val logicalVmResourcePath: String,
        )
    }
}
