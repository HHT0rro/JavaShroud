package io.github.hht0rro.javashroud.transforms.protection.aken

import java.util.Collections

/**
 * Minimal build-only projection for assigning a future physical resource path
 * to one logical NativeChunk. It contains no UTF-8 plaintext, evaluator state,
 * DEK, handle bytes, or call-site proof.
 */
internal class AkenNativeChunkRouteCandidateRef private constructor(
    private var identityPageKeyValue: String,
    private var logicalBindingPathValue: String,
) : AutoCloseable {
    @Volatile
    private var wiped: Boolean = false

    val identityPageKey: String
        get() {
            requireLive()
            return identityPageKeyValue
        }

    val logicalBindingPath: String
        get() {
            requireLive()
            return logicalBindingPathValue
        }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        identityPageKeyValue = ""
        logicalBindingPathValue = ""
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN NativeChunk route candidate ref has been wiped" }
    }

    companion object {
        internal fun create(
            identityPageKey: String,
            logicalBindingPath: String,
        ): AkenNativeChunkRouteCandidateRef {
            requireValidIdentityPageKey(identityPageKey)
            AkenVbc4RouteCandidateRef.requireValidArtifactEntryPath(
                value = logicalBindingPath,
                label = "AKEN NativeChunk route candidate logical binding path",
            )
            return AkenNativeChunkRouteCandidateRef(identityPageKey, logicalBindingPath)
        }

        internal fun requireValidIdentityPageKey(value: String) {
            require(
                value.isNotBlank() &&
                    value.length <= MAX_IDENTITY_PAGE_KEY_LENGTH &&
                    value.all { character ->
                        character in 'A'..'Z' ||
                            character in 'a'..'z' ||
                            character in '0'..'9' ||
                            character == '-' ||
                            character == '_'
                    },
            ) {
                "AKEN NativeChunk route candidate identity key is invalid"
            }
        }

        private const val MAX_IDENTITY_PAGE_KEY_LENGTH = 128
    }
}

/** Sealing-owned allocator for future NativeChunk resource paths. */
internal fun interface AkenNativeChunkPreSealRouteAllocator {
    fun allocate(
        candidate: AkenNativeChunkRouteCandidateRef,
        ordinal: Int,
        reservedEntryPaths: Set<String>,
    ): String
}

/** One scoped final resource route for one logical NativeChunk. */
internal class AkenNativeChunkPreSealRoute private constructor(
    private var identityPageKeyValue: String,
    private var logicalBindingPathValue: String,
    private var futureResourcePathValue: String,
) : AutoCloseable {
    @Volatile
    private var wiped: Boolean = false

    val identityPageKey: String
        get() {
            requireLive()
            return identityPageKeyValue
        }

    val logicalBindingPath: String
        get() {
            requireLive()
            return logicalBindingPathValue
        }

    val futureResourcePath: String
        get() {
            requireLive()
            return futureResourcePathValue
        }

    override fun close() = wipe()

    fun wipe() {
        if (wiped) return
        identityPageKeyValue = ""
        logicalBindingPathValue = ""
        futureResourcePathValue = ""
        wiped = true
    }

    private fun requireLive() {
        check(!wiped) { "AKEN NativeChunk pre-seal route has been wiped" }
    }

    companion object {
        internal fun create(
            identityPageKey: String,
            logicalBindingPath: String,
            futureResourcePath: String,
        ): AkenNativeChunkPreSealRoute {
            AkenNativeChunkRouteCandidateRef.requireValidIdentityPageKey(identityPageKey)
            AkenVbc4RouteCandidateRef.requireValidArtifactEntryPath(
                value = logicalBindingPath,
                label = "AKEN NativeChunk pre-seal logical binding path",
            )
            AkenVbc4RouteCandidateRef.requireValidArtifactEntryPath(
                value = futureResourcePath,
                label = "AKEN NativeChunk pre-seal future resource path",
            )
            return AkenNativeChunkPreSealRoute(
                identityPageKeyValue = identityPageKey,
                logicalBindingPathValue = logicalBindingPath,
                futureResourcePathValue = futureResourcePath,
            )
        }
    }
}

/**
 * Pure build-only reservation of NativeChunk resource paths before final
 * sealing. The allocator runs twice against identical route-safe inputs; a
 * stateful or nondeterministic allocator is rejected before any page
 * plaintext, handle, proof, or evaluator state is consumed.
 */
internal class AkenNativeChunkPreSealRouteReservation private constructor(
    routes: List<RouteAllocation>,
) : AutoCloseable {
    private var routesValue: List<RouteAllocation> = routes

    @Volatile
    private var wiped: Boolean = false

    internal val isWiped: Boolean
        get() = wiped

    fun <T> withRoutesForBuild(block: (List<AkenNativeChunkPreSealRoute>) -> T): T {
        val snapshots = synchronized(this) {
            requireLive()
            routesValue.map { route ->
                AkenNativeChunkPreSealRoute.create(
                    identityPageKey = route.identityPageKey,
                    logicalBindingPath = route.logicalBindingPath,
                    futureResourcePath = route.futureResourcePath,
                )
            }
        }
        try {
            return block(snapshots.toList())
        } finally {
            snapshots.forEach { it.wipe() }
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
        check(!wiped) { "AKEN NativeChunk pre-seal route reservation has been wiped" }
    }

    private data class RouteAllocation(
        val identityPageKey: String,
        val logicalBindingPath: String,
        val futureResourcePath: String,
    )

    companion object {
        fun reserve(
            candidateRefs: Iterable<AkenNativeChunkRouteCandidateRef>,
            occupiedEntryPaths: Set<String>,
            allocator: AkenNativeChunkPreSealRouteAllocator,
        ): AkenNativeChunkPreSealRouteReservation {
            val candidates = snapshotCandidates(candidateRefs)
            val initialNamespace = snapshotNamespace(occupiedEntryPaths)
            val firstPass = allocatePass(candidates, initialNamespace, allocator)
            val verificationPass = allocatePass(candidates, initialNamespace, allocator)
            require(firstPass == verificationPass) {
                "AKEN NativeChunk pre-seal route allocator must return deterministic paths"
            }
            return AkenNativeChunkPreSealRouteReservation(firstPass)
        }

        private fun snapshotCandidates(
            candidateRefs: Iterable<AkenNativeChunkRouteCandidateRef>,
        ): List<CandidateInput> {
            val candidates = candidateRefs.map { candidate ->
                CandidateInput(
                    identityPageKey = candidate.identityPageKey,
                    logicalBindingPath = candidate.logicalBindingPath,
                )
            }
            require(candidates.isNotEmpty()) { "AKEN NativeChunk pre-seal route candidates are not initialized" }
            require(candidates.map { it.identityPageKey }.distinct().size == candidates.size) {
                "AKEN NativeChunk pre-seal route candidates contain duplicate identity keys"
            }
            candidates.forEach { candidate ->
                AkenNativeChunkRouteCandidateRef.requireValidIdentityPageKey(candidate.identityPageKey)
                AkenVbc4RouteCandidateRef.requireValidArtifactEntryPath(
                    value = candidate.logicalBindingPath,
                    label = "AKEN NativeChunk pre-seal route candidate logical binding path",
                )
            }
            return candidates.sortedWith(
                compareBy<CandidateInput> { it.identityPageKey }
                    .thenBy { it.logicalBindingPath },
            )
        }

        private fun snapshotNamespace(occupiedEntryPaths: Set<String>): Set<String> {
            val namespace = LinkedHashSet<String>(occupiedEntryPaths.size)
            occupiedEntryPaths.forEach { path ->
                AkenVbc4RouteCandidateRef.requireValidArtifactEntryPath(
                    value = path,
                    label = "AKEN NativeChunk pre-seal occupied resource path",
                )
                namespace += path
            }
            return Collections.unmodifiableSet(namespace)
        }

        private fun allocatePass(
            candidates: List<CandidateInput>,
            initialNamespace: Set<String>,
            allocator: AkenNativeChunkPreSealRouteAllocator,
        ): List<RouteAllocation> {
            val namespace = LinkedHashSet(initialNamespace)
            val allocations = ArrayList<RouteAllocation>(candidates.size)
            candidates.forEachIndexed { ordinal, candidate ->
                val allocatorCandidate = AkenNativeChunkRouteCandidateRef.create(
                    identityPageKey = candidate.identityPageKey,
                    logicalBindingPath = candidate.logicalBindingPath,
                )
                val futureResourcePath = try {
                    allocator.allocate(
                        candidate = allocatorCandidate,
                        ordinal = ordinal,
                        reservedEntryPaths = Collections.unmodifiableSet(LinkedHashSet(namespace)),
                    )
                } finally {
                    allocatorCandidate.wipe()
                }
                AkenVbc4RouteCandidateRef.requireValidArtifactEntryPath(
                    value = futureResourcePath,
                    label = "AKEN NativeChunk pre-seal allocator output path",
                )
                require(futureResourcePath !in namespace) {
                    "AKEN NativeChunk pre-seal allocator output collides with an occupied resource path"
                }
                namespace += futureResourcePath
                allocations += RouteAllocation(
                    identityPageKey = candidate.identityPageKey,
                    logicalBindingPath = candidate.logicalBindingPath,
                    futureResourcePath = futureResourcePath,
                )
            }
            return allocations
        }

        private data class CandidateInput(
            val identityPageKey: String,
            val logicalBindingPath: String,
        )
    }
}
