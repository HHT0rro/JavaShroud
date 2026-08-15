package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPageBatch
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPagePlanner
import java.security.SecureRandom
import java.util.Arrays

/**
 * Build-only production hand-off from registered VBC4 candidates to the native
 * recompilation stage.
 *
 * The native compiler must receive page-local locator records before it emits a
 * JNI library. This owner therefore consumes the scoped candidate registry,
 * materializes the reserved page containers, publishes the finalization layout
 * to the active build context, and returns an artifact containing only the
 * encrypted page entries. It does not create a runtime catalog or expose a
 * generic page decoder.
 */
internal object AkenVbc4ProductionMaterializer {
    fun materializeBeforeNativeCompilation(
        artifact: BytecodeArtifact,
        seed: Long,
    ): BytecodeArtifact {
        val context = currentVbc4BuildContextOrNull() ?: return artifact
        if (!context.hasAkenVbc4MethodCandidates()) return artifact
        if (context.akenVbc4FinalizationLayoutOrNull() != null) return artifact

        val reservation = context.requireAkenVbc4PreSealRouteReservation()
        val fixedEntries = fixedEntriesForArtifact(artifact)
        val batches = ArrayList<AkenVbc4PendingPageBatch>()
        var layout: AkenVbc4FinalizationLayout? = null
        var pageEntriesTransferred = false

        try {
            context.withAkenVbc4MethodCandidatesForBuild { candidates ->
                reservation.withRoutesForBuild { routes ->
                    candidates.sortedBy { it.entryToken }.forEach { candidate ->
                        val route = routes.singleOrNull { candidateRoute ->
                            candidateRoute.entryToken == candidate.entryToken &&
                                candidateRoute.logicalVmResourcePath == candidate.logicalMethod.logicalVmResourcePath
                        } ?: error(
                            "AKEN VBC4 pre-seal route is missing for entry token ${candidate.entryToken}",
                        )
                        try {
                            batches += AkenVbc4PendingPagePlanner.partitionAndWipe(
                                candidate = candidate,
                                route = route,
                                callSiteProofForPage = { pageIndex ->
                                    AkenVbc4CallSiteProof.derive(
                                        seed = seed,
                                        entryToken = candidate.entryToken,
                                        logicalVmResourcePath = candidate.logicalMethod.logicalVmResourcePath,
                                        pageIndex = pageIndex,
                                    )
                                },
                                random = SecureRandom(),
                            )
                        } finally {
                            route.wipe()
                        }
                    }
                }
            }
            require(batches.isNotEmpty()) { "AKEN VBC4 production materialization found no page batches" }

            consumeBatchesAndMaterialize(
                context = context,
                batches = batches,
                fixedEntries = fixedEntries,
            ) { finalized ->
                layout = finalized
            }

            val finalized = checkNotNull(layout)
            val existingNames = artifact.jarEntries.mapTo(HashSet()) { it.name }
            val pageEntries = ArrayList<JarEntryData>()
            finalized.entriesForBuild()
                .filter { entry -> entry.name !in existingNames }
                .forEach { entry ->
                    val bytes = entry.copyBytesForBuild()
                    pageEntries += JarEntryData(entry.name, bytes)
                }
            require(pageEntries.isNotEmpty()) {
                "AKEN VBC4 production materialization emitted no new page entries"
            }
            pageEntriesTransferred = true
            context.publishAkenVbc4FinalizationLayout(finalized)
            return artifact.copy(
                jarEntries = artifact.jarEntries + pageEntries,
                analysisSummary = artifact.analysisSummary.copy(
                    resourceCount = resourceCount(artifact.jarEntries + pageEntries, artifact.classArtifacts.size),
                ),
            )
        } catch (error: Throwable) {
            layout?.wipe()
            throw error
        } finally {
            batches.forEach { it.wipe() }
            if (!pageEntriesTransferred) {
                layout?.wipe()
            }
        }
    }

    private fun consumeBatchesAndMaterialize(
        context: Vbc4BuildContext,
        batches: List<AkenVbc4PendingPageBatch>,
        fixedEntries: List<AkenArtifactEntry>,
        publish: (AkenVbc4FinalizationLayout) -> Unit,
    ) {
        fun consumeAt(index: Int, pages: List<AkenVbc4PendingPage>) {
            if (index == batches.size) {
                val commitment = AkenVbc4FinalizationLayout.reserve(
                    pendingPages = pages,
                    fixedEntries = fixedEntries,
                )
                val commitmentBytes = commitment.copyBytes()
                val plan = try {
                    context.initializeAkenBuildPlan(commitmentBytes)
                } finally {
                    Arrays.fill(commitmentBytes, 0)
                }
                val finalized = AkenVbc4FinalizationLayout.materializeAndWipe(
                    plan = plan,
                    commitment = commitment,
                    pendingPages = pages,
                    fixedEntries = fixedEntries,
                )
                publish(finalized)
                return
            }

            batches[index].consumePendingPagesForBuild { batchPages ->
                val combined = ArrayList<AkenVbc4PendingPage>(pages.size + batchPages.size)
                combined.addAll(pages)
                combined.addAll(batchPages)
                consumeAt(index + 1, combined)
            }
        }

        consumeAt(0, emptyList())
    }

    private fun fixedEntriesForArtifact(artifact: BytecodeArtifact): List<AkenArtifactEntry> {
        val classesByEntry = artifact.classArtifacts.associateBy { it.entryName }
        return artifact.jarEntries.map { entry ->
            val bytes = classesByEntry[entry.name]?.bytes ?: entry.bytes
            AkenArtifactEntry(entry.name, bytes)
        }
    }
}

/** Build-only, deterministic proof material for one generated VBC4 page call site. */
internal object AkenVbc4CallSiteProof {
    private val DOMAIN = "AKEN-v4-vbc4-call-site-proof-v1".toByteArray(Charsets.US_ASCII)

    fun derive(
        seed: Long,
        entryToken: Long,
        logicalVmResourcePath: String,
        pageIndex: Int,
    ): ByteArray {
        val pathBytes = logicalVmResourcePath.toByteArray(Charsets.UTF_8)
        return try {
            java.security.MessageDigest.getInstance("SHA-256").apply {
                update(DOMAIN)
                updateLong(seed)
                updateLong(entryToken)
                updateInt(pageIndex)
                updateInt(pathBytes.size)
                update(pathBytes)
            }.digest()
        } finally {
            Arrays.fill(pathBytes, 0)
        }
    }

    private fun java.security.MessageDigest.updateLong(value: Long) {
        for (shift in 56 downTo 0 step 8) update((value ushr shift).toByte())
    }

    private fun java.security.MessageDigest.updateInt(value: Int) {
        update((value ushr 24).toByte())
        update((value ushr 16).toByte())
        update((value ushr 8).toByte())
        update(value.toByte())
    }
}
