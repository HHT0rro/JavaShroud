package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPendingStringPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPageBatch
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPagePlanner
import java.security.SecureRandom
import java.util.Arrays

/**
 * Build-only production hand-off from registered VBC4 and typed StringPage
 * candidates to the native recompilation stage.
 *
 * The native compiler must receive page-local locator records before it emits a
 * JNI library. This owner therefore consumes the scoped candidate registry,
 * materializes the reserved page resources through one unified integrity mesh,
 * publishes the finalization layout to the active build context, and returns an
 * artifact containing only encrypted page entries. It does not create a runtime
 * catalog or expose a generic page decoder.
 */
internal object AkenVbc4ProductionMaterializer {
    fun materializeBeforeNativeCompilation(
        artifact: BytecodeArtifact,
        seed: Long,
    ): BytecodeArtifact {
        val context = currentVbc4BuildContextOrNull() ?: return artifact
        val hasVbc4Candidates = context.hasAkenVbc4MethodCandidates()
        val hasStringCandidates = context.hasAkenStringPageCandidates()
        if (!hasVbc4Candidates && !hasStringCandidates) return artifact
        if (context.akenVbc4FinalizationLayoutOrNull() != null) return artifact

        val vbc4Reservation = if (hasVbc4Candidates) {
            context.requireAkenVbc4PreSealRouteReservation()
        } else {
            null
        }
        val stringReservation = if (hasStringCandidates) {
            context.requireAkenStringPagePreSealRouteReservation()
        } else {
            null
        }
        val fixedEntries = fixedEntriesForArtifact(artifact)
        val batches = ArrayList<AkenVbc4PendingPageBatch>()
        val stringPages = ArrayList<AkenPendingStringPage>()
        var layout: AkenVbc4FinalizationLayout? = null
        var pageEntriesTransferred = false

        try {
            if (hasVbc4Candidates) {
                context.withAkenVbc4MethodCandidatesForBuild { candidates ->
                    checkNotNull(vbc4Reservation).withRoutesForBuild { routes ->
                        candidates.sortedBy { it.entryToken }.forEach { candidate ->
                            val route = routes.singleOrNull { candidateRoute ->
                                candidateRoute.entryToken == candidate.entryToken &&
                                    candidateRoute.logicalVmResourcePath == candidate.logicalMethod.logicalVmResourcePath
                            } ?: error(
                                "AKEN VBC4 pre-seal route is missing for entry token " + candidate.entryToken,
                            )
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
                        }
                    }
                }
            }

            if (hasStringCandidates) {
                context.withAkenStringPageCandidatesForBuild { candidates ->
                    checkNotNull(stringReservation).withRoutesForBuild { routes ->
                        candidates
                            .sortedBy { candidate -> candidate.identityPageKeyForBuild() }
                            .forEach { candidate ->
                                val identityPageKey = candidate.identityPageKeyForBuild()
                                val route = routes.singleOrNull { candidateRoute ->
                                    candidateRoute.identityPageKey == identityPageKey &&
                                        candidateRoute.logicalBindingPath == candidate.logicalBindingPath
                                } ?: error(
                                    "AKEN StringPage pre-seal route is missing for candidate " + identityPageKey,
                                )
                                stringPages += candidate.toPendingPage(route)
                            }
                    }
                }
            }

            require(batches.isNotEmpty() || stringPages.isNotEmpty()) {
                "AKEN production materialization found no page candidates"
            }
            consumeBatchesAndMaterialize(
                context = context,
                batches = batches,
                pendingStringPages = stringPages,
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
                "AKEN production materialization emitted no new page entries"
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
            stringPages.forEach { it.wipe() }
            if (!pageEntriesTransferred) {
                layout?.wipe()
            }
        }
    }

    private fun consumeBatchesAndMaterialize(
        context: Vbc4BuildContext,
        batches: List<AkenVbc4PendingPageBatch>,
        pendingStringPages: List<AkenPendingStringPage>,
        fixedEntries: List<AkenArtifactEntry>,
        publish: (AkenVbc4FinalizationLayout) -> Unit,
    ) {
        fun consumeAt(index: Int, pages: List<AkenVbc4PendingPage>) {
            if (index == batches.size) {
                val commitment = AkenVbc4FinalizationLayout.reserve(
                    pendingPages = pages,
                    pendingStringPages = pendingStringPages,
                    fixedEntries = fixedEntries,
                )
                val commitmentBytes = commitment.copyBytes()
                val plan = try {
                    context.initializeAkenBuildPlan(commitmentBytes)
                } finally {
                    Arrays.fill(commitmentBytes, 0)
                }
                val stateBindingLayoutDigest = AkenVbc4InnerMaterial.copyStateBindingLayoutDigest()
                val finalized = try {
                    AkenVbc4FinalizationLayout.materializeAndWipe(
                        plan = plan,
                        commitment = commitment,
                        pendingPages = pages,
                        pendingStringPages = pendingStringPages,
                        fixedEntries = fixedEntries,
                        vbc4StateBindingLayoutDigest = stateBindingLayoutDigest,
                    )
                } finally {
                    Arrays.fill(stateBindingLayoutDigest, 0)
                }
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
