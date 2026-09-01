package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassPageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.qp.QpClassPageDescriptorPage
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingClassPage
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingNativeSegment
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingTextPage
import io.github.hht0rro.javashroud.transforms.protection.qp.QpFinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingPage
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingPageBatch
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPendingPagePlanner
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

/**
 * Build-only production hand-off from registered Qp VM, typed StringPage,
 * encrypted ClassPage, and NativeChunk candidates to the native recompilation
 * stage.
 *
 * The native compiler must receive page-local locator records before it emits a
 * JNI library. This owner therefore consumes the scoped candidate registry,
 * materializes the reserved page resources through one unified integrity mesh,
 * publishes the finalization layout to the active build context, and returns an
 * artifact containing only encrypted page entries. It does not create a runtime
 * catalog or expose a generic page decoder.
 */
internal object QpMethodProductionMaterializer {
    fun materializeBeforeNativeCompilation(
        artifact: BytecodeArtifact,
        seed: Long,
    ): BytecodeArtifact {
        val context = currentQpBuildContextOrNull() ?: return artifact
        val hasQpCandidates = context.hasQpMethodCandidates()
        val hasStringCandidates = context.hasQpTextPageCandidates()
        val hasClassCandidates = context.hasQpClassPageCandidates()
        val hasNativeChunkCandidates = context.hasQpNativeSegmentCandidates()
        if (!hasQpCandidates && !hasStringCandidates && !hasClassCandidates && !hasNativeChunkCandidates) {
            return artifact
        }
        if (context.qpFinalizationLayoutOrNull() != null) return artifact

        val nativeReservation = if (hasQpCandidates) {
            context.requireQpPreSealRouteReservation()
        } else {
            null
        }
        val stringReservation = if (hasStringCandidates) {
            context.requireQpTextRouteReservation()
        } else {
            null
        }
        val classReservation = if (hasClassCandidates) {
            context.requireQpClassRouteReservation()
        } else {
            null
        }
        val nativeChunkReservation = if (hasNativeChunkCandidates) {
            context.requireQpNativeRouteReservation()
        } else {
            null
        }
        val artifactWithClassDescriptors = materializeClassPageDescriptorsIfNeeded(
            artifact = artifact,
            context = context,
        )
        val fixedEntries = fixedEntriesForArtifact(artifactWithClassDescriptors)
        val batches = ArrayList<QpPendingPageBatch>()
        val stringPages = ArrayList<QpPendingTextPage>()
        val classPages = ArrayList<QpPendingClassPage>()
        val nativeChunks = ArrayList<QpPendingNativeSegment>()
        var layout: QpFinalizationLayout? = null
        var pageEntriesTransferred = false

        try {
            if (hasQpCandidates) {
                context.withQpMethodCandidatesForBuild { candidates ->
                    checkNotNull(nativeReservation).withRoutesForBuild { routes ->
                        candidates.sortedBy { it.entryToken }.forEach { candidate ->
                            val route = routes.singleOrNull { candidateRoute ->
                                candidateRoute.entryToken == candidate.entryToken &&
                                    candidateRoute.logicalVmResourcePath == candidate.logicalMethod.logicalVmResourcePath
                            } ?: error(
                                "Qp current-format pre-seal route is missing for entry token " + candidate.entryToken,
                            )
                            batches += QpPendingPagePlanner.partitionAndWipe(
                                candidate = candidate,
                                route = route,
                                callSiteProofForPage = { pageIndex ->
                                    QpCallSiteProof.derive(
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
                context.withQpTextPageCandidatesForBuild { candidates ->
                    checkNotNull(stringReservation).withRoutesForBuild { routes ->
                        candidates
                            .sortedBy { candidate -> candidate.identityPageKeyForBuild() }
                            .forEach { candidate ->
                                val identityPageKey = candidate.identityPageKeyForBuild()
                                val route = routes.singleOrNull { candidateRoute ->
                                    candidateRoute.identityPageKey == identityPageKey &&
                                        candidateRoute.logicalBindingPath == candidate.logicalBindingPath
                                } ?: error(
                                    "Qp StringPage pre-seal route is missing for candidate " + identityPageKey,
                                )
                                stringPages += candidate.toPendingPage(route)
                            }
                    }
                }
            }

            if (hasClassCandidates) {
                context.withQpClassPageCandidatesForBuild { candidates ->
                    checkNotNull(classReservation).withRoutesForBuild { routes ->
                        candidates
                            .sortedBy { candidate -> candidate.identityPageKeyForBuild() }
                            .forEach { candidate ->
                                val identityPageKey = candidate.identityPageKeyForBuild()
                                val route = routes.singleOrNull { candidateRoute ->
                                    candidateRoute.identityPageKey == identityPageKey &&
                                        candidateRoute.logicalBindingPath == candidate.logicalBindingPath
                                } ?: error(
                                    "Qp ClassPage pre-seal route is missing for candidate " + identityPageKey,
                                )
                                classPages += candidate.toPendingPage(route)
                            }
                    }
                }
            }

            if (hasNativeChunkCandidates) {
                context.withQpNativeSegmentCandidatesForBuild { candidates ->
                    checkNotNull(nativeChunkReservation).withRoutesForBuild { routes ->
                        candidates
                            .sortedBy { candidate -> candidate.identityPageKeyForBuild() }
                            .forEach { candidate ->
                                val identityPageKey = candidate.identityPageKeyForBuild()
                                val route = routes.singleOrNull { candidateRoute ->
                                    candidateRoute.identityPageKey == identityPageKey &&
                                        candidateRoute.logicalBindingPath == candidate.logicalBindingPath
                                } ?: error(
                                    "Qp NativeChunk pre-seal route is missing for candidate " + identityPageKey,
                                )
                                nativeChunks += candidate.toPendingPage(route)
                            }
                    }
                }
            }

            require(
                batches.isNotEmpty() ||
                    stringPages.isNotEmpty() ||
                    classPages.isNotEmpty() ||
                    nativeChunks.isNotEmpty(),
            ) {
                "Qp production materialization found no page candidates"
            }
            consumeBatchesAndMaterialize(
                context = context,
                batches = batches,
                pendingStringPages = stringPages,
                pendingClassPages = classPages,
                pendingNativeChunks = nativeChunks,
                fixedEntries = fixedEntries,
            ) { finalized ->
                layout = finalized
            }

            val finalized = checkNotNull(layout)
            val existingNames = artifactWithClassDescriptors.jarEntries.mapTo(HashSet()) { it.name }
            val pageEntries = ArrayList<JarEntryData>()
            finalized.entriesForBuild()
                .filter { entry -> entry.name !in existingNames }
                .forEach { entry ->
                    val bytes = entry.copyBytesForBuild()
                    pageEntries += JarEntryData(entry.name, bytes)
                }
            require(pageEntries.isNotEmpty()) {
                "Qp production materialization emitted no new page entries"
            }
            val output = artifactWithClassDescriptors.copy(
                jarEntries = artifactWithClassDescriptors.jarEntries + pageEntries,
                analysisSummary = artifactWithClassDescriptors.analysisSummary.copy(
                    resourceCount = resourceCount(
                        artifactWithClassDescriptors.jarEntries + pageEntries,
                        artifactWithClassDescriptors.classArtifacts.size,
                    ),
                ),
            )
            verifyClassPageDescriptorsForBuild(
                artifact = output,
                context = context,
                layout = finalized,
            )
            pageEntriesTransferred = true
            context.publishQpFinalizationLayout(finalized)
            return output
        } catch (error: Throwable) {
            layout?.wipe()
            throw error
        } finally {
            batches.forEach { it.wipe() }
            stringPages.forEach { it.wipe() }
            classPages.forEach { it.wipe() }
            nativeChunks.forEach { it.wipe() }
            if (!pageEntriesTransferred) {
                layout?.wipe()
            }
        }
    }

    private fun consumeBatchesAndMaterialize(
        context: QpBuildContext,
        batches: List<QpPendingPageBatch>,
        pendingStringPages: List<QpPendingTextPage>,
        pendingClassPages: List<QpPendingClassPage>,
        pendingNativeChunks: List<QpPendingNativeSegment>,
        fixedEntries: List<QpArtifactEntry>,
        publish: (QpFinalizationLayout) -> Unit,
    ) {
        fun consumeAt(index: Int, pages: List<QpPendingPage>) {
            if (index == batches.size) {
                val commitment = QpFinalizationLayout.reserve(
                    pendingPages = pages,
                    pendingStringPages = pendingStringPages,
                    pendingClassPages = pendingClassPages,
                    pendingNativeChunks = pendingNativeChunks,
                    fixedEntries = fixedEntries,
                )
                val commitmentBytes = commitment.copyBytes()
                val plan = try {
                    context.initializeQpBuildPlan(commitmentBytes)
                } finally {
                    Arrays.fill(commitmentBytes, 0)
                }
                val stateBindingLayoutDigest = QpInnerMaterial.copyStateBindingLayoutDigest(context)
                val finalized = try {
                    QpFinalizationLayout.materializeAndWipe(
                        plan = plan,
                        commitment = commitment,
                        pendingPages = pages,
                        pendingStringPages = pendingStringPages,
                        pendingClassPages = pendingClassPages,
                        pendingNativeChunks = pendingNativeChunks,
                        fixedEntries = fixedEntries,
                        pageStateBindingLayoutDigest = stateBindingLayoutDigest,
                    )
                } finally {
                    Arrays.fill(stateBindingLayoutDigest, 0)
                }
                publish(finalized)
                return
            }

            batches[index].consumePendingPagesForBuild { batchPages ->
                val combined = ArrayList<QpPendingPage>(pages.size + batchPages.size)
                combined.addAll(pages)
                combined.addAll(batchPages)
                consumeAt(index + 1, combined)
            }
        }

        consumeAt(0, emptyList())
    }

    private fun fixedEntriesForArtifact(artifact: BytecodeArtifact): List<QpArtifactEntry> {
        val classesByEntry = artifact.classArtifacts.associateBy { it.entryName }
        return artifact.jarEntries.map { entry ->
            val bytes = classesByEntry[entry.name]?.bytes ?: entry.bytes
            QpArtifactEntry(entry.name, bytes)
        }
    }

    /**
     * Emits deterministic per-class descriptor resources before the canonical
     * Qp commitment is reserved. These resources are class-local inputs to
     * the typed runtime loader, not a central catalog: each contains only its
     * own page handles and proofs.
     */
    private fun materializeClassPageDescriptorsIfNeeded(
        artifact: BytecodeArtifact,
        context: QpBuildContext,
    ): BytecodeArtifact {
        if (!context.hasQpClassPageDescriptorSources()) return artifact
        val occupiedEntryPaths = linkedSetOf<String>().apply {
            artifact.jarEntries.forEach { entry -> add(entry.name) }
            artifact.classArtifacts.forEach { classArtifact -> add(classArtifact.entryName) }
            context.qpPreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureContainerPath) }
            }
            context.qpTextRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            context.qpClassRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            context.qpNativeRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
        }
        val descriptorEntries = ArrayList<JarEntryData>()
        var transferred = false
        try {
            context.withQpClassPageCandidatesForBuild { candidates ->
                val candidatesByPageKey =
                    LinkedHashMap<String, io.github.hht0rro.javashroud.transforms.protection.qp.QpClassPageCandidate>(
                        candidates.size,
                    )
                candidates.forEach { candidate ->
                    val pageKey = candidate.identityPageKeyForBuild()
                    require(candidatesByPageKey.put(pageKey, candidate) == null) {
                        "Qp ClassPage descriptor emission found duplicate candidate identity"
                    }
                }
                context.withQpClassPageDescriptorSourcesForBuild { sources ->
                    sources
                        .groupBy { source -> source.internalName }
                        .toSortedMap()
                        .forEach { (internalName, classSources) ->
                            val descriptorPath =
                                QpClassPageDescriptor.resourcePathForInternalNameForBuild(internalName)
                            require(occupiedEntryPaths.add(descriptorPath)) {
                                "Qp ClassPage descriptor route collides with the materialization namespace: " +
                                    descriptorPath
                            }
                            val descriptorPages = ArrayList<QpClassPageDescriptorPage>(classSources.size)
                            var descriptor: QpClassPageDescriptor? = null
                            try {
                                classSources
                                    .sortedBy { source -> source.pageIndex }
                                    .forEach { source ->
                                        val pageKey = source.identityPageKeyForBuild()
                                        val candidate = candidatesByPageKey[pageKey]
                                            ?: error(
                                                "Qp ClassPage descriptor source has no registered candidate for " +
                                                    internalName,
                                            )
                                        require(candidate.pageIndex == source.pageIndex) {
                                            "Qp ClassPage descriptor source page index drifted from its candidate"
                                        }
                                        var handle: ByteArray? = null
                                        var proof: ByteArray? = null
                                        try {
                                            handle = candidate.copyEncodedHandleForBuild()
                                            proof = candidate.copyCallSiteProofForBuild()
                                            descriptorPages += QpClassPageDescriptorPage.create(
                                                pageIndex = source.pageIndex,
                                                encodedHandle = handle,
                                                callSiteProof = proof,
                                            )
                                        } finally {
                                            handle?.let { Arrays.fill(it, 0) }
                                            proof?.let { Arrays.fill(it, 0) }
                                        }
                                    }
                                descriptor = QpClassPageDescriptor.create(
                                    internalName = internalName,
                                    pages = descriptorPages,
                                )
                                require(descriptor.resourcePathForBuild() == descriptorPath) {
                                    "Qp ClassPage descriptor route drifted from its deterministic binding"
                                }
                                descriptorEntries += JarEntryData(
                                    name = descriptorPath,
                                    bytes = descriptor.copyEncodedForBuild(),
                                )
                            } finally {
                                descriptor?.wipe()
                                descriptorPages.forEach { page -> page.wipe() }
                            }
                        }
                }
            }
            require(descriptorEntries.isNotEmpty()) {
                "Qp ClassPage descriptor sources did not emit any descriptor resources"
            }
            transferred = true
            return artifact.copy(
                jarEntries = artifact.jarEntries + descriptorEntries,
                analysisSummary = artifact.analysisSummary.copy(
                    resourceCount = resourceCount(
                        artifact.jarEntries + descriptorEntries,
                        artifact.classArtifacts.size,
                    ),
                ),
            )
        } finally {
            if (!transferred) {
                descriptorEntries.forEach { entry -> Arrays.fill(entry.bytes, 0) }
            }
        }
    }

    /**
     * Reconstructs every class-local descriptor from the output artifact and
     * binds each record to one finalized ClassPage. This catches descriptor
     * emission drift before native compilation consumes the layout.
     */
    private fun verifyClassPageDescriptorsForBuild(
        artifact: BytecodeArtifact,
        context: QpBuildContext,
        layout: QpFinalizationLayout,
    ) {
        if (!context.hasQpClassPageDescriptorSources()) return
        val entriesByName = LinkedHashMap<String, JarEntryData>()
        artifact.jarEntries.forEach { entry ->
            require(entriesByName.put(entry.name, entry) == null) {
                "Qp ClassPage descriptor verification found duplicate artifact entries"
            }
        }
        context.withQpClassPageDescriptorSourcesForBuild { sources ->
            layout.withClassPageBindingsForBuild { bindings ->
                val bindingsByPageKey = bindings.associateBy { binding -> binding.identityPageKeyForBuild() }
                require(bindingsByPageKey.size == bindings.size) {
                    "Qp ClassPage descriptor verification found duplicate final bindings"
                }
                val matchedSourceKeys = linkedSetOf<String>()
                sources
                    .groupBy { source -> source.internalName }
                    .toSortedMap()
                    .forEach { (internalName, classSources) ->
                        val descriptorPath =
                            QpClassPageDescriptor.resourcePathForInternalNameForBuild(internalName)
                        val entry = entriesByName[descriptorPath]
                            ?: error("Qp ClassPage descriptor resource is missing: " + descriptorPath)
                        val encoded = entry.bytes.copyOf()
                        var descriptor: QpClassPageDescriptor? = null
                        try {
                            descriptor = QpClassPageDescriptor.decodeForBuild(encoded)
                            require(descriptor.internalName == internalName) {
                                "Qp ClassPage descriptor internal name drifted from its source"
                            }
                            descriptor.withPagesForBuild { descriptorPages ->
                                val expectedSources = classSources.sortedBy { source -> source.pageIndex }
                                require(descriptorPages.size == expectedSources.size) {
                                    "Qp ClassPage descriptor page count drifted from final bindings"
                                }
                                expectedSources.forEach { source ->
                                    val pageKey = source.identityPageKeyForBuild()
                                    val binding = bindingsByPageKey[pageKey]
                                        ?: error(
                                            "Qp ClassPage descriptor source has no finalized binding for " +
                                                internalName,
                                        )
                                    require(source.matchesBindingForBuild(binding)) {
                                        "Qp ClassPage descriptor source drifted from its finalized binding"
                                    }
                                    val descriptorPage = descriptorPages.singleOrNull { page ->
                                        page.pageIndex == source.pageIndex
                                    } ?: error(
                                        "Qp ClassPage descriptor is missing page " +
                                            source.pageIndex +
                                            " for " +
                                            internalName,
                                    )
                                    var descriptorHandle: ByteArray? = null
                                    var descriptorProof: ByteArray? = null
                                    var bindingHandle: ByteArray? = null
                                    var bindingProof: ByteArray? = null
                                    try {
                                        descriptorHandle = descriptorPage.copyEncodedHandleForBuild()
                                        descriptorProof = descriptorPage.copyCallSiteProofForBuild()
                                        bindingHandle = binding.copyEncodedHandleForBuild()
                                        bindingProof = binding.copyCallSiteProofForBuild()
                                        require(
                                            MessageDigest.isEqual(descriptorHandle, bindingHandle) &&
                                                MessageDigest.isEqual(descriptorProof, bindingProof),
                                        ) {
                                            "Qp ClassPage descriptor page binding drifted from final materialization"
                                        }
                                    } finally {
                                        descriptorHandle?.let { Arrays.fill(it, 0) }
                                        descriptorProof?.let { Arrays.fill(it, 0) }
                                        bindingHandle?.let { Arrays.fill(it, 0) }
                                        bindingProof?.let { Arrays.fill(it, 0) }
                                    }
                                    matchedSourceKeys += pageKey
                                }
                            }
                        } finally {
                            descriptor?.wipe()
                            Arrays.fill(encoded, 0)
                        }
                    }
                require(matchedSourceKeys.size == sources.size) {
                    "Qp ClassPage descriptor verification did not match every class-local source"
                }
            }
        }
    }
}

/** Build-only, deterministic proof material for one generated Qp VM page call site. */
internal object QpCallSiteProof {
    private val DOMAIN = "javashroud-qp-vm-call-site-proof-v1".toByteArray(Charsets.US_ASCII)

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
