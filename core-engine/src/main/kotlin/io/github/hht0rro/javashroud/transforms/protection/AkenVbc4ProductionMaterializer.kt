package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptorPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPendingClassPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPendingNativeChunk
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPendingStringPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPageBatch
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPagePlanner
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays

/**
 * Build-only production hand-off from registered VBC4, typed StringPage,
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
internal object AkenVbc4ProductionMaterializer {
    fun materializeBeforeNativeCompilation(
        artifact: BytecodeArtifact,
        seed: Long,
    ): BytecodeArtifact {
        val context = currentVbc4BuildContextOrNull() ?: return artifact
        val hasVbc4Candidates = context.hasAkenVbc4MethodCandidates()
        val hasStringCandidates = context.hasAkenStringPageCandidates()
        val hasClassCandidates = context.hasAkenClassPageCandidates()
        val hasNativeChunkCandidates = context.hasAkenNativeChunkCandidates()
        if (!hasVbc4Candidates && !hasStringCandidates && !hasClassCandidates && !hasNativeChunkCandidates) {
            return artifact
        }
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
        val classReservation = if (hasClassCandidates) {
            context.requireAkenClassPagePreSealRouteReservation()
        } else {
            null
        }
        val nativeChunkReservation = if (hasNativeChunkCandidates) {
            context.requireAkenNativeChunkPreSealRouteReservation()
        } else {
            null
        }
        val artifactWithClassDescriptors = materializeClassPageDescriptorsIfNeeded(
            artifact = artifact,
            context = context,
        )
        val fixedEntries = fixedEntriesForArtifact(artifactWithClassDescriptors)
        val batches = ArrayList<AkenVbc4PendingPageBatch>()
        val stringPages = ArrayList<AkenPendingStringPage>()
        val classPages = ArrayList<AkenPendingClassPage>()
        val nativeChunks = ArrayList<AkenPendingNativeChunk>()
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

            if (hasClassCandidates) {
                context.withAkenClassPageCandidatesForBuild { candidates ->
                    checkNotNull(classReservation).withRoutesForBuild { routes ->
                        candidates
                            .sortedBy { candidate -> candidate.identityPageKeyForBuild() }
                            .forEach { candidate ->
                                val identityPageKey = candidate.identityPageKeyForBuild()
                                val route = routes.singleOrNull { candidateRoute ->
                                    candidateRoute.identityPageKey == identityPageKey &&
                                        candidateRoute.logicalBindingPath == candidate.logicalBindingPath
                                } ?: error(
                                    "AKEN ClassPage pre-seal route is missing for candidate " + identityPageKey,
                                )
                                classPages += candidate.toPendingPage(route)
                            }
                    }
                }
            }

            if (hasNativeChunkCandidates) {
                context.withAkenNativeChunkCandidatesForBuild { candidates ->
                    checkNotNull(nativeChunkReservation).withRoutesForBuild { routes ->
                        candidates
                            .sortedBy { candidate -> candidate.identityPageKeyForBuild() }
                            .forEach { candidate ->
                                val identityPageKey = candidate.identityPageKeyForBuild()
                                val route = routes.singleOrNull { candidateRoute ->
                                    candidateRoute.identityPageKey == identityPageKey &&
                                        candidateRoute.logicalBindingPath == candidate.logicalBindingPath
                                } ?: error(
                                    "AKEN NativeChunk pre-seal route is missing for candidate " + identityPageKey,
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
                "AKEN production materialization found no page candidates"
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
                "AKEN production materialization emitted no new page entries"
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
            context.publishAkenVbc4FinalizationLayout(finalized)
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
        context: Vbc4BuildContext,
        batches: List<AkenVbc4PendingPageBatch>,
        pendingStringPages: List<AkenPendingStringPage>,
        pendingClassPages: List<AkenPendingClassPage>,
        pendingNativeChunks: List<AkenPendingNativeChunk>,
        fixedEntries: List<AkenArtifactEntry>,
        publish: (AkenVbc4FinalizationLayout) -> Unit,
    ) {
        fun consumeAt(index: Int, pages: List<AkenVbc4PendingPage>) {
            if (index == batches.size) {
                val commitment = AkenVbc4FinalizationLayout.reserve(
                    pendingPages = pages,
                    pendingStringPages = pendingStringPages,
                    pendingClassPages = pendingClassPages,
                    pendingNativeChunks = pendingNativeChunks,
                    fixedEntries = fixedEntries,
                )
                val commitmentBytes = commitment.copyBytes()
                val plan = try {
                    context.initializeAkenBuildPlan(commitmentBytes)
                } finally {
                    Arrays.fill(commitmentBytes, 0)
                }
                val stateBindingLayoutDigest = AkenVbc4InnerMaterial.copyStateBindingLayoutDigest(context)
                val finalized = try {
                    AkenVbc4FinalizationLayout.materializeAndWipe(
                        plan = plan,
                        commitment = commitment,
                        pendingPages = pages,
                        pendingStringPages = pendingStringPages,
                        pendingClassPages = pendingClassPages,
                        pendingNativeChunks = pendingNativeChunks,
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

    /**
     * Emits deterministic per-class descriptor resources before the canonical
     * AKEN commitment is reserved. These resources are class-local inputs to
     * the typed runtime loader, not a central catalog: each contains only its
     * own page handles and proofs.
     */
    private fun materializeClassPageDescriptorsIfNeeded(
        artifact: BytecodeArtifact,
        context: Vbc4BuildContext,
    ): BytecodeArtifact {
        if (!context.hasAkenClassPageDescriptorSources()) return artifact
        val occupiedEntryPaths = linkedSetOf<String>().apply {
            artifact.jarEntries.forEach { entry -> add(entry.name) }
            artifact.classArtifacts.forEach { classArtifact -> add(classArtifact.entryName) }
            context.akenVbc4PreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureContainerPath) }
            }
            context.akenStringPagePreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            context.akenClassPagePreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            context.akenNativeChunkPreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
        }
        val descriptorEntries = ArrayList<JarEntryData>()
        var transferred = false
        try {
            context.withAkenClassPageCandidatesForBuild { candidates ->
                val candidatesByPageKey =
                    LinkedHashMap<String, io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageCandidate>(
                        candidates.size,
                    )
                candidates.forEach { candidate ->
                    val pageKey = candidate.identityPageKeyForBuild()
                    require(candidatesByPageKey.put(pageKey, candidate) == null) {
                        "AKEN ClassPage descriptor emission found duplicate candidate identity"
                    }
                }
                context.withAkenClassPageDescriptorSourcesForBuild { sources ->
                    sources
                        .groupBy { source -> source.internalName }
                        .toSortedMap()
                        .forEach { (internalName, classSources) ->
                            val descriptorPath =
                                AkenClassPageDescriptor.resourcePathForInternalNameForBuild(internalName)
                            require(occupiedEntryPaths.add(descriptorPath)) {
                                "AKEN ClassPage descriptor route collides with the materialization namespace: " +
                                    descriptorPath
                            }
                            val descriptorPages = ArrayList<AkenClassPageDescriptorPage>(classSources.size)
                            var descriptor: AkenClassPageDescriptor? = null
                            try {
                                classSources
                                    .sortedBy { source -> source.pageIndex }
                                    .forEach { source ->
                                        val pageKey = source.identityPageKeyForBuild()
                                        val candidate = candidatesByPageKey[pageKey]
                                            ?: error(
                                                "AKEN ClassPage descriptor source has no registered candidate for " +
                                                    internalName,
                                            )
                                        require(candidate.pageIndex == source.pageIndex) {
                                            "AKEN ClassPage descriptor source page index drifted from its candidate"
                                        }
                                        var handle: ByteArray? = null
                                        var proof: ByteArray? = null
                                        try {
                                            handle = candidate.copyEncodedHandleForBuild()
                                            proof = candidate.copyCallSiteProofForBuild()
                                            descriptorPages += AkenClassPageDescriptorPage.create(
                                                pageIndex = source.pageIndex,
                                                encodedHandle = handle,
                                                callSiteProof = proof,
                                            )
                                        } finally {
                                            handle?.let { Arrays.fill(it, 0) }
                                            proof?.let { Arrays.fill(it, 0) }
                                        }
                                    }
                                descriptor = AkenClassPageDescriptor.create(
                                    internalName = internalName,
                                    pages = descriptorPages,
                                )
                                require(descriptor.resourcePathForBuild() == descriptorPath) {
                                    "AKEN ClassPage descriptor route drifted from its deterministic binding"
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
                "AKEN ClassPage descriptor sources did not emit any descriptor resources"
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
        context: Vbc4BuildContext,
        layout: AkenVbc4FinalizationLayout,
    ) {
        if (!context.hasAkenClassPageDescriptorSources()) return
        val entriesByName = LinkedHashMap<String, JarEntryData>()
        artifact.jarEntries.forEach { entry ->
            require(entriesByName.put(entry.name, entry) == null) {
                "AKEN ClassPage descriptor verification found duplicate artifact entries"
            }
        }
        context.withAkenClassPageDescriptorSourcesForBuild { sources ->
            layout.withClassPageBindingsForBuild { bindings ->
                val bindingsByPageKey = bindings.associateBy { binding -> binding.identityPageKeyForBuild() }
                require(bindingsByPageKey.size == bindings.size) {
                    "AKEN ClassPage descriptor verification found duplicate final bindings"
                }
                val matchedSourceKeys = linkedSetOf<String>()
                sources
                    .groupBy { source -> source.internalName }
                    .toSortedMap()
                    .forEach { (internalName, classSources) ->
                        val descriptorPath =
                            AkenClassPageDescriptor.resourcePathForInternalNameForBuild(internalName)
                        val entry = entriesByName[descriptorPath]
                            ?: error("AKEN ClassPage descriptor resource is missing: " + descriptorPath)
                        val encoded = entry.bytes.copyOf()
                        var descriptor: AkenClassPageDescriptor? = null
                        try {
                            descriptor = AkenClassPageDescriptor.decodeForBuild(encoded)
                            require(descriptor.internalName == internalName) {
                                "AKEN ClassPage descriptor internal name drifted from its source"
                            }
                            descriptor.withPagesForBuild { descriptorPages ->
                                val expectedSources = classSources.sortedBy { source -> source.pageIndex }
                                require(descriptorPages.size == expectedSources.size) {
                                    "AKEN ClassPage descriptor page count drifted from final bindings"
                                }
                                expectedSources.forEach { source ->
                                    val pageKey = source.identityPageKeyForBuild()
                                    val binding = bindingsByPageKey[pageKey]
                                        ?: error(
                                            "AKEN ClassPage descriptor source has no finalized binding for " +
                                                internalName,
                                        )
                                    require(source.matchesBindingForBuild(binding)) {
                                        "AKEN ClassPage descriptor source drifted from its finalized binding"
                                    }
                                    val descriptorPage = descriptorPages.singleOrNull { page ->
                                        page.pageIndex == source.pageIndex
                                    } ?: error(
                                        "AKEN ClassPage descriptor is missing page " +
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
                                            "AKEN ClassPage descriptor page binding drifted from final materialization"
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
                    "AKEN ClassPage descriptor verification did not match every class-local source"
                }
            }
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
