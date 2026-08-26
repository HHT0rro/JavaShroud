package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.analysis.analyzeClassBytes
import io.github.hht0rro.javashroud.artifact.classArtifactIndex
import io.github.hht0rro.javashroud.artifact.classSummaryIndex
import io.github.hht0rro.javashroud.artifact.resourceCount
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.ClassArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.FinalNativeBinding
import io.github.hht0rro.javashroud.transforms.protection.hardening.HardenedArtifactFinalizer
import io.github.hht0rro.javashroud.transforms.rename.FIELD_RENAME_BINDINGS_RESOURCE
import io.github.hht0rro.javashroud.transforms.rename.METHOD_RENAME_BINDINGS_RESOURCE
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.FieldVisitor
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Type
import org.objectweb.asm.tree.AbstractInsnNode
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.InsnNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.VarInsnNode
import org.objectweb.asm.Opcodes
import org.objectweb.asm.commons.ClassRemapper
import org.objectweb.asm.commons.Remapper
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.security.MessageDigest
import java.util.Arrays

private const val LEGACY_SEALED_NATIVE_INDEX_RESOURCE = "META-INF/.r/0.dat"
private const val LEGACY_SEALED_NATIVE_BINDINGS_RESOURCE = "META-INF/.r/bindings.dat"
private const val AKEN_NATIVE_MAX_LIBRARY_BYTES = 256 * 1024 * 1024
private const val AKEN_NATIVE_BINDINGS_MAX_BYTES = 4 * 1024 * 1024
private const val PROTECTION_HELPER_PACKAGE = "io/github/hht0rro/javashroud/transforms/protection"

private val AUTO_SEALED_HELPER_PASSES = setOf(
    "callsite-rotation-protection",
    "exception-semantic-virtualization",
    "jni-microkernel-loader",
    "method-virtualization",
    "os-anti-debug",
    "os-anti-vm",
)

private val SEALED_RUNTIME_HELPERS = listOf(
    "$PROTECTION_HELPER_PACKAGE/StringEncryptionHelper",
    "$PROTECTION_HELPER_PACKAGE/BootstrapEncryptionHelper",
    "$PROTECTION_HELPER_PACKAGE/ExceptionVirtualizationHelper",
    "$PROTECTION_HELPER_PACKAGE/FlowControlException",
    "$PROTECTION_HELPER_PACKAGE/CallsiteRotationHelper",
    "$PROTECTION_HELPER_PACKAGE/IndyTargetBootstrap",
    "$PROTECTION_HELPER_PACKAGE/DefenseKernelRuntimeHelper",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper${"$"}AkenNativeLibrary",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper${"$"}CatalogBundle",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper${"$"}TypeParseResult",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper${"$"}SamLambdaOptions",
    "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper${"$"}SamInvocationHandler",
)

/**
 * Final output sealing for high-sensitivity runtime artifacts.
 *
 * This intentionally runs after helper/native injection, because regular pass
 * execution happens before embedded helpers are added to the artifact.
 */
object RuntimeArtifactSealing {
    fun isRequested(config: ObfuscationConfig): Boolean {
        val enabledPassIds = config.passes.filter { it.enabled }.map { it.id }.toSet()
        return enabledPassIds.any { it in AUTO_SEALED_HELPER_PASSES }
    }

    /**
     * Reserves deterministic class-local descriptor routes in every pre-seal
     * allocator namespace. The descriptor itself is emitted immediately before
     * page materialization, but its route must already be unavailable to VBC4,
     * StringPage, ClassPage, and NativeChunk payload containers.
     */
    private fun reserveAkenClassPageDescriptorRoutesIfNeeded(
        context: Vbc4BuildContext,
        occupiedEntryPaths: MutableSet<String>,
    ) {
        if (!context.hasAkenClassPageDescriptorSources()) return
        val internalNames = linkedSetOf<String>()
        val descriptorPaths = linkedSetOf<String>()
        context.withAkenClassPageDescriptorSourcesForBuild { sources ->
            sources.forEach { source ->
                internalNames += source.internalName
                descriptorPaths +=
                    io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptor
                        .resourcePathForInternalNameForBuild(source.internalName)
            }
        }
        require(descriptorPaths.size == internalNames.size) {
            "AKEN ClassPage descriptor routes collide across logical classes"
        }
        descriptorPaths.forEach { path ->
            require(occupiedEntryPaths.add(path)) {
                "AKEN ClassPage descriptor route collides with the pre-seal artifact namespace: $path"
            }
        }
    }

    /**
     * Reserves artifact-specific future VBC4 page-container names before native
     * recompilation. This stage deliberately emits no resource and receives only
     * scoped candidate references; page programs, handles, proofs, and evaluator
     * state remain owned by the later build-only page planner.
     */
    internal fun reserveAkenVbc4PreSealRoutesIfNeeded(
        artifact: BytecodeArtifact,
        seed: Long,
    ): Boolean {
        val context = currentVbc4BuildContextOrNull() ?: return false
        if (!context.hasAkenVbc4MethodCandidates()) return false
        if (context.akenVbc4PreSealRouteReservationOrNull() != null) return true

        val occupiedEntryPaths = linkedSetOf<String>().apply {
            artifact.jarEntries.forEach { entry -> add(entry.name) }
            artifact.classArtifacts.forEach { classArtifact -> add(classArtifact.entryName) }
            context.akenStringPagePreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            context.akenClassPagePreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            context.akenNativeChunkPreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            reserveAkenClassPageDescriptorRoutesIfNeeded(context, this)
        }
        context.reserveAkenVbc4PreSealRoutes(
            occupiedEntryPaths = occupiedEntryPaths,
            allocator = io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PreSealRouteAllocator {
                    candidate,
                    ordinal,
                    reservedEntryPaths,
                ->
                val routeIdentity =
                    "aken-vbc4-page-container|" + candidate.entryToken + "|" + candidate.logicalVmResourcePath
                val preferred = sealedResourceName(seed, "a4", routeIdentity, ordinal)
                uniqueSealedResourceName(
                    seed = seed,
                    kind = "a4",
                    originalName = routeIdentity,
                    index = ordinal,
                    preferredName = preferred,
                    reservedEntryNames = reservedEntryPaths,
                )
            },
        )
        return true
    }

    /**
     * Reserves artifact-specific StringPage resources before page materialization.
     * This bridge exposes only the route-safe candidate key and logical binding
     * path to the sealing allocator; plaintext, handle, proof, and evaluator
     * state remain in build-only candidate owners.
     */
    internal fun reserveAkenStringPagePreSealRoutesIfNeeded(
        artifact: BytecodeArtifact,
        seed: Long,
    ): Boolean {
        val context = currentVbc4BuildContextOrNull() ?: return false
        if (!context.hasAkenStringPageCandidates()) return false
        if (context.akenStringPagePreSealRouteReservationOrNull() != null) return true

        val occupiedEntryPaths = linkedSetOf<String>().apply {
            artifact.jarEntries.forEach { entry -> add(entry.name) }
            artifact.classArtifacts.forEach { classArtifact -> add(classArtifact.entryName) }
            context.akenVbc4PreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureContainerPath) }
            }
            context.akenClassPagePreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            context.akenNativeChunkPreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            reserveAkenClassPageDescriptorRoutesIfNeeded(context, this)
        }
        context.reserveAkenStringPagePreSealRoutes(
            occupiedEntryPaths = occupiedEntryPaths,
            allocator = io.github.hht0rro.javashroud.transforms.protection.aken.AkenStringPagePreSealRouteAllocator {
                    candidate,
                    ordinal,
                    reservedEntryPaths,
                ->
                val routeIdentity =
                    "aken-string-page|" + candidate.identityPageKey + "|" + candidate.logicalBindingPath
                val preferred = sealedResourceName(seed, "a4s", routeIdentity, ordinal)
                uniqueSealedResourceName(
                    seed = seed,
                    kind = "a4s",
                    originalName = routeIdentity,
                    index = ordinal,
                    preferredName = preferred,
                    reservedEntryNames = reservedEntryPaths,
                )
            },
        )
        return true
    }



    /**
     * Reserves artifact-specific encrypted ClassPage resources before page
     * materialization. Only the route-safe candidate identity and logical
     * binding path reach this allocator; encrypted-class plaintext, handles,
     * proofs, and evaluator material remain inside build-only owners.
     */
    internal fun reserveAkenClassPagePreSealRoutesIfNeeded(
        artifact: BytecodeArtifact,
        seed: Long,
    ): Boolean {
        val context = currentVbc4BuildContextOrNull() ?: return false
        if (!context.hasAkenClassPageCandidates()) return false
        if (context.akenClassPagePreSealRouteReservationOrNull() != null) return true

        val occupiedEntryPaths = linkedSetOf<String>().apply {
            artifact.jarEntries.forEach { entry -> add(entry.name) }
            artifact.classArtifacts.forEach { classArtifact -> add(classArtifact.entryName) }
            context.akenVbc4PreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureContainerPath) }
            }
            context.akenStringPagePreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            context.akenNativeChunkPreSealRouteReservationOrNull()?.withRoutesForBuild { routes ->
                routes.forEach { route -> add(route.futureResourcePath) }
            }
            reserveAkenClassPageDescriptorRoutesIfNeeded(context, this)
        }
        context.reserveAkenClassPagePreSealRoutes(
            occupiedEntryPaths = occupiedEntryPaths,
            allocator = io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPagePreSealRouteAllocator {
                    candidate,
                    ordinal,
                    reservedEntryPaths,
                ->
                val routeIdentity =
                    "aken-class-page|" + candidate.identityPageKey + "|" + candidate.logicalBindingPath
                val preferred = sealedResourceName(seed, "a4c", routeIdentity, ordinal)
                uniqueSealedResourceName(
                    seed = seed,
                    kind = "a4c",
                    originalName = routeIdentity,
                    index = ordinal,
                    preferredName = preferred,
                    reservedEntryNames = reservedEntryPaths,
                )
            },
        )
        return true
    }

    /**
     * Reserves artifact-specific native shell/handler chunk resources before
     * page materialization. Only the route-safe candidate identity and logical
     * binding path reach this allocator; chunk plaintext, handles, proofs, and
     * evaluator material remain inside build-only owners.
     */
    internal fun reserveAkenNativeChunkPreSealRoutesIfNeeded(
        artifact: BytecodeArtifact,
        seed: Long,
    ): Boolean {
        val context = currentVbc4BuildContextOrNull() ?: return false
        if (!context.hasAkenNativeChunkCandidates()) return false
        if (context.akenNativeChunkPreSealRouteReservationOrNull() != null) return true

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
            reserveAkenClassPageDescriptorRoutesIfNeeded(context, this)
        }
        context.reserveAkenNativeChunkPreSealRoutes(
            occupiedEntryPaths = occupiedEntryPaths,
            allocator = io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkPreSealRouteAllocator {
                    candidate,
                    ordinal,
                    reservedEntryPaths,
                ->
                val routeIdentity =
                    "aken-native-chunk|" + candidate.identityPageKey + "|" + candidate.logicalBindingPath
                val preferred = sealedResourceName(seed, "a4n", routeIdentity, ordinal)
                uniqueSealedResourceName(
                    seed = seed,
                    kind = "a4n",
                    originalName = routeIdentity,
                    index = ordinal,
                    preferredName = preferred,
                    reservedEntryNames = reservedEntryPaths,
                )
            },
        )
        return true
    }

    /**
     * Materializes the build-only AKEN VBC4, typed StringPage, encrypted
     * ClassPage, and native shell/handler chunk resources before native
     * recompilation so the compiler can receive exact current-page records. The returned artifact owns encrypted page-entry
     * bytes; the active build context retains only the adjacent finalization
     * layout.
     */
    internal fun materializeAkenVbc4PagesForNativeCompilation(
        artifact: BytecodeArtifact,
        seed: Long,
    ): BytecodeArtifact =
        AkenVbc4ProductionMaterializer.materializeBeforeNativeCompilation(artifact, seed)

    fun sealIfRequested(artifact: BytecodeArtifact, config: ObfuscationConfig): BytecodeArtifact {
        if (!isRequested(config)) return artifact
        val maxHardening = config.passes.any { pass ->
            pass.enabled && pass.id == "jni-microkernel-loader" &&
                pass.params["nativePackingLevel"]?.asText() == "max-hardening"
        }
        return seal(
            artifact,
            seedFromConfig(config),
            rewritesVmRuntime = config.enablesPass("method-virtualization"),
            maxHardening = maxHardening,
            typedOnlyRuntime = config.enablesPass("jni-microkernel-loader"),
        )
    }

    internal fun seal(
        artifact: BytecodeArtifact,
        seed: Long,
        @Suppress("UNUSED_PARAMETER")
        rewritesVmRuntime: Boolean = true,
        maxHardening: Boolean = false,
        typedOnlyRuntime: Boolean = false,
    ): BytecodeArtifact {
        validateAkenR1NativeInputs(artifact.jarEntries)
        val reservedEntryNames = artifact.jarEntries.map { it.name }.toMutableSet()
        val activeContext = currentVbc4BuildContextOrNull()
        activeContext
            ?.akenVbc4PreSealRouteReservationOrNull()
            ?.withRoutesForBuild { routes ->
                routes.forEach { route ->
                    val isPublishedPageContainer = activeContext
                        .akenVbc4FinalizationLayoutOrNull()
                        ?.hasEntryForBuild(route.futureContainerPath) == true
                    require(route.futureContainerPath !in reservedEntryNames || isPublishedPageContainer) {
                        "AKEN VBC4 pre-seal route collides with the sealing input namespace"
                    }
                    reservedEntryNames += route.futureContainerPath
                }
            }
        activeContext
            ?.akenStringPagePreSealRouteReservationOrNull()
            ?.withRoutesForBuild { routes ->
                routes.forEach { route ->
                    val isPublishedStringPage = activeContext
                        .akenVbc4FinalizationLayoutOrNull()
                        ?.hasEntryForBuild(route.futureResourcePath) == true
                    require(route.futureResourcePath !in reservedEntryNames || isPublishedStringPage) {
                        "AKEN StringPage pre-seal route collides with the sealing input namespace"
                    }
                    reservedEntryNames += route.futureResourcePath
                }
            }
        activeContext
            ?.akenClassPagePreSealRouteReservationOrNull()
            ?.withRoutesForBuild { routes ->
                routes.forEach { route ->
                    val isPublishedClassPage = activeContext
                        .akenVbc4FinalizationLayoutOrNull()
                        ?.hasEntryForBuild(route.futureResourcePath) == true
                    require(route.futureResourcePath !in reservedEntryNames || isPublishedClassPage) {
                        "AKEN ClassPage pre-seal route collides with the sealing input namespace"
                    }
                    reservedEntryNames += route.futureResourcePath
                }
            }
        activeContext
            ?.akenNativeChunkPreSealRouteReservationOrNull()
            ?.withRoutesForBuild { routes ->
                routes.forEach { route ->
                    val isPublishedNativeChunk = activeContext
                        .akenVbc4FinalizationLayoutOrNull()
                        ?.hasEntryForBuild(route.futureResourcePath) == true
                    require(route.futureResourcePath !in reservedEntryNames || isPublishedNativeChunk) {
                        "AKEN NativeChunk pre-seal route collides with the sealing input namespace"
                    }
                    reservedEntryNames += route.futureResourcePath
                }
            }
        val akenNativeLocatorResource = if (artifact.jarEntries.any { entry -> isR1NativeKernelResource(entry.name) }) {
            uniqueSealedResourceName(
                seed = seed,
                kind = "a",
                originalName = "aken-native-locator",
                index = 0,
                preferredName = sealedResourceName(seed, "a", "aken-native-locator", 0),
                reservedEntryNames = reservedEntryNames,
            ).also(reservedEntryNames::add)
        } else {
            null
        }
        var sealedNativeBindingsResource: String? = null
        var akenNativeBindingsLocatorResource: String? = null
        val sealedNativeIndexResource = uniqueSealedResourceName(
            seed = seed,
            kind = "i",
            originalName = "native-index",
            index = 0,
            preferredName = sealedNativeIndexResourceName(seed),
            reservedEntryNames = reservedEntryNames,
        )
        reservedEntryNames += sealedNativeIndexResource
        val helperClassRenameMap = sealedRuntimeHelperRenameMap(artifact, seed, typedOnlyRuntime)
        val helperMemberRenamePlan = sealedJavaOnlyHelperMemberRenamePlan(seed, helperClassRenameMap, typedOnlyRuntime)
        val helperStringRewriteMap = linkedMapOf(
            LEGACY_SEALED_NATIVE_INDEX_RESOURCE to sealedNativeIndexResource,
        )
        akenNativeLocatorResource?.let { sealedPath ->
            helperStringRewriteMap[AKEN_NATIVE_LOCATOR_LOGICAL_RESOURCE] = sealedPath
        }
        if (helperClassRenameMap.isNotEmpty()) {
            sealedNativeBindingsResource = uniqueSealedResourceName(
                seed = seed,
                kind = "b",
                originalName = "native-bindings",
                index = 0,
                preferredName = sealedNativeBindingsResourceName(seed),
                reservedEntryNames = reservedEntryNames,
            )
            val bindingResource = checkNotNull(sealedNativeBindingsResource)
            reservedEntryNames += bindingResource
            helperStringRewriteMap[LEGACY_SEALED_NATIVE_BINDINGS_RESOURCE] = bindingResource
            if (akenNativeLocatorResource != null) {
                akenNativeBindingsLocatorResource = uniqueSealedResourceName(
                    seed = seed,
                    kind = "q",
                    originalName = "aken-native-bindings-locator",
                    index = 0,
                    preferredName = sealedResourceName(seed, "q", "aken-native-bindings-locator", 0),
                    reservedEntryNames = reservedEntryNames,
                )
                val locatorPath = checkNotNull(akenNativeBindingsLocatorResource)
                reservedEntryNames += locatorPath
                helperStringRewriteMap[AKEN_NATIVE_BINDINGS_LOCATOR_LOGICAL_RESOURCE] = locatorPath
            }
        }
        helperStringRewriteMap.putAll(sealedHelperStringRewriteMap(seed, helperClassRenameMap))
        val sealedNativeSpecs = mutableListOf<SealedNativeSpec>()
        val methodRenameBindings = parseMethodRenameBindings(artifact.jarEntries)
        val fieldRenameBindings = parseFieldRenameBindings(artifact.jarEntries)
        val sealedNativeResourceRenameMap = linkedMapOf<String, String>()
        artifact.jarEntries.forEachIndexed { index, entry ->
            if (isR1NativeKernelResource(entry.name)) {
                val nativeSpec = nativeSpecFor(entry.name)
                val sealedName = uniqueSealedNativeResourceName(
                    seed = seed,
                    originalName = entry.name,
                    index = index,
                    suffix = nativeSpec.loadSuffix,
                    reservedEntryNames = reservedEntryNames,
                )
                reservedEntryNames += sealedName
                sealedNativeResourceRenameMap[entry.name] = sealedName
            }
        }

        val renamedJarEntries = artifact.jarEntries.mapIndexedNotNull { index, entry ->
            when {
                isR1NativeKernelResource(entry.name) -> {
                    val nativeSpec = nativeSpecFor(entry.name)
                    val sealedName = sealedNativeResourceRenameMap.getValue(entry.name)
                    sealedNativeSpecs += nativeSpec.copy(resourceName = sealedName)
                    val decoded = RuntimeResourceCodec.decode(entry.bytes)
                    require(decoded != null || entry.bytes.isRawR1NativeImage()) {
                        "AKEN-R1 native resource wrapper failed authentication: ${entry.name}"
                    }
                    entry.copy(name = sealedName, bytes = decoded ?: entry.bytes)
                }
                entry.name == LEGACY_SEALED_NATIVE_INDEX_RESOURCE || entry.name == LEGACY_SEALED_NATIVE_BINDINGS_RESOURCE -> null
                entry.name == METHOD_RENAME_BINDINGS_RESOURCE || entry.name == FIELD_RENAME_BINDINGS_RESOURCE -> null
                else -> renamedClassEntry(entry, helperClassRenameMap)
            }
        }

        if (
            sealedNativeSpecs.isEmpty() &&
            helperClassRenameMap.isEmpty()
        ) {
            publishAkenArtifactCommitment(artifact)
            return artifact
        }

        val rewrittenClassArtifacts = artifact.classArtifacts.map { classArtifact ->
            rewriteClassArtifact(
                classArtifact = classArtifact,
                seed = seed,
                helperStringRewriteMap = helperStringRewriteMap,
                resourceStringRewriteMap = emptyMap(),
                helperClassRenameMap = helperClassRenameMap,
                helperMemberRenamePlan = helperMemberRenamePlan,
            ) ?: classArtifact
        }
        val rewrittenClassBytesByEntry = rewrittenClassArtifacts.flatMap { classArtifact ->
            listOf(
                classArtifact.entryName to classArtifact.bytes,
                "${classArtifact.summary.internalName}.class" to classArtifact.bytes,
            )
        }.toMap()
        var catalogNativeBinding: FinalNativeBinding? = null
        val synchronizedJarEntries = renamedJarEntries.map { entry ->
            val synchronizedEntry = rewrittenClassBytesByEntry[entry.name]?.let { bytes -> entry.copy(bytes = bytes) } ?: entry
            synchronizedEntry
        }.let { entries ->
            val runtimeEntries = entries.toMutableList()
            if (sealedNativeSpecs.isNotEmpty() || helperClassRenameMap.isNotEmpty()) {
                val applicationMethodBindings = expandMethodRenameBindingsAcrossFinalOwners(methodRenameBindings, rewrittenClassArtifacts) +
                    collectApplicationMethodRenameBindings(rewrittenClassArtifacts, helperClassRenameMap)
                val applicationFieldBindings = expandFieldRenameBindingsAcrossFinalOwners(fieldRenameBindings, rewrittenClassArtifacts)
                runtimeEntries += JarEntryData(
                    name = sealedNativeIndexResource,
                    bytes = encodeSealedNativeIndex(sealedNativeSpecs, seed, maxHardening),
                )
                sealedNativeBindingsResource?.let { bindingResource ->
                    runtimeEntries += JarEntryData(
                        name = bindingResource,
                        bytes = encodeSealedNativeBindings(
                            helperClassRenameMap = helperClassRenameMap,
                            helperMemberRenamePlan = helperMemberRenamePlan,
                            applicationMethodBindings = applicationMethodBindings,
                            applicationFieldBindings = applicationFieldBindings,
                            seed = seed,
                        ),
                    )
                }
            }
            if (sealedNativeSpecs.isNotEmpty()) {
                val locatorPath = checkNotNull(akenNativeLocatorResource)
                val nativeEntryCounts = runtimeEntries.groupingBy(JarEntryData::name).eachCount()
                val nativeBytesByPath = runtimeEntries.associate { entry -> entry.name to entry.bytes }
                val locatorEntries = sealedNativeSpecs.map { spec ->
                    require(nativeEntryCounts[spec.resourceName] == 1) {
                        "AKEN-R1 final native target must be emitted exactly once: ${spec.resourceName}"
                    }
                    val nativeBytes = checkNotNull(nativeBytesByPath[spec.resourceName]) {
                        "AKEN native locator target was not emitted: ${spec.resourceName}"
                    }
                    require(nativeBytes.isNotEmpty() && nativeBytes.size <= AKEN_NATIVE_MAX_LIBRARY_BYTES) {
                        "AKEN-R1 final native artifact length is invalid: ${spec.resourceName}"
                    }
                    AkenNativeLocator.entry(
                        platform = spec.platform,
                        resourcePath = spec.resourceName,
                        fileSuffix = spec.loadSuffix,
                        storedBytes = nativeBytes,
                    )
                }
                val bindingsLocatorEntry = akenNativeBindingsLocatorResource?.let {
                    val bindingPath = checkNotNull(sealedNativeBindingsResource) {
                        "AKEN native bindings locator requires a final bindings resource"
                    }
                    require(nativeEntryCounts[bindingPath] == 1) {
                        "AKEN-R1 final native bindings target must be emitted exactly once: $bindingPath"
                    }
                    val bindingBytes = checkNotNull(nativeBytesByPath[bindingPath]) {
                        "AKEN native bindings locator target was not emitted: $bindingPath"
                    }
                    require(bindingBytes.isNotEmpty() && bindingBytes.size <= AKEN_NATIVE_BINDINGS_MAX_BYTES) {
                        "AKEN-R1 final native bindings length is invalid: $bindingPath"
                    }
                    AkenNativeLocator.bindingsEntry(
                        resourcePath = bindingPath,
                        storedBytes = bindingBytes,
                    )
                }
                val finalNativeBindingDigest = AkenNativeLocator.finalNativeBindingDigest(
                    entries = locatorEntries,
                    bindingsEntry = bindingsLocatorEntry,
                )
                val finalArtifactBindingDigest = try {
                    AkenNativeLocator.finalNativeBindingDigestFromArtifact(
                        artifactEntries = runtimeEntries,
                        locatorEntries = locatorEntries,
                        bindingsEntry = bindingsLocatorEntry,
                    )
                } finally {
                    val digestBytes = finalNativeBindingDigest.asBytes()
                    Arrays.fill(digestBytes, 0)
                }
                val expectedDigestBytes = finalNativeBindingDigest.asBytes()
                val actualDigestBytes = finalArtifactBindingDigest.asBytes()
                try {
                    require(MessageDigest.isEqual(expectedDigestBytes, actualDigestBytes)) {
                        "AKEN-R1 final native binding changed during sealing"
                    }
                } finally {
                    Arrays.fill(expectedDigestBytes, 0)
                    Arrays.fill(actualDigestBytes, 0)
                    finalArtifactBindingDigest.asBytes().fill(0)
                }
                val locatorBytes = try {
                    AkenNativeLocator.encode(
                        entries = locatorEntries,
                        bindingsEntry = bindingsLocatorEntry,
                        expectedFinalBindingDigest = finalNativeBindingDigest,
                    )
                } finally {
                    val digestBytes = finalNativeBindingDigest.asBytes()
                    Arrays.fill(digestBytes, 0)
                }
                runtimeEntries += JarEntryData(name = locatorPath, bytes = locatorBytes)
                catalogNativeBinding = catalogNativeBindingFromLocator(locatorEntries)
            }
            runtimeEntries
        }
        val rewrittenSummaries = rewrittenClassArtifacts.map { it.summary }
        val sealedArtifact = artifact.copy(
            jarEntries = synchronizedJarEntries,
            classArtifacts = rewrittenClassArtifacts,
            classArtifactIndex = classArtifactIndex(rewrittenClassArtifacts),
            analysisSummary = artifact.analysisSummary.copy(
                classCount = rewrittenClassArtifacts.size,
                resourceCount = resourceCount(synchronizedJarEntries, rewrittenClassArtifacts.size),
                classSummaries = rewrittenSummaries,
                classNameIndex = classSummaryIndex(rewrittenSummaries),
            ),
        )
        // This is deliberately the last sealing-stage hook: resource names,
        // helper rewrites, and injected native entries have reached their final
        // artifact representation.  It intentionally does not use the early
        // jar-layout digest, RuntimeResourceCodec, or any boot material.
        //
        // No root-shard ranges are supplied yet because the current legacy
        // output has not reserved AKEN root-shard byte ranges.  The metadata
        // layer nonetheless owns the canonical final-entry representation now,
        // so a later AKEN emitter can reserve shards and call the same API
        // without reviving a boot/root-key path.
        publishAkenArtifactCommitment(sealedArtifact)
        val wrappedArtifact = HardenedArtifactFinalizer.wrapIndyTargets(sealedArtifact)
        val nativeBinding = catalogNativeBinding ?: return wrappedArtifact
        try {
            return attachAkenR1CatalogSidecar(wrappedArtifact, nativeBinding)
        } finally {
            nativeBinding.wipe()
        }
    }
}

/**
 * Build-only transition hook for the AKEN v4 sealing pipeline.
 *
 * It is intentionally internal and returns no artifact metadata: current
 * legacy runtime readers must remain behaviorally unchanged until the native
 * AKEN handle path emits per-page route/proof records.  When an AKEN plan has
 * already been initialized by that later phase, its commitment is required to
 * match this final representation; this catches accidental early-plan use.
 */
internal fun publishAkenArtifactCommitment(artifact: BytecodeArtifact): AkenArtifactCommitment {
    val classesByEntry = artifact.classArtifacts.associateBy { classArtifact -> classArtifact.entryName }
    val finalEntries = artifact.jarEntries.map { entry ->
        val finalBytes = classesByEntry[entry.name]?.bytes ?: entry.bytes
        AkenArtifactEntry(name = entry.name, bytes = finalBytes)
    }
    val commitment = AkenArtifactCommitment.compute(finalEntries)
    val context = currentVbc4BuildContextOrNull()
    val plan = context?.akenBuildPlanOrNull()
    if (plan != null) {
        val plannedCommitment = plan.artifactCanonicalCommitment
        val computedCommitment = commitment.bytes
        try {
            check(Arrays.equals(plannedCommitment, computedCommitment)) {
                "AKEN v4 build plan commitment does not match final sealed artifact"
            }
        } finally {
            Arrays.fill(plannedCommitment, 0)
            Arrays.fill(computedCommitment, 0)
        }
    }
    return commitment
}

private fun catalogNativeBindingFromLocator(locatorEntries: List<AkenNativeLocatorEntry>): FinalNativeBinding {
    AkenNativeLocator.catalogBindingInputs(locatorEntries).use { inputs ->
        val context = currentVbc4BuildContextOrNull()
            ?: error("AKEN catalog native binding requires a live VBC4 build context")
        val specializationDigest = context.copyNativeSpecializationDigest(inputs.platform)
        try {
            return FinalNativeBinding(
                nativeSha256 = inputs.nativeSha256,
                abiDigest = inputs.abiDigest,
                targetTriple = inputs.targetTriple,
                specializationDigest = specializationDigest,
                payloadProfile = inputs.payloadProfile,
            )
        } finally {
            Arrays.fill(specializationDigest, 0)
        }
    }
}

private data class SealedNativeSpec(
    val platform: String,
    val resourceName: String,
    val loadSuffix: String,
)

private data class SealedMemberRef(
    val owner: String,
    val name: String,
    val descriptor: String,
)

private data class SealedHelperMemberRenamePlan(
    val methodRenames: Map<SealedMemberRef, String>,
    val fieldRenames: Map<SealedMemberRef, String>,
) {
    fun methodName(owner: String?, name: String?, descriptor: String?): String? =
        if (owner == null || name == null || descriptor == null) {
            name
        } else if (name == "<init>" || name == "<clinit>") {
            name
        } else {
            methodRenames[SealedMemberRef(owner, name, descriptor)] ?: name
        }

    fun fieldName(owner: String?, name: String?, descriptor: String?): String? =
        if (owner == null || name == null || descriptor == null) {
            name
        } else {
            fieldRenames[SealedMemberRef(owner, name, descriptor)] ?: name
        }
}

private fun seedFromConfig(config: ObfuscationConfig): Long = requireVbc4BuildContext().nativeSeed

private fun ObfuscationConfig.enablesPass(passId: String): Boolean =
    passes.any { it.enabled && it.id == passId }

private fun renamedClassEntry(entry: JarEntryData, classRenameMap: Map<String, String>): JarEntryData {
    val internalName = entry.name.takeIf { it.endsWith(".class") }?.removeSuffix(".class") ?: return entry
    val renamedInternalName = classRenameMap[internalName] ?: return entry
    return entry.copy(name = "$renamedInternalName.class")
}

private fun sealedRuntimeHelperRenameMap(
    artifact: BytecodeArtifact,
    seed: Long,
    typedOnlyRuntime: Boolean = false,
): Map<String, String> {
    val presentClassNames = artifact.classArtifacts.map { it.summary.internalName }.toSet()
    val reservedClassNames = artifact.jarEntries
        .asSequence()
        .filter { it.name.endsWith(".class") }
        .map { it.name.removeSuffix(".class") }
        .toMutableSet()
    val renameMap = linkedMapOf<String, String>()
    SEALED_RUNTIME_HELPERS.forEachIndexed { index, helperName ->
        // VBC4 pages can carry opaque invokedynamic terminal records whose
        // bootstrap target embeds this owner.  Until those encrypted page
        // constants are rewritten in the same sealing transaction, retain the
        // helper owner so the native-backed terminal remains resolvable.
        if (typedOnlyRuntime && helperName == "$PROTECTION_HELPER_PACKAGE/StringEncryptionHelper") return@forEachIndexed
        if (helperName in presentClassNames) {
            val outerName = helperName.substringBefore('$')
            val sealedOuterName = renameMap[outerName]
            val preferredName = if (sealedOuterName != null && '$' in helperName) {
                sealedNestedHelperInternalName(seed, sealedOuterName, helperName, index)
            } else {
                sealedHelperInternalName(seed, helperName, index)
            }
            val sealedName = uniqueSealedHelperName(seed, helperName, index, preferredName, reservedClassNames)
            renameMap[helperName] = sealedName
            reservedClassNames += sealedName
        }
    }
    return renameMap
}

private fun uniqueSealedHelperName(
    seed: Long,
    originalName: String,
    index: Int,
    preferredName: String,
    reservedClassNames: Set<String>,
): String {
    if (preferredName !in reservedClassNames || preferredName == originalName) return preferredName
    for (attempt in 1..1024) {
        val digest = sealedDigest(seed, "hc", "$originalName#$attempt", index)
        val candidate = "jsh/${digest.take(2)}/H${digest.drop(2).take(24)}"
        if (candidate !in reservedClassNames) return candidate
    }
    error("Unable to allocate collision-free sealed helper name for $originalName")
}



internal fun sealedRuntimeHelperInternalName(originalName: String, seed: Long = currentRuntimeSealingSeed()): String {
    val index = SEALED_RUNTIME_HELPERS.indexOf(originalName)
    require(index >= 0) { "Unknown sealed runtime helper: $originalName" }
    return sealedHelperInternalName(seed, originalName, index)
}

internal fun sealedRuntimeHelperMethodName(owner: String, name: String, descriptor: String, seed: Long = currentRuntimeSealingSeed()): String =
    sealedMemberName(seed, owner, name, descriptor, "m")

internal fun sealedRuntimeHelperFieldName(owner: String, name: String, descriptor: String, seed: Long = currentRuntimeSealingSeed()): String =
    sealedMemberName(seed, owner, name, descriptor, "f")

private fun currentRuntimeSealingSeed(): Long = requireVbc4BuildContext().nativeSeed
private fun sealedJavaOnlyHelperMemberRenamePlan(
    seed: Long,
    helperClassRenameMap: Map<String, String>,
    typedOnlyRuntime: Boolean = false,
): SealedHelperMemberRenamePlan {
    val methodRenames = linkedMapOf<SealedMemberRef, String>()
    val fieldRenames = linkedMapOf<SealedMemberRef, String>()

    fun addMethod(owner: String, name: String, descriptor: String) {
        val sealedOwner = helperClassRenameMap[owner] ?: return
        if (name == "<init>" || name == "<clinit>") return
        val renamableAkenNativeMethods = setOf(
            "nativeInit",
            "nativeHeartbeat",
            "nativeInstallAkenSessionNonce",
            "nativeInstallAkenCatalog",
            "nativeExecuteAkenVmPage",
            "nativeOpenAkenString",
            "nativeReadAkenClassPage",
            "nativeConsumeAkenNativeChunk",
            "nativeInitializeDefense",
            "nativeProbeDefense",
            "nativeTransformDefense",
        )
        if (name.startsWith("native") && name !in renamableAkenNativeMethods) return
        if (
            owner == "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper" &&
            (name == "createSamLambda" ||
                name == "takeExpectedShellBindingCommitment" || name == "takeBootSecretForNativeShell")
        ) return
        val sealedMethodName = sealedMemberName(seed, owner, name, descriptor, "m")
        for (candidate in listOf(owner, sealedOwner)) {
            methodRenames[SealedMemberRef(candidate, name, descriptor)] = sealedMethodName
        }
    }

    fun addField(owner: String, name: String, descriptor: String) {
        val sealedOwner = helperClassRenameMap[owner] ?: return
        val sealedFieldName = sealedMemberName(seed, owner, name, descriptor, "f")
        for (candidate in listOf(owner, sealedOwner)) {
            fieldRenames[SealedMemberRef(candidate, name, descriptor)] = sealedFieldName
        }
    }

    val exceptionHelper = "$PROTECTION_HELPER_PACKAGE/ExceptionVirtualizationHelper"
    addMethod(exceptionHelper, "shouldVirtualize", "()Z")
    addField(exceptionHelper, "enabled", "Z")
    val flowControlException = "$PROTECTION_HELPER_PACKAGE/FlowControlException"
    addMethod(flowControlException, "<init>", "()V")
    addMethod(flowControlException, "<init>", "(I)V")
    addMethod(flowControlException, "getState", "()I")
    addField(flowControlException, "state", "I")

    // AKEN v4 binds only the typed current-page/native-loader surface.  Do
    // not write legacy boot, generic resource decoder, or central VM dispatch
    // names into a sealed binding map for a new artifact.
    val jniHelper = "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper"
    addMethod(jniHelper, "loadKernel", "(Ljava/lang/String;Ljava/lang/String;)V")
    addMethod(jniHelper, "loadKernel", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V")
    addMethod(jniHelper, "executeAkenVmPage", "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;")
    addMethod(jniHelper, "openAkenString", "([BI[B)Ljava/lang/String;")
    addMethod(jniHelper, "readAkenClassPage", "([BI[B)[B")
    addMethod(jniHelper, "consumeAkenNativeChunk", "([BI[B)V")
    addMethod(jniHelper, "nativeInit", "(Ljava/lang/String;)I")
    addMethod(jniHelper, "nativeHeartbeat", "()I")
    addMethod(jniHelper, "nativeInstallAkenSessionNonce", "([B)Z")
    addMethod(jniHelper, "nativeInstallAkenCatalog", "([B[B)I")
    addMethod(jniHelper, "nativeExecuteAkenVmPage", "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;")
    addMethod(jniHelper, "nativeOpenAkenString", "([BI[B)Ljava/lang/String;")
    addMethod(jniHelper, "nativeReadAkenClassPage", "([BI[B)[B")
    addMethod(jniHelper, "nativeConsumeAkenNativeChunk", "([BI[B)V")
    // Unified defense is part of the current typed JNI ABI.  Keep these
    // declarations in the sealed member map even though their canonical
    // marker literals remain in the helper for native-image validation.
    addMethod(jniHelper, "expectDefenseForProtectedPath", "()V")
    addMethod(jniHelper, "nativeInitializeDefense", "(Ljava/lang/String;Ljava/lang/String;)I")
    addMethod(jniHelper, "nativeProbeDefense", "(Ljava/lang/String;Ljava/lang/String;)I")
    addMethod(jniHelper, "nativeTransformDefense", "([BLjava/lang/String;)[B")
    addMethod(jniHelper, "createSamLambda", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;")

    val bootstrap = "$PROTECTION_HELPER_PACKAGE/BootstrapEncryptionHelper"
    addMethod(bootstrap, "decryptBytes", "(Ljava/lang/String;Ljava/lang/String;)[B")
    addMethod(bootstrap, "encryptedBootstrap", "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;")

    val stringEncryption = "$PROTECTION_HELPER_PACKAGE/StringEncryptionHelper"
    addMethod(stringEncryption, "invokeAkenStringTerminal", "([B)Ljava/lang/String;")
    addMethod(stringEncryption, "invokeAkenStringTerminal", "([BI[B)Ljava/lang/String;")
    addMethod(stringEncryption, "materializeAkenStringToken", "(Ljava/lang/String;)[B")
    val stringBootstrapDescriptor =
        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
            "Ljava/lang/invoke/MethodHandle;)Ljava/lang/invoke/CallSite;"
    listOf("q0", "m7", "x3", "v8").forEach { bootstrapName ->
        addMethod(stringEncryption, bootstrapName, stringBootstrapDescriptor)
    }
    val stringTokenBootstrapDescriptor =
        "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;" +
            "Ljava/lang/String;)Ljava/lang/invoke/CallSite;"
    listOf("u0", "u1", "u2", "u3").forEach { bootstrapName ->
        addMethod(stringEncryption, bootstrapName, stringTokenBootstrapDescriptor)
    }


    return SealedHelperMemberRenamePlan(methodRenames = methodRenames, fieldRenames = fieldRenames)
}
private fun sealedHelperStringRewriteMap(seed: Long, helperClassRenameMap: Map<String, String>): Map<String, String> {
    val rewriteMap = linkedMapOf<String, String>()
    for ((originalName, sealedName) in helperClassRenameMap) {
        rewriteMap[originalName] = sealedName
        rewriteMap[originalName.replace('/', '.')] = sealedName.replace('/', '.')
    }
    val optionalJniHelper = "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper"
    if (optionalJniHelper !in helperClassRenameMap) {
        rewriteMap[optionalJniHelper] = sealedSemanticText(seed, "optional-jni-helper-internal")
        rewriteMap[optionalJniHelper.replace('/', '.')] = sealedSemanticText(seed, "optional-jni-helper-binary")
    }
    if ("$PROTECTION_HELPER_PACKAGE/FlowControlException" in helperClassRenameMap) {
        rewriteMap["Flow control"] = sealedSemanticText(seed, "flow-control")
    }
    rewriteMap["__nvmr1__"] = sealedSemanticText(seed, "native-vm-result-marker")
    rewriteMap["native:abi-missing:nativeExecuteVmResource"] = sealedSemanticText(seed, "native-vm-abi-error")
    return rewriteMap
}

private fun sealedHelperMethodStringRewriteMap(helperMemberRenamePlan: SealedHelperMemberRenamePlan): Map<String, String> {
    // JniMicrokernelHelper validates the bundled native image by searching for
    // the canonical Rust ABI marker names.  Those marker strings describe the
    // native registration surface, not Java call-site members, so they must
    // remain unchanged even when the Java declarations are relocated/renamed.
    // The sealed binding map still carries the Java-side renamed method names
    // for dynamic registration; only these diagnostic marker literals are
    // excluded from string rewriting.
    val nativeAbiMarkers = setOf(
        "nativeInit",
        "nativeHeartbeat",
        "nativeInstallAkenSessionNonce",
        "nativeInstallAkenCatalog",
        "nativeExecuteAkenVmPage",
        "nativeOpenAkenString",
        "nativeReadAkenClassPage",
        "nativeConsumeAkenNativeChunk",
        "nativeInitializeDefense",
        "nativeProbeDefense",
        "nativeTransformDefense",
    )
    val rewriteMap = linkedMapOf<String, String>()
    for ((ref, sealedName) in helperMemberRenamePlan.methodRenames) {
        if (
            ref.owner.startsWith(PROTECTION_HELPER_PACKAGE) &&
                ref.name.startsWith("native") &&
                ref.name !in nativeAbiMarkers
        ) {
            rewriteMap.putIfAbsent(ref.name, sealedName)
        }
        // The sealed helper keeps artifact-specific JNI method names, but its
        // native-image validation table must continue to carry the canonical
        // ABI marker strings.  A previous helper/member rewrite can encounter
        // the marker after the declaration has already been renamed; reverse
        // that string-only rewrite here without changing the actual JNI method
        // binding map.
        if (
            ref.owner.startsWith(PROTECTION_HELPER_PACKAGE) &&
                ref.name in nativeAbiMarkers
        ) {
            rewriteMap.putIfAbsent(sealedName, ref.name)
        }
    }
    return rewriteMap
}

private fun validateAkenR1NativeInputs(entries: Iterable<JarEntryData>) {
    entries.forEach { entry ->
        when {
            isR1NativeKernelResource(entry.name) -> {
                val spec = nativeSpecFor(entry.name)
                require(entry.bytes.isNotEmpty() && entry.bytes.size <= AKEN_NATIVE_MAX_LIBRARY_BYTES) {
                    "AKEN-R1 native input length is invalid: ${entry.name}"
                }
                require(spec.platform == "windows-x64" || spec.platform == "linux-x64") {
                    "AKEN-R1 native input platform is unsupported: ${spec.platform}"
                }
            }
            isRetiredNativeKernelResource(entry.name) -> {
                error("AKEN-R1 rejects retired C/Zig/Mach-O native resource: ${entry.name}")
            }
        }
    }
}

private fun isR1NativeKernelResource(entryName: String): Boolean =
    NativeRecompilationRoute.canonicalPlatformOrder.any { platform ->
        NativeRecompilationRoute.forPlatform(platform).preSealResourcePath == entryName
    }

private fun isRetiredNativeKernelResource(entryName: String): Boolean {
    val lowerName = entryName.lowercase()
    if (!lowerName.startsWith("meta-inf/")) return false
    val dynamicSuffix = lowerName.endsWith(".dll") || lowerName.endsWith(".so") || lowerName.endsWith(".dylib")
    return dynamicSuffix && !isR1NativeKernelResource(entryName)
}

private fun nativeSpecFor(entryName: String): SealedNativeSpec {
    val route = NativeRecompilationRoute.canonicalPlatformOrder
        .map(NativeRecompilationRoute::forPlatform)
        .singleOrNull { it.preSealResourcePath == entryName }
        ?: error("AKEN-R1 rejects unsupported native resource: $entryName")
    return SealedNativeSpec(
        platform = route.platform,
        resourceName = entryName,
        loadSuffix = route.loadSuffix,
    )
}

private fun ByteArray.isRawR1NativeImage(): Boolean =
    size >= 4 && (
        (this[0] == 'M'.code.toByte() && this[1] == 'Z'.code.toByte()) ||
            (this[0] == 0x7F.toByte() && this[1] == 'E'.code.toByte() &&
                this[2] == 'L'.code.toByte() && this[3] == 'F'.code.toByte())
        )

private fun sealedNativeIndexResourceName(seed: Long): String =
    sealedResourceName(seed, "i", "native-index", 0)

private fun sealedNativeBindingsResourceName(seed: Long): String =
    sealedResourceName(seed, "b", "native-bindings", 0)

private fun sealedResourceRoot(seed: Long): String {
    val digest = sealedDigest(seed, "rr", "runtime-artifacts", 0)
    return "META-INF/${digest.take(2)}/${digest.drop(2).take(14)}"
}

private fun sealedResourceName(seed: Long, kind: String, originalName: String, index: Int): String {
    val digest = sealedDigest(seed, kind, originalName, index)
    return "${sealedResourceRoot(seed)}/${digest.take(2)}/${digest.drop(2).take(30)}${sealedInnocuousExtension(digest)}"
}

private fun sealedNativeResourceName(seed: Long, originalName: String, index: Int, suffix: String): String {
    val digest = sealedDigest(seed, "n", originalName, index)
    return "${sealedResourceRoot(seed)}/${digest.take(2)}/${digest.drop(2).take(30)}$suffix"
}

private fun uniqueSealedResourceName(
    seed: Long,
    kind: String,
    originalName: String,
    index: Int,
    preferredName: String,
    reservedEntryNames: Set<String>,
): String {
    if (preferredName !in reservedEntryNames) return preferredName
    for (attempt in 1..1024) {
        val digest = sealedDigest(seed, "$kind-c", "$originalName#$attempt", index)
        val candidate = "${sealedResourceRoot(seed)}/${digest.take(2)}/${digest.drop(2).take(30)}${sealedInnocuousExtension(digest)}"
        if (candidate !in reservedEntryNames) return candidate
    }
    error("Unable to allocate collision-free sealed resource name for $originalName")
}

private fun uniqueSealedNativeResourceName(
    seed: Long,
    originalName: String,
    index: Int,
    suffix: String,
    reservedEntryNames: Set<String>,
): String {
    val preferredName = sealedNativeResourceName(seed, originalName, index, suffix)
    if (preferredName !in reservedEntryNames) return preferredName
    for (attempt in 1..1024) {
        val digest = sealedDigest(seed, "n-c", "$originalName#$attempt", index)
        val candidate = "${sealedResourceRoot(seed)}/${digest.take(2)}/${digest.drop(2).take(30)}$suffix"
        if (candidate !in reservedEntryNames) return candidate
    }
    error("Unable to allocate collision-free sealed native resource name for $originalName")
}

private fun sealedHelperInternalName(seed: Long, originalName: String, index: Int): String {
    val digest = sealedDigest(seed, "h", originalName, index)
    // Never recreate a retired fixed-r helper namespace. This includes the
    // hexadecimal-shard form such as r.d2.C03c6b81f63fb4dc18f2033e7.
    return "jsh/${digest.take(2)}/H${digest.drop(2).take(24)}"
}

private fun sealedNestedHelperInternalName(seed: Long, sealedOuterName: String, originalName: String, index: Int): String {
    val digest = sealedDigest(seed, "hi", originalName, index)
    return "$sealedOuterName\$I${digest.take(16)}"
}

private fun sealedMemberName(seed: Long, owner: String, name: String, descriptor: String, kind: String): String {
    val digest = sealedDigest(seed, kind, "$owner#$name$descriptor", 0)
    return "${kind}_${digest.take(16)}"
}

private fun sealedSemanticText(seed: Long, value: String): String {
    val digest = sealedDigest(seed, "s", value, 0)
    return "x_${digest.take(16)}"
}

private fun sealedDigest(seed: Long, kind: String, value: String, index: Int): String =
    MessageDigest.getInstance("SHA-256")
        .digest("$seed|$kind|$index|$value".toByteArray(Charsets.UTF_8))
        .toHexLower()

private val SEALED_RESOURCE_EXTENSIONS = listOf(
    "properties", "xml", "json", "yml", "cfg", "conf", "ini", "txt"
)

private fun sealedInnocuousExtension(digest: String): String {
    val idx = (digest.hashCode() and 0x7FFFFFFF) % SEALED_RESOURCE_EXTENSIONS.size
    return "." + SEALED_RESOURCE_EXTENSIONS[idx]
}
@Suppress("UNUSED_PARAMETER")
private fun encodeSealedNativeIndex(
    specs: List<SealedNativeSpec>,
    seed: Long,
    maxHardening: Boolean,
): ByteArray {
    return specs
        .joinToString(separator = "\n", postfix = if (specs.isEmpty()) "" else "\n") { spec ->
            listOf(spec.platform, spec.resourceName, spec.loadSuffix).joinToString("|")
        }
        .toByteArray(Charsets.US_ASCII)
}

private fun encodeSealedNativeBindings(
    helperClassRenameMap: Map<String, String>,
    helperMemberRenamePlan: SealedHelperMemberRenamePlan,
    applicationMethodBindings: Map<SealedMemberRef, String> = emptyMap(),
    applicationFieldBindings: Map<SealedMemberRef, String> = emptyMap(),
    seed: Long,
): ByteArray {
    val lines = mutableListOf<String>()
    lines += helperClassRenameMap.map { (originalName, sealedName) -> listOf("B", sealedBindingKey(originalName), sealedName).joinToString("|") }
    /* Helper call sites are rewritten to the sealed owner before VM resource
     * serialization.  The rename plan deliberately carries entries for both
     * the source owner and that sealed owner; publish both keyed identities so
     * native VM symbol resolution can bind a post-remap owner as well as Java
     * side lookups that still use the original helper name. */
    lines += helperMemberRenamePlan.methodRenames
        .filter { (ref, _) -> ref.owner in helperClassRenameMap.keys || ref.owner in helperClassRenameMap.values }
        .map { (ref, sealedName) -> listOf("M", sealedBindingKey("${ref.owner}#${ref.name}#${ref.descriptor}"), sealedName).joinToString("|") }
    lines += applicationMethodBindings
        .map { (ref, renamedName) -> listOf("M", sealedBindingKey("${ref.owner}#${ref.name}#${ref.descriptor}"), renamedName).joinToString("|") }
    lines += helperMemberRenamePlan.fieldRenames
        .filter { (ref, _) -> ref.owner in helperClassRenameMap.keys || ref.owner in helperClassRenameMap.values }
        .map { (ref, renamedName) -> listOf("F", sealedBindingKey("${ref.owner}#${ref.name}#${ref.descriptor}"), renamedName).joinToString("|") }
    lines += applicationFieldBindings
        .map { (ref, renamedName) -> listOf("F", sealedBindingKey("${ref.owner}#${ref.name}#${ref.descriptor}"), renamedName).joinToString("|") }
    return encodeSealedNativeBindingLines(lines, seed)
}

internal fun encodeSealedNativeBindingLines(lines: List<String>, seed: Long): ByteArray {
    @Suppress("UNUSED_VARIABLE")
    val buildDivergenceSeed = seed
    return lines.joinToString(separator = "\n", postfix = "\n").toByteArray(Charsets.US_ASCII)
}

private fun parseMethodRenameBindings(jarEntries: List<JarEntryData>): Map<SealedMemberRef, String> {
    val entry = jarEntries.firstOrNull { it.name == METHOD_RENAME_BINDINGS_RESOURCE } ?: return emptyMap()
    return entry.bytes.toString(Charsets.UTF_8)
        .lineSequence()
        .mapNotNull { line ->
            val parts = line.split('|')
            if (parts.size != 4) return@mapNotNull null
            SealedMemberRef(parts[0], parts[1], parts[2]) to parts[3]
        }
        .toMap(LinkedHashMap())
}

private fun parseFieldRenameBindings(jarEntries: List<JarEntryData>): Map<SealedMemberRef, String> {
    val entry = jarEntries.firstOrNull { it.name == FIELD_RENAME_BINDINGS_RESOURCE } ?: return emptyMap()
    return entry.bytes.toString(Charsets.UTF_8)
        .lineSequence()
        .mapNotNull { line ->
            val parts = line.split('|')
            if (parts.size != 4) return@mapNotNull null
            SealedMemberRef(parts[0], parts[1], parts[2]) to parts[3]
        }
        .toMap(LinkedHashMap())
}

private fun expandMethodRenameBindingsAcrossFinalOwners(
    methodRenameBindings: Map<SealedMemberRef, String>,
    classArtifacts: List<ClassArtifact>,
): Map<SealedMemberRef, String> {
    if (methodRenameBindings.isEmpty()) return emptyMap()
    val expanded = LinkedHashMap<SealedMemberRef, String>()
    expanded.putAll(methodRenameBindings)
    val methodsByRenamedSignature = linkedMapOf<Pair<String, String>, MutableList<String>>()
    for (classArtifact in classArtifacts) {
        val node = ClassNode()
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        for (method in node.methods) {
            val name = method.name ?: continue
            val desc = method.desc ?: continue
            methodsByRenamedSignature.getOrPut(name to desc) { mutableListOf() } += classArtifact.summary.internalName
        }
    }
    for ((ref, renamedName) in methodRenameBindings) {
        for (finalOwner in methodsByRenamedSignature[renamedName to ref.descriptor].orEmpty()) {
            expanded.putIfAbsent(SealedMemberRef(finalOwner, ref.name, ref.descriptor), renamedName)
            expanded.putIfAbsent(SealedMemberRef(finalOwner, renamedName, ref.descriptor), ref.name)
        }
    }
    return expanded
}

private fun expandFieldRenameBindingsAcrossFinalOwners(
    fieldRenameBindings: Map<SealedMemberRef, String>,
    classArtifacts: List<ClassArtifact>,
): Map<SealedMemberRef, String> {
    if (fieldRenameBindings.isEmpty()) return emptyMap()
    val expanded = LinkedHashMap<SealedMemberRef, String>()
    expanded.putAll(fieldRenameBindings)
    val fieldsByRenamedSignature = linkedMapOf<Pair<String, String>, MutableList<String>>()
    for (classArtifact in classArtifacts) {
        val node = ClassNode()
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        for (field in node.fields) {
            val name = field.name ?: continue
            val desc = field.desc ?: continue
            fieldsByRenamedSignature.getOrPut(name to desc) { mutableListOf() } += classArtifact.summary.internalName
        }
    }
    for ((ref, renamedName) in fieldRenameBindings) {
        for (finalOwner in fieldsByRenamedSignature[renamedName to ref.descriptor].orEmpty()) {
            expanded.putIfAbsent(SealedMemberRef(finalOwner, ref.name, ref.descriptor), renamedName)
            expanded.putIfAbsent(SealedMemberRef(finalOwner, renamedName, ref.descriptor), ref.name)
        }
    }
    return expanded
}

private fun collectApplicationMethodRenameBindings(
    classArtifacts: List<ClassArtifact>,
    helperClassRenameMap: Map<String, String>,
): Map<SealedMemberRef, String> {
    val helperNames = helperClassRenameMap.keys + helperClassRenameMap.values
    val bindings = linkedMapOf<SealedMemberRef, String>()
    for (classArtifact in classArtifacts) {
        val owner = classArtifact.summary.internalName
        if (owner in helperNames) continue
        val node = ClassNode()
        ClassReader(classArtifact.bytes).accept(node, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        val declared = node.methods.map { it.name to it.desc }.toSet()
        for (method in node.methods) {
            val bridgeName = method.name ?: continue
            val descriptor = method.desc ?: continue
            val targetCall = pureSameOwnerForwarderTarget(owner, bridgeName, descriptor, method.access, method.instructions.asSequence().toList()) ?: continue
            if ((targetCall.name to descriptor) !in declared) continue
            bindings.putIfAbsent(SealedMemberRef(owner, bridgeName, descriptor), targetCall.name)
            bindings.putIfAbsent(SealedMemberRef(owner, targetCall.name, descriptor), bridgeName)
        }
    }
    return bindings
}


private fun pureSameOwnerForwarderTarget(
    owner: String,
    bridgeName: String,
    descriptor: String,
    access: Int,
    instructions: List<AbstractInsnNode>,
): MethodInsnNode? {
    val meaningful = instructions.filter { instruction ->
        instruction.opcode >= 0 && instruction.type != AbstractInsnNode.LINE && instruction.type != AbstractInsnNode.FRAME && instruction.type != AbstractInsnNode.LABEL
    }
    if (meaningful.isEmpty()) return null
    val callIndex = meaningful.indexOfFirst { instruction ->
        instruction is MethodInsnNode && instruction.owner == owner && instruction.desc == descriptor && instruction.name != bridgeName
    }
    if (callIndex < 0) return null
    val targetCall = meaningful[callIndex] as MethodInsnNode
    if (meaningful.count { it is MethodInsnNode } != 1) return null
    val argumentTypes = Type.getArgumentTypes(descriptor)
    val expectedLoads = mutableListOf<Int>()
    var localIndex = if (access and Opcodes.ACC_STATIC != 0) 0 else 1
    if (access and Opcodes.ACC_STATIC == 0) expectedLoads += Opcodes.ALOAD
    for (argumentType in argumentTypes) {
        expectedLoads += argumentType.getOpcode(Opcodes.ILOAD)
        localIndex += argumentType.size
    }
    val beforeCall = meaningful.take(callIndex)
    if (beforeCall.size != expectedLoads.size) return null
    for ((index, instruction) in beforeCall.withIndex()) {
        val load = instruction as? VarInsnNode ?: return null
        if (load.opcode != expectedLoads[index]) return null
    }
    val afterCall = meaningful.drop(callIndex + 1)
    if (afterCall.size != 1) return null
    val returnInsn = afterCall.single() as? InsnNode ?: return null
    if (returnInsn.opcode != Type.getReturnType(descriptor).getOpcode(Opcodes.IRETURN)) return null
    return targetCall
}

private fun sealedBindingKey(value: String): String {
    /*
     * AKEN v4 binding identity is public relocation material, not a secret.
     * Keep the exact domain and UTF-8 byte sequence in parity with the Java
     * runtime mirror and js_sealed_binding_key().
     */
    val encoded = ("AKEN-BINDING-V1|" + value).toByteArray(Charsets.UTF_8)
    return try {
        val digest = MessageDigest.getInstance("SHA-256").digest(encoded)
        try {
            digest.copyOfRange(0, 8).joinToString("") { "%02x".format(it) }
        } finally {
            Arrays.fill(digest, 0)
        }
    } finally {
        Arrays.fill(encoded, 0)
    }
}


private fun rewriteClassArtifact(
    classArtifact: ClassArtifact,
    seed: Long,
    helperStringRewriteMap: Map<String, String>,
    resourceStringRewriteMap: Map<String, String>,
    helperClassRenameMap: Map<String, String>,
    helperMemberRenamePlan: SealedHelperMemberRenamePlan,
): ClassArtifact? {
    if (isPriorSealedRuntimeArtifact(classArtifact)) return null
    var currentArtifact = classArtifact
    var modified = false
    rewriteSealedNativeVmDispatchCallsites(currentArtifact, helperClassRenameMap)?.let { rewrittenArtifact ->
        currentArtifact = rewrittenArtifact
        modified = true
    }
    remapHelperReferences(currentArtifact, helperClassRenameMap, helperMemberRenamePlan)?.let { remappedArtifact ->
        currentArtifact = remappedArtifact
        modified = true
    }
    scrubRelocatedHelperMetadata(currentArtifact, helperClassRenameMap)?.let { scrubbedArtifact ->
        currentArtifact = scrubbedArtifact
        modified = true
    }
    val effectiveStringRewriteMap = if (currentArtifact.summary.internalName in helperClassRenameMap.values) {
        helperStringRewriteMap + resourceStringRewriteMap + sealedHelperMethodStringRewriteMap(helperMemberRenamePlan)
    } else {
        resourceStringRewriteMap
    }
    rewriteClassStringConstants(currentArtifact, seed, effectiveStringRewriteMap)?.let { rewrittenArtifact ->
        currentArtifact = rewrittenArtifact
        modified = true
    }
    return if (modified) currentArtifact else null
}

private fun isPriorSealedRuntimeArtifact(classArtifact: ClassArtifact): Boolean {
    if (!classArtifact.summary.internalName.startsWith("r/")) return false
    if (hasPriorSealedRuntimeNameShape(classArtifact.summary.internalName)) return true
    val classNode = ClassNode()
    return try {
        ClassReader(classArtifact.bytes).accept(classNode, ClassReader.SKIP_FRAMES)
        isPriorSealedRuntimeClassNode(classNode)
    } catch (_: Exception) {
        false
    }
}

private fun hasPriorSealedRuntimeNameShape(internalName: String): Boolean {
    val parts = internalName.split('/')
    if (parts.size != 3 || parts[1].length != 2) return false
    val simpleName = parts[2]
    if (!simpleName.startsWith('C')) return false
    val outerName = simpleName.substringBefore('$')
    if (outerName.length < 10) return false
    return '$' !in simpleName || simpleName.substringAfter('$').startsWith('I')
}

private fun isPriorSealedRuntimeClassNode(classNode: ClassNode): Boolean {
    var hasKernelComponentString = false
    var hasKernelPlatformString = false
    var hasKernelVmModeString = false
    var invokesKernelLoaderShape = false
    var invokesVmDispatchShape = false
    for (method in classNode.methods) {
        for (instruction in method.instructions?.toArray().orEmpty()) {
            when (instruction) {
                is org.objectweb.asm.tree.LdcInsnNode -> {
                    val value = instruction.cst as? String ?: continue
                    if (value in setOf("loader", "decrypt", "vm", "guards", "all")) hasKernelComponentString = true
                    if (value in setOf("auto", "windows-x64", "linux-x64")) hasKernelPlatformString = true
                    if (value in setOf("vm-diverse", "vm-off")) hasKernelVmModeString = true
                }
                is MethodInsnNode -> {
                    if (instruction.opcode == Opcodes.INVOKESTATIC && instruction.desc == "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V") {
                        invokesKernelLoaderShape = true
                    }
                    if (instruction.opcode == Opcodes.INVOKESTATIC && instruction.owner.startsWith("r/") && instruction.name.startsWith("m_") &&
                        instruction.desc in setOf(
                            "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
                            "(J[Ljava/lang/Object;)Ljava/lang/Object;",
                            "(J)V",
                            "(JI)V",
                        )
                    ) {
                        invokesVmDispatchShape = true
                    }
                }
            }
        }
    }
    return invokesVmDispatchShape || (invokesKernelLoaderShape && hasKernelComponentString && hasKernelPlatformString && hasKernelVmModeString)
}

private fun remapHelperReferences(
    classArtifact: ClassArtifact,
    helperClassRenameMap: Map<String, String>,
    helperMemberRenamePlan: SealedHelperMemberRenamePlan,
): ClassArtifact? {
    if (helperClassRenameMap.isEmpty() && helperMemberRenamePlan.methodRenames.isEmpty() && helperMemberRenamePlan.fieldRenames.isEmpty()) return null
    val reader = ClassReader(classArtifact.bytes)
    val writer = ClassWriter(0)
    var modified = false
    val remapper = object : Remapper(Opcodes.ASM9) {
        override fun map(internalName: String?): String? {
            val replacement = internalName?.let { helperClassRenameMap[it] }
            if (replacement != null) modified = true
            return replacement ?: internalName
        }

        override fun mapMethodName(owner: String?, name: String?, descriptor: String?): String? {
            val replacement = helperMemberRenamePlan.methodName(owner, name, descriptor)
            if (replacement != name) modified = true
            return replacement
        }

        override fun mapFieldName(owner: String?, name: String?, descriptor: String?): String? {
            val replacement = helperMemberRenamePlan.fieldName(owner, name, descriptor)
            if (replacement != name) modified = true
            return replacement
        }
    }
    return try {
        reader.accept(ClassRemapper(writer, remapper), 0)
        var updatedBytes = if (modified) writer.toByteArray() else classArtifact.bytes
        val remappedClassName = ClassReader(updatedBytes).className
        if (
            classArtifact.summary.internalName in helperClassRenameMap.keys ||
            classArtifact.summary.internalName in helperClassRenameMap.values ||
            remappedClassName in helperClassRenameMap.values ||
            classArtifact.summary.internalName == "$PROTECTION_HELPER_PACKAGE/StringEncryptionHelper"
        ) {
            val classNode = ClassNode()
            ClassReader(updatedBytes).accept(classNode, 0)
            var helperMemberModified = false
            for (field in classNode.fields) {
                val replacement = helperMemberRenamePlan.fieldName(classNode.name, field.name, field.desc)
                if (replacement != null && replacement != field.name) {
                    field.name = replacement
                    helperMemberModified = true
                }
            }
            for (method in classNode.methods) {
                val replacement = helperMemberRenamePlan.methodName(classNode.name, method.name, method.desc)
                if (replacement != null && replacement != method.name) {
                    method.name = replacement
                    helperMemberModified = true
                }
            }
            /*
             * openAkenString is intentionally package-private in the source
             * helper so the unsealed Java closure has no broad public page API.
             * After AKEN relocation, however, StringEncryptionHelper and the
             * application call site live in different sealed packages.  Keep
             * the typed terminal narrow, but promote only this relocated bridge
             * to public so the authenticated call site remains linkable.  The
             * native method itself stays package-private and is still reached
             * only through the validated terminal.
             */
            val openStringDescriptor = "([BI[B)Ljava/lang/String;"
            val originalJniOwner = "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper"
            val sealedJniOwner = helperClassRenameMap[originalJniOwner]
            val sealedOpenStringName = helperMemberRenamePlan.methodName(
                originalJniOwner,
                "openAkenString",
                openStringDescriptor,
            )
            if (classNode.name == sealedJniOwner && sealedOpenStringName != null) {
                classNode.methods
                    .filter { it.name == sealedOpenStringName && it.desc == openStringDescriptor }
                    .forEach { method ->
                        val publicAccess =
                            (method.access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_PROTECTED).inv()) or Opcodes.ACC_PUBLIC
                        if (method.access != publicAccess) {
                            method.access = publicAccess
                            helperMemberModified = true
                        }
                    }
            }
            /*
             * The StringPage terminal follows the same boundary rule.  Its
             * source declaration is package-private so the unsealed helper
             * does not expose a stable, repeatable whole-page decoder.  Once
             * helpers are relocated into their artifact-specific sealed
             * package, promote only the build-renamed terminal required by
             * generated application call sites.  No cache or generic decoder
             * API is reintroduced by this linkage adjustment.
             */
            val stringTerminalDescriptor = "([B)Ljava/lang/String;"
            val originalStringOwner = "$PROTECTION_HELPER_PACKAGE/StringEncryptionHelper"
            val sealedStringOwner = helperClassRenameMap[originalStringOwner]
            val sealedStringTerminalName = helperMemberRenamePlan.methodName(
                originalStringOwner,
                "invokeAkenStringTerminal",
                stringTerminalDescriptor,
            )
            if (
                (classNode.name == sealedStringOwner && sealedStringTerminalName != null) ||
                    (classNode.name == originalStringOwner && sealedStringOwner == null)
            ) {
                classNode.methods
                    .filter {
                        it.name == (sealedStringTerminalName ?: "invokeAkenStringTerminal") &&
                            it.desc == stringTerminalDescriptor
                    }
                    .forEach { method ->
                        val publicAccess =
                            (method.access and (Opcodes.ACC_PRIVATE or Opcodes.ACC_PROTECTED).inv()) or Opcodes.ACC_PUBLIC
                        if (method.access != publicAccess) {
                            method.access = publicAccess
                            helperMemberModified = true
                        }
                    }
            }
            if (helperMemberModified) {
                val helperWriter = ClassWriter(0)
                classNode.accept(helperWriter)
                updatedBytes = helperWriter.toByteArray()
                modified = true
            }
        }
        if (!modified) {
            null
        } else {
            val updatedSummary = analyzeClassBytes(updatedBytes)
            classArtifact.copy(
                entryName = "${updatedSummary.internalName}.class",
                summary = updatedSummary,
                bytes = updatedBytes,
            )
        }
    } catch (_: Exception) {
        null
    }
}

private fun scrubRelocatedHelperMetadata(
    classArtifact: ClassArtifact,
    helperClassRenameMap: Map<String, String>,
): ClassArtifact? {
    if (classArtifact.summary.internalName !in helperClassRenameMap.values) return null
    val reader = ClassReader(classArtifact.bytes)
    val writer = ClassWriter(0)
    var modified = false
    val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
        override fun visitSource(source: String?, debug: String?) {
            if (source != null || debug != null) {
                modified = true
                return
            }
            super.visitSource(source, debug)
        }
    }
    return try {
        reader.accept(visitor, 0)
        if (!modified) {
            null
        } else {
            val updatedBytes = writer.toByteArray()
            classArtifact.copy(
                summary = analyzeClassBytes(updatedBytes),
                bytes = updatedBytes,
            )
        }
    } catch (_: Exception) {
        null
    }
}
private fun rewriteSealedNativeVmDispatchCallsites(
    classArtifact: ClassArtifact,
    helperClassRenameMap: Map<String, String>,
): ClassArtifact? {
    val originalOwner = "$PROTECTION_HELPER_PACKAGE/JniMicrokernelHelper"
    val sealedOwner = helperClassRenameMap[originalOwner] ?: return null
    if (classArtifact.summary.internalName == originalOwner || classArtifact.summary.internalName == sealedOwner) return null
    val legacyVmDispatchDescriptor = "(JLjava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;"
    val tokenVmDispatchDescriptor = "(J[Ljava/lang/Object;)Ljava/lang/Object;"
    val reader = ClassReader(classArtifact.bytes)
    val writer = ClassWriter(0)
    var modified = false
    val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
        override fun visitMethod(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            exceptions: Array<String>?,
        ): MethodVisitor {
            val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
            return object : MethodVisitor(Opcodes.ASM9, mv) {
                override fun visitMethodInsn(
                    opcode: Int,
                    owner: String,
                    name: String,
                    methodDescriptor: String,
                    isInterface: Boolean,
                ) {
                    if (
                        opcode == Opcodes.INVOKESTATIC &&
                        (owner == originalOwner || owner == sealedOwner) &&
                        ((name == "nativeExecuteVmResource" && methodDescriptor == legacyVmDispatchDescriptor) ||
                            (name == "nativeExecuteVmResourceByToken" && methodDescriptor == tokenVmDispatchDescriptor))
                    ) {
                        modified = true
                        super.visitMethodInsn(opcode, owner, "executeVmResource", methodDescriptor, false)
                    } else {
                        super.visitMethodInsn(opcode, owner, name, methodDescriptor, isInterface)
                    }
                }
            }
        }
    }
    return try {
        reader.accept(visitor, 0)
        if (!modified) {
            null
        } else {
            val updatedBytes = writer.toByteArray()
            classArtifact.copy(
                summary = analyzeClassBytes(updatedBytes),
                bytes = updatedBytes,
            )
        }
    } catch (_: Exception) {
        null
    }
}
private fun rewriteClassStringConstants(
    classArtifact: ClassArtifact,
    seed: Long,
    stringRewriteMap: Map<String, String>,
): ClassArtifact? {
    if (stringRewriteMap.isEmpty()) return null
    val reader = ClassReader(classArtifact.bytes)
    val writer = ClassWriter(0)
    var modified = false
    val visitor = object : ClassVisitor(Opcodes.ASM9, writer) {
        override fun visitField(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            value: Any?,
        ): FieldVisitor {
            val replacement = if (value is String) sealedReplacementForString(value, seed, stringRewriteMap) else null
            return if (replacement != null) {
                modified = true
                super.visitField(access, name, descriptor, signature, replacement)
            } else {
                super.visitField(access, name, descriptor, signature, value)
            }
        }

        override fun visitMethod(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            exceptions: Array<String>?,
        ): MethodVisitor {
            val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
            return object : MethodVisitor(Opcodes.ASM9, mv) {
                override fun visitLdcInsn(value: Any?) {
                    val replacement = if (value is String) sealedReplacementForString(value, seed, stringRewriteMap) else null
                    if (replacement != null) {
                        modified = true
                        super.visitLdcInsn(replacement)
                    } else {
                        super.visitLdcInsn(value)
                    }
                }
            }
        }
    }
    return try {
        reader.accept(visitor, 0)
        if (!modified) {
            null
        } else {
            val updatedBytes = writer.toByteArray()
            classArtifact.copy(
                summary = analyzeClassBytes(updatedBytes),
                bytes = updatedBytes,
            )
        }
    } catch (_: Exception) {
        null
    }
}


// --- Encrypted class bytecode rewriting ---

/**
 * Parse the class encryption manifest to extract encryption keys for each encrypted class.
 * Returns a map of resourcePath -> AEAD rewrite key material.
 */
private fun sealedReplacementForString(value: String, seed: Long, stringRewriteMap: Map<String, String>): String? {
    stringRewriteMap[value]?.let { return it }
    return null
}
