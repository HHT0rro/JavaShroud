package io.github.hht0rro.javashroud.apk

import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.kernel.buildDoneEvent
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import java.nio.file.Files
import java.nio.file.Path
import java.util.Comparator
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * APK pipeline orchestration (Phases A-E). The obfuscation kernel runs
 * unmodified against a work JAR; this runner owns the dex/class conversions,
 * the keep-rule injection, the byte-faithful re-pack, signing, and the
 * migration of kernel sidecars to final-APK-derived names.
 *
 * Failure contract: every phase failure throws (the CLI turns that into an
 * error event + non-zero exit), the work directory and .tmp artifacts are
 * removed, and the kernel's done event is withheld until Phase E succeeds.
 */
class ApkPipelineRunner(
    private val kernelRunner: (ObfuscationConfig, Path, (EngineEvent) -> Unit) -> Unit =
        { config, configPath, emit -> EngineKernel().run(config, configPath, emit) },
    private val provision: (String, String) -> ApkToolchainProvisioner.ApkToolchain =
        { dex2jarDir, d8Jar -> ApkToolchainProvisioner.ensure(dex2jarDir, d8Jar) },
    private val dexToClassConverter: ApkDex2JarRunner = ApkDex2JarRunner(),
    private val classToDexCompiler: ApkD8Runner = ApkD8Runner(),
    private val signer: (Path, Path, io.github.hht0rro.javashroud.model.config.ApkSigningConfig, Int, Int, (String) -> Unit) -> ApkSignerService.SigningOutcome =
        { unsigned, finalApk, signing, minApi, soPage, log ->
            ApkSignerService.sign(unsigned, finalApk, signing, minApi, soPage, log)
        },
) {
    companion object {
        const val WORK_JAR_NAME = "apk-work.jar"
        const val INPUT_JAR_NAME = "apk-input-classes.jar"
        const val UNSIGNED_APK_NAME = "apk-unsigned.apk"

        /** Env switch honored by real-toolchain tests and this runner's probes. */
        const val SKIP_REAL_TOOLS_ENV = ApkToolchainProvisioner.REAL_TOOLS_SKIP_ENV
    }

    fun run(
        config: ObfuscationConfig,
        configPath: Path,
        emit: (EngineEvent) -> Unit,
    ) {
        val finalApk = Path.of(config.outputJarPath).toAbsolutePath().normalize()
        checkApkCancellation()
        val sidecarTargets = apkSidecarPaths(finalApk)
        val destinations = listOf(finalApk, apkPublicationLock(finalApk)) + sidecarTargets
        val protectedPaths = listOf(
            Path.of(config.inputJarPath).toAbsolutePath().normalize(),
            configPath.toAbsolutePath().normalize(),
            ApkSignerService.keystorePath(config.apk.signing),
        )
        for ((index, destination) in destinations.withIndex()) {
            (protectedPaths + destinations.take(index)).forEach { requireSeparateApkPaths(destination, it) }
        }
        if (config.logFilePath.isNotBlank()) {
            val logPath = Path.of(config.logFilePath).toAbsolutePath().normalize()
            (protectedPaths + destinations).forEach { requireSeparateApkPaths(logPath, it) }
        }
        existingRegularApkFile(finalApk)
        val outputDirectory = finalApk.parent
        val log = ApkLogSupport.open(config.logFilePath.ifBlank { null }) { message ->
            emit(EngineEvent(level = "warn", type = "warn", message = message, progress = null, outPath = null))
        }

        log.use {
            Files.createDirectories(outputDirectory)
            val workDirectory = Files.createTempDirectory(outputDirectory, ".javashroud-apk-work-")
            var preserveRecovery = false
            try {
                executePipeline(config, configPath, finalApk, sidecarTargets, workDirectory, emit, log)
            } catch (error: Throwable) {
                preserveRecovery = error is ApkRollbackException
                // The full failure record (message + stack trace) belongs in
                // the verbose log; stdout keeps the single protocol event.
                runCatching { log.failure(error) }
                throw error
            } finally {
                if (!preserveRecovery) {
                    runCatching { deleteRecursively(workDirectory) }
                }
            }
        }
    }

    private fun executePipeline(
        config: ObfuscationConfig,
        configPath: Path,
        finalApk: Path,
        sidecarTargets: List<Path>,
        workDirectory: Path,
        emit: (EngineEvent) -> Unit,
        log: ApkLogSupport,
    ) {
        // Visible, never-silent profile default announcement (config file
        // carried no explicit protectionProfile and APK mode resolved MINIMAL).
        if (!config.protectionProfileExplicit &&
            config.protectionProfile == io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile.MINIMAL
        ) {
            val announcement = "APK mode: protectionProfile not specified, defaulting to minimal " +
                "(the jni/native passes required by the RELEASE_HARDENED release scan do not apply to Android)"
            emit(EngineEvent(level = "info", type = "log", message = announcement, progress = null, outPath = null))
            log.info(announcement)
        }
        emitProgress(emit, 2, "apk-toolchain-provision")

        // --- Phase A: toolchain (fail-closed before any heavy work) ---
        val toolchain = provision(config.apk.dex2jarDirPath, config.apk.d8JarPath)
        log.info(
            "toolchain: java=${toolchain.javaExecutable} dex2jar=${toolchain.dex2jarDirectory} " +
                "(${toolchain.dex2jarSource}) d8=${toolchain.d8Jar} (${toolchain.d8Source})",
        )

        // --- Phase B: input ---
        emitProgress(emit, 5, "apk-unpack")
        val unpacked = ApkInputUnpacker.read(Path.of(config.inputJarPath).toAbsolutePath().normalize())
        log.info("unpacked ${unpacked.preservedEntries.size} preserved entries, ${unpacked.dexEntries.size} dex")
        val soPageSize = maxOf(config.apk.soPageSize, unpacked.nativeLibraryAlignment)
        if (soPageSize > config.apk.soPageSize) {
            log.info("preserving $soPageSize-byte alignment for uncompressed native libraries from the input APK")
        }

        val manifest = ApkBinaryXmlReader.parse(unpacked.manifestEntry.data)
        log.info("manifest: package=${manifest.packageName} minSdk=${manifest.minSdkVersion} effectiveMinApi=${config.apk.minApi}")
        if (!config.apk.minApiExplicit && manifest.minSdkVersion != null) {
            val derived = "APK mode: apk.minApi not specified, derived minApi=${config.apk.minApi} from " +
                "manifest minSdkVersion=${manifest.minSdkVersion}" +
                if (config.apk.minApi < ApkPassPolicy.MIN_API_FOR_INVOKE_CUSTOM) {
                    " (invoke-dynamic-indirection omitted below API ${ApkPassPolicy.MIN_API_FOR_INVOKE_CUSTOM})"
                } else {
                    ""
                }
            emit(EngineEvent(level = "info", type = "log", message = derived, progress = null, outPath = null))
            log.info(derived)
        }

        val manifestComponentClasses = manifestComponentInternalNames(manifest)

        // Derived-minApi runs whose manifest declares support below the engine
        // floor keep processing: the output dex genuinely requires the floor,
        // so the OUTPUT manifest's minSdkVersion is raised with a warning
        // (config validation already failed closed for explicit minApi values).
        val effectiveUnpacked = if (manifest.minSdkVersion != null && manifest.minSdkVersion < config.apk.minApi) {
            raiseManifestMinSdk(unpacked, config.apk.minApi, manifest.minSdkVersion!!, log, emit)
        } else {
            unpacked
        }

        emitProgress(emit, 10, "apk-dex-to-class")
        val converted = effectiveUnpacked.dexEntries.map { dex ->
            dexToClassConverter.convert(toolchain, dex, workDirectory) { line -> log.info(line) }
        }
        val mergedClasses = mergeConvertedClasses(converted, workDirectory)
        // The per-dex copies and the per-dex class jars are fully consumed by
        // the merge; deleting them immediately keeps the transient work
        // directory footprint down (roughly one input-dex + one class jar per
        // dex) on parallel runs that share a nearly-full disk.
        converted.forEach { convertedDex ->
            runCatching {
                Files.deleteIfExists(workDirectory.resolve("input-${convertedDex.dexIndex}.dex"))
                Files.deleteIfExists(convertedDex.jarPath)
            }
        }
        // dex2jar degrades `new-instance Sub` + direct superclass <init> to
        // `new Super`; the exact allocated class is recovered from the INPUT
        // dex (the authoritative new-instance operand), with the classfile's
        // declared use type as a fallback for unmatched sites.
        val dexNewInstanceSites = ApkDexNewInstanceIndex.build(effectiveUnpacked.dexEntries.map { it.bytes })
        val newTypeRepair = ApkNewTypeRepair.repair(mergedClasses, dexNewInstanceSites)
        if (newTypeRepair.repairedSites > 0) {
            log.info(
                "dex2jar new-type repair: rewrote ${newTypeRepair.repairedSites} construction site(s) " +
                    "in ${newTypeRepair.repairedClassCount} class(es) " +
                    "(dex-exact=${newTypeRepair.dexRecoveredSites}, declared-type=${newTypeRepair.heuristicRecoveredSites})",
            )
        }
        val inputJar = writeMergedInputJar(newTypeRepair.classes, workDirectory)
        log.info("merged ${newTypeRepair.classes.size} classes into ${inputJar.fileName}")

        val loadedClassNames = newTypeRepair.classes.map { it.first.removeSuffix(".class") }.toSet()
        val resourceReferenced = scanResourceReferences(effectiveUnpacked, loadedClassNames, log)
        val serviceReferenced = ApkServiceReferenceScanner.referencedClassNames(effectiveUnpacked.preservedEntries, loadedClassNames)
        val layoutClickMethods = effectiveUnpacked.preservedEntries.asSequence()
            .filter { it.name.startsWith("res/layout") && it.name.endsWith(".xml") && !it.isDirectory }
            .flatMap { ApkBinaryXmlReader.layoutClickMethods(it.data).asSequence() }
            .toSet()
        val nativeReferenced = scanNativeReferences(effectiveUnpacked, loadedClassNames, log)
        val keepPlan = ApkKeepRuleSynthesis.synthesize(
            mergedClassJarPath = inputJar,
            manifestComponentClasses = manifestComponentClasses,
            resourceReferencedClasses = resourceReferenced + serviceReferenced,
            nativeReferencedClasses = nativeReferenced,
            extraKeepPrefixes = config.apk.extraKeepPrefixes,
            layoutClickMethods = layoutClickMethods,
        )
        keepPlan.warnings.forEach { log.warn(it) }
        log.info(
            "keep synthesis: classes=${keepPlan.keepClassCount} members=${keepPlan.memberKeeps.size} " +
                "resourceRefs=${resourceReferenced.size} serviceRefs=${serviceReferenced.size} nativeRefs=${nativeReferenced.size}",
        )
        // Package renames move wholesale packages while the kept set stays
        // behind; every same-package package-private reference across that
        // boundary is widened to public so the moved code keeps its original
        // access rights. Serialization hooks keep their declared access.
        val accessWidening = ApkAccessWidening.widen(newTypeRepair.classes, keepPlan.excludedClassNames) { line -> log.info(line) }
        if (accessWidening.widenedMembers > 0 || accessWidening.widenedClasses > 0) {
            rewriteMergedInputJar(inputJar, accessWidening.classes)
        }

        // --- Phase C: engine over the work JAR ---
        val workJar = workDirectory.resolve(WORK_JAR_NAME).toAbsolutePath().normalize()
        val engineConfig = config.copy(
            inputJarPath = inputJar.toAbsolutePath().toString(),
            outputJarPath = workJar.toString(),
            ruleSet = ApkKeepRuleSynthesis.mergeRuleSet(config.ruleSet, keepPlan),
        )
        emitProgress(emit, 15, "apk-engine-passes")
        val wrappedEmit: (EngineEvent) -> Unit = { event ->
            // The kernel's done event is withheld: Phase E re-emits done with
            // the final APK path only after every stage has succeeded.
            if (event.type != "done") emit(rewriteOutPath(event, workJar, finalApk))
        }
        try {
            kernelRunner(engineConfig, configPath, wrappedEmit)
        } catch (error: SecurityException) {
            // Fail-closed with actionable advice: the RELEASE_HARDENED release
            // scan cannot be satisfied on Android because its required
            // desktop-native companion passes are blacklisted for APK mode.
            val message = error.message.orEmpty()
            if (message.contains("RELEASE artifact scan failed")) {
                throw SecurityException(
                    message + ". APK mode cannot enable the desktop-native passes the RELEASE_HARDENED " +
                        "release scan requires (jni-microkernel-loader and companions stay blacklisted for " +
                        "Android, so the rename-binding index is never consumed and the debug-map provenance " +
                        "chain never materializes). Use protectionProfile = \"minimal\" (the APK default) or " +
                        "provide an explicit pass set.",
                    error,
                )
            }
            throw error
        }
        require(Files.isRegularFile(workJar)) { "engine did not produce the work jar: $workJar" }

        emitProgress(emit, 92, "apk-validation")
        ApkValidation.validateKeepRetention(workJar, keepPlan)
        log.info("keep retention validated against ${workJar.fileName}")

        // --- Phase D: dex compile + pack + sign ---
        emitProgress(emit, 94, "apk-class-to-dex")
        val dexOut = workDirectory.resolve("dex-out")
        val newDexes = classToDexCompiler.compile(
            toolchain = toolchain,
            inputJar = workJar,
            outputDirectory = dexOut,
            minApi = config.apk.minApi,
            androidJarPath = config.apk.androidJarPath,
            log = { line -> log.info(line) },
        )
        newDexes.forEach { (name, bytes) ->
            ApkValidation.validateDexHeader(name, bytes)
        }
        val keepClassLowerBound = keepPlan.keepClassCount
        val definedClasses = newDexes.sumOf { (_, bytes) -> ApkValidation.dexClassCount(bytes) }
        require(definedClasses >= keepClassLowerBound) {
            "output dex defines $definedClasses classes but the keep plan alone requires $keepClassLowerBound"
        }
        log.info("d8 produced ${newDexes.size} dex entries defining $definedClasses classes")

        val unsignedApk = workDirectory.resolve(UNSIGNED_APK_NAME)
        val packResult = ApkOutputPacker.pack(
            unpacked = effectiveUnpacked,
            newDexes = newDexes,
            outputApk = unsignedApk,
            soPageSize = soPageSize,
        )
        log.info("packed unsigned APK ${unsignedApk.fileName} with dex entries ${packResult.dexEntryNames}")

        emitProgress(emit, 97, "apk-sign")
        val stagedApk = workDirectory.resolve("apk-signed.apk")
        val signingOutcome = signer(
            unsignedApk,
            stagedApk,
            config.apk.signing,
            config.apk.minApi,
            soPageSize,
        ) { line -> log.info(line) }
        checkApkCancellation()
        require(signingOutcome.signedApk == stagedApk && existingRegularApkFile(stagedApk)) {
            "Signer did not produce the staged APK: $stagedApk"
        }
        require(signingOutcome.v1Enabled == config.apk.signing.v1Enabled &&
            signingOutcome.v2Enabled == config.apk.signing.v2Enabled) { "Signer reported unexpected APK signing schemes" }

        ApkValidation.validateOutputArchive(
            inputUnpacked = effectiveUnpacked,
            outputApk = stagedApk,
            expectedDexEntryNames = packResult.dexEntryNames,
            soPageSize = soPageSize,
            v1SigningEnabled = config.apk.signing.v1Enabled,
        )
        ZipFile(stagedApk.toFile()).use { archive ->
            val dexNames = archive.entries().asSequence().map { it.name }.filter(ApkOutputPacker::isDexEntry).toSet()
            require(dexNames == packResult.dexEntryNames.toSet()) { "Signed APK contains an unexpected dex set" }
            newDexes.forEach { (name, bytes) ->
                require(archive.getInputStream(archive.getEntry(name)).use { it.readBytes() }.contentEquals(bytes)) {
                    "Signed APK dex entry changed: $name"
                }
            }
        }
        if (config.apk.signing.v1Enabled || config.apk.signing.v2Enabled) {
            val fingerprint = requireNotNull(signingOutcome.signerCertificateSha256) { "Signer certificate fingerprint is missing" }
            ApkSignerService.verifyWithCertificate(stagedApk, config.apk.signing, config.apk.minApi, fingerprint, log::info)
        }
        val finalApkSha256 = ApkToolchainProvisioner.sha256Hex(Files.readAllBytes(stagedApk))
        log.info(
            "final APK ${finalApk.fileName}: sha256=$finalApkSha256 dex=${packResult.dexEntryNames.size} " +
                "sign(v1=${signingOutcome.v1Enabled},v2=${signingOutcome.v2Enabled}) " +
                "debugKeystore=${signingOutcome.usedDebugKeystore}",
        )

        // --- Phase E: sidecars + done ---
        emitProgress(emit, 99, "apk-sidecar-migration")
        val stagedSidecars = stageSidecars(workJar, finalApk, sidecarTargets)
        publishApkFiles(stagedSidecars + (stagedApk to finalApk), workDirectory, apkPublicationLock(finalApk)) {
            emit(
                EngineEvent(
                    level = "info",
                    type = "log",
                    message = "apk-summary: output=$finalApk sha256=$finalApkSha256 " +
                        "dex=${packResult.dexEntryNames.size} keepClasses=${keepPlan.keepClassCount} " +
                        "keepMembers=${keepPlan.memberKeeps.size} v1=${signingOutcome.v1Enabled} " +
                        "v2=${signingOutcome.v2Enabled}",
                    progress = null,
                    outPath = null,
                ),
            )
        }
        emit(buildDoneEvent(finalApk.toString()))
    }

        // --- Phase B helpers ---------------------------------------------------

    /**
     * Rewrites the merged-input jar in place after keep synthesis decided the
     * kept set. dex2jar output is dex-faithful: R8 relies on same-package
     * access between the kept entry classes and their (renamed) package-mates,
     * so package-private members on both sides of that boundary are widened to
     * public before the kernel sees the classes.
     */
    internal fun rewriteMergedInputJar(inputJar: Path, classes: List<Pair<String, ByteArray>>) {
        java.util.jar.JarOutputStream(Files.newOutputStream(inputJar).buffered()).use { jar ->
            for ((name, bytes) in classes) {
                jar.putNextEntry(java.util.jar.JarEntry(name))
                jar.write(bytes)
                jar.closeEntry()
            }
        }
    }

    internal fun raiseManifestMinSdk(
        unpacked: ApkInputUnpacker.ApkUnpacked,
        effectiveMinApi: Int,
        manifestMinSdk: Int,
        log: ApkLogSupport,
        emit: (EngineEvent) -> Unit,
    ): ApkInputUnpacker.ApkUnpacked {
        val patchedData = ApkBinaryXmlReader.patchMinSdkVersion(unpacked.manifestEntry.data, effectiveMinApi)
        val patchedEntry = rebuildPreservedEntry(unpacked.manifestEntry, patchedData)
        val message = "APK mode: AndroidManifest minSdkVersion=$manifestMinSdk raised to the effective " +
            "minApi=$effectiveMinApi in the output APK: the produced dex requires native multidex " +
            "(API >= $effectiveMinApi), so the input's lower declaration cannot be honored"
        emit(EngineEvent(level = "warn", type = "warn", message = message, progress = null, outPath = null))
        log.warn(message)
        return unpacked.copy(
            preservedEntries = unpacked.preservedEntries.map { entry ->
                if (entry.name == unpacked.manifestEntry.name) patchedEntry else entry
            },
            manifestEntry = patchedEntry,
        )
    }

    private fun rebuildPreservedEntry(
        entry: ApkInputUnpacker.ApkPreservedEntry,
        data: ByteArray,
    ): ApkInputUnpacker.ApkPreservedEntry {
        val crc = java.util.zip.CRC32().apply { update(data) }.value
        return if (entry.method == java.util.zip.ZipEntry.STORED) {
            entry.copy(
                rawCompressedBytes = data,
                crc = crc,
                compressedSize = data.size.toLong(),
                size = data.size.toLong(),
                data = data,
            )
        } else {
            val deflated = deflateRaw(data)
            entry.copy(
                rawCompressedBytes = deflated,
                crc = crc,
                compressedSize = deflated.size.toLong(),
                size = data.size.toLong(),
                data = data,
            )
        }
    }

    private fun deflateRaw(data: ByteArray): ByteArray {
        val deflater = java.util.zip.Deflater(java.util.zip.Deflater.DEFAULT_COMPRESSION, true)
        try {
            deflater.setInput(data)
            deflater.finish()
            val buffer = ByteArray(64 * 1024)
            val output = java.io.ByteArrayOutputStream()
            while (!deflater.finished()) {
                val written = deflater.deflate(buffer)
                output.write(buffer, 0, written)
            }
            return output.toByteArray()
        } finally {
            deflater.end()
        }
    }

    internal fun manifestComponentInternalNames(manifest: ApkBinaryXmlReader.ApkManifestInfo): Set<String> {
        val packagePrefix = manifest.packageName
        return manifest.namedClasses.mapNotNull { raw ->
            when {
                raw.startsWith(".") -> packagePrefix + raw
                raw.contains('.') -> raw
                raw.startsWith("java.") || raw.startsWith("android.") || raw.startsWith("androidx.") -> null
                else -> "$packagePrefix.$raw"
            }
        }.map { it.replace('.', '/') }.filter { it.isNotBlank() }.toSet()
    }

    private fun mergeConvertedClasses(
        converted: List<ApkDex2JarRunner.ConvertedDex>,
        workDirectory: Path,
    ): List<Pair<String, ByteArray>> {
        val merged = LinkedHashMap<String, ByteArray>()
        val duplicates = mutableSetOf<String>()
        for (result in converted) {
            val jarStream = java.util.jar.JarInputStream(Files.newInputStream(result.jarPath).buffered())
            jarStream.use { jar ->
                while (true) {
                    val entry: ZipEntry = jar.nextEntry ?: break
                    if (entry.isDirectory || !entry.name.endsWith(".class")) continue
                    val existing = merged[entry.name]
                    if (existing != null) {
                        duplicates += entry.name
                        continue
                    }
                    merged[entry.name] = jar.readBytes()
                }
            }
        }
        require(duplicates.isEmpty()) {
            "cross-dex duplicate class names are rejected: ${duplicates.sorted().take(16)}"
        }
        return merged.map { (name, bytes) -> name to bytes }
    }

    private fun writeMergedInputJar(
        mergedClasses: List<Pair<String, ByteArray>>,
        workDirectory: Path,
    ): Path {
        val inputJar = workDirectory.resolve(INPUT_JAR_NAME)
        JarOutputStream(Files.newOutputStream(inputJar).buffered()).use { jar ->
            for ((name, bytes) in mergedClasses) {
                jar.putNextEntry(ZipEntry(name))
                jar.write(bytes)
                jar.closeEntry()
            }
        }
        return inputJar
    }

    private fun scanResourceReferences(
        unpacked: ApkInputUnpacker.ApkUnpacked,
        loadedSlashClassNames: Set<String>,
        log: ApkLogSupport,
    ): Set<String> {
        val dottedToSlash = loadedSlashClassNames.associateBy { it.replace('/', '.') }
        val hits = sortedSetOf<String>()
        for (entry in unpacked.preservedEntries) {
            if (entry.isDirectory || !(entry.name.startsWith("res/") || entry.name == "resources.arsc")) continue
            val strings = ApkResourceClassReferenceScanner.extractStringPoolStrings(entry.data)
            for (candidate in strings) {
                dottedToSlash[candidate]?.let { hits += it }
            }
            if (entry.name.startsWith("res/")) {
                hits += ApkResourceClassReferenceScanner.preferenceClassReferences(entry.data, loadedSlashClassNames)
            }
        }
        if (hits.isNotEmpty()) log.info("resource string pool keeps ${hits.size} classes")
        return hits
    }

    private fun scanNativeReferences(
        unpacked: ApkInputUnpacker.ApkUnpacked,
        loadedSlashClassNames: Set<String>,
        log: ApkLogSupport,
    ): Set<String> {
        val hits = sortedSetOf<String>()
        for (entry in unpacked.preservedEntries) {
            if (!ApkOutputPacker.isNativeLib(entry.name) || entry.isDirectory) continue
            val scanStartedAt = System.nanoTime()
            val scan = ApkNativeStringScanner.scanClassNames(entry.data, loadedSlashClassNames)
            if (scan.truncated) {
                log.warn("native lib ${entry.name} exceeded the scan cap; kept every scanned string hit")
            }
            hits += scan.matchedClassNames
            // Per-library trace: this phase is otherwise silent for minutes on
            // native-heavy APKs, and the log is the only place the harness or
            // a human can see progress.
            log.info(
                "native lib ${entry.name}: ${entry.data.size} bytes scanned in " +
                    "${(System.nanoTime() - scanStartedAt) / 1_000_000} ms, ${scan.matchedClassNames.size} class hits",
            )
        }
        if (hits.isNotEmpty()) log.info("native string scan keeps ${hits.size} classes")
        return hits
    }

    // --- Phase E helpers ---------------------------------------------------

    private fun stageSidecars(workJar: Path, finalApk: Path, targets: List<Path>): List<Pair<Path?, Path>> {
        val workPath = workJar.toString()
        val finalPath = finalApk.toString()
        val mapper = ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        return apkSidecarPaths(workJar).zip(targets).map { (source, target) ->
            checkApkCancellation()
            if (!existingRegularApkFile(source)) return@map null to target
            val staged = workJar.resolveSibling("publish-" + source.fileName)
            when {
                source.fileName.toString().endsWith(".release-scan.txt") -> {
                    val rewritten = Files.readString(source).replace(workPath, finalPath)
                    require(workPath !in rewritten) { "release-scan sidecar still mentions the work path after rewrite" }
                    Files.writeString(staged, rewritten)
                }
                source.fileName.toString().endsWith(".build-evidence.json") -> {
                    val escapedWork = mapper.writeValueAsString(workPath).drop(1).dropLast(1)
                    val escapedFinal = mapper.writeValueAsString(finalPath).drop(1).dropLast(1)
                    val rewritten = Files.readString(source).replace(escapedWork, escapedFinal)
                    require(escapedWork !in rewritten && workPath !in rewritten) {
                        "build-evidence sidecar still references the work path after rewrite"
                    }
                    require(mapper.readTree(rewritten)?.isObject == true) { "build-evidence sidecar must be a JSON object" }
                    Files.writeString(staged, rewritten)
                }
                // The debug-map signature covers the work JAR. Keep its bytes untouched.
                else -> Files.copy(source, staged)
            }
            staged to target
        }
    }

    // --- shared helpers ----------------------------------------------------

    internal fun rewriteOutPath(event: EngineEvent, workJar: Path, finalApk: Path): EngineEvent {
        val workPathString = workJar.toAbsolutePath().toString()
        val finalPathString = finalApk.toAbsolutePath().toString()
        if (event.outPath != workPathString && !event.message.contains(workPathString)) return event
        return event.copy(
            outPath = if (event.outPath == workPathString) finalPathString else event.outPath,
            message = event.message.replace(workPathString, finalPathString),
        )
    }

    private fun emitProgress(emit: (EngineEvent) -> Unit, progress: Int, stage: String) {
        checkApkCancellation()
        emit(
            EngineEvent(
                level = "info",
                type = "progress",
                message = "APK stage: $stage",
                progress = progress,
                outPath = null,
            ),
        )
        checkApkCancellation()
    }

    private fun deleteRecursively(path: Path) {
        Files.walk(path).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }
}
