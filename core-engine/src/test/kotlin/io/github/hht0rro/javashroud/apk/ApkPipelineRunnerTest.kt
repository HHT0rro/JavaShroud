package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.model.config.ApkConfig
import io.github.hht0rro.javashroud.model.config.ApkSigningConfig
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import java.io.IOException
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.util.concurrent.CancellationException
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.apache.commons.compress.archivers.zip.ZipFile
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Pipeline orchestration with fully faked converters and kernel: emit-wrapper
 * outPath rewriting + done holdback/reissue, sidecar migration with path
 * rewrite, phase-failure propagation with work-directory cleanup.
 */
class ApkPipelineRunnerTest {

    private class FakeToolchain

    private fun minimalValidDex(): ByteArray {
        // Reuse the validation test's dex builder through the shared fixture.
        return ApkPipelineRunnerTestSupport.minimalDex()
    }

    private fun config(inputApk: Path, finalApk: Path): ObfuscationConfig = ObfuscationConfig(
        inputJarPath = inputApk.toAbsolutePath().toString(),
        outputJarPath = finalApk.toAbsolutePath().toString(),
        passes = listOf(PassSpec("strip-compile-debug-info", enabled = true, params = emptyMap())),
        ruleSet = RuleSet(emptyList()),
        artifactFormat = "apk",
        logFilePath = "",
        apk = ApkConfig(minApi = 26, soPageSize = 4096, signing = ApkSigningConfig(v1Enabled = false, v2Enabled = false)),
    )

    private fun fakeRunner(
        recordedStages: MutableList<String>,
        recordedKernelConfigs: MutableList<ObfuscationConfig>,
        recordedEvents: MutableList<EngineEvent>,
        workJarSidecars: Boolean = true,
        signOutput: (Path, Path) -> Unit = { unsigned, staged -> Files.copy(unsigned, staged, REPLACE_EXISTING) },
        fixtureClasses: List<String> = listOf("com/example/app/App"),
        kernelBehavior: (ObfuscationConfig, Path, (EngineEvent) -> Unit) -> Unit = { _, _, emit ->
            emit(EngineEvent("info", "log", "kernel summary output=C:\\work\\apk-work.jar", null, "ignored"))
        },
    ): ApkPipelineRunner {
        val fakeKernel: (ObfuscationConfig, Path, (EngineEvent) -> Unit) -> Unit = { engineConfig, configPath, emit ->
            recordedStages += "kernel"
            recordedKernelConfigs += engineConfig
            // Materialize the work jar the kernel would have written.
            val workJar = Path.of(engineConfig.outputJarPath)
            Files.createDirectories(workJar.parent)
            JarOutputStream(Files.newOutputStream(workJar)).use { jar ->
                for (owner in fixtureClasses) {
                    jar.putNextEntry(ZipEntry("$owner.class"))
                    jar.write(ApkPipelineRunnerTestSupport.appClassBytes(owner))
                    jar.closeEntry()
                }
            }
            if (workJarSidecars) {
                Files.writeString(
                    workJar.resolveSibling(workJar.fileName.toString().removeSuffix(".jar") + ".release-scan.txt"),
                    "release-scan: entry=${workJar.toAbsolutePath()}; pass",
                )
                Files.writeString(
                    workJar.resolveSibling(workJar.fileName.toString().removeSuffix(".jar") + ".build-evidence.json"),
                    """{"output":"${workJar.toAbsolutePath().toString().replace("\\", "\\\\")}","kind":"evidence"}""",
                )
            }
            kernelBehavior(engineConfig, configPath, emit)
        }
        val fakeDexToClass = object : ApkDex2JarRunner(runner = { _, _ -> ApkProcessSupport.ProcessResult(0, "fake", false) }) {
            override fun convert(
                toolchain: ApkToolchainProvisioner.ApkToolchain,
                dex: ApkInputUnpacker.ApkDexInput,
                workDirectory: Path,
                log: (String) -> Unit,
            ): ConvertedDex {
                recordedStages += "dex2jar-${dex.index}"
                val jarPath = workDirectory.resolve("fake-classes-${dex.index}.jar")
                JarOutputStream(Files.newOutputStream(jarPath)).use { jar ->
                    for (owner in fixtureClasses) {
                        jar.putNextEntry(ZipEntry("$owner.class"))
                        jar.write(ApkPipelineRunnerTestSupport.appClassBytes(owner))
                        jar.closeEntry()
                    }
                }
                return ConvertedDex(dex.index, jarPath, fixtureClasses.map { "$it.class" })
            }
        }
        val fakeD8 = object : ApkD8Runner(runner = { _, _ -> ApkProcessSupport.ProcessResult(0, "fake", false) }) {
            override fun compile(
                toolchain: ApkToolchainProvisioner.ApkToolchain,
                inputJar: Path,
                outputDirectory: Path,
                minApi: Int,
                androidJarPath: String,
                log: (String) -> Unit,
            ): List<Pair<String, ByteArray>> {
                recordedStages += "d8"
                return listOf("classes.dex" to ApkPipelineRunnerTestSupport.minimalDex(fixtureClasses.size))
            }
        }
        return ApkPipelineRunner(
            kernelRunner = fakeKernel,
            provision = { _, _ ->
                recordedStages += "provision"
                ApkToolchainProvisioner.ApkToolchain(
                    javaExecutable = Path.of("java"),
                    dex2jarDirectory = Path.of("dex2jar"),
                    d8Jar = Path.of("r8.jar"),
                    dex2jarSource = "test",
                    d8Source = "test",
                )
            },
            dexToClassConverter = fakeDexToClass,
            classToDexCompiler = fakeD8,
            signer = { unsigned, stagedApk, signing, _, _, _ ->
                recordedStages += "sign"
                signOutput(unsigned, stagedApk)
                ApkSignerService.SigningOutcome(stagedApk, true, signing.v1Enabled, signing.v2Enabled, "00".repeat(32))
            },
        )
    }

    @Test
    fun keepsClassesNamedInTheResourceTable() {
        val dir = Files.createTempDirectory("pipeline-resource-table-")
        val className = "com.example.app.App"
        val input = ApkTestFixtures.writeApk(
            dir.resolve("input.apk"),
            ApkTestFixtures.syntheticApk(
                extraEntries = listOf(
                    ApkTestFixtures.ApkTemplateEntry("resources.arsc", ApkTestFixtures.resourceTable(className)),
                ),
            ),
        )
        val kernelConfigs = mutableListOf<ObfuscationConfig>()
        fakeRunner(mutableListOf(), kernelConfigs, mutableListOf()).run(
            config(input, dir.resolve("result.apk")),
            dir.resolve("config.toml"),
        ) {}
        assertTrue(kernelConfigs.single().ruleSet.rules.any { it.target == className.replace('.', '/') && it.action == "exclude" })
    }

    @Test
    fun keepsServiceEntryNamesAndProviderNamesWithoutChangingTheDescriptor() {
        val dir = Files.createTempDirectory("pipeline-service-names-")
        val app = "com.example.app.App"
        val registrations = listOf(
            "META-INF/services/$app" to "external.Provider\r\n",
            "META-INF/services/external.Service" to "# provider list\r\n\t$app  # registered\r\n",
        )
        for ((index, registration) in registrations.withIndex()) {
            val (name, text) = registration
            val descriptor = text.toByteArray(Charsets.UTF_8)
            val input = ApkTestFixtures.writeApk(
                dir.resolve("input-$index.apk"),
                ApkTestFixtures.syntheticApk(extraEntries = listOf(ApkTestFixtures.ApkTemplateEntry(name, descriptor))),
            )
            val output = dir.resolve("result-$index.apk")
            val kernelConfigs = mutableListOf<ObfuscationConfig>()
            fakeRunner(mutableListOf(), kernelConfigs, mutableListOf()).run(config(input, output), dir.resolve("config.toml")) {}
            val exclusions = kernelConfigs.single().ruleSet.rules.filter { it.action == "exclude" }.map { it.target }
            assertEquals(listOf(app.replace('.', '/')), exclusions, name)
            ZipFile.builder().setFile(output.toFile()).get().use { archive ->
                assertContentEquals(descriptor, archive.getInputStream(archive.getEntry(name)).use { it.readBytes() })
            }
        }
    }

    @Test
    fun keepsShortPreferenceTagsAndTheRuntimePackageAnchors() {
        val dir = Files.createTempDirectory("pipeline-preference-tags-")
        val prefix = "androidx/preference/"
        val screen = prefix + "PreferenceScreen"
        val action = prefix + "EditTextPreference"
        val anchors = listOf(prefix + "Preference", prefix + "SwitchPreference")
        val negative = listOf(prefix + "CheckBoxPreference", "fixture/EditTextPreference", prefix + "PreferenceInflater")
        val xml = ApkTestFixtures.binaryXmlElements("PreferenceScreen", "EditTextPreference", otherPoolStrings = listOf("CheckBoxPreference"))
        val name = "res/41.xml" // Optimized resources may no longer carry a res/xml directory name.
        val input = ApkTestFixtures.writeApk(dir.resolve("input.apk"), ApkTestFixtures.syntheticApk(
            extraEntries = listOf(ApkTestFixtures.ApkTemplateEntry(name, xml)),
        ))
        val output = dir.resolve("result.apk")
        val configs = mutableListOf<ObfuscationConfig>()
        fakeRunner(mutableListOf(), configs, mutableListOf(), fixtureClasses = listOf(screen, action) + anchors + negative)
            .run(config(input, output), dir.resolve("config.toml")) {}
        val exclusions = configs.single().ruleSet.rules.filter { it.action == "exclude" }.map { it.target }.toSet()
        assertEquals((listOf(screen, action) + anchors).toSet(), exclusions)
        ZipFile.builder().setFile(output.toFile()).get().use { archive ->
            assertContentEquals(xml, archive.getInputStream(archive.getEntry(name)).use { it.readBytes() })
        }
    }

    @Test
    fun preservesInputNativeAlignmentWhenRebuildingTheArchive() {
        val dir = Files.createTempDirectory("pipeline-native-alignment-")
        val input = dir.resolve("input.apk")
        val output = dir.resolve("result.apk")
        val libraryName = "lib/x86_64/libfixture.so"
        val library = ByteArray(5000) { it.toByte() }
        ApkZipWriter(Files.newOutputStream(input)).use { writer ->
            writer.addDeflatedEntry("AndroidManifest.xml", 0, ApkTestFixtures.binaryManifest("com.example.app", minSdkVersion = 26))
            writer.addDeflatedEntry("classes.dex", 0, ByteArray(4096) { (it * 31).toByte() })
            writer.addRawEntry(
                name = libraryName,
                method = ZipEntry.STORED,
                time = 0,
                crc = ApkInputUnpacker.crc32Of(library),
                size = library.size.toLong(),
                compressedSize = library.size.toLong(),
                externalAttributes = 0,
                rawCompressedBytes = library,
                originalExtra = byteArrayOf(),
                alignment = 16384,
            )
            writer.finish()
        }
        val originalBytes = Files.readAllBytes(input)
        fakeRunner(mutableListOf(), mutableListOf(), mutableListOf()).run(
            config(input, output),
            dir.resolve("config.toml"),
        ) {}

        assertContentEquals(originalBytes, Files.readAllBytes(input))
        ZipFile.builder().setFile(output.toFile()).get().use { archive ->
            val entry = archive.getEntry(libraryName)
            assertEquals(ZipEntry.STORED, entry.method)
            assertEquals(0L, entry.dataOffset % 16384)
            assertContentEquals(library, archive.getInputStream(entry).use { it.readBytes() })
        }
    }

    @Test
    fun rejectsLogAliasesAndSidecarsThatWouldOverwriteUserFilesBeforeOpeningLog() {
        val dir = Files.createTempDirectory("pipeline-paths-")
        val input = ApkTestFixtures.writeApk(dir.resolve("input.apk"), ApkTestFixtures.syntheticApk())
        val configPath = Files.writeString(dir.resolve("config.toml"), "original config")
        val output = Files.writeString(dir.resolve("output.apk"), "old apk")
        val evidence = Files.writeString(dir.resolve("output.build-evidence.json"), "old evidence")
        val alias = Files.createLink(dir.resolve("input-hardlink.log"), input)
        val originalInput = Files.readAllBytes(input)
        val stages = mutableListOf<String>()
        val runner = fakeRunner(stages, mutableListOf(), mutableListOf())

        for (log in listOf(input, alias, configPath, output, evidence, output.resolve("nested.log"))) {
            assertFailsWith<IllegalArgumentException> {
                runner.run(config(input, output).copy(logFilePath = log.toString()), configPath) {}
            }
        }
        assertFailsWith<IllegalArgumentException> { runner.run(config(input, input), configPath) {} }
        assertFailsWith<IllegalArgumentException> { runner.run(config(input, output), evidence) {} }
        val signing = ApkSigningConfig(keystorePath = evidence.toString())
        assertFailsWith<IllegalArgumentException> {
            runner.run(config(input, output).let { it.copy(apk = it.apk.copy(signing = signing)) }, configPath) {}
        }

        assertTrue(stages.isEmpty())
        assertContentEquals(originalInput, Files.readAllBytes(input))
        assertEquals("original config", Files.readString(configPath))
        assertEquals("old apk", Files.readString(output))
        assertEquals("old evidence", Files.readString(evidence))
    }

    @Test
    fun invalidStagedArchiveAndMissingSignatureLeaveDestinationsUntouched() {
        for (requireSignature in listOf(false, true)) {
            val dir = Files.createTempDirectory("pipeline-invalid-")
            val input = ApkTestFixtures.writeApk(dir.resolve("input.apk"), ApkTestFixtures.syntheticApk())
            val output = Files.writeString(dir.resolve("output.apk"), "old apk")
            val events = mutableListOf<EngineEvent>()
            val runConfig = config(input, output).let {
                if (requireSignature) it.copy(apk = it.apk.copy(signing = ApkSigningConfig())) else it
            }
            val runner = fakeRunner(mutableListOf(), mutableListOf(), events, signOutput = { unsigned, staged ->
                if (requireSignature) Files.copy(unsigned, staged, REPLACE_EXISTING)
                else ZipOutputStream(Files.newOutputStream(staged)).close()
            })

            assertFailsWith<IllegalArgumentException> { runner.run(runConfig, dir.resolve("config.toml")) { events += it } }
            assertEquals("old apk", Files.readString(output))
            assertTrue(apkSidecarPaths(output).none { Files.exists(it) })
            assertTrue(events.none { it.type == "done" })
            assertWorkCleaned(dir)
        }
    }

    @Test
    fun malformedEvidenceAndBlockedSidecarLeaveAllOldBytesAndMissingDestinationsUnchanged() {
        for (blockedDestination in listOf(false, true)) {
            val dir = Files.createTempDirectory("pipeline-sidecar-")
            val input = ApkTestFixtures.writeApk(dir.resolve("input.apk"), ApkTestFixtures.syntheticApk())
            val output = Files.writeString(dir.resolve("output.apk"), "old apk")
            val (scan, evidence, debugMap) = apkSidecarPaths(output)
            val oldScan = byteArrayOf(0, -1, 42)
            Files.write(scan, oldScan)
            if (blockedDestination) Files.createDirectory(evidence) else Files.writeString(evidence, "old evidence")
            val events = mutableListOf<EngineEvent>()
            val runner = fakeRunner(mutableListOf(), mutableListOf(), events) { kernelConfig, _, _ ->
                if (!blockedDestination) {
                    val workEvidence = apkSidecarPaths(Path.of(kernelConfig.outputJarPath))[1]
                    Files.writeString(workEvidence, "{} {}")
                }
            }

            assertFailsWith<Exception> { runner.run(config(input, output), dir.resolve("config.toml")) { events += it } }
            assertEquals("old apk", Files.readString(output))
            assertContentEquals(oldScan, Files.readAllBytes(scan))
            if (blockedDestination) assertTrue(Files.isDirectory(evidence))
            else assertEquals("old evidence", Files.readString(evidence))
            assertTrue(!Files.exists(debugMap))
            assertTrue(events.none { it.type == "done" })
            assertWorkCleaned(dir)
        }
    }

    @Test
    fun interruptionDuringPublicationRollsBackReplacedAndNewFiles() {
        val dir = Files.createTempDirectory("pipeline-cancel-")
        val input = ApkTestFixtures.writeApk(dir.resolve("input.apk"), ApkTestFixtures.syntheticApk())
        val output = Files.writeString(dir.resolve("output.apk"), "old apk")
        val (scan, evidence) = apkSidecarPaths(output)
        val oldEvidence = byteArrayOf(0, -1, 42)
        Files.write(evidence, oldEvidence)
        val fixedTempName = Files.writeString(dir.resolve("output.apk.javashroud-signing.tmp"), "user file")
        val events = mutableListOf<EngineEvent>()
        val runner = fakeRunner(mutableListOf(), mutableListOf(), events)

        try {
            assertFailsWith<CancellationException> {
                runner.run(config(input, output), dir.resolve("config.toml")) { event ->
                    events += event
                    if (event.message.startsWith("apk-summary:")) Thread.currentThread().interrupt()
                }
            }
        } finally {
            Thread.interrupted()
        }
        assertEquals("old apk", Files.readString(output))
        assertContentEquals(oldEvidence, Files.readAllBytes(evidence))
        assertEquals("user file", Files.readString(fixedTempName))
        assertTrue(!Files.exists(scan))
        assertTrue(events.none { it.type == "done" })
        assertWorkCleaned(dir)
    }

    @Test
    fun successfulPublicationRemovesMissingSidecars() {
        for (workJarSidecars in listOf(false, true)) {
            val dir = Files.createTempDirectory("pipeline-stale-sidecars-")
            val input = ApkTestFixtures.writeApk(dir.resolve("input.apk"), ApkTestFixtures.syntheticApk())
            val output = Files.writeString(dir.resolve("output.apk"), "old apk")
            val sidecars = apkSidecarPaths(output)
            sidecars.forEach { Files.writeString(it, "old sidecar") }
            val events = mutableListOf<EngineEvent>()

            fakeRunner(mutableListOf(), mutableListOf(), events, workJarSidecars = workJarSidecars)
                .run(config(input, output), dir.resolve("config.toml")) { events += it }

            val missingSidecars = if (workJarSidecars) sidecars.takeLast(1) else sidecars
            missingSidecars.forEach { assertTrue(Files.notExists(it), "Obsolete sidecar remains: $it") }
            assertEquals(1, events.count { it.type == "done" })
            assertWorkCleaned(dir)
        }
    }

    @Test
    fun cancellationAfterDoneKeepsTheCommittedApk() {
        val dir = Files.createTempDirectory("pipeline-cancel-after-done-")
        val input = ApkTestFixtures.writeApk(dir.resolve("input.apk"), ApkTestFixtures.syntheticApk())
        val output = Files.writeString(dir.resolve("output.apk"), "old apk")
        val events = mutableListOf<EngineEvent>()
        try {
            fakeRunner(mutableListOf(), mutableListOf(), events, workJarSidecars = false)
                .run(config(input, output), dir.resolve("config.toml")) { event ->
                    events += event
                    if (event.type == "done") Thread.currentThread().interrupt()
                }
            assertEquals(1, events.count { it.type == "done" })
            assertFalse(Files.readAllBytes(output).contentEquals("old apk".toByteArray()))
            java.util.zip.ZipFile(output.toFile()).use { archive ->
                assertNotNull(archive.getEntry("classes.dex"))
            }
            assertWorkCleaned(dir)
        } finally {
            Thread.interrupted()
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun callbackFailureRestoresDeletedSidecarsAndPreservesMissingDestinations() {
        for (cancel in listOf(false, true)) {
            val dir = Files.createTempDirectory("pipeline-sidecar-delete-rollback-")
            val input = ApkTestFixtures.writeApk(dir.resolve("input.apk"), ApkTestFixtures.syntheticApk())
            val output = Files.writeString(dir.resolve("output.apk"), "old apk")
            val (scan, evidence, debugMap) = apkSidecarPaths(output)
            val oldScan = byteArrayOf(0, -1, 42)
            val oldDebugMap = byteArrayOf(42, -1, 0)
            Files.write(scan, oldScan)
            Files.write(debugMap, oldDebugMap)
            val events = mutableListOf<EngineEvent>()
            val runner = fakeRunner(mutableListOf(), mutableListOf(), events, workJarSidecars = false)
            val failure = if (cancel) CancellationException("cancel after sidecar deletion")
                else IOException("fail after sidecar deletion")

            assertSame(failure, assertFailsWith<Exception> {
                runner.run(config(input, output), dir.resolve("config.toml")) { event ->
                    events += event
                    if (event.message.startsWith("apk-summary:")) {
                        assertTrue(listOf(scan, evidence, debugMap).all { Files.notExists(it) })
                        throw failure
                    }
                }
            })

            assertEquals("old apk", Files.readString(output))
            assertContentEquals(oldScan, Files.readAllBytes(scan))
            assertContentEquals(oldDebugMap, Files.readAllBytes(debugMap))
            assertTrue(Files.notExists(evidence))
            assertTrue(events.none { it.type == "done" })
            assertWorkCleaned(dir)
        }
    }

    @Test
    fun missingSidecarWithDirectoryDestinationFailsBeforePublication() {
        val dir = Files.createTempDirectory("pipeline-sidecar-directory-")
        val input = ApkTestFixtures.writeApk(dir.resolve("input.apk"), ApkTestFixtures.syntheticApk())
        val output = Files.writeString(dir.resolve("output.apk"), "old apk")
        val debugMap = Files.createDirectory(apkSidecarPaths(output)[2])
        val marker = Files.writeString(debugMap.resolve("keep.txt"), "user file")
        val events = mutableListOf<EngineEvent>()

        assertFailsWith<IllegalArgumentException> {
            fakeRunner(mutableListOf(), mutableListOf(), events, workJarSidecars = false)
                .run(config(input, output), dir.resolve("config.toml")) { events += it }
        }

        assertEquals("old apk", Files.readString(output))
        assertEquals("user file", Files.readString(marker))
        assertTrue(events.none { it.type == "done" })
        assertWorkCleaned(dir)
    }

    private fun assertWorkCleaned(dir: Path) {
        assertTrue(Files.list(dir).use { stream ->
            stream.noneMatch { path ->
                val name = path.fileName.toString()
                name.startsWith(".javashroud-apk-work-") || name.endsWith(".javashroud-publish")
            }
        })
    }

    @Test
    fun failedAtomicMoveRestoresEarlierReplacements() {
        val dir = Files.createTempDirectory("pipeline-move-fail-")
        val output = Files.writeString(dir.resolve("output.apk"), "old apk")
        val (scan, evidence) = apkSidecarPaths(output)
        Files.writeString(scan, "old scan")
        val staging = Files.createDirectory(dir.resolve("stage"))
        val stagedScan = Files.writeString(staging.resolve("scan"), "new scan")
        val stagedEvidence = Files.writeString(staging.resolve("evidence"), "new evidence")

        // Reusing the source for the final move makes it disappear only after
        // both sidecars were installed and every preflight check passed.
        assertFailsWith<NoSuchFileException> {
            publishApkFiles(
                listOf(stagedScan to scan, stagedEvidence to evidence, stagedEvidence to output),
                staging,
                apkPublicationLock(output),
            ) { error("missing source should prevent publication") }
        }

        assertEquals("old apk", Files.readString(output))
        assertEquals("old scan", Files.readString(scan))
        assertTrue(!Files.exists(evidence))
        assertTrue(!Files.exists(apkPublicationLock(output)))
    }

    @Test
    fun orchestratesPhasesRewritesDoneAndMigratesSidecars() {
        val dir = Files.createTempDirectory("pipeline-")
        val inputApk = ApkTestFixtures.writeApk(
            dir.resolve("in/app.apk"),
            ApkTestFixtures.syntheticApk(
                manifestBytes = ApkTestFixtures.binaryManifest("com.example.app", minSdkVersion = 26, componentClasses = listOf("com.example.app.App")),
            ),
        )
        val finalApk = dir.resolve("out/final/app-shrouded.apk")
        val stages = mutableListOf<String>()
        val kernelConfigs = mutableListOf<ObfuscationConfig>()
        val events = mutableListOf<EngineEvent>()

        val logFile = Files.writeString(dir.resolve("run.log"), "previous run\n")
        val debugMapBytes = byteArrayOf(0, -1, 42)
        fakeRunner(stages, kernelConfigs, events) { kernelConfig, _, _ ->
            Files.write(apkSidecarPaths(Path.of(kernelConfig.outputJarPath))[2], debugMapBytes)
        }.run(
            config(inputApk, finalApk).copy(logFilePath = logFile.toString()),
            Path.of("cfg.toml"),
        ) { events += it }
        assertTrue(Files.readString(logFile).startsWith("previous run\n"))
        assertTrue(Files.readString(logFile).contains("final APK"))

        // Orchestration order.
        assertEquals(listOf("provision", "dex2jar-1", "kernel", "d8", "sign"), stages)

        // Kernel config anchoring.
        val engineConfig = kernelConfigs.single()
        assertTrue(engineConfig.outputJarPath.endsWith("apk-work.jar"))
        assertEquals("apk-input-classes.jar", Path.of(engineConfig.inputJarPath).fileName.toString())
        assertTrue(engineConfig.ruleSet.rules.isNotEmpty(), "keep rules must be merged into the engine rule set")
        assertTrue(
            engineConfig.ruleSet.rules.any { it.target == "com/example/app/App" && it.action == "exclude" },
            engineConfig.ruleSet.rules.joinToString { it.target },
        )

        // Done event: exactly one, pointing at the final APK.
        val doneEvents = events.filter { it.type == "done" }
        assertEquals(1, doneEvents.size)
        assertEquals(finalApk.toAbsolutePath().toString(), doneEvents.single().outPath)

        // Sidecars migrated and rewritten.
        val releaseScan = dir.resolve("out/final/app-shrouded.release-scan.txt")
        val buildEvidence = dir.resolve("out/final/app-shrouded.build-evidence.json")
        assertTrue(Files.isRegularFile(releaseScan))
        assertTrue(Files.isRegularFile(buildEvidence))
        assertContentEquals(debugMapBytes, Files.readAllBytes(apkSidecarPaths(finalApk)[2]))
        val scanText = Files.readString(releaseScan)
        assertTrue(scanText.contains(finalApk.toAbsolutePath().toString()), scanText)
        assertTrue(!scanText.contains("apk-work.jar"))
        val evidenceJson = Files.readString(buildEvidence)
        com.fasterxml.jackson.databind.ObjectMapper().readTree(evidenceJson)
        assertTrue(evidenceJson.contains(finalApk.toAbsolutePath().toString().replace("\\", "\\\\")) || evidenceJson.contains(finalApk.toAbsolutePath().toString()))

        // Work directory removed.
        assertTrue(Files.list(dir.resolve("out/final")).use { stream ->
            stream.noneMatch { path -> path.fileName.toString().startsWith(".javashroud-apk-work-") }
        })

        // Final APK exists with the new dex.
        assertTrue(Files.isRegularFile(finalApk))
        val unpackedOut = ApkInputUnpacker.read(finalApk)
        assertTrue(unpackedOut.dexEntries.isNotEmpty())
    }

    @Test
    fun phaseFailurePropagatesWithoutDoneAndCleansWorkDir() {
        val dir = Files.createTempDirectory("pipeline-fail-")
        val inputApk = ApkTestFixtures.writeApk(dir.resolve("in/app.apk"), ApkTestFixtures.syntheticApk())
        val finalApk = dir.resolve("out/app.apk")
        val stages = mutableListOf<String>()
        val events = mutableListOf<EngineEvent>()

        val runner = ApkPipelineRunner(
            kernelRunner = { engineConfig, _, _ ->
                stages += "kernel"
                val workJar = Path.of(engineConfig.outputJarPath)
                Files.createDirectories(workJar.parent)
                JarOutputStream(Files.newOutputStream(workJar)).use { jar ->
                    jar.putNextEntry(ZipEntry("com/example/app/App.class"))
                    jar.write(ApkPipelineRunnerTestSupport.appClassBytes())
                    jar.closeEntry()
                }
            },
            provision = { _, _ ->
                ApkToolchainProvisioner.ApkToolchain(
                    Path.of("java"), Path.of("d"), Path.of("r8.jar"), "test", "test",
                )
            },
            dexToClassConverter = object : ApkDex2JarRunner(runner = { _, _ -> ApkProcessSupport.ProcessResult(0, "fake", false) }) {
                override fun convert(
                    toolchain: ApkToolchainProvisioner.ApkToolchain,
                    dex: ApkInputUnpacker.ApkDexInput,
                    workDirectory: Path,
                    log: (String) -> Unit,
                ): ConvertedDex {
                    val jarPath = workDirectory.resolve("fake-classes.jar")
                    JarOutputStream(Files.newOutputStream(jarPath)).use { jar ->
                        jar.putNextEntry(ZipEntry("com/example/app/App.class"))
                        jar.write(ApkPipelineRunnerTestSupport.appClassBytes())
                        jar.closeEntry()
                    }
                    return ConvertedDex(dex.index, jarPath, listOf("com/example/app/App.class"))
                }
            },
            classToDexCompiler = object : ApkD8Runner(runner = { _, _ -> ApkProcessSupport.ProcessResult(0, "fake", false) }) {
                override fun compile(
                    toolchain: ApkToolchainProvisioner.ApkToolchain,
                    inputJar: Path,
                    outputDirectory: Path,
                    minApi: Int,
                    androidJarPath: String,
                    log: (String) -> Unit,
                ): List<Pair<String, ByteArray>> {
                    throw IllegalStateException("d8 exploded for test")
                }
            },
            signer = { _, _, _, _, _, _ -> throw IllegalStateException("unreachable") },
        )

        assertFailsWith<IllegalStateException> {
            runner.run(config(inputApk, finalApk), Path.of("cfg.toml")) { events += it }
        }
        assertTrue(events.none { it.type == "done" }, "no done event may leak from a failed run")
        assertTrue(!Files.isRegularFile(finalApk), "no half-produced APK")
        assertTrue(Files.list(dir.resolve("out")).use { stream ->
            stream.noneMatch { path -> path.fileName.toString().startsWith(".javashroud-apk-work-") }
        }, "work directory must be cleaned on failure")
    }

    @Test
    fun keepSynthesisFailsClosedWhenManifestComponentMissingFromClasses() {
        // Manifest names a component that does not exist in the dex-derived
        // classes: synthesis intersects with loaded classes, so the run must
        // proceed (warn semantics) rather than inventing unmatchable rules.
        val manifest = ApkBinaryXmlReader.parse(
            ApkTestFixtures.binaryManifest("com.example.app", componentClasses = listOf("com.example.app.Missing")),
        )
        val runner = ApkPipelineRunner()
        val internalNames = runner.manifestComponentInternalNames(manifest)
        assertEquals(setOf("com/example/app/Missing"), internalNames)
        // Synthesis intersected with an empty loaded set yields no class rules.
        val jar = Files.createTempFile("empty-classes-", ".jar")
        JarOutputStream(Files.newOutputStream(jar)).close()
        val plan = ApkKeepRuleSynthesis.synthesize(jar, internalNames, emptySet(), emptySet(), emptyList())
        assertTrue(plan.excludedClassNames.isEmpty())
        assertTrue(plan.warnings.isNotEmpty())
    }
}

/** Shared builders used by the fake pipeline tests. */
object ApkPipelineRunnerTestSupport {

    fun minimalDex(classCount: Int = 1): ByteArray {
        val mapOffset = 0x70
        val mapSize = 2
        val total = mapOffset + 4 + mapSize * 12
        val bytes = ByteArray(total)
        fun u16(offset: Int, value: Int) {
            bytes[offset] = (value and 0xFF).toByte()
            bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        }
        fun u32(offset: Int, value: Long) {
            bytes[offset] = (value and 0xFF).toByte()
            bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
            bytes[offset + 2] = ((value ushr 16) and 0xFF).toByte()
            bytes[offset + 3] = ((value ushr 24) and 0xFF).toByte()
        }
        System.arraycopy(byteArrayOf(0x64, 0x65, 0x78, 0x0A), 0, bytes, 0, 4)
        System.arraycopy("035".toByteArray(), 0, bytes, 4, 3)
        u32(32, total.toLong())
        u32(36, 0x70L)
        u32(40, 0x12345678L)
        u32(52, mapOffset.toLong())
        u32(mapOffset, mapSize.toLong())
        u16(mapOffset + 4, 0x0002)
        u32(mapOffset + 8, 0x70L)
        u32(mapOffset + 12, 1L)
        u16(mapOffset + 16, 0x0006)
        u32(mapOffset + 20, 0x70L)
        u32(mapOffset + 24, classCount.toLong())
        val signature = java.security.MessageDigest.getInstance("SHA-1").apply {
            update(bytes, 32, total - 32)
        }.digest()
        signature.copyInto(bytes, 12)
        var a = 1
        var b = 0
        for (index in 12 until total) {
            a = (a + (bytes[index].toInt() and 0xFF)) % 65521
            b = (b + a) % 65521
        }
        u32(8, ((b.toLong() shl 16) or a.toLong()))
        return bytes
    }

    fun appClassBytes(owner: String = "com/example/app/App"): ByteArray {
        val writer = org.objectweb.asm.ClassWriter(0)
        writer.visit(
            org.objectweb.asm.Opcodes.V1_8,
            org.objectweb.asm.Opcodes.ACC_PUBLIC,
            owner,
            null,
            "java/lang/Object",
            null,
        )
        writer.visitMethod(org.objectweb.asm.Opcodes.ACC_PUBLIC, "<init>", "()V", null, null).visitEnd()
        writer.visitEnd()
        return writer.toByteArray()
    }
}
