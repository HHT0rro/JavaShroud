package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.kernel.validateSelectedOnlyPassSelectionsAgainstArtifact
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.kernel.PassExecutionResult
import io.github.hht0rro.javashroud.kernel.buildArtifactSummaryMessage
import io.github.hht0rro.javashroud.kernel.buildDoneEvent
import io.github.hht0rro.javashroud.kernel.buildPassProgressEvent
import io.github.hht0rro.javashroud.kernel.buildPassTickEvent
import io.github.hht0rro.javashroud.kernel.buildRunEvents
import io.github.hht0rro.javashroud.kernel.buildRunSummaryEvent
import io.github.hht0rro.javashroud.kernel.calculatePassTickProgress
import io.github.hht0rro.javashroud.kernel.calculateProgress
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.model.config.PassSelectionMode
import io.github.hht0rro.javashroud.model.config.PassSelectionSpec
import io.github.hht0rro.javashroud.model.config.RuleSpec
import io.github.hht0rro.javashroud.model.analysis.MemberKind
import io.github.hht0rro.javashroud.model.analysis.MemberSummary
import io.github.hht0rro.javashroud.model.passes.PassContext
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.schema.ModuleTargetingCapability
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.modules.ModuleTransform
import io.github.hht0rro.javashroud.modules.ObfuscationModule
import io.github.hht0rro.javashroud.passes.ExecutablePass
import io.github.hht0rro.javashroud.passes.PassDescriptor
import io.github.hht0rro.javashroud.transforms.protection.CandidateProductionBuildEvidence
import io.github.hht0rro.javashroud.transforms.protection.hardening.SignedDebugMap
import java.nio.file.FileSystemException
import java.nio.file.Files
import java.nio.file.Path
import java.util.HexFormat
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class KernelRunSupportTest {
    @Test
    fun calculateProgress_rejects_non_positive_total() {
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            calculateProgress(1, 0)
        }
    }

    @Test
    fun calculateProgress_maps_progress_into_expected_range() {
        assertEquals(15, calculateProgress(0, 4))
        assertEquals(33, calculateProgress(1, 4))
        assertEquals(52, calculateProgress(2, 4))
        assertEquals(71, calculateProgress(3, 4))
        assertEquals(90, calculateProgress(4, 4))
    }

    @Test
    fun buildPassProgressEvent_uses_expected_message_and_progress() {
        val event = buildPassProgressEvent(
            passId = "strip-compile-debug-info",
            completedPassCount = 2,
            totalPassCount = 4,
        )

        assertEquals("info", event.level)
        assertEquals("progress", event.type)
        assertEquals("Executed pass: id=strip-compile-debug-info", event.message)
        assertEquals(52, event.progress)
        assertEquals(null, event.outPath)
    }

    @Test
    fun buildArtifactSummaryMessage_includes_match_and_rename_counts() {
        val message = buildArtifactSummaryMessage(
            config = testConfig(inputJarPath = "in.jar", outputJarPath = "out.jar"),
            classCount = 3,
            resourceCount = 2,
            manifestPresent = true,
            ruleMatches = emptyList(),
            renamePlanSize = 7,
        )

        assertTrue(message.contains("Loaded input jar=in.jar"))
        assertTrue(message.contains(", classes=3"))
        assertTrue(message.contains(", resources=2"))
        assertTrue(message.contains(", manifestPresent=true"))
        assertTrue(message.contains(", matchedRules=0"))
        assertTrue(message.contains(", plannedRenames=7"))
    }

    @Test
    fun calculatePassTickProgress_maps_start_and_end_into_expected_range() {
        assertEquals(24, calculatePassTickProgress(0, 4, isStart = true))
        assertEquals(33, calculatePassTickProgress(0, 4, isStart = false))
        assertEquals(43, calculatePassTickProgress(1, 4, isStart = true))
        assertEquals(52, calculatePassTickProgress(1, 4, isStart = false))
        assertEquals(61, calculatePassTickProgress(2, 4, isStart = true))
        assertEquals(71, calculatePassTickProgress(2, 4, isStart = false))
        assertEquals(80, calculatePassTickProgress(3, 4, isStart = true))
        assertEquals(90, calculatePassTickProgress(3, 4, isStart = false))
    }

    @Test
    fun calculatePassTickProgress_rejects_non_positive_total() {
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            calculatePassTickProgress(0, 0, isStart = true)
        }
    }

    @Test
    fun buildPassTickEvent_uses_pass_id_as_message() {
        val startEvent = buildPassTickEvent(passId = "rename-classes", passIndex = 1, totalPassCount = 4, isStart = true)
        val endEvent = buildPassTickEvent(passId = "rename-classes", passIndex = 1, totalPassCount = 4, isStart = false)

        assertEquals("info", startEvent.level)
        assertEquals("progress", startEvent.type)
        assertEquals("rename-classes", startEvent.message)
        assertEquals(43, startEvent.progress)

        assertEquals("info", endEvent.level)
        assertEquals("progress", endEvent.type)
        assertEquals("rename-classes", endEvent.message)
        assertEquals(52, endEvent.progress)
    }

    @Test
    fun buildRunSummaryEvent_includes_aggregate_metrics() {
        val event = buildRunSummaryEvent(
            executedPassCount = 3,
            totalTransformedClasses = 42,
            totalTransformedMembers = 17,
            totalPlannedRenames = 88,
            outputJarPath = "/tmp/out.jar",
        )

        assertEquals("success", event.level)
        assertEquals("log", event.type)
        assertEquals(95, event.progress)
        assertTrue(event.message.contains("passes=3"))
        assertTrue(event.message.contains("transformedClasses=42"))
        assertTrue(event.message.contains("transformedMembers=17"))
        assertTrue(event.message.contains("plannedRenames=88"))
        assertTrue(event.message.contains("output=/tmp/out.jar"))
    }

    @Test
    fun registered_pass_params_preserve_large_integral_numbers_as_long() {
        val seedValue = 3_000_000_000L
        var observedSeed: Any? = null
        val passSpec = PassSpec(
            id = "capture-params",
            enabled = true,
            params = mapOf("seed" to JsonNodeFactory.instance.numberNode(seedValue)),
        )
        val runConfig = testConfig(passes = listOf(passSpec))
        val artifact = emptyTestArtifact(config = runConfig)
        val executable = ExecutablePass(
            descriptor = PassDescriptor(id = passSpec.id, definition = testModuleDefinition(passSpec.id)),
            module = ObfuscationModule(
                definition = testModuleDefinition(passSpec.id),
                transform = ModuleTransform { currentArtifact, _, params ->
                    observedSeed = params["seed"]
                    TransformResult(
                        artifact = currentArtifact,
                        transformedClassCount = 0,
                        transformedMemberCount = 0,
                    )
                },
            ),
        )

        io.github.hht0rro.javashroud.passes.applyRegisteredPass(
            spec = passSpec,
            executable = executable,
            context = PassContext(config = runConfig, artifact = artifact, events = emptyList()),
        )

        assertEquals(seedValue, observedSeed)
    }

    @Test
    fun selectedOnlyPreflight_accepts_empty_independent_scope() {
        val passId = "strip-compile-debug-info"
        val config = testConfig(
            passes = listOf(testPassSpec(id = passId)),
            passSelections = listOf(
                PassSelectionSpec(passId = passId, mode = PassSelectionMode.SELECTED_ONLY),
            ),
        )
        val artifact = testAttachedArtifact(
            config = config,
            classArtifacts = listOf(testClassArtifact(internalName = "sample/Present")),
        )

        validateSelectedOnlyPassSelectionsAgainstArtifact(config, artifact)
    }

    @Test
    fun selectedOnlyPreflight_ignores_nonMatching_exclusions() {
        val passId = "strip-compile-debug-info"
        val config = testConfig(
            passes = listOf(testPassSpec(id = passId)),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = passId,
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(RuleSpec(target = "sample/Missing", action = "exclude")),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            config = config,
            classArtifacts = listOf(testClassArtifact(internalName = "sample/Present")),
        )

        validateSelectedOnlyPassSelectionsAgainstArtifact(config, artifact)
    }

    @Test
    fun selectedOnlyPreflight_rejects_when_exclusions_remove_every_processable_target() {
        val passId = "strip-compile-debug-info"
        val config = testConfig(
            passes = listOf(testPassSpec(id = passId)),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = passId,
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(RuleSpec(target = "sample/Present", action = "exclude")),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            config = config,
            classArtifacts = listOf(testClassArtifact(internalName = "sample/Present")),
        )

        val error = assertFailsWith<IllegalArgumentException> {
            validateSelectedOnlyPassSelectionsAgainstArtifact(config, artifact)
        }
        assertTrue(error.message.orEmpty().contains(passId))
        assertTrue(error.message.orEmpty().contains("independent scope excludes every processable class or method"))
    }

    @Test
    fun selectedOnlyPreflight_allows_method_restore_inside_excluded_class() {
        val passId = "method-virtualization"
        val config = testConfig(
            passes = listOf(testPassSpec(id = passId)),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = passId,
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(
                        RuleSpec(target = "sample/Target", action = "exclude"),
                        RuleSpec(target = "sample/Target#present:()I", action = "obfuscate"),
                    ),
                ),
            ),
        )
        val artifact = testAttachedArtifact(
            config = config,
            classArtifacts = listOf(
                testClassArtifact(
                    internalName = "sample/Target",
                    methodSummaries = listOf(MemberSummary(MemberKind.METHOD, "present", "()I", 0)),
                ),
            ),
        )

        validateSelectedOnlyPassSelectionsAgainstArtifact(config, artifact)
    }

    @Test
    fun selectedOnlyPreflight_ignores_disabled_and_inherited_pass_selections() {
        val disabledPassId = "strip-compile-debug-info"
        val inheritedPassId = "member-hide"
        val config = testConfig(
            passes = listOf(
                testPassSpec(id = disabledPassId, enabled = false),
                testPassSpec(id = inheritedPassId, enabled = true),
            ),
            passSelections = listOf(
                PassSelectionSpec(
                    passId = disabledPassId,
                    mode = PassSelectionMode.SELECTED_ONLY,
                    rules = listOf(RuleSpec(target = "sample/Missing", action = "obfuscate")),
                ),
                PassSelectionSpec(passId = inheritedPassId, mode = PassSelectionMode.INHERIT_GLOBAL),
            ),
        )
        val artifact = emptyTestArtifact(config)

        validateSelectedOnlyPassSelectionsAgainstArtifact(config, artifact)
    }

    @Test
    fun buildRunEvents_preserves_expected_event_order() {
        val runConfig = testConfig(inputJarPath = "in.jar", outputJarPath = "out.jar")
        val bootstrapEvent = EngineEvent(level = "info", type = "log", message = "boot", progress = 0, outPath = null)
        val summaryEvent = EngineEvent(level = "info", type = "log", message = "summary", progress = 15, outPath = null)
        val phaseEvent = EngineEvent(level = "info", type = "progress", message = "phase", progress = 50, outPath = null)
        val passEvent = EngineEvent(level = "info", type = "log", message = "pass", progress = 50, outPath = null)
        val doneEvent = buildDoneEvent("out.jar")

        val events = buildRunEvents(
            bootstrapEvents = listOf(bootstrapEvent),
            summaryEvent = summaryEvent,
            passExecution = PassExecutionResult(
                context = io.github.hht0rro.javashroud.model.passes.PassContext(
                    config = runConfig,
                    artifact = emptyTestArtifact(config = runConfig),
                    events = listOf(passEvent),
                ),
                events = listOf(phaseEvent),
            ),
            doneEvent = doneEvent,
        )

        assertEquals(listOf("boot", "summary", "phase", "pass", doneEvent.message), events.map { event: EngineEvent -> event.message })
    }

    @Test
    fun engineKernelRun_rejects_removed_boot_key_delivery_before_bootstrap_or_artifact_io() {
        val tempDir = Files.createTempDirectory("javashroud-kernel-current-format-removed-param")
        try {
            val inputJar = tempDir.resolve("must-not-be-read.jar")
            val outputJar = tempDir.resolve("must-not-be-written.jar")
            val emittedEvents = mutableListOf<EngineEvent>()

            val error = assertFailsWith<IllegalArgumentException> {
                EngineKernel().run(
                    config = testConfig(
                        inputJarPath = inputJar.toString(),
                        outputJarPath = outputJar.toString(),
                        passes = listOf(
                            testPassSpec(
                                id = "jni-microkernel-loader",
                                params = mapOf(
                                    "bootKeyDelivery" to JsonNodeFactory.instance.textNode("embedded"),
                                ),
                            ),
                        ),
                    ),
                    configPath = tempDir.resolve("config.toml"),
                    emit = { event -> emittedEvents += event },
                )
            }

            assertEquals(
                "jni-microkernel-loader bootKeyDelivery 已由当前格式移除；删除该配置项后重新构建。",
                error.message,
            )
            assertTrue(Files.notExists(inputJar), "The rejected configuration must not load its input artifact")
            assertTrue(Files.notExists(outputJar), "The rejected configuration must not write an output artifact")
            assertTrue(emittedEvents.isEmpty(), "The rejected configuration must fail before bootstrap events")
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun engineKernelRun_preserves_original_jar_and_sidecars_when_final_scan_rejects() {
        assertRejectedJarPublication(hasPreviousOutput = true)
    }

    @Test
    fun engineKernelRun_creates_no_output_when_final_scan_rejects() {
        assertRejectedJarPublication(hasPreviousOutput = false)
    }

    @Test
    fun engineKernelRun_restores_replaced_outputs_after_late_publication_failure() {
        assertJarPublicationRollsBack(hasPreviousOutput = true)
    }

    @Test
    fun engineKernelRun_removes_new_outputs_after_late_publication_failure() {
        assertJarPublicationRollsBack(hasPreviousOutput = false)
    }

    @Test
    fun engineKernelRun_publishes_validated_jar_and_report_under_requested_names() {
        val tempDir = Files.createTempDirectory("javashroud-jar-publication")
        try {
            val inputJar = tempDir.resolve("input.jar")
            val outputJar = tempDir.resolve("release candidate.jar")
            val report = tempDir.resolve("release candidate.release-scan.txt")
            val debugMap = SignedDebugMap.sidecarPath(outputJar)
            val evidence = CandidateProductionBuildEvidence.evidencePath(outputJar)
            writePublicationJar(inputJar, "resource.txt", "new contents")
            writePublicationJar(outputJar, "resource.txt", "old contents")
            listOf(report, debugMap, evidence).forEach { Files.writeString(it, "old sidecar") }

            val events = mutableListOf<EngineEvent>()
            runPublicationJar(inputJar, outputJar, events)

            JarFile(outputJar.toFile()).use { jar ->
                val contents = jar.getInputStream(jar.getJarEntry("resource.txt")).reader().use { it.readText() }
                assertEquals("new contents", contents)
            }
            val digest = HexFormat.of().formatHex(SignedDebugMap.sha256(outputJar))
            val reportLines = Files.readAllLines(report)
            assertTrue("artifactSha256=$digest" in reportLines)
            assertTrue("RESULT=PASS" in reportLines)
            assertEquals(outputJar.toString(), events.single { it.type == "done" }.outPath)
            assertEquals(setOf(inputJar, outputJar, report), Files.list(tempDir).use { it.toList().toSet() })
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    private fun assertRejectedJarPublication(hasPreviousOutput: Boolean) {
        val tempDir = Files.createTempDirectory("javashroud-jar-publication")
        try {
            val inputJar = tempDir.resolve("input.jar")
            val outputJar = tempDir.resolve("release candidate.jar")
            val sidecars = listOf(
                SignedDebugMap.sidecarPath(outputJar),
                tempDir.resolve("release candidate.release-scan.txt"),
                CandidateProductionBuildEvidence.evidencePath(outputJar),
            )
            writePublicationJar(inputJar, "metadata.debugmap", "an embedded debug map is rejected by the final scan")
            if (hasPreviousOutput) {
                writePublicationJar(outputJar, "resource.txt", "old contents")
                sidecars.forEach { Files.writeString(it, "old " + it.fileName) }
            }
            val originalFiles = Files.list(tempDir).use { it.toList() }.associateWith(Files::readAllBytes)
            val events = mutableListOf<EngineEvent>()

            val error = assertFailsWith<SecurityException> { runPublicationJar(inputJar, outputJar, events) }

            assertTrue(error.message.orEmpty().contains("debug-map-provenance: embedded=metadata.debugmap"))
            val remainingFiles = Files.list(tempDir).use { it.toList().toSet() }
            val changedFiles = originalFiles.filter { (path, bytes) ->
                path !in remainingFiles || !Files.readAllBytes(path).contentEquals(bytes)
            }.keys
            assertEquals(emptySet(), changedFiles, "Original files changed or disappeared")
            assertEquals(originalFiles.keys, remainingFiles, "Unexpected files left after failed publication")
            assertTrue(events.none { it.type == "done" })
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    private fun assertJarPublicationRollsBack(hasPreviousOutput: Boolean) {
        val tempDir = Files.createTempDirectory("javashroud-jar-rollback")
        try {
            val inputJar = tempDir.resolve("input.jar")
            val outputJar = tempDir.resolve("release candidate.jar")
            val report = tempDir.resolve("release candidate.release-scan.txt")
            val debugMap = SignedDebugMap.sidecarPath(outputJar)
            writePublicationJar(inputJar, "resource.txt", "new contents")
            if (hasPreviousOutput) {
                writePublicationJar(outputJar, "resource.txt", "old contents")
                Files.writeString(report, "old report")
            }
            Files.writeString(debugMap, "old debug map")
            // Build evidence is the last target, after the JAR, report and old debug map removal.
            val blockedTarget = Files.createDirectory(CandidateProductionBuildEvidence.evidencePath(outputJar))
            val marker = Files.writeString(blockedTarget.resolve("keep.txt"), "keep")
            val originalFiles = Files.list(tempDir).use { it.toList() }
                .filter { it != blockedTarget }.associateWith(Files::readAllBytes)
            val events = mutableListOf<EngineEvent>()

            val failure = assertFailsWith<FileSystemException> { runPublicationJar(inputJar, outputJar, events) }

            assertEquals(blockedTarget.toString(), failure.file)
            val remaining = Files.list(tempDir).use { it.toList().toSet() }
            val changed = originalFiles.filter { (path, bytes) ->
                path !in remaining || !Files.readAllBytes(path).contentEquals(bytes)
            }.keys
            assertEquals(emptySet(), changed, "Original outputs were not restored")
            assertEquals(originalFiles.keys + setOf(blockedTarget), remaining, "New outputs or staging files remain")
            assertEquals("keep", Files.readString(marker))
            assertTrue(events.none { it.type == "done" })
        } finally {
            tempDir.toFile().deleteRecursively()
        }
    }

    private fun runPublicationJar(inputJar: Path, outputJar: Path, events: MutableList<EngineEvent>) {
        EngineKernel().run(
            config = testConfig(inputJarPath = inputJar.toString(), outputJarPath = outputJar.toString())
                .copy(protectionProfile = HardenedProtectionProfile.ANALYSIS_ONLY),
            configPath = inputJar.resolveSibling("config.toml"),
            emit = { events += it },
        )
    }

    private fun writePublicationJar(path: Path, entryName: String, content: String) {
        JarOutputStream(Files.newOutputStream(path)).use { jar ->
            jar.putNextEntry(JarEntry(entryName))
            jar.write(content.toByteArray())
            jar.closeEntry()
        }
    }

    private fun testModuleDefinition(id: String): ModuleDefinition = ModuleDefinition(
        id = id,
        name = id,
        description = id,
        tagIds = emptyList(),
        params = emptyList(),
        stability = "experimental",
        targeting = ModuleTargetingCapability(
            supported = true,
            targetKinds = listOf("class"),
        ),
    )
}
