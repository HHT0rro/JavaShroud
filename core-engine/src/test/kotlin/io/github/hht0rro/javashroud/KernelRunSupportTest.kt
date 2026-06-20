package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.node.JsonNodeFactory
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
import io.github.hht0rro.javashroud.model.passes.PassContext
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import io.github.hht0rro.javashroud.model.schema.ModuleDefinition
import io.github.hht0rro.javashroud.model.transforms.TransformResult
import io.github.hht0rro.javashroud.modules.ModuleTransform
import io.github.hht0rro.javashroud.modules.ObfuscationModule
import io.github.hht0rro.javashroud.passes.ExecutablePass
import io.github.hht0rro.javashroud.passes.PassDescriptor
import kotlin.test.Test
import kotlin.test.assertEquals
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

    private fun testModuleDefinition(id: String): ModuleDefinition = ModuleDefinition(
        id = id,
        name = id,
        description = id,
        tagIds = emptyList(),
        params = emptyList(),
        stability = "experimental",
    )
}
