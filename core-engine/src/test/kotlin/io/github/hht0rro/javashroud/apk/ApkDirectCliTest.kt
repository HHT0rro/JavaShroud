package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.adapters.protocol.buildRunRequest
import io.github.hht0rro.javashroud.adapters.protocol.parseCommand
import io.github.hht0rro.javashroud.adapters.protocol.parseRunFlags
import io.github.hht0rro.javashroud.model.config.ARTIFACT_FORMAT_APK
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Config-less direct CLI (--input/--output): flag parsing, default-pipeline
 * synthesis with the visible MINIMAL profile default, and fail-closed
 * behavior on missing inputs.
 */
class ApkDirectCliTest {

    @Test
    fun directFlagsParseInBothShapes() {
        val noLog = parseRunFlags(arrayOf("--input", "C:/in/app.apk", "--output", "C:/out/app-s.apk"))
        assertEquals(Path.of("C:/in/app.apk").toAbsolutePath().normalize(), noLog.directInput)
        assertEquals(Path.of("C:/out/app-s.apk").toAbsolutePath().normalize(), noLog.directOutput)
        assertEquals(null, noLog.logFilePath)

        val withLog = parseRunFlags(
            arrayOf("--input", "C:/in/app.apk", "--output", "C:/out/app-s.apk", "--log-file", "C:/out/run.log"),
        )
        assertEquals(Path.of("C:/out/run.log").toAbsolutePath().normalize(), withLog.logFilePath)
    }

    @Test
    fun parseCommandAcceptsDirectShapesAndRejectsMalformed() {
        assertEquals(
            io.github.hht0rro.javashroud.adapters.protocol.EngineCommand.Run,
            parseCommand(arrayOf("--input", "a.apk", "--output", "b.apk")),
        )
        assertEquals(
            io.github.hht0rro.javashroud.adapters.protocol.EngineCommand.Run,
            parseCommand(arrayOf("--input", "a.apk", "--output", "b.apk", "--log-file", "c.log")),
        )
        // Wrong ordering / unknown extra tokens must not match any spec.
        assertFailsWith<IllegalArgumentException> {
            parseCommand(arrayOf("--input", "a.apk", "--bogus", "b.apk"))
        }
        assertFailsWith<IllegalArgumentException> {
            parseCommand(arrayOf("--input", "a.apk", "--output", "b.apk", "--log-file"))
        }
    }

    @Test
    fun directRunSynthesizesApkDefaults() {
        val input = Files.createTempFile("direct-", ".apk")
        Files.write(input, ApkTestFixtures.syntheticApk())
        val output = input.resolveSibling("direct-out.apk")
        val request = buildRunRequest(
            arrayOf("--input", input.toAbsolutePath().toString(), "--output", output.toAbsolutePath().toString()),
        )
        assertEquals(ARTIFACT_FORMAT_APK, request.config.artifactFormat)
        assertEquals(HardenedProtectionProfile.MINIMAL, request.config.protectionProfile, "visible default applies in direct mode")
        assertTrue(request.config.passes.isNotEmpty(), "default pipeline must be filled")
        assertTrue(request.config.allowOptInPasses)
        assertTrue(request.config.passes.none { it.id in ApkPassPolicy.forbiddenPassIds })
    }

    @Test
    fun directRunFailsClosedOnMissingInput() {
        val thrown = runCatching {
            buildRunRequest(arrayOf("--input", "C:/definitely/missing.apk", "--output", "C:/tmp/out.apk"))
        }
        assertTrue(thrown.exceptionOrNull() is IllegalArgumentException, "missing input must fail closed")
    }
}
