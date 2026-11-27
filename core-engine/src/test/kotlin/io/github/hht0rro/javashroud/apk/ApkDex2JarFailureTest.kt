package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.model.config.ApkConfig
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions
import org.junit.jupiter.api.io.TempDir

class ApkDex2JarFailureTest {
    @Test
    fun rejectsAnErrorReportEvenWhenTheConverterReturnsZero(@TempDir directory: Path) {
        val runner = ApkDex2JarRunner(runner = { command, _ ->
            val output = Path.of(command[command.indexOf("--output") + 1])
            writeClassJar(output)
            val reportOption = command.indexOf("--exception-file")
            val report = if (reportOption < 0) output.resolveSibling("conversion-errors.zip")
                else Path.of(command[reportOption + 1])
            Files.writeString(report, "conversion failed")
            ApkProcessSupport.ProcessResult(0, "Detail Error Information in File $report", false)
        })

        val failure = assertFailsWith<IllegalStateException> {
            runner.convert(fakeToolchain(), ApkInputUnpacker.ApkDexInput("classes.dex", 1, byteArrayOf()), directory) {}
        }
        assertTrue(failure.message.orEmpty().contains("dex2jar"))
        assertTrue(failure.message.orEmpty().contains("conversion"))
    }

    @Test
    fun conversionUsesFreshPathsAndPreservesFilesFromAnEarlierAttempt(@TempDir directory: Path) {
        val earlierFiles = listOf("input-1.dex", "dex-1-classes.jar", "conversion-errors.zip")
            .associate { name -> Files.writeString(directory.resolve(name), "earlier $name") to "earlier $name" }
        val reportPaths = mutableListOf<Path>()
        val runner = ApkDex2JarRunner(runner = { command, _ ->
            assertTrue("--not-handle-exception" in command)
            assertTrue("--compute-frames" in command)
            val reportIndex = command.indexOf("--exception-file")
            assertTrue(reportIndex >= 0)
            val report = Path.of(command[reportIndex + 1])
            assertFalse(Files.exists(report))
            assertTrue(report.startsWith(directory.toAbsolutePath()))
            reportPaths.add(report)
            writeClassJar(Path.of(command[command.indexOf("--output") + 1]))
            ApkProcessSupport.ProcessResult(0, "clean conversion", false)
        })
        repeat(2) {
            val converted = runner.convert(fakeToolchain(), ApkInputUnpacker.ApkDexInput("classes.dex", 1, byteArrayOf()), directory) {}
            assertEquals(listOf("fixture/Clean.class"), converted.classNames)
        }
        assertEquals(2, reportPaths.distinct().size)
        for ((path, bytes) in earlierFiles) assertEquals(bytes, Files.readString(path))
    }

    @Test
    fun rejectsTheTopLevelCommandsCaughtExceptionDespiteExitZero(@TempDir directory: Path) {
        val runner = ApkDex2JarRunner(runner = { command, _ ->
            writeClassJar(Path.of(command[command.indexOf("--output") + 1]))
            ApkProcessSupport.ProcessResult(0,
                "java.lang.RuntimeException: conversion failed\n\tat com.googlecode.dex2jar.tools.BaseCmd.doMain(BaseCmd.java:297)", false)
        })
        val failure = assertFailsWith<IllegalStateException> {
            runner.convert(fakeToolchain(), ApkInputUnpacker.ApkDexInput("classes.dex", 1, byteArrayOf()), directory) {}
        }
        assertTrue(failure.message.orEmpty().contains("conversion failed"))
    }

    @Test
    fun realPartialConversionFailsBeforePublishingAnyApkOrSidecar(@TempDir directory: Path) {
        Assumptions.assumeTrue(System.getenv(ApkToolchainProvisioner.REAL_TOOLS_SKIP_ENV) != "skip")
        val toolchain = ApkToolchainProvisioner.ensure("", "")
        val source = Files.writeString(directory.resolve("Broken.smali"), """
            .class public Lfixture/Broken;
            .super Ljava/lang/Object;

            .method public static make()Ljava/lang/Object;
                .registers 1
                new-instance v0, Ljava/lang/StringBuilder;
                const v1, 42
                invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(I)V
                return-object v0
            .end method
        """.trimIndent())
        val dex = directory.resolve("broken.dex")
        val command = listOf(toolchain.javaExecutable.toString(), "-Xmx256m", "-cp",
            ApkDex2JarRunner.wildcardClasspath(toolchain.dex2jarDirectory),
            "com.googlecode.d2j.smali.SmaliCmd", "--output", dex.toString(), source.toString())
        ApkProcessSupport.requireSuccess("assemble broken conversion fixture", command,
            ApkProcessSupport.runProcess(command, 60_000))
        val dexBytes = Files.readAllBytes(dex)
        ApkValidation.validateDexHeader("classes.dex", dexBytes)

        for (existingOutput in listOf(false, true)) {
            val work = Files.createDirectory(directory.resolve("pipeline-$existingOutput"))
            val input = ApkTestFixtures.writeApk(work.resolve("input.apk"), ApkTestFixtures.syntheticApk(dexBytes = listOf(dexBytes)))
            val output = work.resolve("output.apk")
            val configFile = Files.writeString(work.resolve("config.toml"), "original config")
            val protectedFiles = listOf(input, configFile).associateWith { Files.readAllBytes(it) }.toMutableMap()
            if (existingOutput) {
                for (path in listOf(output) + apkSidecarPaths(output)) {
                    protectedFiles[path] = "old ${path.fileName}".toByteArray().also { Files.write(path, it) }
                }
            }
            val events = mutableListOf<EngineEvent>()
            val config = ObfuscationConfig(inputJarPath = input.toString(), outputJarPath = output.toString(),
                passes = emptyList(), ruleSet = RuleSet(emptyList()), artifactFormat = "apk", apk = ApkConfig(minApi = 26))
            val pipeline = ApkPipelineRunner(provision = { _, _ -> toolchain }, kernelRunner = { _, _, _ ->
                error("An incomplete conversion reached the kernel")
            })

            val failure = assertFailsWith<IllegalStateException> { pipeline.run(config, configFile) { events += it } }
            assertTrue(failure.message.orEmpty().contains("dex2jar"), failure.message)
            for ((path, bytes) in protectedFiles) assertContentEquals(bytes, Files.readAllBytes(path))
            if (!existingOutput) assertTrue((listOf(output) + apkSidecarPaths(output)).none { Files.exists(it) })
            assertTrue(events.none { it.type == "done" })
            Files.list(work).use { paths -> assertTrue(paths.noneMatch { it.fileName.toString().startsWith(".javashroud-apk-work-") }) }
        }
    }

    private fun fakeToolchain() = ApkToolchainProvisioner.ApkToolchain(Path.of("java"), Path.of("dex2jar"), Path.of("d8.jar"), "test", "test")

    private fun writeClassJar(output: Path) {
        JarOutputStream(Files.newOutputStream(output)).use { jar ->
            jar.putNextEntry(ZipEntry("fixture/Clean.class"))
            jar.write(ApkPipelineRunnerTestSupport.appClassBytes("fixture/Clean"))
            jar.closeEntry()
        }
    }
}
