package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.artifact.publishValidatedJar
import java.io.IOException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.util.concurrent.CancellationException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ApkPublicationTest {
    @Test
    fun jarAndApkPublicationsShareTheLockThroughRollback() {
        val dir = Files.createTempDirectory("publication-shared-lock-")
        try {
            val apk = Files.writeString(dir.resolve("app.apk"), "old apk")
            val jar = dir.resolve("app.jar")
            val report = Files.writeString(apkSidecarPaths(apk)[0], "old report")
            val work = Files.createDirectory(dir.resolve("work"))
            val stagedApk = Files.writeString(work.resolve("new.apk"), "new apk")
            val stagedReport = Files.writeString(work.resolve("new-report"), "new apk report")
            val failure = CancellationException("cancel after publication")

            assertSame(failure, assertFailsWith<CancellationException> {
                publishApkFiles(listOf(stagedReport to report, stagedApk to apk), work, apkPublicationLock(apk)) {
                    assertFailsWith<FileAlreadyExistsException> {
                        publishValidatedJar(jar) { stagedJar ->
                            Files.writeString(stagedJar, "new jar")
                            listOf(Files.writeString(stagedJar.resolveSibling(report.fileName), "new jar report"))
                        }
                    }
                    assertTrue(Files.isDirectory(apkPublicationLock(apk)))
                    throw failure
                }
            })

            assertEquals("old apk", Files.readString(apk))
            assertEquals("old report", Files.readString(report))
            assertTrue(Files.notExists(jar))
            assertTrue(Files.notExists(apkPublicationLock(apk)))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun afterPublishFailureRestoresReplacedFilesAndRemovesNewFiles() {
        val dir = Files.createTempDirectory("publication-callback-failure-")
        try {
            val apk = Files.writeString(dir.resolve("app.apk"), "old apk")
            val report = apkSidecarPaths(apk)[0]
            val work = Files.createDirectory(dir.resolve("work"))
            val stagedApk = Files.writeString(work.resolve("new.apk"), "new apk")
            val stagedReport = Files.writeString(work.resolve("new-report"), "new report")
            val failure = IOException("publication callback failed")

            assertSame(failure, assertFailsWith<IOException> {
                publishApkFiles(listOf(stagedReport to report, stagedApk to apk), work, apkPublicationLock(apk)) {
                    throw failure
                }
            })

            assertEquals("old apk", Files.readString(apk))
            assertTrue(Files.notExists(report))
            assertTrue(Files.notExists(apkPublicationLock(apk)))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test
    fun interruptionInsideAfterPublishRollsBackThePublication() {
        val dir = Files.createTempDirectory("publication-callback-interruption-")
        try {
            val apk = Files.writeString(dir.resolve("app.apk"), "old apk")
            val work = Files.createDirectory(dir.resolve("work"))
            val stagedApk = Files.writeString(work.resolve("new.apk"), "new apk")

            try {
                assertFailsWith<CancellationException> {
                    publishApkFiles(listOf(stagedApk to apk), work, apkPublicationLock(apk)) {
                        Thread.currentThread().interrupt()
                    }
                }
            } finally {
                Thread.interrupted()
            }

            assertEquals("old apk", Files.readString(apk))
            assertTrue(Files.notExists(apkPublicationLock(apk)))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }
}
