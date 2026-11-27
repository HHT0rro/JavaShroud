package io.github.hht0rro.javashroud.apk

import io.github.hht0rro.javashroud.testfixtures.main as runHangingProcessFixture
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE
import java.nio.file.StandardOpenOption.WRITE
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.io.TempDir

@Timeout(value = 30, unit = TimeUnit.SECONDS)
class ApkProcessSupportTest {
    @Test
    fun timeoutTerminatesDescendantsAndReturnsOutputDespiteInheritedStdout(@TempDir directory: Path) {
        val result = AtomicReference<ApkProcessSupport.ProcessResult>()
        val failure = AtomicReference<Throwable>()
        val caller = thread(isDaemon = true, name = "apk-timeout-test") {
            try {
                result.set(ApkProcessSupport.runProcess(fixtureCommand("tree", directory), 5_000))
            } catch (error: Throwable) {
                failure.set(error)
            }
        }
        try {
            awaitReady(directory)
            val pids = fixturePids(directory)
            assertEquals(3, pids.size, "The fixture must contain a parent, child, and grandchild")
            caller.join(12_000)
            assertFalse(caller.isAlive, "runProcess blocked on stdout inherited by a descendant")
            failure.get()?.let { throw it }
            val completed = checkNotNull(result.get()) { "runProcess did not return a result" }
            assertTrue(completed.timedOut, "A running fixture must time out")
            assertTrue(completed.output.contains("parent-ready"), "Output before timeout was lost")
            assertTrue(completed.output.contains("grandchild-ready"), "Inherited grandchild stdout was lost")
            assertTrue(completed.output.contains("child-stderr"), "Inherited stderr was lost")
            awaitDead(pids)
            assertOutputUnlocked(directory)
        } finally {
            cleanupFixture(directory, caller)
        }
    }

    @Test
    fun callerInterruptionPropagatesCancellationAfterTerminatingTheTree(@TempDir directory: Path) {
        val failure = AtomicReference<Throwable>()
        val interruptedOnReturn = AtomicBoolean()
        val returnedNormally = AtomicBoolean()
        val caller = thread(isDaemon = true, name = "apk-interruption-test") {
            try {
                ApkProcessSupport.runProcess(fixtureCommand("tree", directory), 20_000)
                returnedNormally.set(true)
            } catch (error: Throwable) {
                interruptedOnReturn.set(Thread.currentThread().isInterrupted)
                failure.set(error)
            }
        }
        try {
            awaitReady(directory)
            val pids = fixturePids(directory)
            assertEquals(3, pids.size)
            caller.interrupt()
            caller.join(8_000)
            assertFalse(caller.isAlive, "Interrupted tool cleanup did not return within its bound")
            assertFalse(returnedNormally.get(), "Caller interruption must propagate cancellation")
            assertIs<InterruptedException>(failure.get())
            assertTrue(interruptedOnReturn.get(), "Caller interrupt status was cleared by cleanup")
            awaitDead(pids)
            assertOutputUnlocked(directory)
        } finally {
            cleanupFixture(directory, caller)
        }
    }

    @Test
    fun exitedParentDoesNotWaitForDescendantsToCloseInheritedStdout(@TempDir directory: Path) {
        val result = AtomicReference<ApkProcessSupport.ProcessResult>()
        val failure = AtomicReference<Throwable>()
        val caller = thread(isDaemon = true, name = "apk-inherited-stdout-test") {
            try {
                result.set(ApkProcessSupport.runProcess(fixtureCommand("orphan", directory), 20_000))
            } catch (error: Throwable) {
                failure.set(error)
            }
        }
        try {
            awaitReady(directory)
            val pids = fixturePids(directory)
            caller.join(8_000)
            assertFalse(caller.isAlive, "A descendant kept the exited parent's stdout drain blocked")
            failure.get()?.let { throw it }
            val completed = checkNotNull(result.get())
            assertFalse(completed.timedOut, "The parent exited normally")
            assertEquals(0, completed.exitCode)
            assertTrue(completed.output.contains("parent-ready"))
            assertTrue(completed.output.contains("grandchild-ready"))
            awaitDead(pids)
            assertOutputUnlocked(directory)
        } finally {
            cleanupFixture(directory, caller)
        }
    }

    @Test
    fun successfulAndNonzeroExitsPreserveUtf8StderrAndPartialLines(@TempDir directory: Path) {
        for (exitCode in listOf(0, 7)) {
            val result = ApkProcessSupport.runProcess(
                fixtureCommand("output", directory) + exitCode.toString(), 10_000,
                mapOf("JAVASHROUD_APK_PROCESS_FIXTURE" to "environment-42"),
            )
            assertFalse(result.timedOut)
            assertEquals(exitCode, result.exitCode)
            val expected = "stdout=42\nstderr=42\nenvironment-42\n" + "line=42\n".repeat(20_000) + "résultat=42"
            assertEquals(expected.length, result.output.length, "Output was lost or its line endings changed")
            assertEquals(expected, result.output, "Merged output must preserve the final unterminated UTF-8 line")
        }
    }

    private fun awaitReady(directory: Path) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (!Files.exists(directory.resolve("ready")) && System.nanoTime() < deadline) Thread.sleep(20)
        assertTrue(Files.exists(directory.resolve("ready")), "Java process-tree fixture failed to become ready")
    }

    private fun fixturePids(directory: Path): List<Long> = listOf("parent.pid", "child.pid", "grandchild.pid")
        .filter { Files.exists(directory.resolve(it)) }
        .map { Files.readString(directory.resolve(it)).trim().toLong() }

    private fun awaitDead(pids: List<Long>) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
        while (pids.any(::isAlive) && System.nanoTime() < deadline) Thread.sleep(20)
        assertTrue(pids.none(::isAlive), "Fixture processes survived cleanup: ${pids.filter(::isAlive)}")
    }

    private fun isAlive(pid: Long): Boolean = ProcessHandle.of(pid).map { it.isAlive }.orElse(false)

    private fun assertOutputUnlocked(directory: Path) {
        FileChannel.open(directory.resolve("locked-output.bin"), WRITE).use { channel ->
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3)
            while (System.nanoTime() < deadline) {
                val lock = channel.tryLock()
                if (lock != null) {
                    lock.release()
                    return
                }
                Thread.sleep(20)
            }
            assertNotNull(channel.tryLock(), "Descendant kept its output file locked after bounded cleanup").use { }
        }
    }

    private fun cleanupFixture(directory: Path, caller: Thread) {
        // Keep a deliberately failing regression from leaving its own fixture JVMs behind.
        fixturePids(directory).reversed().forEach { pid -> ProcessHandle.of(pid).ifPresent { it.destroyForcibly() } }
        caller.interrupt()
        caller.join(3_000)
        awaitDead(fixturePids(directory))
    }

    private fun fixtureCommand(mode: String, directory: Path): List<String> =
        ApkProcessSupportFixture.javaCommand(ApkProcessSupportFixture::class.java.name) + listOf(mode, directory.toString())
}

/** Owned bounded subprocess fixture. Descendants inherit the tool's stdout and stderr pipes. */
object ApkProcessSupportFixture {
    @JvmStatic
    fun main(arguments: Array<String>) {
        val directory = Path.of(arguments[1])
        when (arguments[0]) {
            "tree", "orphan" -> {
                Files.writeString(directory.resolve("parent.pid"), ProcessHandle.current().pid().toString())
                ProcessBuilder(javaCommand(javaClass.name) + listOf("child", directory.toString())).inheritIO().start()
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (!Files.exists(directory.resolve("grandchild-ready")) && System.nanoTime() < deadline) Thread.sleep(20)
                check(Files.exists(directory.resolve("grandchild-ready"))) { "Grandchild fixture failed to start" }
                println("parent-ready")
                System.out.flush()
                Files.writeString(directory.resolve("ready"), "ready")
                // Give the owner time to observe descendants even when this parent exits normally.
                Thread.sleep(if (arguments[0] == "orphan") 500 else 45_000)
            }
            "child" -> {
                Files.writeString(directory.resolve("child.pid"), ProcessHandle.current().pid().toString())
                FileChannel.open(directory.resolve("locked-output.bin"), CREATE, WRITE).use { output ->
                    output.lock().use {
                        val grandchild = ProcessBuilder(javaCommand(javaClass.name) +
                            listOf("grandchild", directory.toString())).inheritIO().start()
                        Files.writeString(directory.resolve("grandchild.pid"), grandchild.pid().toString())
                        System.err.println("child-stderr")
                        System.err.flush()
                        Thread.sleep(45_000)
                    }
                }
            }
            "grandchild" -> {
                println("grandchild-ready")
                System.out.flush()
                Files.writeString(directory.resolve("grandchild-ready"), "ready")
                runHangingProcessFixture()
            }
            "output" -> {
                System.out.write("stdout=42\n".toByteArray(Charsets.UTF_8))
                System.out.flush()
                System.err.write("stderr=42\n".toByteArray(Charsets.UTF_8))
                System.err.flush()
                val text = System.getenv("JAVASHROUD_APK_PROCESS_FIXTURE") + "\n" +
                    "line=42\n".repeat(20_000) + "résultat=42"
                System.out.write(text.toByteArray(Charsets.UTF_8))
                System.out.flush()
                kotlin.system.exitProcess(arguments[2].toInt())
            }
            else -> error("Unknown fixture mode: ${arguments[0]}")
        }
    }

    internal fun javaCommand(mainClass: String): List<String> {
        val executable = if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) "java.exe" else "java"
        val classpath = listOf(javaClass, kotlin.Unit::class.java).map {
            Path.of(it.protectionDomain.codeSource.location.toURI()).toString()
        }.distinct().joinToString(java.io.File.pathSeparator)
        return listOf(Path.of(System.getProperty("java.home"), "bin", executable).toString(), "-cp", classpath, mainClass)
    }
}
