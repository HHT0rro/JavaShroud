package io.github.hht0rro.javashroud.apk

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.channels.FileChannel
import java.nio.channels.OverlappingFileLockException
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.time.Instant

/**
 * Verbose APK-pipeline log. Everything the child tools print, every
 * toolchain decision, and every digest lands here; stdout stays
 * protocol-events-only. Log write failures degrade to a warn callback —
 * they never fail the run. Signing passwords are never logged.
 */
open class ApkLogSupport private constructor(
    private val sink: (String) -> Unit,
    private val warnings: (String) -> Unit,
) : AutoCloseable {

    fun info(message: String) = sink(format("INFO", message))

    fun warn(message: String) {
        warnings(message)
        sink(format("WARN", message))
    }

    /** Terminal failure record: single-line message plus the full stack trace. */
    fun failure(error: Throwable) {
        sink(format("ERROR", "run failed: " + (error.message ?: error::class.qualifiedName ?: "unknown-error")))
        val trace = java.io.StringWriter().also { error.printStackTrace(java.io.PrintWriter(it)) }.toString()
        trace.lineSequence().filter { it.isNotBlank() }.forEach { line -> sink(format("ERROR", line.trim())) }
    }

    private fun format(level: String, message: String): String =
        Instant.now().toString() + " [" + level + "] apk: " + message.replace('\n', ' ').replace('\r', ' ')

    override fun close() {}

    companion object {
        fun open(logFilePath: String?, warn: (String) -> Unit): ApkLogSupport {
            if (logFilePath.isNullOrBlank()) {
                return ApkLogSupport(sink = {}, warnings = warn)
            }
            return try {
                val path = Path.of(logFilePath).toAbsolutePath().normalize()
                existingRegularApkFile(path)
                path.parent?.let { Files.createDirectories(it) }
                val channel = FileChannel.open(
                    path,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND,
                    NOFOLLOW_LINKS,
                )
                val lock = try {
                    channel.tryLock() ?: throw IOException("log file is already locked")
                } catch (error: Throwable) {
                    runCatching { channel.close() }
                    throw error
                }
                object : ApkLogSupport(
                    sink = { line ->
                        try {
                            val bytes = ByteBuffer.wrap((line + "\n").toByteArray(StandardCharsets.UTF_8))
                            while (bytes.hasRemaining()) channel.write(bytes)
                        } catch (_: IOException) {
                            // Deliberately swallowed: logging must never fail the pipeline.
                        }
                    },
                    warnings = warn,
                ) {
                    override fun close() {
                        runCatching { lock.release() }
                        runCatching { channel.close() }
                    }
                }
            } catch (error: Exception) {
                if (error !is IOException && error !is IllegalArgumentException &&
                    error !is OverlappingFileLockException && error !is SecurityException) throw error
                warn("APK log file is not writable (${error.message}); detailed logging disabled: $logFilePath")
                ApkLogSupport(sink = {}, warnings = warn)
            }
        }

        /**
         * Appends the terminal failure record to the requested log file when a
         * run dies before the pipeline's own log is open (config validation,
         * toolchain probing). Best effort by contract: directory creation and
         * every IO failure are swallowed so logging can never mask the
         * original error or alter the exit code. A null/blank path is a no-op.
         */
        fun appendFailure(logFilePath: String?, error: Throwable) {
            if (logFilePath.isNullOrBlank()) return
            try {
                ApkLogSupport.open(logFilePath) { }.use { log -> log.failure(error) }
            } catch (_: Exception) {
                // Deliberately swallowed: failure logging must never fail.
            }
        }
    }
}
