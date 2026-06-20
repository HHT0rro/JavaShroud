package io.github.hht0rro.javashroud

import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

data class JavaProcessResult(
    val exitCode: Int,
    val output: String,
    val timedOut: Boolean,
)

internal fun runJavaProcessWithTimeout(
    processBuilder: ProcessBuilder,
    timeoutSeconds: Long = 30,
): JavaProcessResult {
    val process = processBuilder.redirectErrorStream(true).start()
    val output = ByteArrayOutputStream()
    val reader = thread(start = true, isDaemon = true, name = "javashroud-test-process-output") {
        process.inputStream.use { input -> input.copyTo(output) }
    }

    val exited = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
    if (!exited) {
        process.destroyForcibly()
        process.waitFor(5, TimeUnit.SECONDS)
    }
    reader.join(5_000)

    return JavaProcessResult(
        exitCode = if (exited) process.exitValue() else -1,
        output = output.toString(Charsets.UTF_8),
        timedOut = !exited,
    )
}
