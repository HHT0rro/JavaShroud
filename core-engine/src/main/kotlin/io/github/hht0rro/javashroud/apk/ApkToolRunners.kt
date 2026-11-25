package io.github.hht0rro.javashroud.apk

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.jar.JarFile
import java.util.jar.JarInputStream
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry

/**
 * Spawned tool invocations for the APK pipeline. Both runners capture all
 * child output (nothing leaks to stdout), enforce a timeout with process-tree
 * cleanup, and fail closed with truncated output on non-zero exits.
 *
 * Both children are separate JVMs. Without an explicit -Xmx each defaults to a
 * max heap of 1/4 of physical RAM; when several engine processes run in
 * parallel (each spawning one child at a time), several such reservations
 * exhaust the Windows commit limit (os::commit_memory ... errno=1455 /
 * ERROR_COMMITMENT_LIMIT) and the children die with "insufficient memory for
 * the JRE". Both runners therefore pin a modest fixed max heap (operator
 * overridable) and fail fast on OOM instead of hanging.
 */
object ApkProcessSupport {

    const val DEFAULT_TIMEOUT_MILLIS: Long = 10L * 60L * 1000L
    private const val OUTPUT_PREVIEW_LIMIT = 8_000

    /** Fixed, modest max heap for the spawned dex2jar JVM (overridable). */
    const val DEX2JAR_XMX_ENV = "JAVASHROUD_APK_DEX2JAR_XMX"
    const val DEX2JAR_XMX_DEFAULT = "3g"

    /** Fixed, modest max heap for the spawned r8/D8 JVM (overridable). */
    const val D8_XMX_ENV = "JAVASHROUD_APK_D8_XMX"
    const val D8_XMX_DEFAULT = "4g"

    fun childJvmMemoryFlags(xmxEnvVariable: String, defaultXmx: String): List<String> {
        val xmx = System.getenv(xmxEnvVariable)?.trim()?.takeIf { it.isNotEmpty() && it.matches(Regex("[0-9]+[kKmMgG]?")) }
            ?: defaultXmx
        return listOf("-Xmx$xmx", "-XX:+ExitOnOutOfMemoryError")
    }

    class ProcessResult(val exitCode: Int, val output: String, val timedOut: Boolean)

    fun runProcess(command: List<String>, timeoutMillis: Long, environment: Map<String, String> = emptyMap()): ProcessResult {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8_192)
        val descendants = linkedMapOf<Long, ProcessHandle>()
        val process = ProcessBuilder(command)
            .apply {
                redirectErrorStream(true)
                environment().putAll(environment)
            }
            .start()
        val started = System.nanoTime()
        val timeoutNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis.coerceAtLeast(0))
        var lastSnapshot = started - TimeUnit.MILLISECONDS.toNanos(50)
        var timedOut = false
        try {
            while (true) {
                val now = System.nanoTime()
                if (now - lastSnapshot >= TimeUnit.MILLISECONDS.toNanos(50)) {
                    rememberProcessDescendants(process, descendants)
                    lastSnapshot = now
                }
                // Read only bytes already available. A descendant can inherit stdout after the
                // parent exits, so waiting for EOF would exceed the tool's timeout.
                val available = process.inputStream.available()
                if (available > 0) {
                    val count = process.inputStream.read(buffer, 0, minOf(available, buffer.size))
                    if (count > 0) output.write(buffer, 0, count)
                }
                if (Thread.currentThread().isInterrupted) throw InterruptedException("APK tool execution interrupted")
                if (!process.isAlive) break
                val remaining = timeoutNanos - (System.nanoTime() - started)
                if (remaining <= 0) {
                    timedOut = true
                    break
                }
                if (available == 0) process.waitFor(minOf(remaining, TimeUnit.MILLISECONDS.toNanos(20)), TimeUnit.NANOSECONDS)
            }
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw error
        } finally {
            try {
                terminateProcessTree(process, descendants)
                // With the recorded tree stopped, collect its remaining buffered diagnostics.
                // The deadline also bounds output from a descendant that escaped observation.
                val drainDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1)
                while (System.nanoTime() < drainDeadline) {
                    val available = process.inputStream.available()
                    if (available == 0) break
                    val count = process.inputStream.read(buffer, 0, minOf(available, buffer.size))
                    if (count <= 0) break
                    output.write(buffer, 0, count)
                }
            } finally {
                closeProcessStreams(process)
            }
        }
        if (Thread.currentThread().isInterrupted) throw InterruptedException("APK tool execution interrupted during cleanup")
        return ProcessResult(
            exitCode = if (process.isAlive) -1 else process.exitValue(),
            output = output.toString(StandardCharsets.UTF_8),
            timedOut = timedOut,
        )
    }

    private fun rememberProcessDescendants(process: Process, descendants: MutableMap<Long, ProcessHandle>) {
        try {
            process.descendants().use { handles -> handles.forEach { descendants[it.pid()] = it } }
        } catch (error: RuntimeException) {
            // Windows process enumeration can lose a snapshot during process churn. Keep the
            // previously observed handles and retry on the next bounded sampling interval.
            if (error.message != "snapshot not available") throw error
        }
    }

    private fun terminateProcessTree(process: Process, descendants: MutableMap<Long, ProcessHandle>) {
        // Clear interruption only while performing bounded cleanup, then restore cancellation.
        var interrupted = Thread.interrupted()
        try {
            rememberProcessDescendants(process, descendants)
            if (process.isAlive && System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) {
                val killer = try {
                    ProcessBuilder("taskkill", "/PID", process.pid().toString(), "/T", "/F")
                        .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                        .redirectError(ProcessBuilder.Redirect.DISCARD)
                        .start()
                } catch (_: java.io.IOException) {
                    null // ProcessHandle cleanup below also works when taskkill is unavailable.
                }
                if (killer != null) {
                    try {
                        killer.waitFor(2, TimeUnit.SECONDS)
                    } catch (_: InterruptedException) {
                        interrupted = true
                    } finally {
                        if (killer.isAlive) killer.toHandle().destroyForcibly()
                        closeProcessStreams(killer)
                    }
                }
            }
            val handles = descendants.values.toList().asReversed() + process.toHandle()
            handles.forEach { if (it.isAlive) it.destroyForcibly() }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
            while (handles.any { it.isAlive } && System.nanoTime() < deadline) {
                try {
                    Thread.sleep(20)
                } catch (_: InterruptedException) {
                    interrupted = true
                }
            }
            check(handles.none { it.isAlive }) {
                "APK tool process tree survived cleanup: ${handles.filter { it.isAlive }.map { it.pid() }}"
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
    }

    private fun closeProcessStreams(process: Process) {
        for (stream in listOf(process.outputStream, process.inputStream, process.errorStream)) {
            try {
                stream.close()
            } catch (_: java.io.IOException) {
                // The process may already have closed its pipe during termination.
            }
        }
    }

    fun requireSuccess(label: String, command: List<String>, result: ProcessResult) {
        if (result.timedOut) {
            throw IllegalStateException(
                "$command[0] $label timed out after exceeded output: ${preview(result.output)}",
            )
        }
        if (result.exitCode != 0) {
            throw IllegalStateException(
                "$label failed with exit code ${result.exitCode}: ${preview(result.output)}",
            )
        }
    }

    fun preview(output: String): String {
        if (output.length <= OUTPUT_PREVIEW_LIMIT) return output.trim()
        val errors = output.lineSequence().filter { it.startsWith("Error") || it.startsWith("Caused by:") }
            .take(5).joinToString("\n") { it.take(400) }
        val window = (OUTPUT_PREVIEW_LIMIT - errors.length - 24) / 2
        return output.take(window).trimEnd() + "\n…\n" +
            (if (errors.isEmpty()) "" else "$errors\n…\n") + output.takeLast(window).trimStart()
    }
}

/** dex -> class jar conversion via the vendored Dex2jarCmd closure. */
open class ApkDex2JarRunner(
    private val timeoutMillis: Long = ApkProcessSupport.DEFAULT_TIMEOUT_MILLIS,
    private val runner: (List<String>, Long) -> ApkProcessSupport.ProcessResult = ApkProcessSupport::runProcess,
) {
    data class ConvertedDex(val dexIndex: Int, val jarPath: Path, val classNames: List<String>)

    open fun convert(
        toolchain: ApkToolchainProvisioner.ApkToolchain,
        dex: ApkInputUnpacker.ApkDexInput,
        workDirectory: Path,
        log: (String) -> Unit,
    ): ConvertedDex {
        // Each attempt owns its input, output and diagnostics. The CLI otherwise writes
        // error ZIPs into the caller's current directory, even when it exits with zero.
        val conversionDirectory = Files.createTempDirectory(workDirectory, "dex-${dex.index}-")
        val dexFile = conversionDirectory.resolve("input-${dex.index}.dex")
        Files.write(dexFile, dex.bytes)
        val outputJar = conversionDirectory.resolve("classes.jar")
        val exceptionFile = conversionDirectory.resolve("conversion-errors.zip")
        val command = listOf(
            toolchain.javaExecutable.toAbsolutePath().toString(),
        ) + ApkProcessSupport.childJvmMemoryFlags(
            ApkProcessSupport.DEX2JAR_XMX_ENV,
            ApkProcessSupport.DEX2JAR_XMX_DEFAULT,
        ) + listOf(
            "-cp",
            wildcardClasspath(toolchain.dex2jarDirectory),
            ApkToolchainProvisioner.DEX2JAR_MAIN_CLASS,
            // DEX identities must match the source allocation index and Android references.
            "--dont-sanitize-names",
            // The default handler replaces failed methods with throwing stubs.
            "--not-handle-exception",
            "--exception-file",
            exceptionFile.toAbsolutePath().toString(),
            "--output",
            outputJar.toAbsolutePath().toString(),
            dexFile.toAbsolutePath().toString(),
        )
        log("dex2jar argv: ${command.joinToString(" ")}")
        val result = runner(command, timeoutMillis)
        log("dex2jar exit=${result.exitCode} timedOut=${result.timedOut} output:\n${ApkProcessSupport.preview(result.output)}")
        ApkProcessSupport.requireSuccess("dex2jar(classes-${dex.index}.dex)", command, result)
        // The pinned BaseCmd catches top-level exceptions and prints their stacks
        // without setting a failing exit status, including with exception handling off.
        val conversionFailed = Files.exists(exceptionFile, LinkOption.NOFOLLOW_LINKS) ||
            result.output.lineSequence().any { line ->
                val diagnostic = line.trimStart()
                diagnostic.startsWith("at ") || diagnostic.startsWith("Caused by:") ||
                    diagnostic.startsWith("Detail Error Information in File")
            }
        check(!conversionFailed) {
            "dex2jar(${dex.entryName}) conversion failed; refusing incomplete classes: ${ApkProcessSupport.preview(result.output)}"
        }
        require(Files.isRegularFile(outputJar)) { "dex2jar produced no output jar for ${dex.entryName}" }
        return ConvertedDex(
            dexIndex = dex.index,
            jarPath = outputJar,
            classNames = listClassEntries(outputJar),
        )
    }

    companion object {
        /** Windows wildcard classpath uses the bare directory; POSIX appends a star entry. */
        fun wildcardClasspath(directory: Path): String {
            val isWindows = System.getProperty("os.name").lowercase(Locale.ROOT).startsWith("windows")
            return if (isWindows) directory.toAbsolutePath().toString() + "\\*"
            else directory.toAbsolutePath().toString() + "/*"
        }

        fun listClassEntries(jar: Path): List<String> {
            val names = mutableListOf<String>()
            JarInputStream(Files.newInputStream(jar).buffered()).use { jarStream ->
                while (true) {
                    val entry: ZipEntry = jarStream.nextEntry ?: break
                    if (!entry.isDirectory && entry.name.endsWith(".class")) names += entry.name
                }
            }
            return names
        }
    }
}

/** class jar -> dex compilation via the pinned r8/D8 entry point. */
open class ApkD8Runner(
    private val timeoutMillis: Long = ApkProcessSupport.DEFAULT_TIMEOUT_MILLIS,
    private val runner: (List<String>, Long) -> ApkProcessSupport.ProcessResult = ApkProcessSupport::runProcess,
) {
    open fun compile(
        toolchain: ApkToolchainProvisioner.ApkToolchain,
        inputJar: Path,
        outputDirectory: Path,
        minApi: Int,
        androidJarPath: String,
        log: (String) -> Unit,
    ): List<Pair<String, ByteArray>> {
        Files.createDirectories(outputDirectory)
        val split = splitDesugaredLibraryInputs(inputJar, outputDirectory)
        if (split == null) return compileGroup(toolchain, inputJar, outputDirectory, minApi, androidJarPath, log)

        val (app, library) = split
        // D8 prohibits merging DEX containing j$. with application classes. The two program
        // groups see each other for resolution, but the archive keeps their DEX files separate.
        log("d8: compiling application and packaged desugared library as separate DEX groups")
        val appDex = compileGroup(toolchain, app, outputDirectory.resolve("application"), minApi, androidJarPath, log, library)
        val libraryDex = compileGroup(toolchain, library, outputDirectory.resolve("desugared-library"), minApi, androidJarPath, log, app)
        return (appDex + libraryDex).mapIndexed { index, (_, bytes) ->
            (if (index == 0) "classes.dex" else "classes${index + 1}.dex") to bytes
        }.also(ApkValidation::validateDisjointDexClasses)
    }

    private fun compileGroup(
        toolchain: ApkToolchainProvisioner.ApkToolchain,
        inputJar: Path,
        outputDirectory: Path,
        minApi: Int,
        androidJarPath: String,
        log: (String) -> Unit,
        counterpart: Path? = null,
    ): List<Pair<String, ByteArray>> {
        Files.createDirectories(outputDirectory)
        val command = mutableListOf(
            toolchain.javaExecutable.toAbsolutePath().toString(),
        )
        command += ApkProcessSupport.childJvmMemoryFlags(
            ApkProcessSupport.D8_XMX_ENV,
            ApkProcessSupport.D8_XMX_DEFAULT,
        )
        command += listOf(
            "-cp",
            toolchain.d8Jar.toAbsolutePath().toString(),
            ApkToolchainProvisioner.D8_MAIN_CLASS,
            "--release",
            "--min-api",
            minApi.toString(),
            "--output",
            outputDirectory.toAbsolutePath().toString(),
        )
        if (androidJarPath.isNotBlank()) {
            command += listOf("--lib", Path.of(androidJarPath).toAbsolutePath().toString())
        }
        if (counterpart != null) command += listOf("--classpath", counterpart.toAbsolutePath().toString())
        command += inputJar.toAbsolutePath().toString()
        log("d8 argv: ${command.joinToString(" ")}")
        val result = runner(command, timeoutMillis)
        log("d8 exit=${result.exitCode} timedOut=${result.timedOut} output:\n${ApkProcessSupport.preview(result.output)}")
        ApkProcessSupport.requireSuccess("d8(compile)", command, result)
        val dexes = outputDirectory.toFile().listFiles()
            ?.filter { it.isFile && Regex("^classes(\\d*)\\.dex$").matches(it.name) }
            ?.sortedBy { ApkOutputPacker.dexIndex(it.name) }
            .orEmpty()
        require(dexes.isNotEmpty()) { "D8 produced no classes.dex in ${outputDirectory}" }
        return dexes.map { file -> file.name to Files.readAllBytes(file.toPath()) }
    }

    private fun splitDesugaredLibraryInputs(inputJar: Path, outputDirectory: Path): Pair<Path, Path>? =
        JarFile(inputJar.toFile()).use { jar ->
            val classes = jar.entries().asSequence().filter { !it.isDirectory && it.name.endsWith(".class") }.toList()
            if (classes.none { it.name.startsWith("j\$/") }) return null
            val (library, app) = classes.partition { it.name.startsWith("j\$/") || it.name.startsWith("java/") }
            if (app.isEmpty()) return null
            val work = Files.createTempDirectory(outputDirectory, "d8-inputs-")
            fun writeGroup(name: String, group: List<java.util.jar.JarEntry>): Path {
                val output = work.resolve(name)
                JarOutputStream(Files.newOutputStream(output)).use { target ->
                    for (entry in group) {
                        target.putNextEntry(ZipEntry(entry.name))
                        jar.getInputStream(entry).use { it.copyTo(target) }
                        target.closeEntry()
                    }
                }
                return output
            }
            writeGroup("application.jar", app) to writeGroup("desugared-library.jar", library)
        }
}
