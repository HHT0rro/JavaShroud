package io.github.hht0rro.javashroud.apk

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Locale
import java.util.concurrent.TimeUnit
import java.util.jar.JarInputStream
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
        val process = ProcessBuilder(command)
            .apply {
                redirectErrorStream(true)
                environment().putAll(environment)
            }
            .start()
        val output = StringBuilder()
        val readerThread = Thread {
            process.inputStream.bufferedReader(StandardCharsets.UTF_8).useLines { lines ->
                synchronized(output) { lines.forEach { output.appendLine(it) } }
            }
        }
        readerThread.isDaemon = true
        readerThread.start()
        val finished = process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)
        if (!finished) {
            process.destroyForcibly()
            process.waitFor(10, TimeUnit.SECONDS)
        }
        readerThread.join(5_000)
        val outputText = synchronized(output) { output.toString() }
        return ProcessResult(
            exitCode = runCatching { process.exitValue() }.getOrElse { -1 },
            output = outputText,
            timedOut = !finished,
        )
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

    fun preview(output: String): String =
        if (output.length <= OUTPUT_PREVIEW_LIMIT) output.trim() else output.take(OUTPUT_PREVIEW_LIMIT) + "…"
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
        val dexFile = workDirectory.resolve("input-${dex.index}.dex")
        Files.write(dexFile, dex.bytes)
        val outputJar = workDirectory.resolve("dex-${dex.index}-classes.jar")
        Files.deleteIfExists(outputJar)
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
            "--output",
            outputJar.toAbsolutePath().toString(),
            dexFile.toAbsolutePath().toString(),
        )
        log("dex2jar argv: ${command.joinToString(" ")}")
        val result = runner(command, timeoutMillis)
        log("dex2jar exit=${result.exitCode} timedOut=${result.timedOut} output:\n${ApkProcessSupport.preview(result.output)}")
        ApkProcessSupport.requireSuccess("dex2jar(classes-${dex.index}.dex)", command, result)
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
}
