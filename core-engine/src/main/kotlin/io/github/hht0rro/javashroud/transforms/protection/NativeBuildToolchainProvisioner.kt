package io.github.hht0rro.javashroud.transforms.protection

import java.io.InputStream
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.Comparator
import java.util.Locale
import java.util.zip.ZipInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream

/**
 * Downloads the locked Zig 0.13.0 + cargo-zigbuild 0.18.0 pair used by AKEN-R1.
 * Clean user machines do not need a preinstalled compiler; the first native
 * recompile fetches and caches the archives under ~/.javashroud/toolchains.
 */
object NativeBuildToolchainProvisioner {
    const val ZIG_VERSION: String = "0.13.0"
    const val CARGO_ZIGBUILD_VERSION: String = "0.23.2"

    private const val DEFAULT_MAX_ARCHIVE_BYTES = 512L * 1024L * 1024L
    private const val DEFAULT_MAX_EXTRACTED_BYTES = 2L * 1024L * 1024L * 1024L
    private const val DEFAULT_MAX_ARCHIVE_ENTRIES = 65_536
    private const val ARCHIVE_READ_BUFFER = 64 * 1024

    data class BuildTools(
        val zigPath: Path,
        val cargoZigbuildPath: Path,
        val pathEntries: List<Path>,
        val messages: List<RustToolchainProvisioner.ResolutionMessage>,
    )

    data class ArchiveSpec(
        val url: String,
        val size: Long,
        val sha256: String,
        val root: String,
        val format: Format,
        val executableRelative: String,
    ) {
        enum class Format { ZIP, TAR_XZ, TAR_GZ }

        val normalizedSha256: String get() = sha256.lowercase(Locale.ROOT)
    }

    fun interface ArchiveFetcher {
        fun fetch(spec: ArchiveSpec): Pair<InputStream, Long>
    }

    fun resolve(
        osName: String = System.getProperty("os.name"),
        osArch: String = System.getProperty("os.arch"),
        userHome: Path = Paths.get(System.getProperty("user.home")),
        pathEnv: String? = System.getenv("PATH"),
        fetcher: ArchiveFetcher = ArchiveFetcher(::fetchArchive),
        versionRunner: RustToolchainProvisioner.VersionRunner = RustToolchainProvisioner.VersionRunner(::runVersion),
        specOverrides: Map<String, ArchiveSpec> = emptyMap(),
    ): BuildTools {
        val host = RustToolchainProvisioner.hostPlatform(osName, osArch)
        val messages = mutableListOf<RustToolchainProvisioner.ResolutionMessage>()
        val zig = ensureTool(
            host = host,
            spec = specOverrides["zig"] ?: zigArchive(host),
            command = "zig",
            expectedVersion = ZIG_VERSION,
            cacheName = "zig-$ZIG_VERSION-${host.runtimeId}",
            userHome = userHome,
            pathEnv = pathEnv,
            fetcher = fetcher,
            versionRunner = versionRunner,
            messages = messages,
        )
        val cargoZigbuild = ensureTool(
            host = host,
            spec = specOverrides["cargo-zigbuild"] ?: cargoZigbuildArchive(host),
            command = "cargo-zigbuild",
            expectedVersion = CARGO_ZIGBUILD_VERSION,
            cacheName = "cargo-zigbuild-$CARGO_ZIGBUILD_VERSION-${host.runtimeId}",
            userHome = userHome,
            pathEnv = pathEnv,
            fetcher = fetcher,
            versionRunner = versionRunner,
            messages = messages,
        )
        return BuildTools(
            zigPath = zig,
            cargoZigbuildPath = cargoZigbuild,
            pathEntries = listOf(zig.parent, cargoZigbuild.parent),
            messages = messages,
        )
    }

    internal fun zigArchive(host: RustToolchainProvisioner.HostPlatform): ArchiveSpec = when (host) {
        RustToolchainProvisioner.HostPlatform.WINDOWS_X64 -> ArchiveSpec(
            url = "https://ziglang.org/download/0.13.0/zig-windows-x86_64-0.13.0.zip",
            size = 79_163_968L,
            sha256 = "d859994725ef9402381e557c60bb57497215682e355204d754ee3df75ee3c158",
            root = "zig-windows-x86_64-0.13.0",
            format = ArchiveSpec.Format.ZIP,
            executableRelative = "zig.exe",
        )
        RustToolchainProvisioner.HostPlatform.LINUX_X64 -> ArchiveSpec(
            url = "https://ziglang.org/download/0.13.0/zig-linux-x86_64-0.13.0.tar.xz",
            size = 47_082_308L,
            sha256 = "d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea",
            root = "zig-linux-x86_64-0.13.0",
            format = ArchiveSpec.Format.TAR_XZ,
            executableRelative = "zig",
        )
    }

    internal fun cargoZigbuildArchive(host: RustToolchainProvisioner.HostPlatform): ArchiveSpec = when (host) {
        RustToolchainProvisioner.HostPlatform.WINDOWS_X64 -> ArchiveSpec(
            url = "https://github.com/rust-cross/cargo-zigbuild/releases/download/v0.23.2/cargo-zigbuild-x86_64-pc-windows-msvc.zip",
            size = 1_552_212L,
            sha256 = "fd78b74953eff30b67ad91947aea8b4c449fb1761b6658dd672706e894e1cb5c",
            root = "",
            format = ArchiveSpec.Format.ZIP,
            executableRelative = "cargo-zigbuild.exe",
        )
        RustToolchainProvisioner.HostPlatform.LINUX_X64 -> ArchiveSpec(
            url = "https://github.com/rust-cross/cargo-zigbuild/releases/download/v0.23.2/cargo-zigbuild-x86_64-unknown-linux-musl.tar.xz",
            size = 1_255_160L,
            sha256 = "505f028a380f16dab50213307d5deb809845633a8a8d4ca2a0df6dd70554c47d",
            root = "cargo-zigbuild-x86_64-unknown-linux-musl",
            format = ArchiveSpec.Format.TAR_XZ,
            executableRelative = "cargo-zigbuild",
        )
    }

    private fun ensureTool(
        host: RustToolchainProvisioner.HostPlatform,
        spec: ArchiveSpec,
        command: String,
        expectedVersion: String,
        cacheName: String,
        userHome: Path,
        pathEnv: String?,
        fetcher: ArchiveFetcher,
        versionRunner: RustToolchainProvisioner.VersionRunner,
        messages: MutableList<RustToolchainProvisioner.ResolutionMessage>,
    ): Path {
        findOnPath(command, host, pathEnv)?.let { existing ->
            if (versionMatches(existing, expectedVersion, versionRunner)) {
                messages += RustToolchainProvisioner.ResolutionMessage("info", "Using $command $expectedVersion from PATH")
                return existing
            }
        }
        val installRoot = userHome.toAbsolutePath().normalize()
            .resolve(".javashroud")
            .resolve("toolchains")
            .resolve(cacheName)
        val executable = installRoot.resolve(spec.executableRelative)
        if (Files.isRegularFile(executable) && versionMatches(executable, expectedVersion, versionRunner)) {
            messages += RustToolchainProvisioner.ResolutionMessage("info", "Using cached $command $expectedVersion")
            return executable
        }
        messages += RustToolchainProvisioner.ResolutionMessage("info", "Downloading locked $command $expectedVersion")
        Files.createDirectories(installRoot.parent)
        acquireInstallLock(installRoot.parent.resolve(".install.lock")).use {
            // Another process may have completed the same install while we waited.
            if (Files.isRegularFile(executable) && versionMatches(executable, expectedVersion, versionRunner)) {
                messages += RustToolchainProvisioner.ResolutionMessage("info", "Using cached $command $expectedVersion")
                return executable
            }
            val staging = Files.createTempDirectory(installRoot.parent, ".stage-$cacheName-")
            try {
                val archivePath = staging.resolve("archive.bin")
                val extracted = staging.resolve("extracted")
                Files.createDirectories(extracted)
                withTransientIoRetry { downloadAndVerify(spec, archivePath, fetcher) }
                withTransientIoRetry { extractArchive(spec, archivePath, extracted) }
                val stagedRoot = if (spec.root.isEmpty()) extracted else extracted.resolve(spec.root)
                val stagedExecutable = stagedRoot.resolve(spec.executableRelative)
                require(Files.isRegularFile(stagedExecutable)) { "locked $command archive is missing ${spec.executableRelative}" }
                stagedExecutable.toFile().setExecutable(true, false)
                if (!versionMatches(stagedExecutable, expectedVersion, versionRunner)) {
                    throw RustToolchainProvisioner.RustToolchainException("locked $command version probe rejected $expectedVersion")
                }
                if (Files.exists(installRoot)) withTransientIoRetry { deleteRecursively(installRoot) }
                moveDirectory(stagedRoot, installRoot)
            } finally {
                runCatching { if (Files.exists(staging)) deleteRecursively(staging) }
            }
        }
        require(Files.isRegularFile(executable)) { "locked $command installation is missing $executable" }
        return executable
    }

    private class InstallLockHandle(private val lock: FileLock, private val channel: FileChannel) : AutoCloseable {
        override fun close() {
            runCatching { lock.release() }
            runCatching { channel.close() }
        }
    }

    private fun acquireInstallLock(path: Path, timeoutMillis: Long = 120_000L): AutoCloseable {
        Files.createDirectories(path.parent)
        val channel = FileChannel.open(path, StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        val deadline = System.nanoTime() + timeoutMillis * 1_000_000L
        var held: FileLock? = null
        try {
            while (System.nanoTime() < deadline) {
                try {
                    held = channel.tryLock()
                    if (held != null) break
                } catch (_: OverlappingFileLockException) {
                    // Another thread in this JVM owns the same install lock.
                }
                try {
                    Thread.sleep(25L)
                } catch (error: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw RustToolchainProvisioner.RustToolchainException("build-tool install lock acquisition was interrupted", error)
                }
            }
            if (held == null) throw RustToolchainProvisioner.RustToolchainException("timed out acquiring build-tool install lock: $path")
            return InstallLockHandle(held, channel)
        } catch (error: Exception) {
            runCatching { held?.release() }
            runCatching { channel.close() }
            if (error is RustToolchainProvisioner.RustToolchainException) throw error
            throw RustToolchainProvisioner.RustToolchainException("failed to acquire build-tool install lock: ${error.message.orEmpty()}", error)
        }
    }

    private fun <T> withTransientIoRetry(times: Int = 4, delayMillis: Long = 300L, block: () -> T): T {
        var lastError: Exception? = null
        repeat(times) { attempt ->
            try {
                return block()
            } catch (error: Exception) {
                lastError = error
                if (attempt + 1 < times) {
                    try {
                        Thread.sleep(delayMillis * (attempt + 1))
                    } catch (interrupted: InterruptedException) {
                        Thread.currentThread().interrupt()
                        throw lastError!!
                    }
                }
            }
        }
        throw lastError!!
    }

    private fun versionMatches(
        executable: Path,
        expectedVersion: String,
        versionRunner: RustToolchainProvisioner.VersionRunner,
    ): Boolean {
        // Zig 0.13 reports its version through `zig version` (no dashes), while
        // cargo-zigbuild accepts `--version`. Try both before rejecting.
        for (arguments in listOf(listOf("version"), listOf("--version"))) {
            val result = runCatching { versionRunner.run(executable, arguments, emptyMap()) }.getOrNull() ?: continue
            val output = listOf(result.stdout, result.stderr).filter(String::isNotBlank).joinToString("\n")
            if (result.exitCode == 0 && output.contains(expectedVersion)) return true
        }
        return false
    }

    private fun findOnPath(command: String, host: RustToolchainProvisioner.HostPlatform, pathEnv: String?): Path? {
        if (pathEnv.isNullOrBlank()) return null
        val windowsHost = host == RustToolchainProvisioner.HostPlatform.WINDOWS_X64
        val names = if (windowsHost) listOf("$command.exe", command) else listOf(command)
        val separator = if (windowsHost) ';' else ':'
        return pathEnv.split(separator)
            .asSequence()
            .filter(String::isNotBlank)
            .mapNotNull { runCatching { Paths.get(it) }.getOrNull() }
            .flatMap { directory -> names.asSequence().map { directory.resolve(it) } }
            .firstOrNull { path -> path.isAbsolute && Files.isRegularFile(path) }
    }

    private fun downloadAndVerify(spec: ArchiveSpec, destination: Path, fetcher: ArchiveFetcher) {
        val (input, contentLength) = fetcher.fetch(spec)
        input.use { stream ->
            if (contentLength >= 0L && contentLength != spec.size) {
                throw RustToolchainProvisioner.RustToolchainException(
                    "build-tool archive content length mismatch for ${spec.url}: expected ${spec.size}, got $contentLength",
                )
            }
            val digest = MessageDigest.getInstance("SHA-256")
            var count = 0L
            Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { output ->
                val buffer = ByteArray(ARCHIVE_READ_BUFFER)
                while (true) {
                    val read = stream.read(buffer)
                    if (read < 0) break
                    if (read == 0) continue
                    count += read.toLong()
                    if (count > spec.size || count > DEFAULT_MAX_ARCHIVE_BYTES) {
                        throw RustToolchainProvisioner.RustToolchainException("build-tool archive exceeds its locked size: ${spec.url}")
                    }
                    digest.update(buffer, 0, read)
                    output.write(buffer, 0, read)
                }
            }
            if (count != spec.size || !MessageDigest.isEqual(digest.digest(), hexToBytes(spec.normalizedSha256))) {
                Files.deleteIfExists(destination)
                throw RustToolchainProvisioner.RustToolchainException("build-tool archive size or SHA-256 verification failed: ${spec.url}")
            }
        }
    }

    private fun extractArchive(spec: ArchiveSpec, archive: Path, staging: Path) {
        Files.newInputStream(archive).use { fileInput ->
            when (spec.format) {
                ArchiveSpec.Format.ZIP -> extractZip(fileInput, staging)
                ArchiveSpec.Format.TAR_XZ -> extractTar(XZCompressorInputStream(fileInput), staging)
                ArchiveSpec.Format.TAR_GZ -> extractTar(GzipCompressorInputStream(fileInput), staging)
            }
        }
    }

    private fun extractZip(input: InputStream, staging: Path) {
        ZipInputStream(input).use { zip ->
            var entries = 0
            var extracted = 0L
            while (true) {
                val entry = zip.nextEntry ?: break
                entries++
                require(entries <= DEFAULT_MAX_ARCHIVE_ENTRIES) { "build-tool zip has too many entries" }
                val output = staging.resolve(safeRelative(entry.name)).normalize()
                require(output.startsWith(staging.normalize())) { "build-tool zip entry escapes staging: ${entry.name}" }
                if (entry.isDirectory) {
                    Files.createDirectories(output)
                    continue
                }
                Files.createDirectories(output.parent)
                Files.newOutputStream(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { dest ->
                    extracted += copyBounded(zip, dest, DEFAULT_MAX_EXTRACTED_BYTES - extracted)
                }
            }
        }
    }

    private fun extractTar(input: InputStream, staging: Path) {
        TarArchiveInputStream(input).use { tar ->
            var entries = 0
            var extracted = 0L
            while (true) {
                val entry = tar.nextTarEntry ?: break
                entries++
                require(entries <= DEFAULT_MAX_ARCHIVE_ENTRIES) { "build-tool tar has too many entries" }
                if (entry.isSymbolicLink || entry.isLink) {
                    throw RustToolchainProvisioner.RustToolchainException("build-tool tar links are rejected: ${entry.name}")
                }
                val output = staging.resolve(safeRelative(entry.name)).normalize()
                require(output.startsWith(staging.normalize())) { "build-tool tar entry escapes staging: ${entry.name}" }
                if (entry.isDirectory) {
                    Files.createDirectories(output)
                    continue
                }
                Files.createDirectories(output.parent)
                Files.newOutputStream(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { dest ->
                    extracted += copyBounded(tar, dest, minOf(entry.size, DEFAULT_MAX_EXTRACTED_BYTES - extracted))
                }
            }
        }
    }

    private fun safeRelative(name: String): Path {
        require(name.isNotBlank() && !name.contains('\u0000')) { "build-tool archive contains an unsafe entry name" }
        val parts = name.replace('\\', '/').trimStart('/').split('/').filter { it.isNotEmpty() }
        require(parts.none { it == "." || it == ".." }) { "build-tool archive contains traversal syntax: $name" }
        require(parts.isNotEmpty()) { "build-tool archive entry is empty" }
        return if (parts.size == 1) Paths.get(parts[0]) else Paths.get(parts[0], *parts.drop(1).toTypedArray())
    }

    private fun copyBounded(input: InputStream, output: OutputStream, maxBytes: Long): Long {
        var copied = 0L
        val buffer = ByteArray(ARCHIVE_READ_BUFFER)
        while (copied < maxBytes) {
            val wanted = minOf(buffer.size.toLong(), maxBytes - copied).toInt()
            val read = input.read(buffer, 0, wanted)
            if (read < 0) break
            if (read == 0) continue
            output.write(buffer, 0, read)
            copied += read.toLong()
        }
        return copied
    }

    internal fun fetchArchiveForTest(spec: ArchiveSpec): Pair<InputStream, Long> = fetchArchive(spec)

    private fun fetchArchive(spec: ArchiveSpec): Pair<InputStream, Long> {
        val parsed = URI.create(spec.url)
        require(parsed.scheme.equals("https", ignoreCase = true)) { "build-tool URL must use HTTPS: ${spec.url}" }
        val host = parsed.host?.lowercase(Locale.ROOT).orEmpty()
        require(
            host == "ziglang.org" ||
                host.endsWith(".ziglang.org") ||
                host == "github.com" ||
                host.endsWith(".github.com") ||
                host.endsWith(".githubusercontent.com"),
        ) { "build-tool URL host is not locked: ${spec.url}" }
        val connection = parsed.toURL().openConnection()
        if (connection !is HttpURLConnection) {
            throw RustToolchainProvisioner.RustToolchainException("build-tool URL did not produce an HTTP connection: ${spec.url}")
        }
        connection.instanceFollowRedirects = true
        connection.connectTimeout = 15_000
        connection.readTimeout = 120_000
        if (connection.responseCode != HttpURLConnection.HTTP_OK) {
            connection.disconnect()
            throw RustToolchainProvisioner.RustToolchainException("build-tool server returned HTTP ${connection.responseCode}: ${spec.url}")
        }
        return connection.inputStream to connection.contentLengthLong
    }

    private fun runVersion(
        executable: Path,
        arguments: List<String>,
        environment: Map<String, String>,
    ): RustToolchainProvisioner.CommandResult {
        val process = ProcessBuilder(listOf(executable.toString()) + arguments).apply {
            redirectErrorStream(true)
            environment().putAll(environment)
        }.start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        return RustToolchainProvisioner.CommandResult(process.waitFor(), stdout = output)
    }

    private fun moveDirectory(source: Path, target: Path) {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: Exception) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING)
        }
    }

    private fun deleteRecursively(path: Path) {
        if (!Files.exists(path)) return
        Files.walk(path).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    private fun hexToBytes(value: String): ByteArray {
        require(value.length == 64) { "SHA-256 hexadecimal value must be 64 characters" }
        return ByteArray(32) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
}
