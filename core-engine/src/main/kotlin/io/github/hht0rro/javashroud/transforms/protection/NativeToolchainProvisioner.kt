package io.github.hht0rro.javashroud.transforms.protection

import java.io.File
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path

/**
 * Provisions a zig toolchain for cross-compiling native microkernels.
 *
 * Resolution order:
 * 1. JAVASHROUD_ZIG environment variable (absolute path to zig binary)
 * 2. zig on PATH
 * 3. Local cache: ~/.javashroud/zig/<version>/zig[.exe]
 * 4. Auto-download into the same cache directory for later reuse.
 */
object NativeToolchainProvisioner {

    private const val ZIG_VERSION = "0.13.0"
    private const val ZIG_ENV_VAR = "JAVASHROUD_ZIG"
    private const val DISABLE_DOWNLOAD_PROPERTY = "javashroud.zig.disableDownload"
    private const val ZIG_PROGRESS_PREPARING = 88
    private const val ZIG_PROGRESS_DOWNLOAD_START = 89
    private const val ZIG_PROGRESS_DOWNLOAD_END = 93
    private const val ZIG_PROGRESS_READY = 94

    data class ZigToolchain(val zigPath: Path, val source: String = "unknown") {
        val isAvailable: Boolean get() = isUsableZigBinary(zigPath)
    }

    data class ResolutionMessage(
        val level: String,
        val message: String,
        val progress: Int? = null,
    )

    data class ResolutionResult(
        val toolchain: ZigToolchain?,
        val messages: List<ResolutionMessage>,
    )

    /**
     * Resolve the zig toolchain path, downloading if necessary.
     * Returns null if zig is unavailable and cannot be downloaded.
     */
    fun resolve(): ZigToolchain? = resolveWithMessages().toolchain

    fun resolveWithMessages(onMessage: (ResolutionMessage) -> Unit = {}): ResolutionResult {
        return resolveWithMessages(System.getenv(), System.getenv("PATH"), onMessage)
    }

    internal fun resolveWithMessages(
        environment: Map<String, String>,
        pathEnv: String?,
        onMessage: (ResolutionMessage) -> Unit = {},
    ): ResolutionResult {
        val messages = mutableListOf<ResolutionMessage>()

        fun report(level: String, message: String, progress: Int? = null) {
            val resolutionMessage = ResolutionMessage(level, message, progress)
            messages += resolutionMessage
            onMessage(resolutionMessage)
        }

        environment[ZIG_ENV_VAR]?.takeIf { it.isNotBlank() }?.let { envPath ->
            val path = Path.of(envPath)
            if (isUsableZigBinary(path)) {
                report("info", "Using Zig toolchain from $ZIG_ENV_VAR: $path", ZIG_PROGRESS_READY)
                return ResolutionResult(ZigToolchain(path, "env"), messages)
            }
            report("warn", "$ZIG_ENV_VAR is set but is not a usable Zig executable: $path", ZIG_PROGRESS_PREPARING)
        }

        resolveFromPath(pathEnv)?.let { path ->
            report("info", "Using Zig toolchain from system PATH: $path", ZIG_PROGRESS_READY)
            return ResolutionResult(ZigToolchain(path, "path"), messages)
        }

        val cacheDir = cacheDirectory()
        findCachedZigBinary(cacheDir)?.let { cachedBinary ->
            report("info", "Using cached Zig toolchain: $cachedBinary", ZIG_PROGRESS_READY)
            return ResolutionResult(ZigToolchain(cachedBinary, "cache"), messages)
        }

        report("info", "正在准备 Zig 工具链: Zig toolchain was not found; preparing Zig under $cacheDir", ZIG_PROGRESS_PREPARING)
        if (System.getProperty(DISABLE_DOWNLOAD_PROPERTY).equals("true", ignoreCase = true)) {
            report("warn", "Automatic Zig download is disabled by $DISABLE_DOWNLOAD_PROPERTY", ZIG_PROGRESS_PREPARING)
            return ResolutionResult(null, messages)
        }
        val downloaded = downloadToCache(cacheDir, ::report)
        return ResolutionResult(downloaded, messages)
    }

    private fun resolveFromPath(pathEnv: String?): Path? {
        if (pathEnv.isNullOrBlank()) return null
        for (dir in pathEnv.split(File.pathSeparator)) {
            for (zigName in linkedSetOf("zig$exeSuffix", "zig")) {
                val candidate = Path.of(dir).resolve(zigName)
                if (isUsableZigBinary(candidate)) return candidate
            }
        }
        return null
    }

    private fun findCachedZigBinary(cacheDir: Path): Path? {
        val direct = cacheDir.resolve("zig$exeSuffix")
        if (isUsableZigBinary(direct)) return direct
        if (!Files.exists(cacheDir)) return null
        return Files.walk(cacheDir).use { stream ->
            stream.filter { it.fileName.toString() == "zig$exeSuffix" && isUsableZigBinary(it) }
                .findFirst()
                .orElse(null)
        }
    }

    private fun isUsableZigBinary(path: Path): Boolean {
        if (!Files.isExecutable(path)) return false
        if (!isWindows) return true
        // Windows Zig portable archives require the adjacent lib directory. A copied
        // root-level zig.exe is executable but fails with "unable to find zig installation directory".
        return Files.isDirectory(path.parent?.resolve("lib"))
    }

    internal fun cacheDirectory(): Path = Path.of(System.getProperty("user.home"), ".javashroud", "zig", ZIG_VERSION)

    private fun detectPlatform(): String? = detectPlatform(System.getProperty("os.name"), System.getProperty("os.arch"))

    internal fun detectPlatform(osName: String, osArch: String): String? {
        val os = osName.lowercase()
        val arch = when (val value = osArch.lowercase()) {
            "amd64", "x86_64" -> "x86_64"
            "aarch64", "arm64" -> "aarch64"
            else -> when {
                value.contains("amd64") || value.contains("x86_64") -> "x86_64"
                value.contains("aarch64") || value.contains("arm64") -> "aarch64"
                else -> return null
            }
        }
        val target = when {
            os.contains("win") -> "windows"
            os.contains("linux") -> "linux"
            os.contains("mac") -> "macos"
            else -> return null
        }
        return "$target-$arch"
    }

    private fun downloadToCache(
        cacheDir: Path,
        report: (level: String, message: String, progress: Int?) -> Unit,
    ): ZigToolchain? {
        val platform = detectPlatform()
        if (platform == null) {
            report("warn", "Cannot auto-download Zig because this OS/architecture is unsupported", ZIG_PROGRESS_PREPARING)
            return null
        }
        val extension = if (isWindows) "zip" else "tar.xz"
        val url = "https://ziglang.org/download/$ZIG_VERSION/zig-$platform-$ZIG_VERSION.$extension"

        return try {
            Files.createDirectories(cacheDir)
            val archivePath = Files.createTempFile(cacheDir, "zig-download-", ".$extension")
            report("info", "Downloading Zig $ZIG_VERSION for $platform from $url", ZIG_PROGRESS_DOWNLOAD_START)
            val connection = URI.create(url).toURL().openConnection()
            connection.connectTimeout = 10_000
            connection.readTimeout = 30_000
            val contentLength = connection.contentLengthLong
            connection.getInputStream().use { input ->
                Files.newOutputStream(archivePath).use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    var totalRead = 0L
                    var lastProgress = ZIG_PROGRESS_DOWNLOAD_START
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        output.write(buffer, 0, read)
                        totalRead += read.toLong()
                        val progress = downloadProgress(totalRead, contentLength)
                        if (progress != null && progress > lastProgress) {
                            lastProgress = progress
                            val percent = ((progress - ZIG_PROGRESS_DOWNLOAD_START).toDouble() /
                                (ZIG_PROGRESS_DOWNLOAD_END - ZIG_PROGRESS_DOWNLOAD_START).toDouble() * 100.0).toInt().coerceIn(0, 100)
                            report("info", "Downloading Zig $ZIG_VERSION: $percent%", progress)
                        }
                    }
                }
            }
            report("info", "Extracting Zig $ZIG_VERSION to $cacheDir", ZIG_PROGRESS_DOWNLOAD_END)
            extractArchive(archivePath, cacheDir)
            try {
                Files.deleteIfExists(archivePath)
            } catch (_: Exception) {
                // A locked temporary archive should not block reuse once zig.exe is ready.
            }

            val zigBinary = findCachedZigBinary(cacheDir)
            if (zigBinary != null) {
                report("info", "Downloaded Zig toolchain to $zigBinary", ZIG_PROGRESS_READY)
                ZigToolchain(zigBinary, "download")
            } else {
                report("warn", "Downloaded Zig archive did not contain a usable zig$exeSuffix toolchain", ZIG_PROGRESS_DOWNLOAD_END)
                null
            }
        } catch (error: Exception) {
            report("warn", "Failed to download or extract Zig: ${error.message ?: error::class.java.simpleName}", ZIG_PROGRESS_DOWNLOAD_START)
            null
        }
    }

    private fun downloadProgress(totalRead: Long, contentLength: Long): Int? {
        if (contentLength <= 0L) return null
        val range = ZIG_PROGRESS_DOWNLOAD_END - ZIG_PROGRESS_DOWNLOAD_START
        return ZIG_PROGRESS_DOWNLOAD_START + ((totalRead.toDouble() / contentLength.toDouble()) * range).toInt().coerceIn(0, range)
    }

    private fun extractArchive(archive: Path, destDir: Path) {
        if (isWindows) {
            extractZip(archive, destDir)
        } else {
            extractTarXz(archive, destDir)
        }
    }

    private fun extractZip(zipPath: Path, destDir: Path) {
        java.util.zip.ZipFile(zipPath.toFile()).use { zip ->
            val entries = zip.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val slashIndex = entry.name.indexOf('/')
                if (slashIndex < 0) continue
                val relativePath = entry.name.substring(slashIndex + 1)
                if (relativePath.isEmpty()) continue
                val outFile = destDir.resolve(relativePath)
                if (entry.isDirectory) {
                    Files.createDirectories(outFile)
                } else {
                    Files.createDirectories(outFile.parent)
                    zip.getInputStream(entry).use { input ->
                        Files.newOutputStream(outFile).use { output -> input.copyTo(output) }
                    }
                }
            }
        }
    }

    private fun extractTarXz(tarXzPath: Path, destDir: Path) {
        Files.newInputStream(tarXzPath).use { fileIn ->
            org.apache.commons.compress.compressors.xz.XZCompressorInputStream(fileIn).use { xzIn ->
                org.apache.commons.compress.archivers.tar.TarArchiveInputStream(xzIn).use { tarIn ->
                    var entry = tarIn.nextTarEntry
                    while (entry != null) {
                        val slashIndex = entry.name.indexOf('/')
                        if (slashIndex >= 0) {
                            val relativePath = entry.name.substring(slashIndex + 1)
                            if (relativePath.isNotEmpty()) {
                                val outFile = destDir.resolve(relativePath)
                                if (entry.isDirectory) {
                                    Files.createDirectories(outFile)
                                } else {
                                    Files.createDirectories(outFile.parent)
                                    Files.newOutputStream(outFile).use { out -> tarIn.copyTo(out) }
                                    if (relativePath == "zig$exeSuffix") {
                                        outFile.toFile().setExecutable(true)
                                    }
                                }
                            }
                        }
                        entry = tarIn.nextTarEntry
                    }
                }
            }
        }
    }

    private val isWindows: Boolean
        get() = System.getProperty("os.name").lowercase().contains("win")

    private val exeSuffix: String
        get() = if (isWindows) ".exe" else ""
}