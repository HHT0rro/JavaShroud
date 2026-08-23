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
import java.util.UUID
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream

/**
 * Resolves and deploys the one Rust toolchain used by the AKEN-R1 runtime.
 *
 * The deployment path is deliberately archive based. Every archive, extracted
 * path, executable, and compiler version is checked before a cache directory
 * becomes visible. No compiler or platform fallback is permitted.
 */
object RustToolchainProvisioner {
    const val LOCKED_CHANNEL: String = "1.78.0"
    const val LOCKED_PROFILE: String = "minimal"
    const val RUNTIME_TARGET_WINDOWS: String = "windows-x64"
    const val RUNTIME_TARGET_LINUX: String = "linux-x64"
    const val WINDOWS_RUSTUP_TARGET: String = "x86_64-pc-windows-gnu"
    const val LINUX_RUSTUP_TARGET: String = "x86_64-unknown-linux-gnu"
    const val LINUX_RUNTIME_TARGET: String = "x86_64-unknown-linux-gnu.2.17"
    const val LINUX_GLIBC_FLOOR: String = "2.17"

    private const val RUSTC_ENV = "JAVASHROUD_RUSTC"
    private const val CARGO_ENV = "JAVASHROUD_CARGO"
    private const val RUSTUP_ENV = "JAVASHROUD_RUSTUP"
    private const val RUSTUP_HOME = "RUSTUP_HOME"
    private const val CARGO_HOME = "CARGO_HOME"
    private const val DEFAULT_MAX_ARCHIVE_BYTES = 512L * 1024L * 1024L
    private const val DEFAULT_MAX_EXTRACTED_BYTES = 2L * 1024L * 1024L * 1024L
    private const val DEFAULT_MAX_ARCHIVE_ENTRIES = 65_536
    private const val ARCHIVE_READ_BUFFER = 64 * 1024
    private const val INSTALL_LOCK_NAME = ".install.lock"

    /** Parsed from core-engine/src/main/rust/native-toolchain.lock. */
    val lock: ToolchainLock by lazy { parseLock(readDefaultLock()) }

    data class RuntimeTarget(
        val id: String,
        val rustupTarget: String,
        val artifactSuffix: String,
        val glibcFloor: String?,
    )

    data class ArchiveSpec(
        val host: String,
        val target: String,
        val kind: String,
        val url: String,
        val size: Long,
        val sha256: String,
        val root: String,
    ) {
        init {
            require(host in setOf(RUNTIME_TARGET_WINDOWS, RUNTIME_TARGET_LINUX)) {
                "Rust archive host is outside the AKEN-R1 whitelist: $host"
            }
            require(target in setOf(RUNTIME_TARGET_WINDOWS, RUNTIME_TARGET_LINUX)) {
                "Rust archive target is outside the AKEN-R1 whitelist: $target"
            }
            require(kind in setOf("rust", "cargo", "rustfmt", "clippy")) {
                "unsupported locked Rust archive kind: $kind"
            }
            require(size > 0L) { "Rust archive size must be positive" }
            require(sha256.matches(Regex("[0-9a-fA-F]{64}"))) {
                "Rust archive SHA-256 must contain exactly 64 hexadecimal characters"
            }
            require(root.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]*"))) {
                "Rust archive root is not a single safe path component: $root"
            }
            val parsed = URI.create(url)
            require(parsed.scheme?.equals("https", ignoreCase = true) == true) {
                "Rust archive URL must use HTTPS: $url"
            }
            require(parsed.host?.equals("static.rust-lang.org", ignoreCase = true) == true) {
                "Rust archive URL host is not the locked Rust distribution host: $url"
            }
            require(parsed.userInfo == null && parsed.query == null && parsed.fragment == null) {
                "Rust archive URL has unsafe authority or suffix: $url"
            }
            require(parsed.path?.endsWith(".tar.xz") == true) {
                "Rust archive URL must name a .tar.xz archive: $url"
            }
        }

        val normalizedSha256: String get() = sha256.lowercase(Locale.ROOT)
    }

    data class ToolchainLock(
        val channel: String,
        val profile: String,
        val components: List<String>,
        val targets: List<RuntimeTarget>,
        val archives: List<ArchiveSpec> = emptyList(),
        val formatVersion: Int = 1,
        val maxArchiveBytes: Long = DEFAULT_MAX_ARCHIVE_BYTES,
        val maxExtractedBytes: Long = DEFAULT_MAX_EXTRACTED_BYTES,
        val maxArchiveEntries: Int = DEFAULT_MAX_ARCHIVE_ENTRIES,
    ) {
        init {
            require(formatVersion == 1) { "unsupported Rust toolchain lock format: $formatVersion" }
            require(channel == LOCKED_CHANNEL) { "AKEN-R1 requires Rust $LOCKED_CHANNEL, got $channel" }
            require(channel.matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+"))) {
                "Rust toolchain channel must be an exact semantic version"
            }
            require(profile == LOCKED_PROFILE) { "AKEN-R1 requires the minimal Rust profile" }
            require(components.distinct() == components) { "Rust toolchain components must be unique" }
            require(components.toSet() == setOf("rustfmt", "clippy")) {
                "AKEN-R1 requires exactly rustfmt and clippy components"
            }
            require(targets.map(RuntimeTarget::id).distinct().size == targets.size) {
                "Rust runtime targets must be unique"
            }
            require(targets.map(RuntimeTarget::id).toSet() == setOf(RUNTIME_TARGET_WINDOWS, RUNTIME_TARGET_LINUX)) {
                "AKEN-R1 requires exactly the Windows x64 and Linux x64 runtime routes"
            }
            require(targets.first { it.id == RUNTIME_TARGET_WINDOWS }.rustupTarget == WINDOWS_RUSTUP_TARGET) {
                "AKEN-R1 Windows target drifted from x86_64-pc-windows-gnu"
            }
            require(targets.first { it.id == RUNTIME_TARGET_LINUX }.rustupTarget == LINUX_RUSTUP_TARGET) {
                "AKEN-R1 Linux rustup target drifted"
            }
            require(targets.first { it.id == RUNTIME_TARGET_WINDOWS }.artifactSuffix == ".dll") {
                "AKEN-R1 Windows artifacts must use .dll"
            }
            require(targets.first { it.id == RUNTIME_TARGET_WINDOWS }.glibcFloor == null) {
                "AKEN-R1 Windows artifacts must not carry a glibc floor"
            }
            require(targets.first { it.id == RUNTIME_TARGET_LINUX }.artifactSuffix == ".so") {
                "AKEN-R1 Linux artifacts must use .so"
            }
            require(targets.first { it.id == RUNTIME_TARGET_LINUX }.glibcFloor == LINUX_GLIBC_FLOOR) {
                "AKEN-R1 Linux artifacts must declare glibc 2.17"
            }
            require(maxArchiveBytes > 0L && maxArchiveBytes <= 4L * 1024L * 1024L * 1024L) {
                "Rust archive bound is outside the supported range"
            }
            require(maxExtractedBytes > 0L && maxExtractedBytes <= 8L * 1024L * 1024L * 1024L) {
                "Rust extracted-size bound is outside the supported range"
            }
            require(maxArchiveEntries in 1..1_000_000) { "Rust archive entry bound is invalid" }
            require(archives.distinctBy { Triple(it.host, it.target, it.kind) }.size == archives.size) {
                "Rust archive lock contains duplicate host/target/kind entries"
            }
            archives.forEach { archive ->
                require(archive.size <= maxArchiveBytes) {
                    "Rust archive ${archive.kind} exceeds the locked size bound"
                }
                require(archive.host in targets.map(RuntimeTarget::id)) {
                    "Rust archive host is not a locked target: ${archive.host}"
                }
                require(archive.target in targets.map(RuntimeTarget::id)) {
                    "Rust archive target is not a locked target: ${archive.target}"
                }
            }
        }

        fun target(value: String): RuntimeTarget {
            val normalized = value.trim().lowercase(Locale.ROOT)
            return targets.firstOrNull {
                it.id == normalized ||
                    (it.id == RUNTIME_TARGET_WINDOWS && normalized == it.rustupTarget) ||
                    (it.id == RUNTIME_TARGET_LINUX && normalized == LINUX_RUNTIME_TARGET)
            } ?: throw RustToolchainException("unsupported AKEN-R1 Rust target: $value")
        }

        fun archivesFor(host: HostPlatform, target: RuntimeTarget): List<ArchiveSpec> {
            val hostId = host.runtimeId
            return archives.filter { it.host == hostId && it.target == target.id }
                .sortedBy { it.kind }
                .also { selected ->
                    val required = buildSet {
                        add("rust")
                        add("cargo")
                        components.forEach(::add)
                    }
                    if (selected.map(ArchiveSpec::kind).toSet() != required) {
                        throw RustToolchainException(
                            "locked Rust deployment is incomplete for $hostId/${target.id}",
                        )
                    }
                }
        }

        fun canonicalMaterial(host: HostPlatform, target: RuntimeTarget): String = buildString {
            append("format=").append(formatVersion).append('\n')
            append("channel=").append(channel).append('\n')
            append("profile=").append(profile).append('\n')
            append("host=").append(host.runtimeId).append('\n')
            append("target=").append(target.id).append('\n')
            append("rustup=").append(target.rustupTarget).append('\n')
            append("components=").append(components.joinToString(",")).append('\n')
            archivesFor(host, target).forEach { archive ->
                append(archive.kind).append('|')
                    .append(archive.url).append('|')
                    .append(archive.size).append('|')
                    .append(archive.normalizedSha256).append('|')
                    .append(archive.root).append('\n')
            }
        }
    }

    enum class HostPlatform {
        WINDOWS_X64,
        LINUX_X64,
        ;

        val runtimeId: String
            get() = when (this) {
                WINDOWS_X64 -> RUNTIME_TARGET_WINDOWS
                LINUX_X64 -> RUNTIME_TARGET_LINUX
            }
    }

    data class RustToolchain(
        val rustcPath: Path,
        val cargoPath: Path,
        val host: HostPlatform,
    )

    data class InstalledToolchain(
        val root: Path,
        val rustcPath: Path,
        val cargoPath: Path,
        val host: HostPlatform,
        val target: RuntimeTarget,
        val digest: String,
        val environment: Map<String, String>,
    )

    data class ResolutionMessage(
        val level: String,
        val message: String,
    )

    data class ResolutionResult(
        val toolchain: RustToolchain?,
        val messages: List<ResolutionMessage>,
    )

    data class CommandResult(
        val exitCode: Int,
        val stdout: String = "",
        val stderr: String = "",
    )

    data class ArchiveFetch(
        val input: InputStream,
        val contentLength: Long = -1L,
    )

    fun interface ArchiveFetcher {
        fun fetch(spec: ArchiveSpec): ArchiveFetch
    }

    fun interface VersionRunner {
        fun run(executable: Path, arguments: List<String>, environment: Map<String, String>): CommandResult
    }

    interface InstallLock : AutoCloseable {
        override fun close()
    }

    /** Filesystem seam used by deterministic deployment tests. */
    interface ToolchainFileSystem {
        fun exists(path: Path): Boolean
        fun isRegularFile(path: Path): Boolean
        fun createDirectories(path: Path)
        fun createTempDirectory(parent: Path, prefix: String): Path
        fun openInput(path: Path): InputStream
        fun openOutput(path: Path): OutputStream
        fun setExecutable(path: Path)
        fun deleteRecursively(path: Path)
        fun moveAtomically(source: Path, target: Path)
        fun acquireInstallLock(path: Path, timeoutMillis: Long): InstallLock
    }

    class RustToolchainException(message: String, cause: Throwable? = null) : IllegalStateException(message, cause)

    fun target(value: String): RuntimeTarget = lock.target(value)

    fun hostPlatform(osName: String, osArch: String): HostPlatform {
        val os = osName.trim().lowercase(Locale.ROOT)
        val arch = osArch.trim().lowercase(Locale.ROOT)
        return when {
            os.contains("mac") || os.contains("darwin") -> {
                throw RustToolchainException("AKEN-R1 rejects macOS hosts and Mach-O builds: $osName/$osArch")
            }
            os.startsWith("windows") -> {
                requireSupportedArchitecture(arch)
                HostPlatform.WINDOWS_X64
            }
            os == "linux" || os.startsWith("linux ") -> {
                requireSupportedArchitecture(arch)
                HostPlatform.LINUX_X64
            }
            else -> throw RustToolchainException("AKEN-R1 Rust host is unsupported: $osName/$osArch")
        }
    }

    /**
     * Installs one locked route. Host and target validation deliberately happen
     * before user cache access, temporary-directory creation, or archive fetch.
     */
    fun installLocked(
        target: String,
        osName: String = System.getProperty("os.name"),
        osArch: String = System.getProperty("os.arch"),
        userHome: Path = Paths.get(System.getProperty("user.home")),
        lockText: String? = null,
        fetcher: ArchiveFetcher = ArchiveFetcher(::fetchArchive),
        versionRunner: VersionRunner = VersionRunner(::runVersion),
        fileSystem: ToolchainFileSystem = REAL_FILE_SYSTEM,
        installLockTimeoutMillis: Long = 30_000L,
    ): InstalledToolchain {
        val host = hostPlatform(osName, osArch)
        val selectedLock = lockText?.let(::parseLock) ?: lock
        val selectedTarget = selectedLock.target(target)
        val archives = selectedLock.archivesFor(host, selectedTarget)
        require(installLockTimeoutMillis > 0L) { "Rust install lock timeout must be positive" }

        val cacheRoot = userHome.toAbsolutePath().normalize()
            .resolve(".javashroud")
            .resolve("toolchains")
        val digest = installationDigest(selectedLock, host, selectedTarget)
        val installRoot = cacheRoot.resolve(digest)
        fileSystem.createDirectories(cacheRoot)
        fileSystem.acquireInstallLock(cacheRoot.resolve(INSTALL_LOCK_NAME), installLockTimeoutMillis).use {
            if (fileSystem.exists(installRoot)) {
                if (isUsableInstallation(installRoot, host, selectedLock, versionRunner, fileSystem)) {
                    return installedToolchain(installRoot, digest, host, selectedTarget)
                }
                throw RustToolchainException("cached Rust toolchain failed locked validation: $installRoot")
            }

            val staging = fileSystem.createTempDirectory(cacheRoot, ".stage-$digest-")
            try {
                val archiveDirectory = staging.resolve(".archives")
                fileSystem.createDirectories(archiveDirectory)
                var extractedTotal = 0L
                archives.forEachIndexed { index, spec ->
                    val archivePath = archiveDirectory.resolve("${index}-${spec.kind}.tar.xz")
                    downloadAndVerify(spec, archivePath, selectedLock, fetcher, fileSystem)
                    val extracted = extractArchive(spec, archivePath, staging, selectedLock, fileSystem)
                    if (extracted > selectedLock.maxExtractedBytes - extractedTotal) {
                        throw RustToolchainException("Rust deployment extracted size exceeds its locked bound")
                    }
                    extractedTotal += extracted
                    fileSystem.deleteRecursively(archivePath)
                }
                fileSystem.deleteRecursively(archiveDirectory)
                val stagedEnvironment = isolatedEnvironment(staging, host)
                verifyInstallation(staging, host, selectedLock, stagedEnvironment, versionRunner, fileSystem)
                fileSystem.createDirectories(staging.resolve("rustup-home"))
                fileSystem.createDirectories(staging.resolve("cargo-home"))
                fileSystem.moveAtomically(staging, installRoot)
                return installedToolchain(installRoot, digest, host, selectedTarget)
            } finally {
                if (fileSystem.exists(staging)) fileSystem.deleteRecursively(staging)
            }
        }
    }

    /** Alias with a deployment-oriented name for callers that do not use rustup terminology. */
    fun deployLocked(
        target: String,
        osName: String = System.getProperty("os.name"),
        osArch: String = System.getProperty("os.arch"),
        userHome: Path = Paths.get(System.getProperty("user.home")),
        lockText: String? = null,
        fetcher: ArchiveFetcher = ArchiveFetcher(::fetchArchive),
        versionRunner: VersionRunner = VersionRunner(::runVersion),
        fileSystem: ToolchainFileSystem = REAL_FILE_SYSTEM,
        installLockTimeoutMillis: Long = 30_000L,
    ): InstalledToolchain = installLocked(
        target = target,
        osName = osName,
        osArch = osArch,
        userHome = userHome,
        lockText = lockText,
        fetcher = fetcher,
        versionRunner = versionRunner,
        fileSystem = fileSystem,
        installLockTimeoutMillis = installLockTimeoutMillis,
    )

    /**
     * Compatibility-shaped entry point for the current build integration. It
     * still performs the locked archive deployment; the command runner is only
     * used as the injectable version-probe seam.
     */
    fun provision(
        environment: Map<String, String> = System.getenv(),
        pathEnv: String? = environment["PATH"],
        osName: String = System.getProperty("os.name"),
        osArch: String = System.getProperty("os.arch"),
        commandRunner: (List<String>) -> CommandResult = ::runCommand,
        target: String? = null,
        userHome: Path = Paths.get(System.getProperty("user.home")),
        lockText: String? = null,
        fetcher: ArchiveFetcher = ArchiveFetcher(::fetchArchive),
        fileSystem: ToolchainFileSystem = REAL_FILE_SYSTEM,
        installLockTimeoutMillis: Long = 30_000L,
    ): CommandResult {
        val host = hostPlatform(osName, osArch)
        val selectedTarget = target ?: host.runtimeId
        val installed = installLocked(
            target = selectedTarget,
            osName = osName,
            osArch = osArch,
            userHome = userHome,
            lockText = lockText,
            fetcher = fetcher,
            versionRunner = VersionRunner { executable, arguments, _ ->
                commandRunner(listOf(executable.toString()) + arguments)
            },
            fileSystem = fileSystem,
            installLockTimeoutMillis = installLockTimeoutMillis,
        )
        return CommandResult(0, stdout = installed.root.toString())
    }

    fun rustupInstallCommand(rustup: Path = Paths.get("rustup")): List<String> {
        val arguments = mutableListOf(
            rustup.toString(),
            "toolchain",
            "install",
            lock.channel,
            "--profile",
            lock.profile,
            "--no-self-update",
        )
        lock.components.forEach { arguments += listOf("--component", it) }
        lock.targets.forEach { arguments += listOf("--target", it.rustupTarget) }
        return arguments
    }

    fun resolve(
        environment: Map<String, String> = System.getenv(),
        pathEnv: String? = environment["PATH"],
        osName: String = System.getProperty("os.name"),
        osArch: String = System.getProperty("os.arch"),
        commandRunner: (List<String>) -> CommandResult = ::runCommand,
    ): ResolutionResult {
        val messages = mutableListOf<ResolutionMessage>()
        fun report(level: String, message: String) {
            messages += ResolutionMessage(level, message)
        }

        val host = try {
            hostPlatform(osName, osArch)
        } catch (error: RustToolchainException) {
            report("warn", error.message.orEmpty())
            return ResolutionResult(null, messages)
        }
        val rustc = findExecutable(RUSTC_ENV, "rustc", environment, pathEnv, host)
        val cargo = findExecutable(CARGO_ENV, "cargo", environment, pathEnv, host)
        if (rustc == null || cargo == null) {
            report("warn", "AKEN-R1 Rust toolchain is incomplete: rustc and cargo are both required")
            return ResolutionResult(null, messages)
        }

        fun verifyVersion(path: Path, command: String, validator: (String) -> Boolean): Boolean {
            val result = try {
                commandRunner(listOf(path.toString(), "--version"))
            } catch (error: Exception) {
                report("warn", "AKEN-R1 $command probe failed: ${error.message.orEmpty()}")
                return false
            }
            val output = commandOutput(result)
            if (result.exitCode != 0 || !validator(output)) {
                report("warn", "AKEN-R1 $command is not locked to Rust $LOCKED_CHANNEL")
                return false
            }
            return true
        }

        if (!verifyVersion(rustc, "rustc", ::validateRustcVersion) ||
            !verifyVersion(cargo, "cargo", ::validateCargoVersion)
        ) {
            return ResolutionResult(null, messages)
        }
        report("info", "Using locked Rust $LOCKED_CHANNEL on ${host.name.lowercase(Locale.ROOT)}")
        return ResolutionResult(RustToolchain(rustc, cargo, host), messages)
    }

    fun validateRustcVersion(versionOutput: String): Boolean = validateLockedVersion(versionOutput, "rustc", LOCKED_CHANNEL)

    fun validateCargoVersion(versionOutput: String): Boolean = validateLockedVersion(versionOutput, "cargo", LOCKED_CHANNEL)

    fun parseLock(text: String): ToolchainLock {
        if (text.isBlank()) throw RustToolchainException("Rust toolchain lock is empty")
        val sections = parseSections(text)
        val lockValues = section(sections, "lock")
        val format = lockValues.requiredLong("format").toIntChecked("format")
        val channel = lockValues.requiredString("channel")
        val profile = lockValues.requiredString("profile")
        val components = lockValues.requiredStringList("components")
        val maxArchiveBytes = lockValues.optionalLong("max_archive_bytes") ?: DEFAULT_MAX_ARCHIVE_BYTES
        val maxExtractedBytes = lockValues.optionalLong("max_extracted_bytes") ?: DEFAULT_MAX_EXTRACTED_BYTES
        val maxArchiveEntries = (lockValues.optionalLong("max_archive_entries") ?: DEFAULT_MAX_ARCHIVE_ENTRIES.toLong())
            .toIntChecked("max_archive_entries")
        val archiveCount = lockValues.requiredLong("archive_count").toIntChecked("archive_count")
        lockValues.requireOnly(
            "format", "channel", "profile", "components", "max_archive_bytes",
            "max_extracted_bytes", "max_archive_entries", "archive_count",
        )

        val targets = listOf(RUNTIME_TARGET_WINDOWS, RUNTIME_TARGET_LINUX).map { id ->
            val values = section(sections, "target.$id")
            val rustupTarget = values.requiredString("rustup_target")
            val artifactSuffix = values.requiredString("artifact_suffix")
            val glibcFloor = values.requiredString("glibc_floor").ifEmpty { null }
            values.requireOnly("rustup_target", "artifact_suffix", "glibc_floor")
            RuntimeTarget(id, rustupTarget, artifactSuffix, glibcFloor)
        }

        val archives = sections.asSequence()
            .filter { it.key.startsWith("archive.") }
            .map { (name, values) ->
                require(name.length > "archive.".length) { "Rust archive section must have a name" }
                val host = values.requiredString("host")
                val target = values.requiredString("target")
                val kind = values.requiredString("kind")
                val url = values.requiredString("url")
                val size = values.requiredLong("size")
                val sha256 = values.requiredString("sha256")
                val root = values.requiredString("root")
                values.requireOnly("host", "target", "kind", "url", "size", "sha256", "root")
                try {
                    ArchiveSpec(host, target, kind, url, size, sha256, root)
                } catch (error: Exception) {
                    throw RustToolchainException("invalid locked Rust archive '$name': ${error.message.orEmpty()}", error)
                }
            }
            .toList()
        require(archives.size == archiveCount) {
            "Rust toolchain lock archive count mismatch: expected $archiveCount, got ${archives.size}"
        }
        val knownSections = setOf("lock", "target.windows-x64", "target.linux-x64") + sections.keys.filter { it.startsWith("archive.") }
        require(sections.keys.all { it in knownSections }) { "Rust toolchain lock contains an unknown section" }
        return try {
            ToolchainLock(
                channel = channel,
                profile = profile,
                components = components,
                targets = targets,
                archives = archives,
                formatVersion = format,
                maxArchiveBytes = maxArchiveBytes,
                maxExtractedBytes = maxExtractedBytes,
                maxArchiveEntries = maxArchiveEntries,
            )
        } catch (error: IllegalArgumentException) {
            throw RustToolchainException(error.message ?: "invalid Rust toolchain lock", error)
        }
    }

    fun installationDirectory(
        userHome: Path,
        host: HostPlatform,
        target: String,
        lockText: String? = null,
    ): Path {
        val selectedLock = lockText?.let(::parseLock) ?: lock
        val selectedTarget = selectedLock.target(target)
        val digest = installationDigest(selectedLock, host, selectedTarget)
        return userHome.toAbsolutePath().normalize().resolve(".javashroud").resolve("toolchains").resolve(digest)
    }

    private fun readDefaultLock(): String {
        val resource = RustToolchainProvisioner::class.java.getResourceAsStream("/native-toolchain.lock")
        if (resource != null) return resource.bufferedReader(Charsets.UTF_8).use { it.readText() }
        val relativeCandidates = listOf(
            Paths.get("core-engine", "src", "main", "rust", "native-toolchain.lock"),
            Paths.get("src", "main", "rust", "native-toolchain.lock"),
            Paths.get("native-toolchain.lock"),
        )
        var current: Path? = Paths.get("").toAbsolutePath().normalize()
        while (current != null) {
            relativeCandidates.firstOrNull { candidate ->
                val path = current.resolve(candidate).normalize()
                Files.isRegularFile(path)
            }?.let { candidate ->
                return Files.readString(current.resolve(candidate).normalize(), Charsets.UTF_8)
            }
            current = current.parent
        }
        throw RustToolchainException("AKEN-R1 native-toolchain.lock is missing")
    }

    private fun downloadAndVerify(
        spec: ArchiveSpec,
        destination: Path,
        selectedLock: ToolchainLock,
        fetcher: ArchiveFetcher,
        fileSystem: ToolchainFileSystem,
    ) {
        require(spec.size <= selectedLock.maxArchiveBytes) { "locked Rust archive exceeds the maximum size" }
        val expectedDigest = hexToBytes(spec.normalizedSha256)
        val fetched = try {
            fetcher.fetch(spec)
        } catch (error: Exception) {
            throw RustToolchainException("Rust archive fetch failed for ${spec.url}: ${error.message.orEmpty()}", error)
        }
        fetched.input.use { input ->
            if (fetched.contentLength >= 0L && fetched.contentLength != spec.size) {
                throw RustToolchainException(
                    "Rust archive content length mismatch for ${spec.url}: expected ${spec.size}, got ${fetched.contentLength}",
                )
            }
            fileSystem.createDirectories(destination.parent)
            val digest = MessageDigest.getInstance("SHA-256")
            var count = 0L
            try {
                fileSystem.openOutput(destination).use { output ->
                    val buffer = ByteArray(ARCHIVE_READ_BUFFER)
                    while (true) {
                        val read = input.read(buffer)
                        if (read < 0) break
                        if (read == 0) continue
                        count += read.toLong()
                        if (count > spec.size || count > selectedLock.maxArchiveBytes) {
                            throw RustToolchainException("Rust archive exceeds its locked size bound: ${spec.url}")
                        }
                        digest.update(buffer, 0, read)
                        output.write(buffer, 0, read)
                    }
                }
            } catch (error: Exception) {
                fileSystem.deleteRecursively(destination)
                throw error
            }
            if (count != spec.size || !MessageDigest.isEqual(digest.digest(), expectedDigest)) {
                fileSystem.deleteRecursively(destination)
                throw RustToolchainException("Rust archive size or SHA-256 verification failed: ${spec.url}")
            }
        }
    }

    private fun extractArchive(
        spec: ArchiveSpec,
        archive: Path,
        staging: Path,
        selectedLock: ToolchainLock,
        fileSystem: ToolchainFileSystem,
    ): Long {
        var entryCount = 0
        var extractedBytes = 0L
        val seen = HashSet<String>()
        fileSystem.openInput(archive).use { fileInput ->
            XZCompressorInputStream(fileInput).use { xzInput ->
                TarArchiveInputStream(xzInput).use { tarInput ->
                    while (true) {
                        val entry = tarInput.getNextTarEntry() ?: break
                        entryCount++
                        if (entryCount > selectedLock.maxArchiveEntries) {
                            throw RustToolchainException("Rust archive contains too many entries: ${spec.url}")
                        }
                        val parts = safeArchiveParts(entry.name, spec.root)
                        val relativeParts = parts.drop(1)
                        val relative = if (relativeParts.isEmpty()) {
                            Paths.get("")
                        } else {
                            Paths.get(relativeParts.joinToString("/"))
                        }
                        val output = staging.resolve(relative).normalize()
                        require(output.startsWith(staging.normalize())) {
                            "Rust archive entry escapes staging: ${entry.name}"
                        }
                        val key = relative.toString()
                        require(seen.add(key)) { "Rust archive contains a duplicate entry: ${entry.name}" }
                        if (entry.isSymbolicLink || entry.isLink) {
                            throw RustToolchainException("Rust archive links are rejected: ${entry.name}")
                        }
                        if (entry.isDirectory) {
                            fileSystem.createDirectories(output)
                            continue
                        }
                        val entrySize = entry.size
                        require(entrySize >= 0L) { "Rust archive entry has an invalid size: ${entry.name}" }
                        if (entrySize > selectedLock.maxExtractedBytes - extractedBytes) {
                            throw RustToolchainException("Rust archive extracted size exceeds its locked bound: ${spec.url}")
                        }
                        fileSystem.createDirectories(output.parent)
                        fileSystem.openOutput(output).use { outputStream ->
                            copyEntry(tarInput, outputStream, entrySize)
                        }
                        extractedBytes += entrySize
                        if (relativeParts.firstOrNull() == "bin") fileSystem.setExecutable(output)
                    }
                }
            }
        }
        return extractedBytes
    }

    private fun copyEntry(input: InputStream, output: OutputStream, expectedSize: Long) {
        var copied = 0L
        val buffer = ByteArray(ARCHIVE_READ_BUFFER)
        while (copied < expectedSize) {
            val wanted = minOf(buffer.size.toLong(), expectedSize - copied).toInt()
            val read = input.read(buffer, 0, wanted)
            if (read < 0) throw RustToolchainException("Rust archive entry is truncated")
            if (read == 0) continue
            output.write(buffer, 0, read)
            copied += read.toLong()
        }
        if (copied != expectedSize) throw RustToolchainException("Rust archive entry length mismatch")
    }

    private fun safeArchiveParts(name: String, expectedRoot: String): List<String> {
        require(name.isNotBlank() && !name.contains('\u0000') && !name.contains('\\')) {
            "Rust archive contains an unsafe entry name"
        }
        require(!name.startsWith('/')) { "Rust archive contains an absolute entry name: $name" }
        val rawParts = name.split('/')
        val parts = if (rawParts.lastOrNull().isNullOrEmpty()) rawParts.dropLast(1) else rawParts
        require(parts.firstOrNull() == expectedRoot) {
            "Rust archive entry is outside its locked root: $name"
        }
        require(parts.drop(1).none { it.isEmpty() || it == "." || it == ".." }) {
            "Rust archive contains traversal syntax: $name"
        }
        return parts
    }

    private fun verifyInstallation(
        root: Path,
        host: HostPlatform,
        selectedLock: ToolchainLock,
        environment: Map<String, String>,
        versionRunner: VersionRunner,
        fileSystem: ToolchainFileSystem,
    ) {
        val suffix = if (host == HostPlatform.WINDOWS_X64) ".exe" else ""
        val rustc = root.resolve("bin").resolve("rustc$suffix")
        val cargo = root.resolve("bin").resolve("cargo$suffix")
        require(fileSystem.isRegularFile(rustc) && fileSystem.isRegularFile(cargo)) {
            "locked Rust archive did not produce rustc and cargo in bin"
        }
        verifyVersionProbe(rustc, "rustc", selectedLock.channel, environment, versionRunner)
        verifyVersionProbe(cargo, "cargo", selectedLock.channel, environment, versionRunner)
    }

    private fun isUsableInstallation(
        root: Path,
        host: HostPlatform,
        selectedLock: ToolchainLock,
        versionRunner: VersionRunner,
        fileSystem: ToolchainFileSystem,
    ): Boolean {
        return try {
            verifyInstallation(root, host, selectedLock, isolatedEnvironment(root, host), versionRunner, fileSystem)
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun verifyVersionProbe(
        executable: Path,
        command: String,
        expectedVersion: String,
        environment: Map<String, String>,
        versionRunner: VersionRunner,
    ) {
        val result = try {
            versionRunner.run(executable, listOf("--version"), environment)
        } catch (error: Exception) {
            throw RustToolchainException("locked $command version probe failed: ${error.message.orEmpty()}", error)
        }
        if (result.exitCode != 0 || !validateLockedVersion(commandOutput(result), command, expectedVersion)) {
            throw RustToolchainException("locked $command version probe rejected the deployed compiler")
        }
    }

    private fun installedToolchain(
        root: Path,
        digest: String,
        host: HostPlatform,
        target: RuntimeTarget,
    ): InstalledToolchain {
        val suffix = if (host == HostPlatform.WINDOWS_X64) ".exe" else ""
        return InstalledToolchain(
            root = root,
            rustcPath = root.resolve("bin").resolve("rustc$suffix"),
            cargoPath = root.resolve("bin").resolve("cargo$suffix"),
            host = host,
            target = target,
            digest = digest,
            environment = isolatedEnvironment(root, host),
        )
    }

    private fun isolatedEnvironment(root: Path, host: HostPlatform): Map<String, String> {
        val bin = root.resolve("bin").toAbsolutePath().normalize()
        val existingPath = System.getenv("PATH").orEmpty()
        val pathSeparator = if (host == HostPlatform.WINDOWS_X64) ';' else ':'
        return linkedMapOf(
            RUSTUP_HOME to root.resolve("rustup-home").toAbsolutePath().normalize().toString(),
            CARGO_HOME to root.resolve("cargo-home").toAbsolutePath().normalize().toString(),
            "PATH" to if (existingPath.isBlank()) bin.toString() else "$bin$pathSeparator$existingPath",
        )
    }

    private fun installationDigest(
        selectedLock: ToolchainLock,
        host: HostPlatform,
        target: RuntimeTarget,
    ): String = sha256Hex(selectedLock.canonicalMaterial(host, target).toByteArray(Charsets.UTF_8))

    private fun parseSections(text: String): LinkedHashMap<String, LinkedHashMap<String, Any>> {
        val sections = LinkedHashMap<String, LinkedHashMap<String, Any>>()
        var current: LinkedHashMap<String, Any>? = null
        text.lineSequence().forEachIndexed { index, rawLine ->
            val line = stripComment(rawLine).trim()
            if (line.isEmpty()) return@forEachIndexed
            if (line.startsWith('[')) {
                require(line.endsWith(']') && line.count { it == '[' } == 1 && line.count { it == ']' } == 1) {
                    "invalid Rust toolchain lock section at line ${index + 1}"
                }
                val name = line.substring(1, line.length - 1).trim()
                require(name.matches(Regex("[A-Za-z0-9_.-]+"))) {
                    "invalid Rust toolchain lock section at line ${index + 1}"
                }
                require(sections[name] == null) { "duplicate Rust toolchain lock section: $name" }
                current = LinkedHashMap()
                sections[name] = current
                return@forEachIndexed
            }
            val match = Regex("([A-Za-z][A-Za-z0-9_]*)\\s*=\\s*(.+)").matchEntire(line)
                ?: throw RustToolchainException("invalid Rust toolchain lock assignment at line ${index + 1}")
            val destination = current ?: throw RustToolchainException("Rust toolchain lock assignment precedes a section")
            val key = match.groupValues[1]
            require(destination[key] == null) { "duplicate Rust toolchain lock key: $key" }
            destination[key] = parseTomlValue(match.groupValues[2], index + 1)
        }
        require(sections.isNotEmpty()) { "Rust toolchain lock has no sections" }
        return sections
    }

    private fun stripComment(line: String): String {
        var quoted = false
        var escaped = false
        for (index in line.indices) {
            val character = line[index]
            if (escaped) {
                escaped = false
            } else if (character == '\\' && quoted) {
                escaped = true
            } else if (character == '"') {
                quoted = !quoted
            } else if (character == '#' && !quoted) {
                return line.substring(0, index)
            }
        }
        require(!quoted && !escaped) { "unterminated string in Rust toolchain lock" }
        return line
    }

    private fun parseTomlValue(raw: String, line: Int): Any {
        val value = raw.trim()
        if (value.startsWith('"')) {
            require(value.length >= 2 && value.endsWith('"')) { "invalid string at line $line" }
            return decodeString(value.substring(1, value.length - 1), line)
        }
        if (value.startsWith('[')) {
            require(value.endsWith(']')) { "invalid list at line $line" }
            val body = value.substring(1, value.length - 1).trim()
            if (body.isEmpty()) return emptyList<String>()
            return splitList(body).map { item ->
                val trimmed = item.trim()
                require(trimmed.startsWith('"') && trimmed.endsWith('"')) { "lock lists may contain only strings at line $line" }
                decodeString(trimmed.substring(1, trimmed.length - 1), line)
            }
        }
        require(value.matches(Regex("[0-9]+"))) { "invalid scalar at line $line" }
        return value.toLongOrNull() ?: throw RustToolchainException("numeric lock value is out of range at line $line")
    }

    private fun splitList(body: String): List<String> {
        val values = mutableListOf<String>()
        var start = 0
        var quoted = false
        var escaped = false
        body.forEachIndexed { index, character ->
            if (escaped) escaped = false
            else if (character == '\\' && quoted) escaped = true
            else if (character == '"') quoted = !quoted
            else if (character == ',' && !quoted) {
                values += body.substring(start, index)
                start = index + 1
            }
        }
        require(!quoted && !escaped) { "unterminated list string in Rust toolchain lock" }
        values += body.substring(start)
        return values
    }

    private fun decodeString(value: String, line: Int): String {
        val output = StringBuilder(value.length)
        var escaped = false
        value.forEach { character ->
            if (escaped) {
                output.append(
                    when (character) {
                        '\\' -> '\\'
                        '"' -> '"'
                        'n' -> '\n'
                        'r' -> '\r'
                        't' -> '\t'
                        else -> throw RustToolchainException("unsupported string escape at line $line")
                    },
                )
                escaped = false
            } else if (character == '\\') {
                escaped = true
            } else {
                output.append(character)
            }
        }
        require(!escaped) { "unterminated string escape at line $line" }
        return output.toString()
    }

    private fun section(
        sections: Map<String, LinkedHashMap<String, Any>>,
        name: String,
    ): LinkedHashMap<String, Any> = sections[name] ?: throw RustToolchainException("Rust toolchain lock is missing [$name]")

    private fun Map<String, Any>.requiredString(key: String): String = get(key) as? String
        ?: throw RustToolchainException("Rust toolchain lock key '$key' must be a string")

    private fun Map<String, Any>.requiredLong(key: String): Long = get(key) as? Long
        ?: throw RustToolchainException("Rust toolchain lock key '$key' must be an integer")

    private fun Map<String, Any>.optionalLong(key: String): Long? = get(key)?.let {
        it as? Long ?: throw RustToolchainException("Rust toolchain lock key '$key' must be an integer")
    }

    @Suppress("UNCHECKED_CAST")
    private fun Map<String, Any>.requiredStringList(key: String): List<String> = get(key)?.let { value ->
        (value as? List<*>)?.map {
            it as? String ?: throw RustToolchainException("Rust toolchain lock list '$key' must contain strings")
        } ?: throw RustToolchainException("Rust toolchain lock key '$key' must be a string list")
    } ?: throw RustToolchainException("Rust toolchain lock is missing key '$key'")

    private fun Map<String, Any>.requireOnly(vararg allowed: String) {
        val unknown = keys - allowed.toSet()
        require(unknown.isEmpty()) { "Rust toolchain lock contains unknown keys: ${unknown.joinToString()}" }
    }

    private fun Long.toIntChecked(name: String): Int {
        require(this in 0L..Int.MAX_VALUE.toLong()) { "Rust toolchain lock $name is out of range" }
        return toInt()
    }

    private fun validateLockedVersion(versionOutput: String, command: String, expectedVersion: String): Boolean =
        Regex("\\A$command\\s+([0-9]+\\.[0-9]+\\.[0-9]+)(?=\\s|\\z)")
            .find(versionOutput.trimStart())
            ?.groupValues
            ?.get(1) == expectedVersion

    private fun commandOutput(result: CommandResult): String = listOf(result.stdout, result.stderr)
        .filter(String::isNotBlank)
        .joinToString("\n")

    private fun findExecutable(
        environmentVariable: String,
        command: String,
        environment: Map<String, String>,
        pathEnv: String?,
        host: HostPlatform,
    ): Path? {
        val configured = environment[environmentVariable]?.trim()?.takeIf(String::isNotEmpty)
        if (configured != null) {
            val path = try {
                Paths.get(configured)
            } catch (_: java.nio.file.InvalidPathException) {
                return null
            }
            return path.takeIf { isUsableExecutable(it, host) }
        }
        if (pathEnv.isNullOrBlank()) return null
        val windowsHost = host == HostPlatform.WINDOWS_X64
        val names = if (windowsHost) listOf("$command.exe", command) else listOf(command)
        val pathSeparator = if (windowsHost) ';' else ':'
        return pathEnv.split(pathSeparator)
            .asSequence()
            .filter(String::isNotBlank)
            .mapNotNull {
                try {
                    Paths.get(it)
                } catch (_: java.nio.file.InvalidPathException) {
                    null
                }
            }
            .flatMap { directory -> names.asSequence().map { directory.resolve(it) } }
            .firstOrNull { isUsableExecutable(it, host) }
    }

    private fun requireSupportedArchitecture(arch: String) {
        if (arch !in setOf("amd64", "x86_64", "x64")) {
            throw RustToolchainException("AKEN-R1 Rust runtime requires x86_64; host architecture was $arch")
        }
    }

    private fun isUsableExecutable(path: Path, host: HostPlatform): Boolean {
        if (!path.isAbsolute) return false
        return try {
            if (!Files.isRegularFile(path) || !Files.isExecutable(path)) return false
            when (host) {
                HostPlatform.WINDOWS_X64 -> path.fileName?.toString()?.endsWith(".exe", ignoreCase = true) == true
                HostPlatform.LINUX_X64 -> true
            }
        } catch (_: SecurityException) {
            false
        }
    }

    private fun fetchArchive(spec: ArchiveSpec): ArchiveFetch {
        val connection = URI.create(spec.url).toURL().openConnection()
        if (connection is HttpURLConnection) {
            connection.instanceFollowRedirects = false
            connection.connectTimeout = 15_000
            connection.readTimeout = 60_000
            if (connection.responseCode != HttpURLConnection.HTTP_OK) {
                connection.disconnect()
                throw RustToolchainException("Rust archive server returned HTTP ${connection.responseCode}: ${spec.url}")
            }
        } else {
            throw RustToolchainException("Rust archive URL did not produce an HTTP connection: ${spec.url}")
        }
        val length = connection.contentLengthLong
        return ArchiveFetch(connection.inputStream, length)
    }

    private fun runVersion(executable: Path, arguments: List<String>, environment: Map<String, String>): CommandResult {
        val command = listOf(executable.toString()) + arguments
        return try {
            val process = ProcessBuilder(command).apply {
                redirectErrorStream(true)
                environment().putAll(environment)
            }.start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            val exitCode = process.waitFor()
            CommandResult(exitCode, stdout = output)
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw RustToolchainException("Rust compiler version probe was interrupted", error)
        } catch (error: Exception) {
            throw RustToolchainException("failed to execute Rust compiler version probe: ${error.message.orEmpty()}", error)
        }
    }

    private fun runCommand(command: List<String>): CommandResult {
        if (command.isEmpty()) throw RustToolchainException("cannot execute an empty Rust command")
        return try {
            val process = ProcessBuilder(command).redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().use { it.readText() }
            CommandResult(process.waitFor(), stdout = output)
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw RustToolchainException("Rust command was interrupted", error)
        } catch (error: Exception) {
            throw RustToolchainException("failed to execute Rust command: ${error.message.orEmpty()}", error)
        }
    }

    private fun sha256Hex(value: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(value)
        .joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xff) }

    private fun hexToBytes(value: String): ByteArray {
        require(value.length == 64) { "SHA-256 hexadecimal value must be 64 characters" }
        return ByteArray(32) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private val REAL_FILE_SYSTEM: ToolchainFileSystem = object : ToolchainFileSystem {
        override fun exists(path: Path): Boolean = Files.exists(path)

        override fun isRegularFile(path: Path): Boolean = Files.isRegularFile(path)

        override fun createDirectories(path: Path) {
            Files.createDirectories(path)
        }

        override fun createTempDirectory(parent: Path, prefix: String): Path = Files.createTempDirectory(parent, prefix)

        override fun openInput(path: Path): InputStream = Files.newInputStream(path, StandardOpenOption.READ)

        override fun openOutput(path: Path): OutputStream = Files.newOutputStream(
            path,
            StandardOpenOption.CREATE_NEW,
            StandardOpenOption.WRITE,
        )

        override fun setExecutable(path: Path) {
            if (!path.toFile().setExecutable(true, false) && !Files.isExecutable(path)) {
                throw RustToolchainException("unable to mark extracted Rust binary executable: $path")
            }
        }

        override fun deleteRecursively(path: Path) {
            if (!Files.exists(path)) return
            Files.walk(path).use { stream ->
                stream.sorted(Comparator.reverseOrder()).forEach { candidate ->
                    Files.deleteIfExists(candidate)
                }
            }
        }

        override fun moveAtomically(source: Path, target: Path) {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE)
        }

        override fun acquireInstallLock(path: Path, timeoutMillis: Long): InstallLock {
            createDirectories(path.parent)
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
                        throw RustToolchainException("Rust install lock acquisition was interrupted", error)
                    }
                }
                if (held == null) throw RustToolchainException("timed out acquiring Rust install lock: $path")
                val acquired = held
                return object : InstallLock {
                    override fun close() {
                        runCatching { acquired.release() }
                        runCatching { channel.close() }
                    }
                }
            } catch (error: Exception) {
                runCatching { held?.release() }
                runCatching { channel.close() }
                if (error is RustToolchainException) throw error
                throw RustToolchainException("failed to acquire Rust install lock: ${error.message.orEmpty()}", error)
            }
        }
    }
}
