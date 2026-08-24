package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeBuildToolchainProvisioner
import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RustToolchainProvisionerTest {
    @Test
    fun locked_targets_have_only_the_r1_windows_and_linux_routes() {
        assertEquals("1.78.0", RustToolchainProvisioner.lock.channel)
        assertEquals(
            listOf("windows-x64", "linux-x64"),
            RustToolchainProvisioner.lock.targets.map { it.id },
        )
        assertEquals(
            listOf("x86_64-pc-windows-gnu", "x86_64-unknown-linux-gnu"),
            RustToolchainProvisioner.lock.targets.map { it.rustupTarget },
        )
        assertEquals("2.17", RustToolchainProvisioner.target("x86_64-unknown-linux-gnu.2.17").glibcFloor)
        assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
            RustToolchainProvisioner.target("x86_64-apple-darwin")
        }
        assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
            RustToolchainProvisioner.target("x86_64-unknown-linux-gnu")
        }
    }

    @Test
    fun host_validation_rejects_macos_and_non_x86_hosts() {
        assertEquals(
            RustToolchainProvisioner.HostPlatform.WINDOWS_X64,
            RustToolchainProvisioner.hostPlatform("Windows 11", "amd64"),
        )
        assertEquals(
            RustToolchainProvisioner.HostPlatform.LINUX_X64,
            RustToolchainProvisioner.hostPlatform("Linux", "x86_64"),
        )
        assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
            RustToolchainProvisioner.hostPlatform("macOS", "x86_64")
        }
        val armMacError = assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
            RustToolchainProvisioner.hostPlatform("macOS", "aarch64")
        }
        assertTrue(armMacError.message.orEmpty().contains("macOS"))
        assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
            RustToolchainProvisioner.hostPlatform("Linux", "aarch64")
        }
    }

    @Test
    fun resolution_uses_explicit_tool_paths_and_fails_closed_when_incomplete() {
        withTempDirectory { home ->
            val rustc = createTool(home, "rustc", RustToolchainProvisioner.HostPlatform.WINDOWS_X64)
            val cargo = createTool(home, "cargo", RustToolchainProvisioner.HostPlatform.WINDOWS_X64)
            val result = RustToolchainProvisioner.resolve(
                environment = mapOf(
                    "JAVASHROUD_RUSTC" to rustc.toString(),
                    "JAVASHROUD_CARGO" to cargo.toString(),
                ),
                pathEnv = null,
                osName = "Windows 11",
                osArch = "amd64",
                commandRunner = lockedVersionRunner(rustc, cargo),
            )
            assertEquals(rustc, result.toolchain?.rustcPath)
            assertEquals(cargo, result.toolchain?.cargoPath)

            val incomplete = RustToolchainProvisioner.resolve(
                environment = mapOf("JAVASHROUD_RUSTC" to rustc.toString()),
                pathEnv = null,
                osName = "Windows 11",
                osArch = "amd64",
            )
            assertEquals(null, incomplete.toolchain)
            assertTrue(incomplete.messages.any { it.level == "warn" })
        }
    }

    @Test
    fun resolution_uses_linux_route_rules_when_host_platform_is_linux() {
        withTempDirectory { home ->
            val rustc = createTool(home, "rustc", RustToolchainProvisioner.HostPlatform.LINUX_X64)
            val cargo = createTool(home, "cargo", RustToolchainProvisioner.HostPlatform.LINUX_X64)
            val result = RustToolchainProvisioner.resolve(
                environment = mapOf(
                    "JAVASHROUD_RUSTC" to rustc.toString(),
                    "JAVASHROUD_CARGO" to cargo.toString(),
                ),
                pathEnv = null,
                osName = "Linux",
                osArch = "x86_64",
                commandRunner = lockedVersionRunner(rustc, cargo),
            )

            assertEquals(RustToolchainProvisioner.HostPlatform.LINUX_X64, result.toolchain?.host)
            assertEquals(rustc, result.toolchain?.rustcPath)
            assertEquals(cargo, result.toolchain?.cargoPath)
        }
    }

    @Test
    fun resolution_rejects_macos_before_toolchain_lookup() {
        val result = RustToolchainProvisioner.resolve(
            environment = mapOf(
                "JAVASHROUD_RUSTC" to "macos-rustc",
                "JAVASHROUD_CARGO" to "macos-cargo",
            ),
            pathEnv = null,
            osName = "macOS",
            osArch = "aarch64",
        )

        assertEquals(null, result.toolchain)
        assertTrue(result.messages.any { it.level == "warn" && it.message.contains("rejects macOS") })
    }

    @Test
    fun resolution_rejects_unlocked_versions_and_relative_overrides() {
        withTempDirectory { home ->
            val rustc = createTool(home, "rustc", RustToolchainProvisioner.HostPlatform.LINUX_X64)
            val cargo = createTool(home, "cargo", RustToolchainProvisioner.HostPlatform.LINUX_X64)
            val mismatched = RustToolchainProvisioner.resolve(
                environment = mapOf(
                    "JAVASHROUD_RUSTC" to rustc.toString(),
                    "JAVASHROUD_CARGO" to cargo.toString(),
                ),
                pathEnv = null,
                osName = "Linux",
                osArch = "x86_64",
                commandRunner = {
                    if (it[0] == rustc.toString()) {
                        RustToolchainProvisioner.CommandResult(0, stdout = "rustc 1.95.0 (future)")
                    } else {
                        RustToolchainProvisioner.CommandResult(0, stdout = "cargo 1.78.0 (locked)")
                    }
                },
            )
            assertEquals(null, mismatched.toolchain)
            assertTrue(mismatched.messages.any { it.level == "warn" })

            val relative = RustToolchainProvisioner.resolve(
                environment = mapOf(
                    "JAVASHROUD_RUSTC" to rustc.fileName.toString(),
                    "JAVASHROUD_CARGO" to cargo.fileName.toString(),
                ),
                pathEnv = null,
                osName = "Linux",
                osArch = "x86_64",
            )
            assertEquals(null, relative.toolchain)
        }
    }

    @Test
    fun lookup_uses_the_requested_windows_separator_and_suffix() {
        withTempDirectory { home ->
            val rustc = createTool(home, "rustc", RustToolchainProvisioner.HostPlatform.WINDOWS_X64)
            val cargo = createTool(home, "cargo", RustToolchainProvisioner.HostPlatform.WINDOWS_X64)
            val result = RustToolchainProvisioner.resolve(
                environment = emptyMap(),
                pathEnv = "${home.resolve("missing")};$home",
                osName = "Windows 11",
                osArch = "amd64",
                commandRunner = lockedVersionRunner(rustc, cargo),
            )
            assertEquals(rustc, result.toolchain?.rustcPath)
            assertEquals(cargo, result.toolchain?.cargoPath)
        }
    }

    @Test
    fun rustup_command_contains_only_the_locked_targets() {
        val command = RustToolchainProvisioner.rustupInstallCommand(Path.of("rustup"))
        assertEquals(
            listOf(
                "rustup", "toolchain", "install", "1.78.0", "--profile", "minimal", "--no-self-update",
                "--component", "rustfmt", "--component", "clippy",
                "--target", "x86_64-pc-windows-gnu", "--target", "x86_64-unknown-linux-gnu",
            ),
            command,
        )
        assertFalse(command.any { it.contains("dylib") || it.contains("zig") || it.endsWith(".c") })
    }

    @Test
    fun locked_deployment_verifies_archives_stages_atomically_and_reuses_cache() {
        withTempDirectory { home ->
            val fixtures = fixtureArchives()
            val lockText = fixtureLock(fixtures)
            val fetched = mutableListOf<String>()
            val versionRunner = RustToolchainProvisioner.VersionRunner { executable, _, _ ->
                when (executable.fileName.toString()) {
                    "rustc" -> RustToolchainProvisioner.CommandResult(0, stdout = "rustc 1.78.0 (fixture)")
                    "cargo" -> RustToolchainProvisioner.CommandResult(0, stdout = "cargo 1.78.0 (fixture)")
                    else -> RustToolchainProvisioner.CommandResult(1, stderr = "unexpected probe")
                }
            }
            val fetcher = RustToolchainProvisioner.ArchiveFetcher { spec ->
                fetched += spec.kind
                val bytes = fixtures.getValue(spec.kind)
                RustToolchainProvisioner.ArchiveFetch(ByteArrayInputStream(bytes), bytes.size.toLong())
            }

            val installed = RustToolchainProvisioner.installLocked(
                target = "linux-x64",
                osName = "Linux",
                osArch = "x86_64",
                userHome = home,
                lockText = lockText,
                fetcher = fetcher,
                versionRunner = versionRunner,
            )
            assertEquals(listOf("cargo", "clippy", "rust", "rustfmt"), fetched)
            assertEquals(installed.root, RustToolchainProvisioner.installationDirectory(home, installed.host, "linux-x64", lockText))
            assertTrue(Files.isRegularFile(installed.rustcPath))
            assertTrue(Files.isRegularFile(installed.cargoPath))
            assertEquals(installed.root.resolve("rustup-home").toString(), installed.environment.getValue("RUSTUP_HOME"))
            assertEquals(installed.root.resolve("cargo-home").toString(), installed.environment.getValue("CARGO_HOME"))

            val reused = RustToolchainProvisioner.installLocked(
                target = "linux-x64",
                osName = "Linux",
                osArch = "x86_64",
                userHome = home,
                lockText = lockText,
                fetcher = RustToolchainProvisioner.ArchiveFetcher { error("cache hit must not fetch") },
                versionRunner = versionRunner,
            )
            assertEquals(installed.root, reused.root)
        }
    }

    @Test
    fun deployment_rejects_tampered_archive_and_cleans_staging() {
        withTempDirectory { home ->
            val fixtures = fixtureArchives()
            val lockText = fixtureLock(fixtures)
            val result = assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
                RustToolchainProvisioner.installLocked(
                    target = "linux-x64",
                    osName = "Linux",
                    osArch = "x86_64",
                    userHome = home,
                    lockText = lockText,
                    fetcher = RustToolchainProvisioner.ArchiveFetcher { spec ->
                        val bytes = fixtures.getValue(spec.kind).copyOf()
                        if (spec.kind == "cargo") bytes[bytes.lastIndex] = (bytes.last().toInt() xor 0x01).toByte()
                        RustToolchainProvisioner.ArchiveFetch(ByteArrayInputStream(bytes), bytes.size.toLong())
                    },
                    versionRunner = RustToolchainProvisioner.VersionRunner { _, _, _ ->
                        error("version probe must not run after archive tamper")
                    },
                )
            }
            assertTrue(result.message.orEmpty().contains("verification"))
            val cache = home.resolve(".javashroud").resolve("toolchains")
            assertTrue(Files.exists(cache))
            assertEquals(0L, Files.list(cache).use { stream ->
                stream.filter { it.fileName.toString().startsWith(".stage-") }.count()
            })
        }
    }

    @Test
    fun unsupported_host_is_rejected_before_cache_temp_or_network() {
        withTempDirectory { home ->
            var fetchCount = 0
            assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
                RustToolchainProvisioner.installLocked(
                    target = "linux-x64",
                    osName = "macOS",
                    osArch = "x86_64",
                    userHome = home.resolve("must-not-be-touched"),
                    fetcher = RustToolchainProvisioner.ArchiveFetcher {
                        fetchCount++
                        error("unsupported host must stop before fetch")
                    },
                )
            }
            assertEquals(0, fetchCount)
            assertFalse(Files.exists(home.resolve("must-not-be-touched")))
        }
    }

    @Test
    fun lock_parser_rejects_non_rust_distribution_urls_and_unknown_values() {
        val validLock = fixtureLock(fixtureArchives())
        val nonRustUrl = validLock.replace(
            "https://static.rust-lang.org",
            "https://example.invalid",
        )
        assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
            RustToolchainProvisioner.parseLock(nonRustUrl)
        }
        assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
            RustToolchainProvisioner.parseLock(validLock.replace("format = 1", "format = 2"))
        }
    }

    @Test
    fun locked_zig_and_cargo_zigbuild_archives_are_https_and_versioned() {
        val windowsZig = NativeBuildToolchainProvisioner.zigArchive(RustToolchainProvisioner.HostPlatform.WINDOWS_X64)
        val linuxZig = NativeBuildToolchainProvisioner.zigArchive(RustToolchainProvisioner.HostPlatform.LINUX_X64)
        val windowsCargo = NativeBuildToolchainProvisioner.cargoZigbuildArchive(RustToolchainProvisioner.HostPlatform.WINDOWS_X64)
        val linuxCargo = NativeBuildToolchainProvisioner.cargoZigbuildArchive(RustToolchainProvisioner.HostPlatform.LINUX_X64)
        assertTrue(windowsZig.url.startsWith("https://ziglang.org/download/0.13.0/"))
        assertTrue(linuxZig.url.startsWith("https://ziglang.org/download/0.13.0/"))
        assertTrue(windowsCargo.url.startsWith("https://github.com/rust-cross/cargo-zigbuild/releases/download/v0.23.2/"))
        assertTrue(linuxCargo.url.startsWith("https://github.com/rust-cross/cargo-zigbuild/releases/download/v0.23.2/"))
        assertEquals(64, windowsZig.sha256.length)
        assertEquals(64, linuxCargo.sha256.length)
    }

    @Test
    fun rust_and_cargo_versions_must_match_the_lock() {
        assertTrue(RustToolchainProvisioner.validateRustcVersion("rustc 1.78.0 (9b00956e5 2024-04-29)"))
        assertTrue(RustToolchainProvisioner.validateCargoVersion("cargo 1.78.0 (54d8815d 2024-03-26)"))
        assertFalse(RustToolchainProvisioner.validateRustcVersion("rustc 1.79.0 (future)"))
        assertFalse(RustToolchainProvisioner.validateCargoVersion("cargo 1.78.0-dev"))
        assertFalse(RustToolchainProvisioner.validateRustcVersion("rustc 1.78.0evil"))
        assertFalse(RustToolchainProvisioner.validateRustcVersion("cargo 1.78.0"))
    }

    private fun fixtureArchives(): Map<String, ByteArray> = listOf("rust", "cargo", "rustfmt", "clippy")
        .associateWith { kind ->
            val root = "fixture-$kind"
            val files = when (kind) {
                "rust" -> mapOf("bin/rustc" to "rustc fixture", "lib/rustlib/stamp" to "std fixture")
                "cargo" -> mapOf("bin/cargo" to "cargo fixture")
                "rustfmt" -> mapOf("bin/rustfmt" to "rustfmt fixture")
                "clippy" -> mapOf("bin/clippy-driver" to "clippy fixture")
                else -> error("unexpected fixture component: $kind")
            }
            val tarBytes = ByteArrayOutputStream()
            XZCompressorOutputStream(tarBytes).use { xz ->
                TarArchiveOutputStream(xz).use { tar ->
                    files.forEach { (relative, content) ->
                        val bytes = content.toByteArray()
                        val entry = TarArchiveEntry("$root/$relative")
                        entry.size = bytes.size.toLong()
                        tar.putArchiveEntry(entry)
                        tar.write(bytes)
                        tar.closeArchiveEntry()
                    }
                    tar.finish()
                }
            }
            tarBytes.toByteArray()
        }

    private fun fixtureLock(fixtures: Map<String, ByteArray>): String = buildString {
        appendLine("[lock]")
        appendLine("format = 1")
        appendLine("channel = \"1.78.0\"")
        appendLine("profile = \"minimal\"")
        appendLine("components = [\"rustfmt\", \"clippy\"]")
        appendLine("max_archive_bytes = 1048576")
        appendLine("max_extracted_bytes = 4194304")
        appendLine("max_archive_entries = 64")
        appendLine("archive_count = ${fixtures.size}")
        appendLine()
        appendLine("[target.windows-x64]")
        appendLine("rustup_target = \"x86_64-pc-windows-gnu\"")
        appendLine("artifact_suffix = \".dll\"")
        appendLine("glibc_floor = \"\"")
        appendLine()
        appendLine("[target.linux-x64]")
        appendLine("rustup_target = \"x86_64-unknown-linux-gnu\"")
        appendLine("artifact_suffix = \".so\"")
        appendLine("glibc_floor = \"2.17\"")
        fixtures.toSortedMap().forEach { (kind, bytes) ->
            val sha = MessageDigest.getInstance("SHA-256").digest(bytes)
                .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            appendLine()
            appendLine("[archive.$kind]")
            appendLine("host = \"linux-x64\"")
            appendLine("target = \"linux-x64\"")
            appendLine("kind = \"$kind\"")
            appendLine("url = \"https://static.rust-lang.org/dist/fixture-$kind.tar.xz\"")
            appendLine("size = ${bytes.size}")
            appendLine("sha256 = \"$sha\"")
            appendLine("root = \"fixture-$kind\"")
        }
    }

    private fun lockedVersionRunner(
        rustc: Path,
        cargo: Path,
    ): (List<String>) -> RustToolchainProvisioner.CommandResult = { command ->
        when (command) {
            listOf(rustc.toString(), "--version") ->
                RustToolchainProvisioner.CommandResult(0, stdout = "rustc 1.78.0 (9b00956e5 2024-04-29)")
            listOf(cargo.toString(), "--version") ->
                RustToolchainProvisioner.CommandResult(0, stdout = "cargo 1.78.0 (54d8815d 2024-03-26)")
            else -> error("unexpected toolchain probe command: $command")
        }
    }

    private fun createTool(
        directory: Path,
        name: String,
        host: RustToolchainProvisioner.HostPlatform,
    ): Path {
        val filename = if (host == RustToolchainProvisioner.HostPlatform.WINDOWS_X64) "$name.exe" else name
        return directory.resolve(filename).also {
            Files.writeString(it, "fixture")
            it.toFile().setExecutable(true)
        }
    }

    private fun <T> withTempDirectory(block: (Path) -> T): T {
        val directory = Files.createTempDirectory("javashroud-rust-toolchain-")
        return try {
            block(directory)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }
}
