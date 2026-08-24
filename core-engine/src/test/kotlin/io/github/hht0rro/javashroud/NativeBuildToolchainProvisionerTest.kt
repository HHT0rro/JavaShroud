package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeBuildToolchainProvisioner
import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NativeBuildToolchainProvisionerTest {
    @Test
    fun clean_machine_downloads_and_caches_zig_and_cargo_zigbuild() {
        withTempDirectory { home ->
            val zigBytes = zipBytesOf(mapOf("zig-windows-x86_64-0.13.0/zig.exe" to "zig fixture"))
            val cargoBytes = zipBytesOf(mapOf("cargo-zigbuild.exe" to "cargo-zigbuild fixture"))
            val specOverrides = mapOf(
                "zig" to fixtureSpec(
                    NativeBuildToolchainProvisioner.zigArchive(RustToolchainProvisioner.HostPlatform.WINDOWS_X64),
                    zigBytes,
                ),
                "cargo-zigbuild" to fixtureSpec(
                    NativeBuildToolchainProvisioner.cargoZigbuildArchive(RustToolchainProvisioner.HostPlatform.WINDOWS_X64),
                    cargoBytes,
                ),
            )
            val fetcher = NativeBuildToolchainProvisioner.ArchiveFetcher { spec ->
                val bytes = if (spec.url.contains("ziglang")) zigBytes else cargoBytes
                ByteArrayInputStream(bytes) to bytes.size.toLong()
            }
            val versionRunner = RustToolchainProvisioner.VersionRunner { executable, _, _ ->
                val output = when (executable.fileName.toString()) {
                    "zig.exe" -> "0.13.0"
                    "cargo-zigbuild.exe" -> "cargo-zigbuild 0.23.2"
                    else -> error("unexpected probe: $executable")
                }
                RustToolchainProvisioner.CommandResult(0, stdout = output)
            }
            val tools = NativeBuildToolchainProvisioner.resolve(
                osName = "Windows 11",
                osArch = "amd64",
                userHome = home,
                pathEnv = null,
                fetcher = fetcher,
                versionRunner = versionRunner,
                specOverrides = specOverrides,
            )
            assertTrue(Files.isRegularFile(tools.zigPath))
            assertTrue(Files.isRegularFile(tools.cargoZigbuildPath))
            assertEquals(2, tools.pathEntries.size)
            assertTrue(tools.messages.any { it.message.contains("Downloading locked zig") })

            val cached = NativeBuildToolchainProvisioner.resolve(
                osName = "Windows 11",
                osArch = "amd64",
                userHome = home,
                pathEnv = null,
                fetcher = NativeBuildToolchainProvisioner.ArchiveFetcher { error("cache hit must not fetch") },
                versionRunner = versionRunner,
            )
            assertEquals(tools.zigPath, cached.zigPath)
        }
    }

    private fun fixtureSpec(
        spec: NativeBuildToolchainProvisioner.ArchiveSpec,
        bytes: ByteArray,
    ): NativeBuildToolchainProvisioner.ArchiveSpec = spec.copy(
        size = bytes.size.toLong(),
        sha256 = sha256Hex(bytes),
    )

    private fun zipBytesOf(files: Map<String, String>): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            files.forEach { (name, content) ->
                zip.putNextEntry(ZipEntry(name))
                zip.write(content.toByteArray())
                zip.closeEntry()
            }
        }
        return output.toByteArray()
    }

    private fun sha256Hex(bytes: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun withTempDirectory(block: (Path) -> Unit) {
        val directory = Files.createTempDirectory("javashroud-build-tools-")
        try {
            block(directory)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }
}
