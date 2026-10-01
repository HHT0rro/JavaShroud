package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import io.github.hht0rro.javashroud.model.config.HardenedProtectionProfile
import io.github.hht0rro.javashroud.model.config.ObfuscationConfig
import io.github.hht0rro.javashroud.model.config.PassSpec
import io.github.hht0rro.javashroud.model.config.RuleSet
import io.github.hht0rro.javashroud.model.protocol.EngineEvent
import io.github.hht0rro.javashroud.transforms.protection.NativeShroudPacker
import io.github.hht0rro.javashroud.transforms.protection.QpNativeCompilerPass
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NativeShroudPackerTest {
    @Test
    fun disabled_pass_leaves_compiled_natives_unchanged() {
        val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(1, 2, 3))
        val linux = native("linux-x64", "libqp_ffi.so", byteArrayOf(9, 8, 7))
        val result = NativeShroudPacker.packIfRequested(
            config = config(enabled = false),
            compiled = listOf(windows, linux),
        )
        assertEquals(listOf(windows, linux), result)
    }

    @Test
    fun enabled_pass_without_packed_path_or_handoff_fails_closed() {
        val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(1, 2, 3))
        val error = assertFailsWith<IllegalStateException> {
            NativeShroudPacker.packIfRequested(
                config = config(enabled = true),
                compiled = listOf(windows),
                handoffEnabled = false,
            )
        }
        assertTrue(error.message.orEmpty().contains("packedPath"))
        assertTrue(windows.bytes.all { it == 0.toByte() })
    }

    @Test
    fun packed_path_replaces_windows_bytes() {
        val workDir = Files.createTempDirectory("javashroud-pack-path")
        try {
            val packedBytes = SyntheticPackedImages.windowsPackedDll()
            val packedFile = workDir.resolve("packed.dll").also { Files.write(it, packedBytes) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(10, 20, 30, 40))
            val result = NativeShroudPacker.packIfRequested(
                config = config(enabled = true, packedPath = packedFile.toString()),
                compiled = listOf(windows),
                workDir = workDir,
                handoffEnabled = false,
            )
            assertTrue(result.single().bytes.contentEquals(packedBytes))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun handoff_stdin_path_replaces_bytes_and_emits_need_pack() {
        val workDir = Files.createTempDirectory("javashroud-pack-handoff-stdin")
        try {
            val packedBytes = SyntheticPackedImages.windowsPackedDll()
            val packedFile = workDir.resolve("user-packed.dll").also { Files.write(it, packedBytes) }
            val events = mutableListOf<EngineEvent>()
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(1, 1, 1, 1))
            val result = NativeShroudPacker.packIfRequested(
                config = config(enabled = true),
                compiled = listOf(windows),
                emit = { events.add(it) },
                workDir = workDir,
                handoffEnabled = true,
                readHandoffLine = { packedFile.toAbsolutePath().toString() },
            )
            assertTrue(result.single().bytes.contentEquals(packedBytes))
            val needPack = events.single { it.type == "need-pack" }
            assertEquals("info", needPack.level)
            assertEquals(94, needPack.progress)
            assertTrue(needPack.outPath.orEmpty().endsWith("qp_ffi.dll"))
            assertTrue(Files.isRegularFile(Path.of(needPack.outPath!!)))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun windows_handoff_cancel_zeros_bytes_and_fails_closed() {
        val workDir = Files.createTempDirectory("javashroud-pack-cancel")
        try {
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(11, 12, 13))
            val error = assertFailsWith<IllegalStateException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = true,
                    readHandoffLine = { null },
                )
            }
            assertTrue(error.message.orEmpty().contains("canceled") || error.message.orEmpty().contains("stdin"))
            assertTrue(windows.bytes.all { it == 0.toByte() })
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun windows_empty_packed_file_fails_closed() {
        val workDir = Files.createTempDirectory("javashroud-pack-empty")
        try {
            val emptyPacked = workDir.resolve("empty.dll").also { Files.write(it, ByteArray(0)) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(8, 8, 8))
            val error = assertFailsWith<IllegalStateException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true, packedPath = emptyPacked.toString()),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                )
            }
            assertTrue(error.message.orEmpty().contains("empty"))
            assertTrue(windows.bytes.all { it == 0.toByte() })
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun windows_packed_bytes_without_js_measurement_section_fail_with_named_error() {
        val workDir = Files.createTempDirectory("javashroud-pack-nosection")
        try {
            val brokenBytes = SyntheticPackedImages.windowsPackedDll(dropSection = ".jsmk")
            val brokenFile = workDir.resolve("broken.dll").also { Files.write(it, brokenBytes) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(8, 8, 8))
            val error = assertFailsWith<IllegalStateException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true, packedPath = brokenFile.toString()),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                )
            }
            assertTrue(error.message.orEmpty().contains(".jsmk"))
            assertTrue(windows.bytes.all { it == 0.toByte() })
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun linux_skip_ships_unpacked_cdylib() {
        val workDir = Files.createTempDirectory("javashroud-pack-linux-skip")
        try {
            val linux = native("linux-x64", "libqp_ffi.so", byteArrayOf(7, 7, 7))
            val events = mutableListOf<EngineEvent>()
            val result = NativeShroudPacker.packIfRequested(
                config = config(enabled = true),
                compiled = listOf(linux),
                emit = { events.add(it) },
                workDir = workDir,
                handoffEnabled = true,
                readHandoffLine = { "SKIP" },
            )
            assertTrue(result.single().bytes.contentEquals(byteArrayOf(7, 7, 7)))
            assertTrue(events.any { it.type == "need-pack" && it.outPath.orEmpty().endsWith("libqp_ffi.so") })
            assertTrue(events.any { it.message.contains("skipped linux-x64") })
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun linux_packed_path_replaces_bytes() {
        val workDir = Files.createTempDirectory("javashroud-pack-linux-path")
        try {
            val packedBytes = SyntheticPackedImages.linuxPackedSo()
            val packedFile = workDir.resolve("packed.so").also { Files.write(it, packedBytes) }
            val linux = native("linux-x64", "libqp_ffi.so", byteArrayOf(9, 9, 9))
            val result = NativeShroudPacker.packIfRequested(
                config = config(enabled = true, packedPathLinux = packedFile.toString()),
                compiled = listOf(linux),
                workDir = workDir,
                handoffEnabled = false,
            )
            assertTrue(result.single().bytes.contentEquals(packedBytes))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun linux_bytes_that_are_not_elf_fail_with_named_error() {
        val workDir = Files.createTempDirectory("javashroud-pack-linux-bad")
        try {
            val brokenFile = workDir.resolve("packed.so").also { Files.write(it, byteArrayOf(1, 2, 3, 4)) }
            val linux = native("linux-x64", "libqp_ffi.so", byteArrayOf(9, 9, 9))
            val error = assertFailsWith<IllegalStateException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true, packedPathLinux = brokenFile.toString()),
                    compiled = listOf(linux),
                    workDir = workDir,
                    handoffEnabled = false,
                )
            }
            assertTrue(error.message.orEmpty().contains("ELF"))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun multi_platform_emits_need_pack_sequentially() {
        val workDir = Files.createTempDirectory("javashroud-pack-multi")
        try {
            val packedWindowsBytes = SyntheticPackedImages.windowsPackedDll()
            val packedLinuxBytes = SyntheticPackedImages.linuxPackedSo()
            val packedWindows = workDir.resolve("w.dll").also { Files.write(it, packedWindowsBytes) }
            val packedLinux = workDir.resolve("l.so").also { Files.write(it, packedLinuxBytes) }
            val replies = listOf(packedWindows.toString(), packedLinux.toString())
            val index = AtomicInteger(0)
            val events = mutableListOf<EngineEvent>()
            val result = NativeShroudPacker.packIfRequested(
                config = config(enabled = true),
                compiled = listOf(
                    native("windows-x64", "qp_ffi.dll", byteArrayOf(1)),
                    native("linux-x64", "libqp_ffi.so", byteArrayOf(1)),
                ),
                emit = { events.add(it) },
                workDir = workDir,
                handoffEnabled = true,
                readHandoffLine = { replies[index.getAndIncrement()] },
            )
            assertEquals(2, events.count { it.type == "need-pack" })
            assertTrue(result[0].bytes.contentEquals(packedWindowsBytes))
            assertTrue(result[1].bytes.contentEquals(packedLinuxBytes))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_cli_spawn_replaces_windows_bytes_with_version_and_pack_invocations() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val packedBytes = SyntheticPackedImages.windowsPackedDll()
            val runner = FakeXenolithCli(packedBytes)
            val events = mutableListOf<EngineEvent>()
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(3, 3, 3))
            val result = NativeShroudPacker.packIfRequested(
                config = config(enabled = true, cliPath = cliFile.toString(), profile = "fast"),
                compiled = listOf(windows),
                emit = { events.add(it) },
                workDir = workDir,
                handoffEnabled = false,
                cliRunner = runner,
            )
            assertTrue(result.single().bytes.contentEquals(packedBytes))
            assertEquals(listOf("--version"), runner.invocations.first())
            val packArgs = runner.invocations[1]
            assertEquals("pack", packArgs[0])
            assertTrue(packArgs[1].endsWith("qp_ffi.dll"))
            assertEquals("-o", packArgs[2])
            assertTrue(packArgs[3].endsWith("qp_ffi.dll.xenolith-packed"))
            assertEquals("--profile", packArgs[4])
            assertEquals("fast", packArgs[5])
            assertEquals("--json", packArgs[6])
            assertTrue(events.any { it.message.contains("xenolith 0.1.0-test") })
            assertTrue(events.any { it.message.contains("Xenolith packed qp_ffi.dll") })
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_cli_spawn_takes_priority_over_packed_path() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-priority")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val manualBytes = SyntheticPackedImages.windowsPackedDll(dropExport = "JNI_OnUnload")
            val manualPacked = workDir.resolve("manual.dll").also { Files.write(it, manualBytes) }
            val spawnedBytes = SyntheticPackedImages.windowsPackedDll()
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(4, 4))
            val result = NativeShroudPacker.packIfRequested(
                config = config(
                    enabled = true,
                    cliPath = cliFile.toString(),
                    profile = "standard",
                    packedPath = manualPacked.toString(),
                ),
                compiled = listOf(windows),
                workDir = workDir,
                handoffEnabled = false,
                cliRunner = FakeXenolithCli(spawnedBytes),
            )
            assertTrue(result.single().bytes.contentEquals(spawnedBytes))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_cli_spawn_nonzero_exit_fails_closed_and_zeros_bytes() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-fail")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(5, 5))
            val error = assertFailsWith<IllegalStateException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true, cliPath = cliFile.toString()),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                    cliRunner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll(), exitCode = 2),
                )
            }
            assertTrue(error.message.orEmpty().contains("exited with code 2"))
            assertTrue(windows.bytes.all { it == 0.toByte() })
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_cli_spawn_without_output_file_fails_closed() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-nooutput")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(6, 6))
            val error = assertFailsWith<IllegalStateException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true, cliPath = cliFile.toString()),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                    cliRunner = FakeXenolithCli(packedBytes = null),
                )
            }
            assertTrue(error.message.orEmpty().contains("does not exist"))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_cli_spawn_report_profile_mismatch_fails_closed() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-mismatch")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(7, 7))
            val error = assertFailsWith<IllegalStateException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true, cliPath = cliFile.toString(), profile = "fast"),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                    cliRunner = FakeXenolithCli(
                        SyntheticPackedImages.windowsPackedDll(),
                        report = """{"report_version":1,"profile":"max","format":"pe-dll"}""",
                    ),
                )
            }
            assertTrue(error.message.orEmpty().contains("does not match requested profile"))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_cli_spawn_output_without_js_measurement_sections_fails_closed() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-badoutput")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(9, 9))
            val error = assertFailsWith<IllegalStateException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true, cliPath = cliFile.toString()),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                    cliRunner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll(dropSection = ".jsms")),
                )
            }
            assertTrue(error.message.orEmpty().contains(".jsms"))
            assertTrue(windows.bytes.all { it == 0.toByte() })
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_invalid_profile_fails_immediately() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-badprofile")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(1, 2))
            val error = assertFailsWith<IllegalArgumentException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true, cliPath = cliFile.toString(), profile = "ultra"),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                    cliRunner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll()),
                )
            }
            assertTrue(error.message.orEmpty().contains("fast/standard/max"))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_missing_cli_file_fails_with_named_error() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-nocli")
        try {
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(1, 2))
            val error = assertFailsWith<IllegalStateException> {
                NativeShroudPacker.packIfRequested(
                    config = config(enabled = true, cliPath = workDir.resolve("missing.exe").toString()),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                    cliRunner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll()),
                )
            }
            assertTrue(error.message.orEmpty().contains("cliPath does not exist"))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun linux_ignores_xenolith_cli_and_keeps_skip_flow() {
        val workDir = Files.createTempDirectory("javashroud-pack-linux-cli")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val linux = native("linux-x64", "libqp_ffi.so", byteArrayOf(2, 2, 2))
            val events = mutableListOf<EngineEvent>()
            val runner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll())
            val result = NativeShroudPacker.packIfRequested(
                config = config(enabled = true, cliPath = cliFile.toString()),
                compiled = listOf(linux),
                emit = { events.add(it) },
                workDir = workDir,
                handoffEnabled = true,
                readHandoffLine = { "SKIP" },
                cliRunner = runner,
            )
            assertTrue(result.single().bytes.contentEquals(byteArrayOf(2, 2, 2)))
            assertTrue(events.any { it.message.contains("windows-x64 only") })
            assertTrue(runner.invocations.isNotEmpty() && runner.invocations.all { it.firstOrNull() == "--version" })
            assertTrue(runner.invocations.none { it.firstOrNull() == "pack" })
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun real_xenolith_cli_round_trip_when_env_gates_are_set() {
        val cliPath = System.getenv("JAVASHROUD_TEST_XENOLITH") ?: return
        val inputPath = System.getenv("JAVASHROUD_TEST_XENOLITH_INPUT") ?: return
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-real")
        try {
            val unpacked = Files.readAllBytes(Path.of(inputPath))
            val windows = native("windows-x64", "qp_ffi.dll", unpacked)
            val result = NativeShroudPacker.packIfRequested(
                config = config(enabled = true, cliPath = cliPath, profile = "fast"),
                compiled = listOf(windows),
                workDir = workDir,
                handoffEnabled = false,
            )
            val packedBytes = result.single().bytes
            assertTrue(packedBytes.size > 0x228)
            assertTrue(!packedBytes.contentEquals(unpacked))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_cli_spawn_passes_selection_and_g5_flags() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-flags")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val runner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll())
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(3, 3))
            NativeShroudPacker.packIfRequested(
                config(
                    enabled = true,
                    cliPath = cliFile.toString(),
                    profile = "max",
                    extraParams = mapOf(
                        "vmExports" to JsonNodeFactory.instance.textNode("fnA, fnB"),
                        "selectRva" to JsonNodeFactory.instance.textNode("0x1000:64,0x2000:32"),
                        "selectFunction" to JsonNodeFactory.instance.textNode("js_vm_parse_program"),
                        "selectAll" to JsonNodeFactory.instance.booleanNode(true),
                        "allowNativeFallback" to JsonNodeFactory.instance.booleanNode(true),
                        "protectImports" to JsonNodeFactory.instance.booleanNode(true),
                        "strictConstants" to JsonNodeFactory.instance.booleanNode(true),
                        "traceDiverge" to JsonNodeFactory.instance.booleanNode(true),
                    ),
                ),
                compiled = listOf(windows),
                workDir = workDir,
                handoffEnabled = false,
                cliRunner = runner,
            )
            val packArgs = runner.invocations.single { it.firstOrNull() == "pack" }
            assertEquals(listOf("pack", packArgs[1], "-o", packArgs[3], "--profile", "max", "--json"), packArgs.take(7))
            assertEquals(
                listOf(
                    "--vm-export", "fnA,fnB",
                    "--select-rva", "0x1000:64",
                    "--select-rva", "0x2000:32",
                    "--select-function", "js_vm_parse_program",
                    "--select-all",
                    "--allow-native-fallback",
                    "--protect-imports",
                    "--strict-constants",
                    "--trace-diverge",
                ),
                packArgs.drop(7),
            )
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_fast_profile_rejects_vm_exports() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-fastvm")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(1))
            val error = assertFailsWith<IllegalArgumentException> {
                NativeShroudPacker.packIfRequested(
                    config(
                        enabled = true,
                        cliPath = cliFile.toString(),
                        profile = "fast",
                        extraParams = mapOf("vmExports" to JsonNodeFactory.instance.textNode("someFn")),
                    ),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                    cliRunner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll()),
                )
            }
            assertTrue(error.message.orEmpty().contains("fast"))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_strict_coverage_conflicts_with_native_fallback() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-mutual")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(1))
            val error = assertFailsWith<IllegalArgumentException> {
                NativeShroudPacker.packIfRequested(
                    config(
                        enabled = true,
                        cliPath = cliFile.toString(),
                        extraParams = mapOf(
                            "strictCoverage" to JsonNodeFactory.instance.booleanNode(true),
                            "allowNativeFallback" to JsonNodeFactory.instance.booleanNode(true),
                        ),
                    ),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                    cliRunner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll()),
                )
            }
            assertTrue(error.message.orEmpty().contains("mutually exclusive"))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_vm_exports_reject_jvm_abi_names() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-abi")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            for (name in listOf("JNI_OnLoad", "Java_com_x_y", "qp_r1_open_frame", "DllMain", "_start", "ucrtbase_fn")) {
                val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(1))
                val error = assertFailsWith<IllegalArgumentException> {
                    NativeShroudPacker.packIfRequested(
                        config(
                            enabled = true,
                            cliPath = cliFile.toString(),
                            extraParams = mapOf("vmExports" to JsonNodeFactory.instance.textNode(name)),
                        ),
                        compiled = listOf(windows),
                        workDir = workDir,
                        handoffEnabled = false,
                        cliRunner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll()),
                    )
                }
                assertTrue(
                    error.message.orEmpty().contains("JVM/CRT ABI"),
                    "expected ABI rejection for $name, got: ${error.message}",
                )
            }
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    @Test
    fun xenolith_lazy_regions_is_rejected_for_jni_host_boot() {
        val workDir = Files.createTempDirectory("javashroud-pack-xenolith-lazy")
        try {
            val cliFile = workDir.resolve("xenolith.exe").also { Files.write(it, byteArrayOf(0x4D, 0x5A)) }
            val windows = native("windows-x64", "qp_ffi.dll", byteArrayOf(1))
            val error = assertFailsWith<IllegalArgumentException> {
                NativeShroudPacker.packIfRequested(
                    config(
                        enabled = true,
                        cliPath = cliFile.toString(),
                        extraParams = mapOf("lazyRegions" to JsonNodeFactory.instance.booleanNode(true)),
                    ),
                    compiled = listOf(windows),
                    workDir = workDir,
                    handoffEnabled = false,
                    cliRunner = FakeXenolithCli(SyntheticPackedImages.windowsPackedDll()),
                )
            }
            assertTrue(error.message.orEmpty().contains("loader lock"))
        } finally {
            workDir.toFile().deleteRecursively()
        }
    }

    private class FakeXenolithCli(
        private val packedBytes: ByteArray?,
        private val exitCode: Int = 0,
        private val report: String? = null,
    ) : NativeShroudPacker.XenolithCliRunner {
        val invocations = mutableListOf<List<String>>()

        override fun run(
            cliPath: String,
            args: List<String>,
            timeoutMillis: Long,
        ): NativeShroudPacker.XenolithCliResult {
            invocations.add(args.toList())
            if (args.firstOrNull() == "--version") {
                return NativeShroudPacker.XenolithCliResult(0, "xenolith 0.1.0-test\n", false)
            }
            if (exitCode != 0) {
                return NativeShroudPacker.XenolithCliResult(exitCode, "boom\n", false)
            }
            val outputIndex = args.indexOf("-o")
            if (outputIndex >= 0 && packedBytes != null) {
                Files.write(Path.of(args[outputIndex + 1]), packedBytes)
            }
            val profileIndex = args.indexOf("--profile")
            val requestedProfile = if (profileIndex >= 0) args[profileIndex + 1] else "standard"
            return NativeShroudPacker.XenolithCliResult(
                0,
                report ?: """{"report_version":1,"profile":"$requestedProfile","format":"pe-dll","output_bytes":128}""",
                false,
            )
        }
    }

    private fun native(platform: String, libName: String, bytes: ByteArray) =
        QpNativeCompilerPass.RecompiledNative(
            platform = platform,
            libName = libName,
            bytes = bytes,
            specializationDigest = ByteArray(32) { (it + 1).toByte() },
        )

    private fun config(
        enabled: Boolean,
        packedPath: String = "",
        packedPathLinux: String = "",
        cliPath: String = "",
        profile: String = "",
        extraParams: Map<String, com.fasterxml.jackson.databind.JsonNode> = emptyMap(),
    ): ObfuscationConfig {
        val params = buildMap {
            if (packedPath.isNotEmpty()) {
                put("packedPath", JsonNodeFactory.instance.textNode(packedPath))
            }
            if (packedPathLinux.isNotEmpty()) {
                put("packedPathLinux", JsonNodeFactory.instance.textNode(packedPathLinux))
            }
            if (cliPath.isNotEmpty()) {
                put("cliPath", JsonNodeFactory.instance.textNode(cliPath))
            }
            if (profile.isNotEmpty()) {
                put("profile", JsonNodeFactory.instance.textNode(profile))
            }
            putAll(extraParams)
        }
        return ObfuscationConfig(
            inputJarPath = "in.jar",
            outputJarPath = "out.jar",
            passes = listOf(
                PassSpec(id = "jni-microkernel-loader", enabled = true, params = emptyMap()),
                PassSpec(id = "nativeshroud", enabled = enabled, params = params),
            ),
            ruleSet = RuleSet(rules = emptyList()),
            allowIncomplete = true,
            allowOptInPasses = true,
            protectionProfile = HardenedProtectionProfile.MINIMAL,
        )
    }
}
