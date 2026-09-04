package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class QpProtectedJarLoadTest {
    @Test
    fun windows_gnu_runtime_initializes_renamed_native_surface_and_rejects_unbound_page() {
        val dll = resolveGnuDll()
        val bytes = Files.readAllBytes(dll)
        assertTrue(bytes.size > 64, "Windows gnu cdylib must be non-empty")
        assertEquals('M'.code.toByte(), bytes[0])
        assertEquals('Z'.code.toByte(), bytes[1])

        val extracted = Files.createTempFile("qp-qp-ffi-", ".dll")
        val previousLoader = System.getProperty(LOADER_PROPERTY)
        val previousMethods = System.getProperty(METHOD_PROPERTY)
        try {
            System.setProperty(LOADER_PROPERTY, RENAMED_OWNER)
            System.setProperty(METHOD_PROPERTY, renamedMethodBindings())
            Files.write(extracted, bytes)
            try {
                System.load(extracted.toAbsolutePath().toString())
            } catch (_: UnsatisfiedLinkError) {
                return
            }

            assertEquals(0, RenamedNativeSurface.nInit("windows-x64"))
            assertEquals(0, RenamedNativeSurface.nBeat())
            val nonce = ByteArray(32)
            try {
                java.security.SecureRandom().nextBytes(nonce)
                assertTrue(RenamedNativeSurface.nNonce(nonce))
            } finally {
                nonce.fill(0)
            }
            val error = assertFailsWith<SecurityException> {
                RenamedNativeSurface.nStr(ByteArray(24), 0, byteArrayOf(1))
            }
            assertTrue(
                error.message.orEmpty().contains("route") ||
                    error.message.orEmpty().contains("catalog") ||
                    error.message.orEmpty().contains("page"),
            )
        } finally {
            restoreProperty(LOADER_PROPERTY, previousLoader)
            restoreProperty(METHOD_PROPERTY, previousMethods)
            runCatching { Files.deleteIfExists(extracted) }
        }
    }

    @Test
    fun fresh_jvm_native_defense_probe_stays_within_call_budget() {
        val dll = resolveGnuDll()
        val extracted = Files.createTempFile("qp-overhead-", ".dll")
        try {
            Files.copy(dll, extracted, java.nio.file.StandardCopyOption.REPLACE_EXISTING)
            val classes = resolveJavaTestClasses()
            val javaHome = Path.of(System.getProperty("java.home"), "bin", "java.exe")
            val process = ProcessBuilder(
                javaHome.toString(),
                "-cp",
                classes.toAbsolutePath().toString(),
                "io.github.hht0rro.javashroud.WindowsNativeOverheadProbe",
                extracted.toAbsolutePath().toString(),
            ).redirectErrorStream(true).start()
            val finished = process.waitFor(90, java.util.concurrent.TimeUnit.SECONDS)
            val output = process.inputStream.bufferedReader().readText()
            assertTrue(finished, "fresh JVM overhead probe timed out:\n$output")
            assertEquals(0, process.exitValue(), "fresh JVM overhead probe failed:\n$output")
            assertTrue("OVERHEAD_OK" in output, output)
            assertTrue("BUDGET=3.0" in output, output)
        } finally {
            runCatching { Files.deleteIfExists(extracted) }
        }
    }

    @Test
    fun production_helper_does_not_reintroduce_the_retired_catalog_sidecar() {
        assertFailsWith<NoSuchMethodException> {
            QpBridge::class.java.getDeclaredMethod("extractQpCatalogEmitter", File::class.java)
        }
        val source = Files.readString(workspacePath(
            "core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge.java",
        ))
        assertTrue("readQpCatalogBundle" in source)
        assertTrue("installQpCatalog" in source)
        assertFalse("directory.jsr1" in source)
        assertFalse("dek.bin" in source)
    }

    @Test
    fun linux_glibc217_runtime_initializes_native_bridge_and_rejects_unbound_page_under_wsl() {
        val so = resolveLinuxSo()
        val bytes = Files.readAllBytes(so)
        assertEquals(0x7f.toByte(), bytes[0])
        assertEquals('E'.code.toByte(), bytes[1])
        val extracted = Files.createTempFile("qp-qp-ffi-", ".so")
        try {
            val preflight = ProcessBuilder("wsl", "-d", "Ubuntu-24.04", "--", "true")
                .redirectErrorStream(true)
                .start()
            val preflightFinished = preflight.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)
            val preflightOutput = preflight.inputStream.bufferedReader().readText()
            assumeTrue(
                preflightFinished && preflight.exitValue() == 0,
                "Ubuntu-24.04 WSL is unavailable; Linux runtime probe is skipped: $preflightOutput",
            )
            Files.write(extracted, bytes)
            extracted.toFile().setExecutable(true, false)
            val classes = resolveJavaTestClasses()
            val process = ProcessBuilder(
                "wsl",
                "-d",
                "Ubuntu-24.04",
                "--",
                "java",
                "-cp",
                toWslPath(classes),
                "io.github.hht0rro.javashroud.LinuxNativeLoadProbe",
                toWslPath(extracted),
            ).redirectErrorStream(true).start()
            val finished = process.waitFor(90, java.util.concurrent.TimeUnit.SECONDS)
            val output = process.inputStream.bufferedReader().readText()
            assertTrue(finished, "WSL Linux load probe timed out:\n$output")
            assertEquals(0, process.exitValue(), "WSL Linux load probe failed:\n$output")
            assertTrue("INIT=0" in output, output)
            assertTrue("BEAT=0" in output, output)
            assertTrue("SESSION=ok" in output, output)
            assertTrue("UNBOUND=ok" in output, output)
        } finally {
            runCatching { Files.deleteIfExists(extracted) }
        }
    }

    @Test
    fun linux_glibc217_runtime_is_an_elf_shared_object_ready_for_jar_packaging() {
        val so = resolveLinuxSo()
        val bytes = Files.readAllBytes(so)
        assertTrue(bytes.size > 64)
        assertEquals(0x7f.toByte(), bytes[0])
        assertEquals('E'.code.toByte(), bytes[1])
        assertEquals('L'.code.toByte(), bytes[2])
        assertEquals('F'.code.toByte(), bytes[3])
        val jar = Files.createTempFile("qp-linux-gnu-", ".jar")
        try {
            JarOutputStream(Files.newOutputStream(jar)).use { output ->
                output.putNextEntry(JarEntry("META-INF/jsrt/linux-x64/libqp_ffi.so"))
                output.write(bytes)
                output.closeEntry()
            }
            JarFile(jar.toFile()).use { packed ->
                val entry = packed.getJarEntry("META-INF/jsrt/linux-x64/libqp_ffi.so")
                assertTrue(entry != null && entry.size > 64L, "protected JAR must contain the Linux native runtime")
            }
        } finally {
            Files.deleteIfExists(jar)
        }
    }

    private fun resolveLinuxSo(): Path {
        val candidates = listOf(
            Path.of("src/main/rust/target/x86_64-unknown-linux-gnu.2.17/release/libqp_ffi.so"),
            Path.of("core-engine/src/main/rust/target/x86_64-unknown-linux-gnu.2.17/release/libqp_ffi.so"),
            Path.of("src/main/rust/target/x86_64-unknown-linux-gnu/release/libqp_ffi.so"),
            Path.of("core-engine/src/main/rust/target/x86_64-unknown-linux-gnu/release/libqp_ffi.so"),
        )
        return candidates.firstOrNull { Files.isRegularFile(it) }
            ?: error("Linux glibc 2.17 libqp_ffi.so is missing")
    }

    private fun resolveJavaTestClasses(): Path {
        val relative = Path.of("build/core-engine/classes/java/test")
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val candidate = current.resolve(relative)
            if (Files.isDirectory(candidate.resolve("io/github/hht0rro/javashroud"))) return candidate
            current = current.parent ?: break
        }
        error("compiled Java test classes are missing")
    }

    private fun toWslPath(path: Path): String {
        val absolute = path.toAbsolutePath().normalize().toString().replace('\\', '/')
        val match = Regex("^([A-Za-z]):/(.*)$").matchEntire(absolute)
            ?: error("cannot convert path to WSL: $absolute")
        return "/mnt/${match.groupValues[1].lowercase()}/${match.groupValues[2]}"
    }

    private fun resolveGnuDll(): Path {
        val candidates = listOf(
            Path.of("src/main/rust/target/x86_64-pc-windows-gnu/release/qp_ffi.dll"),
            Path.of("core-engine/src/main/rust/target/x86_64-pc-windows-gnu/release/qp_ffi.dll"),
        )
        return candidates.firstOrNull { Files.isRegularFile(it) }
            ?: error("Windows gnu qp_ffi.dll is missing; cargo zigbuild --target x86_64-pc-windows-gnu must succeed first")
    }

    private fun workspacePath(relative: String): Path {
        val path = Path.of(relative)
        var current = Path.of("").toAbsolutePath().normalize()
        while (true) {
            val candidate = current.resolve(path).normalize()
            if (Files.exists(candidate)) return candidate
            current = current.parent ?: break
        }
        error("workspace file is missing: $relative")
    }

    private fun renamedMethodBindings(): String = SOURCE_METHODS.joinToString("\n") { (source, signature, renamed) ->
        "${bindingKey(source, signature)}=$renamed"
    }

    private fun bindingKey(name: String, signature: String): String {
        val material = "QP-BINDING-V1|$SOURCE_OWNER#$name#$signature"
        val digest = MessageDigest.getInstance("SHA-256").digest(material.toByteArray(Charsets.US_ASCII))
        return digest.take(8).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) }
    }

    private fun restoreProperty(name: String, previous: String?) {
        if (previous == null) System.clearProperty(name) else System.setProperty(name, previous)
    }

    private companion object {
        const val LOADER_PROPERTY = "j.l"
        const val METHOD_PROPERTY = "j.m"
        const val SOURCE_OWNER = "io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge"
        const val RENAMED_OWNER = "io/github/hht0rro/javashroud/RenamedNativeSurface"
        val SOURCE_METHODS = listOf(
            Triple("nativeInit", "(Ljava/lang/String;)I", "nInit"),
            Triple("nativeHeartbeat", "()I", "nBeat"),
            Triple("nativeInstallSessionNonce", "([B)Z", "nNonce"),
            Triple("nativeInstallCatalog", "([B[B[B)I", "nCatalog"),
            Triple("nativeExecuteVmPage", "(Ljava/lang/String;[B[Ljava/lang/Object;)Ljava/lang/Object;", "nVm"),
            Triple("nativeOpenStringPage", "([B)Ljava/lang/String;", "nStr"),
            Triple("nativeReadClassPage", "([B)[B", "nCls"),
            Triple("nativeConsumeNativeSegment", "([B)V", "nNat"),
            Triple("nativeInitializeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nDefenseInit"),
            Triple("nativeProbeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nDefenseProbe"),
            Triple("nativeTransformDefense", "([BLjava/lang/String;)[B", "nDefenseTransform"),
            Triple("nativeInvokeSite", "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[B[Ljava/lang/Object;Z)Ljava/lang/Object;", "nInvokeSite"),
        )
    }
}
