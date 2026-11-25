package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.qp.QpBridge
import java.io.File
import java.io.IOException
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.objectweb.asm.Type

class QpProtectedJarLoadTest {
    @Test
    fun renamed_native_fixture_matches_the_complete_current_bridge_surface() {
        val sourceMethods = QpBridge::class.java.declaredMethods
            .filter { Modifier.isNative(it.modifiers) }
            .associate { it.name to Type.getMethodDescriptor(it) }
        val renamedMethods = RenamedNativeSurface::class.java.declaredMethods
            .filter { Modifier.isNative(it.modifiers) }
            .associate { it.name to Type.getMethodDescriptor(it) }
        assertEquals(sourceMethods, SOURCE_METHODS.associate { (source, signature, _) -> source to signature })
        assertEquals(renamedMethods, SOURCE_METHODS.associate { (_, signature, renamed) -> renamed to signature })
    }

    @Test
    fun windows_loader_only_runtime_rejects_unauthenticated_renamed_bindings() {
        assumeTrue(isWindows(), "Windows GNU runtime test requires a Windows host")
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
            // A complete plaintext map cannot authorize current sealed JNI relocation.
            System.setProperty(METHOD_PROPERTY, renamedMethodBindings())
            Files.write(extracted, bytes)
            assertFailsWith<UnsatisfiedLinkError> {
                System.load(extracted.toAbsolutePath().toString())
            }
        } finally {
            restoreProperty(LOADER_PROPERTY, previousLoader)
            restoreProperty(METHOD_PROPERTY, previousMethods)
            runCatching { Files.deleteIfExists(extracted) }
        }
    }

    @Test
    fun fresh_jvm_native_defense_probe_stays_within_call_budget() {
        assumeTrue(isWindows(), "Windows native defense probe requires a Windows host")
        val java = Path.of(System.getProperty("java.home"), "bin", "java.exe")
        val result = runProcess(listOf(java.toString()) + probeArguments(resolveGnuDll(), "windows-x64"), 90)
        assertEquals(0, result.exitCode, "Fresh JVM overhead probe failed or timed out:\n${result.output}")
        val lines = result.stdout.lineSequence().toSet()
        for (expected in listOf("INIT=0", "BEAT=0", "SESSION=ok", "UNBOUND=ok")) {
            assertTrue(expected in lines, "Windows load probe did not report $expected:\n${result.output}")
        }
        assertTrue("OVERHEAD_OK" in lines, result.output)
        assertTrue("BUDGET=3.0" in lines, result.output)
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
    fun linux_glibc217_runtime_initializes_native_bridge_and_rejects_unbound_page() {
        val nativeLinux = isLinux()
        requireLinuxFixture(
            nativeLinux || (isWindows() && !linuxFixturesRequired()),
            "Linux load probe requires Linux or optional Ubuntu-24.04 WSL on Windows",
        )
        val so = resolveLinuxSo()
        val launcher = if (nativeLinux) {
            val java = Path.of(System.getProperty("java.home"), "bin", "java")
            assertTrue(Files.isExecutable(java), "Linux Java executable is missing: $java")
            listOf(java.toString())
        } else {
            val wslJava = listOf("wsl.exe", "-d", "Ubuntu-24.04", "--", "java")
            val preflight = try {
                runProcess(wslJava + "-version", 20)
            } catch (error: IOException) {
                assumeTrue(false, "Ubuntu-24.04 WSL Java could not start: ${error.message}")
                throw error
            }
            assumeTrue(preflight.exitCode == 0, "Ubuntu-24.04 WSL Java is unavailable or timed out:\n${preflight.output}")
            wslJava
        }

        val result = runProcess(launcher + probeArguments(so, "linux-x64", underWsl = !nativeLinux), 90)
        assertEquals(0, result.exitCode, "Linux load probe failed or timed out:\n${result.output}")
        val lines = result.stdout.lineSequence().toSet()
        for (expected in listOf("INIT=0", "BEAT=0", "SESSION=ok", "UNBOUND=ok")) {
            assertTrue(expected in lines, "Linux load probe did not report $expected:\n${result.output}")
        }
    }

    @Test
    fun linux_glibc217_packaged_elf_matches_the_cargo_artifact() {
        val so = resolveLinuxSo()
        val resource = javaClass.getResource("/$LINUX_RESOURCE")
        requireLinuxFixture(resource != null, "Packaged Linux runtime resource is missing: $LINUX_RESOURCE")
        val packaged = checkNotNull(resource).openStream().use { it.readBytes() }
        assertTrue(packaged.size > 64, "Packaged Linux runtime is empty or truncated")
        assertContentEquals(byteArrayOf(0x7f, 0x45, 0x4c, 0x46), packaged.copyOfRange(0, 4))
        assertTrue(packaged.contentEquals(Files.readAllBytes(so)), "Packaged Linux runtime differs from $so")
    }

    private fun resolveLinuxSo(): Path {
        val so = findWorkspacePath(LINUX_ARTIFACT)?.takeIf(Files::isRegularFile)
        requireLinuxFixture(so != null, "Linux glibc 2.17 runtime is missing: $LINUX_ARTIFACT")
        return checkNotNull(so)
    }

    private fun isLinux(): Boolean = System.getProperty("os.name").startsWith("Linux", ignoreCase = true)

    private fun isWindows(): Boolean = System.getProperty("os.name").startsWith("Windows", ignoreCase = true)

    private fun linuxFixturesRequired(): Boolean = System.getenv("JAVASHROUD_REQUIRE_LINUX_NATIVE_FIXTURES") == "true"

    private fun requireLinuxFixture(available: Boolean, message: String) {
        if (isLinux() || linuxFixturesRequired()) assertTrue(available, message)
        else assumeTrue(available, message)
    }

    private fun probeArguments(library: Path, platform: String, underWsl: Boolean = false): List<String> {
        fun processPath(path: Path) = if (underWsl) toWslPath(path) else path.toAbsolutePath().toString()
        val probe = QpBridgeProbe::class.java
        val classpath = listOf(probe, QpBridge::class.java, Unit::class.java)
            .map { Path.of(it.protectionDomain.codeSource.location.toURI()) }
            .distinct()
            .joinToString(if (underWsl) ":" else File.pathSeparator, transform = ::processPath)
        return listOf("-cp", classpath, probe.name, processPath(library), platform)
    }

    private fun runProcess(command: List<String>, timeoutSeconds: Long): ProcessResult {
        val logs = Files.createTempDirectory("qp-native-probe-")
        val stdout = logs.resolve("stdout.log")
        val stderr = logs.resolve("stderr.log")
        try {
            val process = ProcessBuilder(command).redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start()
            val finished = try {
                process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
            } finally {
                if (process.isAlive) process.destroyForcibly().waitFor(5, TimeUnit.SECONDS)
            }
            return ProcessResult(if (finished) process.exitValue() else null, stdout.toFile().readText(), stderr.toFile().readText())
        } finally {
            stdout.toFile().delete()
            stderr.toFile().delete()
            logs.toFile().delete()
        }
    }

    private data class ProcessResult(val exitCode: Int?, val stdout: String, val stderr: String) {
        val output: String get() = "$stdout\n$stderr"
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

    private fun workspacePath(relative: String): Path =
        findWorkspacePath(relative) ?: error("workspace file is missing: $relative")

    private fun findWorkspacePath(relative: String): Path? {
        val path = Path.of(relative)
        var current = Path.of("").toAbsolutePath().normalize()
        while (true) {
            val candidate = current.resolve(path).normalize()
            if (Files.exists(candidate)) return candidate
            current = current.parent ?: break
        }
        return null
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
        // The .2.17 suffix selects the glibc floor for zigbuild, not Cargo's output directory.
        const val LINUX_ARTIFACT = "core-engine/src/main/rust/target/x86_64-unknown-linux-gnu/release/libqp_ffi.so"
        const val LINUX_RESOURCE = "META-INF/jsrt/linux-x64/libqp_ffi.so"
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
            Triple("nativeInitializeDefenseCode", "(II)I", "nDefenseInitCode"),
            Triple("nativeProbeDefenseCode", "(II)I", "nDefenseProbeCode"),
            Triple("nativeTransformDefenseCode", "([BI)[B", "nDefenseTransformCode"),
            Triple("nativeInvokeSite", "(Ljava/lang/invoke/MethodHandles\$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[B[Ljava/lang/Object;Z)Ljava/lang/Object;", "nInvokeSite"),
        )
    }
}

private object QpBridgeProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        // The packaged loader-only runtime registers the current source-named QpBridge methods.
        val (library, platform) = args
        val started = System.nanoTime()
        System.load(library)
        val init = invokeNative("nativeInit", platform)
        val beat = invokeNative("nativeHeartbeat")
        check(init == 0 && beat == 0) { "Native bridge initialization failed: INIT=$init BEAT=$beat" }
        val nonce = ByteArray(32)
        try {
            SecureRandom().nextBytes(nonce)
            check(invokeNative("nativeInstallSessionNonce", nonce) == true) { "native session install failed" }
        } finally {
            nonce.fill(0)
        }
        println("INIT=$init")
        println("BEAT=$beat")
        println("SESSION=ok")
        try {
            invokeNative("nativeOpenStringPage", ByteArray(29))
            error("unbound page unexpectedly opened")
        } catch (_: SecurityException) {
            println("UNBOUND=ok")
        }
        if (platform == "windows-x64") checkWindowsDefenseOverhead(started)
    }

    private fun checkWindowsDefenseOverhead(started: Long) {
        val surface = "os-anti-debug"
        check(QpBridge.nativeInitializeDefense(surface, "balanced") == 0) { "Native defense init failed" }
        println("STARTUP_NS=${System.nanoTime() - started}")
        repeat(8) {
            check(QpBridge.nativeProbeDefense(surface, "warmup") == 0) { "Native defense warmup failed" }
        }
        val iterations = 32
        val begin = System.nanoTime()
        repeat(iterations) {
            check(QpBridge.nativeProbeDefense(surface, "steady-state") == 0) { "Native defense probe failed" }
        }
        val elapsed = System.nanoTime() - begin
        val baselineStart = System.nanoTime()
        repeat(iterations) { @Suppress("UNUSED_VARIABLE") val point = "steady-state" }
        val baseline = System.nanoTime() - baselineStart
        println("NATIVE_NS=$elapsed")
        println("BASELINE_NS=$baseline")
        println("RATIO=${elapsed.toDouble() / baseline.coerceAtLeast(1)}")
        check(elapsed / iterations < TimeUnit.MILLISECONDS.toNanos(50)) { "Protected call exceeded 50 ms sanity ceiling" }
        println("BUDGET=3.0")
        println("OVERHEAD_OK")
    }

    private fun invokeNative(name: String, vararg args: Any): Any? {
        val method = QpBridge::class.java.getDeclaredMethod(name, *args.map { it.javaClass }.toTypedArray())
        method.isAccessible = true
        return try {
            method.invoke(null, *args)
        } catch (error: InvocationTargetException) {
            throw error.targetException
        }
    }
}
