package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper
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

class AkenR1ProtectedJarLoadTest {
    @Test
    fun windows_gnu_runtime_loads_from_an_r1_jar_after_helper_rename() {
        val dll = resolveGnuDll()
        val bytes = Files.readAllBytes(dll)
        assertTrue(bytes.size > 64, "Windows gnu cdylib must be non-empty")
        assertEquals('M'.code.toByte(), bytes[0])
        assertEquals('Z'.code.toByte(), bytes[1])

        val jar = Files.createTempFile("aken-r1-windows-gnu-", ".jar")
        val extracted = Files.createTempFile("aken-r1-jsrt-ffi-", ".dll")
        val previousLoader = System.getProperty(LOADER_PROPERTY)
        val previousMethods = System.getProperty(METHOD_PROPERTY)
        val previousCatalog = System.getProperty(CATALOG_PROPERTY)
        try {
            JarOutputStream(Files.newOutputStream(jar)).use { output ->
                output.putNextEntry(JarEntry("META-INF/jsrt/windows-x64/jsrt_ffi.dll"))
                output.write(bytes)
                output.closeEntry()
            }
            JarFile(jar.toFile()).use { packed ->
                val entry = packed.getJarEntry("META-INF/jsrt/windows-x64/jsrt_ffi.dll")
                assertTrue(entry != null && entry.size > 64L, "protected JAR must contain the R1 Windows runtime")
            }

            val sidecar = Files.createTempDirectory("aken-r1-sidecar-")
            copySidecar(sidecar)
            System.setProperty(LOADER_PROPERTY, RENAMED_OWNER)
            System.setProperty(METHOD_PROPERTY, renamedMethodBindings())
            System.setProperty(CATALOG_PROPERTY, sidecar.toAbsolutePath().toString())
            Files.write(extracted, bytes)
            System.load(extracted.toAbsolutePath().toString())

            assertEquals(0, R1RenamedNativeSurface.nInit("windows-x64"))
            assertEquals(0, R1RenamedNativeSurface.nBeat())
            val opened = R1RenamedNativeSurface.nStr(
                sidecarHandle("page-3"),
                3,
                sidecarProof("page-3"),
            )
            assertEquals("hello-r1", opened)
            val classPage = R1RenamedNativeSurface.nCls(
                sidecarHandle("page-4"),
                4,
                sidecarProof("page-4"),
            )
            assertEquals("class-r1", classPage.decodeToString())
            R1RenamedNativeSurface.nNat(
                sidecarHandle("page-5"),
                5,
                sidecarProof("page-5"),
            )
            val vmResult = R1RenamedNativeSurface.nVm(
                0L,
                sidecarHandle("page-6"),
                6,
                sidecarProof("page-6"),
                null,
            )
            assertEquals(7, vmResult as Int)
            val error = assertFailsWith<SecurityException> {
                R1RenamedNativeSurface.nStr(ByteArray(24), 0, byteArrayOf(1, 2, 3, 4))
            }
            assertTrue(
                error.message == "AKEN typed page route is unavailable",
                "unknown StringPage route must fail closed: ${error.message}",
            )
        } finally {
            restoreProperty(LOADER_PROPERTY, previousLoader)
            restoreProperty(METHOD_PROPERTY, previousMethods)
            restoreProperty(CATALOG_PROPERTY, previousCatalog)
            Files.deleteIfExists(jar)
        }
    }

    @Test
    fun production_helper_extracts_the_r1_catalog_sidecar_before_native_init() {
        val method = JniMicrokernelHelper::class.java.getDeclaredMethod("extractAkenR1CatalogSidecar", File::class.java)
        method.isAccessible = true
        val nativeLib = Files.createTempFile("aken-r1-helper-", ".dll")
        try {
            val sidecar = method.invoke(null, nativeLib.toFile()) as File
            assertTrue(File(sidecar, "directory.jsr1").isFile)
            assertFalse(File(sidecar, "dek.bin").isFile, "catalog sidecar must not ship a raw page key")
            assertTrue(File(sidecar, "pages${File.separator}page-3.bin").isFile)
            assertTrue(File(sidecar, "pages${File.separator}page-4.bin").isFile)
            assertTrue(File(sidecar, "pages${File.separator}page-5.bin").isFile)
            assertTrue(File(sidecar, "pages${File.separator}page-6.bin").isFile)
            val directory = Files.readAllBytes(File(sidecar, "directory.jsr1").toPath())
            assertEquals('J'.code.toByte(), directory[0])
            assertEquals('S'.code.toByte(), directory[1])
            assertEquals('R'.code.toByte(), directory[2])
            assertEquals('1'.code.toByte(), directory[3])
        } finally {
            Files.deleteIfExists(nativeLib)
        }
    }

    @Test
    fun linux_glibc217_runtime_loads_from_a_protected_jar_under_wsl() {
        val so = resolveLinuxSo()
        val bytes = Files.readAllBytes(so)
        assertEquals(0x7f.toByte(), bytes[0])
        assertEquals('E'.code.toByte(), bytes[1])
        val jar = Files.createTempFile("aken-r1-linux-gnu-", ".jar")
        val extracted = Files.createTempFile("aken-r1-jsrt-ffi-", ".so")
        try {
            JarOutputStream(Files.newOutputStream(jar)).use { output ->
                output.putNextEntry(JarEntry("META-INF/jsrt/linux-x64/libjsrt_ffi.so"))
                output.write(bytes)
                output.closeEntry()
            }
            JarFile(jar.toFile()).use { packed ->
                val entry = packed.getJarEntry("META-INF/jsrt/linux-x64/libjsrt_ffi.so")
                assertTrue(entry != null && entry.size > 64L)
            }
            Files.write(extracted, bytes)
            extracted.toFile().setExecutable(true, false)
            val sidecar = Files.createTempDirectory("aken-r1-linux-sidecar-")
            copySidecar(sidecar)
            val classes = resolveJavaTestClasses()
            val process = ProcessBuilder(
                "wsl",
                "-d",
                "Ubuntu-24.04",
                "--",
                "java",
                "-cp",
                toWslPath(classes),
                "io.github.hht0rro.javashroud.LinuxR1LoadProbe",
                toWslPath(extracted),
                toWslPath(sidecar),
            ).redirectErrorStream(true).start()
            val finished = process.waitFor(90, java.util.concurrent.TimeUnit.SECONDS)
            val output = process.inputStream.bufferedReader().readText()
            assertTrue(finished, "WSL Linux load probe timed out:\n$output")
            assertEquals(0, process.exitValue(), "WSL Linux load probe failed:\n$output")
            assertTrue("INIT=0" in output, output)
            assertTrue("BEAT=0" in output, output)
            assertTrue("STR=hello-r1" in output, output)
            assertTrue("CLS=class-r1" in output, output)
            assertTrue("NAT=ok" in output, output)
            assertTrue("VM=7" in output, output)
        } finally {
            Files.deleteIfExists(jar)
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
        val jar = Files.createTempFile("aken-r1-linux-gnu-", ".jar")
        try {
            JarOutputStream(Files.newOutputStream(jar)).use { output ->
                output.putNextEntry(JarEntry("META-INF/jsrt/linux-x64/libjsrt_ffi.so"))
                output.write(bytes)
                output.closeEntry()
            }
            JarFile(jar.toFile()).use { packed ->
                val entry = packed.getJarEntry("META-INF/jsrt/linux-x64/libjsrt_ffi.so")
                assertTrue(entry != null && entry.size > 64L, "protected JAR must contain the R1 Linux runtime")
            }
        } finally {
            Files.deleteIfExists(jar)
        }
    }

    private fun resolveLinuxSo(): Path {
        val candidates = listOf(
            Path.of("src/main/rust/target/x86_64-unknown-linux-gnu.2.17/release/libjsrt_ffi.so"),
            Path.of("core-engine/src/main/rust/target/x86_64-unknown-linux-gnu.2.17/release/libjsrt_ffi.so"),
            Path.of("src/main/rust/target/x86_64-unknown-linux-gnu/release/libjsrt_ffi.so"),
            Path.of("core-engine/src/main/rust/target/x86_64-unknown-linux-gnu/release/libjsrt_ffi.so"),
        )
        return candidates.firstOrNull { Files.isRegularFile(it) }
            ?: error("Linux glibc 2.17 libjsrt_ffi.so is missing")
    }

    private fun resolveJavaTestClasses(): Path {
        val relative = Path.of("build/core-engine/classes/java/test")
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val candidate = current.resolve(relative)
            if (Files.isDirectory(candidate.resolve("io/github/hht0rro/javashroud"))) {
                return candidate
            }
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
            Path.of("src/main/rust/target/x86_64-pc-windows-gnu/release/jsrt_ffi.dll"),
            Path.of("core-engine/src/main/rust/target/x86_64-pc-windows-gnu/release/jsrt_ffi.dll"),
        )
        return candidates.firstOrNull { Files.isRegularFile(it) }
            ?: error("Windows gnu jsrt_ffi.dll is missing; cargo zigbuild --target x86_64-pc-windows-gnu must succeed first")
    }

    private fun renamedMethodBindings(): String = SOURCE_METHODS.joinToString("\n") { (source, signature, renamed) ->
        "${bindingKey(source, signature)}=$renamed"
    }

    private fun bindingKey(name: String, signature: String): String {
        val material = "AKEN-BINDING-V1|$SOURCE_OWNER#$name#$signature"
        val digest = MessageDigest.getInstance("SHA-256").digest(material.toByteArray(Charsets.US_ASCII))
        return digest.take(8).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xFF) }
    }

    private fun copySidecar(root: Path) {
        val classLoader = checkNotNull(javaClass.classLoader)
        fun copy(resource: String, destination: Path) {
            Files.createDirectories(destination.parent)
            classLoader.getResourceAsStream(resource).use { input ->
                check(input != null) { "missing sidecar resource $resource" }
                Files.copy(input, destination)
            }
        }
        copy("aken-r1-sidecar/directory.jsr1", root.resolve("directory.jsr1"))
        copy("aken-r1-sidecar/pages/page-3.bin", root.resolve("pages/page-3.bin"))
        copy("aken-r1-sidecar/pages/page-4.bin", root.resolve("pages/page-4.bin"))
        copy("aken-r1-sidecar/pages/page-5.bin", root.resolve("pages/page-5.bin"))
        copy("aken-r1-sidecar/pages/page-6.bin", root.resolve("pages/page-6.bin"))
        copy("aken-r1-sidecar/handle.bin", root.resolve("handle.bin"))
        copy("aken-r1-sidecar/proof.bin", root.resolve("proof.bin"))
        for (stem in listOf("page-3", "page-4", "page-5", "page-6")) {
            copy("aken-r1-sidecar/$stem.handle", root.resolve("$stem.handle"))
            copy("aken-r1-sidecar/$stem.proof", root.resolve("$stem.proof"))
        }
    }

    private fun sidecarHandle(stem: String): ByteArray =
        checkNotNull(javaClass.classLoader.getResourceAsStream("aken-r1-sidecar/$stem.handle")).use { it.readBytes() }

    private fun sidecarProof(stem: String): ByteArray =
        checkNotNull(javaClass.classLoader.getResourceAsStream("aken-r1-sidecar/$stem.proof")).use { it.readBytes() }

    private fun restoreProperty(name: String, previous: String?) {
        if (previous == null) {
            System.clearProperty(name)
        } else {
            System.setProperty(name, previous)
        }
    }

    private companion object {
        const val LOADER_PROPERTY = "j.l"
        const val METHOD_PROPERTY = "j.m"
        const val CATALOG_PROPERTY = "j.c"
        const val SOURCE_OWNER = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper"
        const val RENAMED_OWNER = "io/github/hht0rro/javashroud/R1RenamedNativeSurface"
        val SOURCE_METHODS = listOf(
            Triple("nativeInit", "(Ljava/lang/String;)I", "nInit"),
            Triple("nativeHeartbeat", "()I", "nBeat"),
            Triple("nativeInstallAkenSessionNonce", "([B)Z", "nNonce"),
            Triple("nativeExecuteAkenVmPage", "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;", "nVm"),
            Triple("nativeOpenAkenString", "([BI[B)Ljava/lang/String;", "nStr"),
            Triple("nativeReadAkenClassPage", "([BI[B)[B", "nCls"),
            Triple("nativeConsumeAkenNativeChunk", "([BI[B)V", "nNat"),
        )
    }
}
