package io.github.hht0rro.javashroud.apk

import java.io.IOException
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.Locale
import java.util.jar.JarFile

/**
 * Locates and authenticates the external APK toolchain before any heavy work:
 * the vendored dex2jar closure (SHA-256SUMS-verified on every extraction),
 * the r8/D8 jar (pinned when it comes from an SDK path), and a java launcher
 * (java.home > JAVA_HOME > PATH, matching d8.bat's own resolution).
 */
object ApkToolchainProvisioner {

    const val DEX_TOOLS_RESOURCE_DIR = "META-INF/apk-tools/dex2jar"
    const val DEX_TOOLS_SUMS_RESOURCE = "$DEX_TOOLS_RESOURCE_DIR/SHA-256SUMS"
    const val DEX2JAR_MAIN_CLASS = "com.googlecode.dex2jar.tools.Dex2jarCmd"
    const val D8_MAIN_CLASS = "com.android.tools.r8.D8"
    const val REAL_TOOLS_SKIP_ENV = "JAVASHROUD_APK_REAL_TOOLS"

    private const val DEX2JAR_FIX_JAR = "javashroud-dex2jar-fixes.jar"

    /** build-tools 34.0.0 d8.jar (dev fallback only; the fat jar embeds r8). */
    private const val SDK_D8_SHA256 = "d43c8a94c9b1f1da1a7cc49c32b81e8cee1708b37ee8b530a81a0688222b42c0"
    private const val SDK_D8_SIZE = 14_929_869L

    data class ApkToolchain(
        val javaExecutable: Path,
        val dex2jarDirectory: Path,
        val d8Jar: Path,
        val dex2jarSource: String,
        val d8Source: String,
        val fixJar: Path? = null,
    )

    fun ensure(
        dex2jarDirOverride: String,
        d8JarOverride: String,
        userHome: Path = Paths.get(System.getProperty("user.home")),
        androidHome: String? = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT"),
        environment: (String) -> String? = System::getenv,
    ): ApkToolchain {
        val javaExecutable = resolveJavaExecutable(environment)
        val bundledDex2jar = resolveDex2Jar("", userHome)
        val fixJar = bundledDex2jar.first.resolve(DEX2JAR_FIX_JAR)
        require(Files.isRegularFile(fixJar)) {
            "vendored dex2jar fix jar is missing from the verified toolchain: $fixJar"
        }
        val dex2jar = if (dex2jarDirOverride.isBlank()) bundledDex2jar
            else resolveDex2Jar(dex2jarDirOverride, userHome)
        val d8 = resolveD8(d8JarOverride, androidHome)
        return ApkToolchain(
            javaExecutable = javaExecutable,
            dex2jarDirectory = dex2jar.first,
            dex2jarSource = dex2jar.second,
            d8Jar = d8.first,
            d8Source = d8.second,
            fixJar = fixJar,
        )
    }

    // --- java launcher ----------------------------------------------------

    fun resolveJavaExecutable(environment: (String) -> String? = System::getenv): Path {
        val javaHome = System.getProperty("java.home")
        if (!javaHome.isNullOrBlank()) {
            val candidate = executable(Paths.get(javaHome, "bin"), "java")
            if (Files.isRegularFile(candidate)) return candidate
        }
        val envJavaHome = environment("JAVA_HOME")
        if (!envJavaHome.isNullOrBlank()) {
            val candidate = executable(Paths.get(envJavaHome, "bin"), "java")
            if (Files.isRegularFile(candidate)) return candidate
        }
        val path = environment("PATH") ?: failClosed("No java launcher found: java.home and JAVA_HOME are unset and PATH is empty")
        val separator = if (isWindows()) ';' else ':'
        val names = if (isWindows()) listOf("java.exe", "java") else listOf("java")
        for (directory in path.split(separator)) {
            if (directory.isBlank()) continue
            val candidate = names.firstOrNull { name -> Files.isRegularFile(Paths.get(directory, name)) }
                ?: continue
            return Paths.get(directory, candidate)
        }
        failClosed("No java launcher found on PATH (java.home and JAVA_HOME did not yield one either)")
    }

    // --- dex2jar -----------------------------------------------------------

    private fun resolveDex2Jar(override: String, userHome: Path): Pair<Path, String> {
        if (override.isNotBlank()) {
            val directory = Paths.get(override).toAbsolutePath().normalize()
            require(Files.isDirectory(directory)) { "apk.dex2jarDirPath does not exist: $directory" }
            require(Files.isRegularFile(directory.resolve("dex-tools-2.4.28.jar"))) {
                "apk.dex2jarDirPath does not look like a dex2jar lib directory: $directory"
            }
            return directory to "config"
        }
        val cacheRoot = userHome.toAbsolutePath().normalize().resolve(".javashroud/apk-tools")
        val sumsBytes = requireNotNull(classLoaderResource(DEX_TOOLS_SUMS_RESOURCE)) {
            "vendored dex2jar manifest is missing from the engine classpath: $DEX_TOOLS_SUMS_RESOURCE"
        }
        val sums = decodeSums(sumsBytes)
        require(sums.isNotEmpty()) { "vendored dex2jar manifest is empty" }
        require(sums.containsKey(DEX2JAR_FIX_JAR)) {
            "vendored dex2jar manifest does not authenticate $DEX2JAR_FIX_JAR"
        }
        val directoryName = "dex2jar-" + sha256Hex(sumsBytes).substring(0, 16)
        val installDir = cacheRoot.resolve(directoryName)
        Files.createDirectories(cacheRoot)
        // Cross-process serialization: concurrent engine runs re-extracting the
        // same cache directory previously deleted jars out from under a running
        // `java -cp <dir>\*` child (ClassNotFoundException: Dex2jarCmd).
        provisioningLock(cacheRoot).use {
            if (Files.isDirectory(installDir) && verifyDirectory(installDir, sums)) {
                return installDir to "engine-resource-cache"
            }
            cleanupStalePrivateDirectories(cacheRoot, directoryName)
            // A canonical directory that fails verification is NEVER deleted in
            // place: another process may be executing against it right now.
            // Extract into a private sibling and atomically claim the canonical
            // name; whoever loses the race re-verifies the winner and otherwise
            // keeps its private copy for this run.
            // A canonical directory that fails verification while the lock is
            // held is broken (tampered or truncated by a full disk): replacing
            // it repairs the cache in place for every later run. Healthy
            // canonicals are never touched (the early return above already
            // served them).
            if (Files.isDirectory(installDir) && !verifyDirectory(installDir, sums)) {
                runCatching { deleteRecursively(installDir) }
            }
            val privateDir = Files.createTempDirectory(cacheRoot, "$directoryName-private-")
            extractDexTools(sums, privateDir)
            val claimed = try {
                Files.move(privateDir, installDir, StandardCopyOption.ATOMIC_MOVE)
                true
            } catch (_: IOException) {
                false
            }
            // A full disk (or any write failure) can leave a truncated cache
            // that verification of the resource bytes would never catch, so
            // the materialized directory itself is re-verified before use;
            // a broken claim falls back to the private copy.
            val candidate = if (claimed) installDir else privateDir
            if (verifyDirectory(candidate, sums)) {
                if (claimed) {
                    return installDir to "engine-resource"
                }
                if (verifyDirectory(installDir, sums)) {
                    // Lost the claim race to another process that just wrote a
                    // healthy canonical; reuse it.
                    runCatching { deleteRecursively(privateDir) }
                    return installDir to "engine-resource-cache"
                }
                return candidate to "engine-resource-private"
            }
            // The extraction itself came back broken (disk full / antivirus);
            // drop a broken claim, retry once with a fresh private copy, and
            // fail closed with an actionable message when it persists.
            if (claimed) {
                runCatching { deleteRecursively(installDir) }
            }
            val retryDir = Files.createTempDirectory(cacheRoot, "$directoryName-private-")
            extractDexTools(sums, retryDir)
            if (verifyDirectory(retryDir, sums)) {
                if (!Files.isDirectory(installDir)) {
                    if (runCatching { Files.move(retryDir, installDir, StandardCopyOption.ATOMIC_MOVE) }.isSuccess) {
                        return installDir to "engine-resource"
                    }
                }
                return retryDir to "engine-resource-private"
            }
            throw IllegalStateException(
                "vendored dex2jar extraction failed verification twice under $cacheRoot " +
                    "(disk full or antivirus interference); free disk space or clear the directory",
            )
        }
    }

    private fun provisioningLock(cacheRoot: Path): java.io.Closeable {
        val lockFile = cacheRoot.resolve(".provision.lock")
        val channel = java.nio.channels.FileChannel.open(
            lockFile,
            java.nio.file.StandardOpenOption.CREATE,
            java.nio.file.StandardOpenOption.WRITE,
            java.nio.file.StandardOpenOption.READ,
        )
        channel.lock() // blocks until every concurrent provisioner releases
        return java.io.Closeable { runCatching { channel.close() } }
    }

    /** Best-effort GC of private extraction copies abandoned by earlier runs. */
    private fun cleanupStalePrivateDirectories(cacheRoot: Path, directoryName: String) {
        val cutoff = System.currentTimeMillis() - 3_600_000L
        cacheRoot.toFile().listFiles()
            ?.filter { file -> file.isDirectory && file.name.startsWith("$directoryName-private-") }
            ?.forEach { file ->
                runCatching {
                    if (file.lastModified() < cutoff) deleteRecursively(file.toPath())
                }
            }
    }

    private fun extractDexTools(sums: Map<String, String>, targetDir: Path) {
        for ((name, expectedSha) in sums) {
            val bytes = requireNotNull(classLoaderResource("$DEX_TOOLS_RESOURCE_DIR/$name")) {
                "vendored dex2jar jar is missing from the engine classpath: $name"
            }
            val actual = sha256Hex(bytes)
            require(actual == expectedSha) {
                "vendored dex2jar jar failed SHA-256 verification: $name expected=$expectedSha actual=$actual"
            }
            Files.createDirectories(targetDir)
            Files.newOutputStream(targetDir.resolve(name)).use { it.write(bytes) }
        }
    }

    private fun verifyDirectory(directory: Path, sums: Map<String, String>): Boolean {
        return try {
            sums.all { (name, expected) ->
                val file = directory.resolve(name)
                Files.isRegularFile(file) && sha256Hex(Files.readAllBytes(file)) == expected
            }
        } catch (_: Exception) {
            false
        } finally {
            // Mismatch is handled by the caller via re-extraction.
        }
    }

    private fun decodeSums(bytes: ByteArray): Map<String, String> =
        // Returns fileName -> expectedSha256.
        bytes.toString(Charsets.UTF_8).lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { line ->
                val parts = line.split(Regex("\\s+"), limit = 2)
                if (parts.size == 2 && parts[0].length == 64) parts[1].trim() to parts[0].lowercase(Locale.ROOT) else null
            }
            .toMap()

    // --- r8 / D8 -----------------------------------------------------------

    private fun resolveD8(override: String, androidHome: String?): Pair<Path, String> {
        if (override.isNotBlank()) {
            val jar = Paths.get(override).toAbsolutePath().normalize()
            require(Files.isRegularFile(jar)) { "apk.d8JarPath does not exist: $jar" }
            requireJarContains(jar, D8_MAIN_CLASS)
            return jar to "config"
        }
        locateEngineD8Jar()?.let { return it }
        val sdkJar = locateSdkD8Jar(androidHome)
        if (sdkJar != null) return sdkJar
        failClosed(
            "No D8 jar located: probed engine code source and ANDROID_HOME/build-tools/*/lib/d8.jar. " +
                "Set apk.d8JarPath explicitly.",
        )
    }

    private fun locateEngineD8Jar(): Pair<Path, String>? {
        val codeSource = ApkToolchainProvisioner::class.java.protectionDomain.codeSource ?: return null
        val location = runCatching { Path.of(codeSource.location.toURI()) }.getOrNull() ?: return null
        if (Files.isRegularFile(location)) {
            if (runCatching { requireJarContains(location, D8_MAIN_CLASS) }.isSuccess) {
                return location to "engine-code-source"
            }
            return null
        }
        // Test/classpath layout: locate the r8 jar via the class loader.
        val resource = ApkToolchainProvisioner::class.java.classLoader.getResource("${D8_MAIN_CLASS.replace('.', '/')}.class")
        val url = resource?.toString() ?: return null
        if (!url.startsWith("jar:file:")) return null
        val fileUri = url.removePrefix("jar:").substringBefore("!")
        val jar = runCatching { Paths.get(java.net.URI.create(fileUri)) }.getOrNull() ?: return null
        return if (Files.isRegularFile(jar)) jar to "engine-classpath" else null
    }

    private fun locateSdkD8Jar(androidHome: String?): Pair<Path, String>? {
        val candidates = mutableListOf<Path>()
        if (!androidHome.isNullOrBlank()) {
            val buildTools = Paths.get(androidHome, "build-tools")
            if (Files.isDirectory(buildTools)) {
                buildTools.toFile().listFiles()?.filter { it.isDirectory }?.forEach { directory ->
                    candidates.add(directory.toPath().resolve("lib/d8.jar"))
                }
            }
        }
        for (candidate in candidates.sortedByDescending { it.toString() }) {
            if (!Files.isRegularFile(candidate)) continue
            val size = Files.size(candidate)
            val digest = sha256Hex(Files.readAllBytes(candidate))
            if (size == SDK_D8_SIZE && digest == SDK_D8_SHA256) {
                return candidate to "android-sdk"
            }
        }
        return null
    }

    private fun requireJarContains(jar: Path, mainClass: String) {
        JarFile(jar.toFile()).use { file ->
            require(file.getJarEntry("${mainClass.replace('.', '/')}.class") != null) {
                "jar does not contain $mainClass: $jar"
            }
        }
    }

    // --- helpers -----------------------------------------------------------

    internal fun classLoaderResource(name: String): ByteArray? {
        val loader = ApkToolchainProvisioner::class.java.classLoader
        return loader.getResourceAsStream(name)?.use(InputStream::readBytes)
            ?: ClassLoader.getSystemResourceAsStream(name)?.use(InputStream::readBytes)
    }

    internal fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { byte -> "%02x".format(byte) }

    private fun executable(directory: Path, name: String): Path =
        if (isWindows()) directory.resolve("$name.exe") else directory.resolve(name)

    private fun isWindows(): Boolean =
        System.getProperty("os.name").lowercase(Locale.ROOT).startsWith("windows")

    private fun deleteRecursively(path: Path) {
        if (!Files.exists(path)) return
        Files.walk(path).use { stream ->
            stream.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
        }
    }

    private fun failClosed(message: String): Nothing = throw IllegalStateException(message)
}
