import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest
import org.gradle.api.GradleException
import org.gradle.api.tasks.Sync
import org.gradle.language.jvm.tasks.ProcessResources
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    application
    id("org.jetbrains.kotlin.jvm")
    id("org.graalvm.buildtools.native")
}

val asmVersion = rootProject.extra["asmVersion"] as String
val jacksonVersion = rootProject.extra["jacksonVersion"] as String
val slf4jVersion = rootProject.extra["slf4jVersion"] as String
val snakeyamlVersion = rootProject.extra["snakeyamlVersion"] as String
val commonsIoVersion = rootProject.extra["commonsIoVersion"] as String
val commonsCompressVersion = rootProject.extra["commonsCompressVersion"] as String
val xzVersion = rootProject.extra["xzVersion"] as String
val guavaVersion = rootProject.extra["guavaVersion"] as String
val gsonVersion = rootProject.extra["gsonVersion"] as String
val jphantomVersion = rootProject.extra["jphantomVersion"] as String
val dex2jarVersion = rootProject.extra["dex2jarVersion"] as String
val r8Version = rootProject.extra["r8Version"] as String
val apksigVersion = rootProject.extra["apksigVersion"] as String
val cafed00dVersion = rootProject.extra["cafed00dVersion"] as String
val jlinkerVersion = rootProject.extra["jlinkerVersion"] as String
val aircompressorVersion = rootProject.extra["aircompressorVersion"] as String
val javaShroudVersion = rootProject.extra["javaShroudVersion"] as String

private data class RustRuntimeTarget(
    val platform: String,
    val cargoTarget: String,
)

private fun resolveCargoExecutable(): String {
    val cargoHome = System.getenv("CARGO_HOME")?.takeIf { it.isNotBlank() } ?: return "cargo"
    val executableName = if (System.getProperty("os.name").lowercase().startsWith("windows")) "cargo.exe" else "cargo"
    val candidate = File(cargoHome, "bin/$executableName")
    return if (candidate.isFile) candidate.absolutePath else "cargo"
}

private fun lockedNativeToolchainExecutables(): List<File> {
    val root = File(System.getProperty("user.home"), ".javashroud/toolchains")
    if (!root.isDirectory) return emptyList()
    val zig = root.listFiles()
        .orEmpty()
        .firstOrNull { it.isDirectory && it.name.startsWith("zig-0.13.0-") }
        ?.resolve(if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) "zig.exe" else "zig")
    val cargoZigbuild = root.listFiles()
        .orEmpty()
        .firstOrNull { it.isDirectory && it.name.startsWith("cargo-zigbuild-0.23.2-") }
        ?.resolve(if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) "cargo-zigbuild.exe" else "cargo-zigbuild")
    return listOfNotNull(zig, cargoZigbuild).filter(File::isFile)
}

private fun hostRustRuntimePlatform(osName: String, osArch: String): String {
    val normalizedOs = osName.lowercase()
    val normalizedArch = osArch.lowercase()
    if (normalizedArch !in setOf("amd64", "x86_64")) {
        throw GradleException(
            "Qp Rust native runtime is supported only on x86_64 hosts; host architecture '$osArch' is unsupported",
        )
    }
    return when {
        normalizedOs.startsWith("windows") -> "windows-x64"
        normalizedOs.startsWith("linux") -> "linux-x64"
        else -> throw GradleException(
            "Qp Rust native runtime is supported only on Windows x64 and Linux x64; host '$osName' is unsupported",
        )
    }
}

private fun resolveRustRuntimeTarget(value: String): RustRuntimeTarget = when (value.lowercase()) {
    "windows-x64", "x86_64-pc-windows-gnu" -> RustRuntimeTarget("windows-x64", "x86_64-pc-windows-gnu")
    "linux-x64", "x86_64-unknown-linux-gnu.2.17" -> RustRuntimeTarget("linux-x64", "x86_64-unknown-linux-gnu.2.17")
    else -> throw GradleException(
        "Qp Rust native runtime target '$value' is unsupported; macOS, Mach-O, and .dylib targets are rejected",
    )
}

// cargo-zigbuild accepts the glibc floor as part of the command target
// (`x86_64-unknown-linux-gnu.2.17`) but emits Cargo artifacts below the base
// Rust target directory (`x86_64-unknown-linux-gnu`). Keep the command target
// and the on-disk output target distinct so Linux packaging consumes the
// artifact that the just-completed build actually produced.
private fun cargoOutputTarget(target: RustRuntimeTarget): String =
    if (target.cargoTarget == "x86_64-unknown-linux-gnu.2.17") {
        "x86_64-unknown-linux-gnu"
    } else {
        target.cargoTarget
    }

private val requiredWindowsNativeExports = listOf(
    "JNI_OnLoad",
    "JNI_OnUnload",
    "qp_r1_runtime_binding_digest",
    "qp_r1_open_frame",
)

private fun nativeReleaseRustFlags(target: RustRuntimeTarget): String {
    if (target.platform != "windows-x64") return ""
    return requiredWindowsNativeExports.joinToString(" ") { export ->
        "-C link-arg=/EXPORT:$export"
    }
}

private val rustRuntimeTarget: RustRuntimeTarget = providers.gradleProperty("javashroud.rust.platform").orNull
    ?.let(::resolveRustRuntimeTarget)
    ?: resolveRustRuntimeTarget(
        hostRustRuntimePlatform(System.getProperty("os.name"), System.getProperty("os.arch")),
    )
val rustLibraryName = providers.gradleProperty("javashroud.rust.library").orElse("qp_ffi").get()
require(rustLibraryName.isNotEmpty() && rustLibraryName.all { it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '_' }) {
    "javashroud.rust.library must contain only ASCII letters, digits, and underscores"
}
val rustLibraryFileName = if (rustRuntimeTarget.platform == "windows-x64") {
    "$rustLibraryName.dll"
} else {
    "lib$rustLibraryName.so"
}
val rustWorkspaceDir = layout.projectDirectory.dir("src/main/rust")
val rustCargoManifest = rustWorkspaceDir.file("Cargo.toml")
val rustOutputTarget = cargoOutputTarget(rustRuntimeTarget)
val rustReleaseDir = rustWorkspaceDir.dir("target/$rustOutputTarget/release")
val rustLibraryArtifact = rustReleaseDir.file(rustLibraryFileName)
val rustNativeResourceOutput = layout.buildDirectory.dir("generated/rust-native-resources")

// --- APK toolchain wiring -------------------------------------------------
// dex-tools (with its transitive dex2jar closure) is vendored as engine
// resources and spawned as a separate Java process, so the published engine
// never depends on a local Android SDK for dex -> class conversion. r8 (D8)
// and apksig are linked into the fat jar as regular dependencies; both pins
// were verified against the Google Maven artifacts (see THIRD_PARTY_NOTICES.md).
val apkDexToolsVersion = dex2jarVersion
val pinnedR8Sha256 = "58366f77067207c39a17d469de7b05701d2877212a9c55201bcb0af43e59e903"
val pinnedR8SizeBytes = 17_650_417L
val pinnedApksigSha256 = "c4f6fdf2148490296f422a7eb37647ea11d1c3b02f1f2349c33ce257f3c29b1f"
val pinnedApksigSizeBytes = 496_313L
val apkDexToolsConfiguration = configurations.create("apkDexTools")
val apkDexToolsResourceRoot = layout.buildDirectory.dir("generated/apk-dex-tools")

kotlin {
    compilerOptions {
        languageVersion.set(KotlinVersion.KOTLIN_2_1)
        apiVersion.set(KotlinVersion.KOTLIN_2_1)
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(false)
        suppressWarnings.set(false)
        freeCompilerArgs.addAll(
            listOf(
                "-Xjsr305=strict",
                "-Xjvm-default=all",
                "-Xemit-jvm-type-annotations",
            ),
        )
    }
}

application {
    mainClass.set("io.github.hht0rro.javashroud.MainKt")
}

// A stale Gradle/Kotlin output snapshot can report compileKotlin as up-to-date
// after the relocated root build directory has lost a production class. Keep
// the runtime entrypoint from starting with a partial classpath.
val runtimeGarbageCollectorClass = layout.buildDirectory.file(
    "classes/kotlin/main/io/github/hht0rro/javashroud/maintenance/RuntimeGarbageCollector.class",
)

tasks.named<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>("compileKotlin") {
    outputs.file(runtimeGarbageCollectorClass)
}

// Runtime helper classes under src/main/java are embedded into obfuscated
// output jars and must load on the oldest supported runtime (Java 8).
tasks.withType<JavaCompile>().configureEach {
    sourceCompatibility = "8"
    targetCompatibility = "8"
}

// Engine bytecode stays at 21; helper sources are the only Java inputs and
// they are intentionally emitted as Java 8 bytecode for embedded runtimes.
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    jvmTargetValidationMode.set(org.jetbrains.kotlin.gradle.dsl.jvm.JvmTargetValidationMode.WARNING)
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib")
    implementation("org.jetbrains.kotlin:kotlin-reflect")

    implementation("org.ow2.asm:asm:$asmVersion")
    implementation("org.ow2.asm:asm-tree:$asmVersion")
    implementation("org.ow2.asm:asm-commons:$asmVersion")
    implementation("org.ow2.asm:asm-util:$asmVersion")
    implementation("org.ow2.asm:asm-analysis:$asmVersion")

    implementation("com.fasterxml.jackson.core:jackson-databind:$jacksonVersion")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-toml:$jacksonVersion")
    implementation("org.slf4j:slf4j-api:$slf4jVersion")
    implementation("org.yaml:snakeyaml:$snakeyamlVersion")
    implementation("commons-io:commons-io:$commonsIoVersion")
    implementation("org.apache.commons:commons-compress:$commonsCompressVersion")
    implementation("org.tukaani:xz:$xzVersion")
    implementation("com.google.guava:guava:$guavaVersion")
    implementation("com.google.code.gson:gson:$gsonVersion")

    implementation("com.github.Col-E:jphantom:$jphantomVersion")
    implementation("com.android.tools:r8:$r8Version")
    implementation("com.android.tools.build:apksig:$apksigVersion")
    implementation("com.github.Col-E:CAFED00D:$cafed00dVersion")
    implementation("com.github.xxDark:jlinker:$jlinkerVersion")
    implementation("io.airlift:aircompressor:$aircompressorVersion")

    // The de.femtopedia.dex2jar:dex2jar coordinate is a 283-byte empty shell
    // jar; the real CLI lives in dex-tools. It is vendored below instead of
    // linked, because it is spawned as an isolated Java 8 process.
    apkDexToolsConfiguration("de.femtopedia.dex2jar:dex-tools:$apkDexToolsVersion")

    testImplementation(kotlin("test"))
}

tasks.test {
    maxHeapSize = "2g"
    useJUnitPlatform()
    val engineJar = tasks.jar.flatMap { it.archiveFile }
    dependsOn(tasks.jar)
    inputs.file(engineJar)
    systemProperty("javashroud.test.engineJar", engineJar.get().asFile.absolutePath)
    // Real-toolchain APK tests resolve the vendored dex2jar closure from the
    // test classpath; r8/apksig arrive via the runtime classpath.
    dependsOn("packageApkDexTools")
    classpath += files(apkDexToolsResourceRoot)
}

tasks.named<JavaExec>("run") {
    outputs.upToDateWhen { false }
    inputs.file(runtimeGarbageCollectorClass)
}

val buildRustNativeRuntime = tasks.register<Exec>("buildRustNativeRuntime") {
    group = "build"
    description = "Builds the Qp Rust native runtime for the selected Windows or Linux target."
    val workspace = rustWorkspaceDir.asFile
    val cargoManifest = rustCargoManifest.asFile
    val artifact = rustLibraryArtifact.asFile
    val cargoTarget = rustRuntimeTarget.cargoTarget
    workingDir = workspace
    inputs.files(fileTree(workspace) { exclude("target/**") })
    outputs.file(artifact)
    doFirst {
        if (!cargoManifest.isFile) {
            throw GradleException("Qp Rust workspace is missing: $cargoManifest")
        }
    }
    val inheritedRustFlags = System.getenv("RUSTFLAGS").orEmpty().trim()
    val requiredRustFlags = nativeReleaseRustFlags(rustRuntimeTarget)
    val lockedToolExecutables = lockedNativeToolchainExecutables()
    val inheritedPath = System.getenv("PATH").orEmpty()
    val toolDirectories = lockedToolExecutables.map { it.parentFile.absolutePath }
    if (toolDirectories.isNotEmpty()) {
        environment("PATH", (toolDirectories + inheritedPath).joinToString(File.pathSeparator))
        lockedToolExecutables.firstOrNull { it.name.startsWith("zig", ignoreCase = true) }?.let { zig ->
            environment("ZIG", zig.absolutePath)
        }
    }
    if (rustRuntimeTarget.platform == "linux-x64") {
        val inheritedArgs = System.getenv("CARGO_ENCODED_RUSTFLAGS")?.split('\u001f')
            ?: inheritedRustFlags.split(Regex("\\s+"))
        val sourcePathFlag = "--remap-path-prefix=${workspace.canonicalPath}/=core-engine/src/main/rust/"
        val compilerArgs = inheritedArgs.filter(String::isNotEmpty) + sourcePathFlag
        inputs.property("rustCompilerArgs", compilerArgs)
        environment("CARGO_ENCODED_RUSTFLAGS", compilerArgs.joinToString("\u001f"))
    } else {
        environment(
            "RUSTFLAGS",
            listOf(inheritedRustFlags, requiredRustFlags)
                .filter { it.isNotEmpty() }
                .joinToString(" "),
        )
    }
    environment("CARGO_TERM_COLOR", "never")
    commandLine(resolveCargoExecutable(), "zigbuild", "--locked", "--workspace", "--release", "--target", cargoTarget)
}

val packageRustWorkspaceSources = tasks.register<Sync>("packageRustWorkspaceSources") {
    group = "build"
    description = "Packages the Qp Rust workspace sources for on-machine recompilation."
    val outputRoot = layout.buildDirectory.dir("generated/rust-workspace-sources/META-INF/rust-runtime")
    from(fileTree(rustWorkspaceDir) {
        exclude("target/**")
        exclude("**/.target*/**")
        exclude("**/*.pdb")
    })
    into(outputRoot)
    doLast {
        val root = outputRoot.get().asFile
        val files = root.walkTopDown()
            .filter { it.isFile && it.name != "file-list.txt" }
            .map { it.relativeTo(root).invariantSeparatorsPath }
            .sorted()
            .toList()
        root.resolve("file-list.txt").writeText(files.joinToString("\n"))
        if (files.none { it == "Cargo.toml" } || files.none { it == "Cargo.lock" }) {
            throw GradleException("Qp Rust workspace sources are missing Cargo.toml or Cargo.lock")
        }
    }
}

val packageRustNativeRuntime = tasks.register<Sync>("packageRustNativeRuntime") {
    group = "build"
    description = "Packages exactly one authenticated Qp Rust native runtime resource."
    val artifact = rustLibraryArtifact.asFile
    val targetPlatform = rustRuntimeTarget.platform
    val releaseDirectory = rustReleaseDir.asFile
    // Capture script state by value: the configuration cache forbids task
    // actions from holding references to the build script instance.
    val requiredExports = requiredWindowsNativeExports.toList()
    dependsOn(buildRustNativeRuntime)
    into(rustNativeResourceOutput)
    from(artifact) {
        into("META-INF/jsrt/$targetPlatform")
    }
    doFirst {
        if (!artifact.isFile || artifact.length() == 0L) {
            throw GradleException("Qp Rust runtime artifact is missing or empty: $artifact")
        }
        if (artifact.extension.equals("dylib", ignoreCase = true) || artifact.name.contains(".dylib", ignoreCase = true)) {
            throw GradleException("Qp rejects Mach-O/.dylib runtime artifacts: $artifact")
        }
        val header = artifact.inputStream().use { it.readNBytes(20) }
        val validImage = when (targetPlatform) {
            "windows-x64" -> RandomAccessFile(artifact, "r").use { input ->
                val fileLength = input.length()
                if (fileLength < 0x40) {
                    false
                } else {
                    val dosHeader = ByteArray(0x40)
                    input.readFully(dosHeader)
                    if (dosHeader[0] != 'M'.code.toByte() || dosHeader[1] != 'Z'.code.toByte()) {
                        false
                    } else {
                        val peOffset = (dosHeader[0x3c].toLong() and 0xFFL) or
                            ((dosHeader[0x3d].toLong() and 0xFFL) shl 8) or
                            ((dosHeader[0x3e].toLong() and 0xFFL) shl 16) or
                            ((dosHeader[0x3f].toLong() and 0xFFL) shl 24)
                        if (peOffset > fileLength - 26) {
                            false
                        } else {
                            input.seek(peOffset)
                            val peHeader = ByteArray(26)
                            input.readFully(peHeader)
                            val machine = (peHeader[4].toInt() and 0xFF) or ((peHeader[5].toInt() and 0xFF) shl 8)
                            val optionalMagic = (peHeader[24].toInt() and 0xFF) or ((peHeader[25].toInt() and 0xFF) shl 8)
                            peHeader.copyOfRange(0, 4).contentEquals(byteArrayOf('P'.code.toByte(), 'E'.code.toByte(), 0, 0)) &&
                                machine == 0x8664 && optionalMagic == 0x20B
                        }
                    }
                }
            }
            "linux-x64" -> header.size >= 20 &&
                header.copyOfRange(0, 4).contentEquals(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())) &&
                header[4].toInt() == 2 && header[5].toInt() == 1 &&
                header[18].toInt() == 0x3e && header[19].toInt() == 0
            else -> false
        }
        if (!validImage) {
            throw GradleException("Qp Rust runtime artifact has an invalid $targetPlatform image header: $artifact")
        }
        if (targetPlatform == "windows-x64") {
            val imageBytes = artifact.readBytes()
            try {
                fun containsAscii(value: String): Boolean {
                    val needle = value.toByteArray(Charsets.US_ASCII)
                    return imageBytes.indices.any { start ->
                        start + needle.size <= imageBytes.size &&
                            needle.indices.all { offset -> imageBytes[start + offset] == needle[offset] }
                    }
                }
                val missing = requiredExports.filterNot { export ->
                    containsAscii(export)
                }
                if (missing.isNotEmpty()) {
                    throw GradleException(
                        "Qp Windows runtime is missing required exported JNI symbols: ${missing.joinToString(",")}",
                    )
                }
            } finally {
                imageBytes.fill(0)
            }
        }
        val machOArtifacts = releaseDirectory.listFiles().orEmpty()
            .filter { it.extension.equals("dylib", ignoreCase = true) }
        if (machOArtifacts.isNotEmpty()) {
            throw GradleException("Qp release directory contains rejected Mach-O artifacts: ${machOArtifacts.joinToString()}")
        }
    }
}

val packageApkDexTools = tasks.register<Sync>("packageApkDexTools") {
    group = "build"
    description = "Vendors the dex-tools jar closure as engine resources with a generated SHA-256SUMS manifest."
    val resourceRoot = apkDexToolsResourceRoot
    into(resourceRoot.map { root -> root.dir("META-INF/apk-tools/dex2jar") })
    from(apkDexToolsConfiguration)
    doLast {
        fun sha256Of(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            }
            return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
        }
        val root = resourceRoot.get().asFile.resolve("META-INF/apk-tools/dex2jar")
        val jars = root.listFiles().orEmpty().filter { it.isFile && it.extension == "jar" }.sortedBy { it.name }
        if (jars.none { it.name.startsWith("dex-tools-") }) {
            throw GradleException("apk dex-tools vendoring is missing the dex-tools jar: ${jars.map { it.name }}")
        }
        val sums = jars.joinToString("\n") { jar -> "${sha256Of(jar)}  ${jar.name}" } + "\n"
        root.resolve("SHA-256SUMS").writeText(sums)
        // Build-time assertion: every vendored jar is covered by the manifest.
        val manifestNames = sums.lineSequence().map { it.substringAfter("  ").trim() }.filter { it.isNotEmpty() }.toSet()
        val uncovered = jars.map { it.name }.filterNot { it in manifestNames }
        if (uncovered.isNotEmpty()) {
            throw GradleException("apk dex-tools SHA-256SUMS does not cover: $uncovered")
        }
    }
}

val verifyApkPinnedArtifacts = tasks.register("verifyApkPinnedArtifacts") {
    group = "verification"
    description = "Asserts the resolved r8 and apksig artifacts match their pinned SHA-256 digests."
    val r8JarName = "r8-$r8Version.jar"
    val apksigJarName = "apksig-$apksigVersion.jar"
    val expectedR8 = pinnedR8Sha256 to pinnedR8SizeBytes
    val expectedApksig = pinnedApksigSha256 to pinnedApksigSizeBytes
    val pinnedFiles = configurations.runtimeClasspath.get()
        .files
        .filter { it.name == r8JarName || it.name == apksigJarName }
    doLast {
        fun sha256Of(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            }
            return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
        }
        val r8Jar = pinnedFiles.firstOrNull { it.name == r8JarName }
            ?: throw GradleException("runtime classpath does not contain $r8JarName")
        val apksigJar = pinnedFiles.firstOrNull { it.name == apksigJarName }
            ?: throw GradleException("runtime classpath does not contain $apksigJarName")
        if (r8Jar.length() != expectedR8.second || sha256Of(r8Jar) != expectedR8.first) {
            throw GradleException("r8 artifact failed its pinned size/SHA-256 check: $r8Jar")
        }
        if (apksigJar.length() != expectedApksig.second || sha256Of(apksigJar) != expectedApksig.first) {
            throw GradleException("apksig artifact failed its pinned size/SHA-256 check: $apksigJar")
        }
    }
}

tasks.named<ProcessResources>("processResources") {
    dependsOn(packageRustNativeRuntime, packageRustWorkspaceSources, packageApkDexTools, verifyApkPinnedArtifacts)
    from(packageRustNativeRuntime)
    from(layout.buildDirectory.dir("generated/rust-workspace-sources"))
    from(apkDexToolsResourceRoot)
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

tasks.jar {
    archiveBaseName.set("obfuscator-engine")
    manifest {
        attributes["Main-Class"] = application.mainClass.get()
        attributes["Implementation-Title"] = "JavaShroud Core Engine"
        attributes["Implementation-Version"] = javaShroudVersion
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    from(layout.buildDirectory.dir("classes/kotlin/main"))
    from(layout.buildDirectory.dir("classes/kotlin/main")) {
        include("io/github/hht0rro/javashroud/transforms/protection/**/*.class")
        exclude("io/github/hht0rro/javashroud/transforms/protection/FlowControlException.class")
        exclude("io/github/hht0rro/javashroud/transforms/protection/FlowControlException${'$'}Companion.class")
        into("META-INF/javashroud-helpers")
    }
    from(layout.buildDirectory.dir("classes/kotlin/main")) {
        include("io/github/hht0rro/javashroud/transforms/protection/**/*.class")
        exclude("io/github/hht0rro/javashroud/transforms/protection/FlowControlException.class")
        exclude("io/github/hht0rro/javashroud/transforms/protection/FlowControlException${'$'}Companion.class")
        rename("(.*)\\.class", "$1.bin")
        into("META-INF/javashroud-helpers")
    }
    from(layout.buildDirectory.dir("classes/java/main")) {
        include("io/github/hht0rro/javashroud/transforms/protection/**/*.class")
        into("META-INF/javashroud-helpers")
    }
    from(layout.buildDirectory.dir("classes/java/main")) {
        include("io/github/hht0rro/javashroud/transforms/protection/**/*.class")
        rename("(.*)\\.class", "$1.bin")
        into("META-INF/javashroud-helpers")
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

tasks.register<Exec>("buildNativeEngine") {
    group = "build"
    description = "Builds the core-engine native executable via the repository batch script."
    workingDir = projectDir
    commandLine("cmd", "/c", "build-native.bat")
}

graalvmNative {
    binaries {
        named("main") {
            imageName.set("obfuscator-engine")
            mainClass.set(application.mainClass.get())
            buildArgs.addAll(
                listOf(
                    "--no-fallback",
                    "--enable-url-protocols=https",
                    "--gc=serial",
                    "-O2",
                    "-march=compatibility",
                    "-H:+UnlockExperimentalVMOptions",
                    "-H:+ReportExceptionStackTraces",
                    "-H:IncludeResources=META-INF/javashroud-helpers/.*\\.class",
                    "-H:IncludeResources=META-INF/javashroud-helpers/.*\\.bin",
                    "-H:IncludeResources=io/github/hht0rro/javashroud/transforms/protection/.*\\.class",
                    "-H:IncludeResources=META-INF/.*",
                ),
            )
        }
    }
}
