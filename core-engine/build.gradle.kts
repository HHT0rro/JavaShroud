import java.io.RandomAccessFile
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
val cafed00dVersion = rootProject.extra["cafed00dVersion"] as String
val jlinkerVersion = rootProject.extra["jlinkerVersion"] as String
val aircompressorVersion = rootProject.extra["aircompressorVersion"] as String
val javaShroudVersion = rootProject.extra["javaShroudVersion"] as String

private data class RustRuntimeTarget(
    val platform: String,
    val cargoTarget: String,
)

private fun hostRustRuntimePlatform(osName: String, osArch: String): String {
    val normalizedOs = osName.lowercase()
    val normalizedArch = osArch.lowercase()
    if (normalizedArch !in setOf("amd64", "x86_64")) {
        throw GradleException(
            "AKEN-R1 Rust native runtime is supported only on x86_64 hosts; host architecture '$osArch' is unsupported",
        )
    }
    return when {
        normalizedOs.startsWith("windows") -> "windows-x64"
        normalizedOs.startsWith("linux") -> "linux-x64"
        else -> throw GradleException(
            "AKEN-R1 Rust native runtime is supported only on Windows x64 and Linux x64; host '$osName' is unsupported",
        )
    }
}

private fun resolveRustRuntimeTarget(value: String): RustRuntimeTarget = when (value.lowercase()) {
    "windows-x64", "x86_64-pc-windows-gnu" -> RustRuntimeTarget("windows-x64", "x86_64-pc-windows-gnu")
    "linux-x64", "x86_64-unknown-linux-gnu.2.17" -> RustRuntimeTarget("linux-x64", "x86_64-unknown-linux-gnu.2.17")
    else -> throw GradleException(
        "AKEN-R1 Rust native runtime target '$value' is unsupported; macOS, Mach-O, and .dylib targets are rejected",
    )
}

private val rustRuntimeTarget: RustRuntimeTarget = providers.gradleProperty("javashroud.rust.platform").orNull
    ?.let(::resolveRustRuntimeTarget)
    ?: resolveRustRuntimeTarget(
        hostRustRuntimePlatform(System.getProperty("os.name"), System.getProperty("os.arch")),
    )
val rustLibraryName = providers.gradleProperty("javashroud.rust.library").orElse("jsrt_ffi").get()
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
val rustReleaseDir = rustWorkspaceDir.dir("target/${rustRuntimeTarget.cargoTarget}/release")
val rustLibraryArtifact = rustReleaseDir.file(rustLibraryFileName)
val rustNativeResourceOutput = layout.buildDirectory.dir("generated/rust-native-resources")

kotlin {
    jvmToolchain(21)
    compilerOptions {
        languageVersion.set(KotlinVersion.KOTLIN_2_1)
        apiVersion.set(KotlinVersion.KOTLIN_2_1)
        jvmTarget.set(JvmTarget.JVM_21)
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
    implementation("de.femtopedia.dex2jar:dex2jar:$dex2jarVersion")
    implementation("com.github.Col-E:CAFED00D:$cafed00dVersion")
    implementation("com.github.xxDark:jlinker:$jlinkerVersion")
    implementation("io.airlift:aircompressor:$aircompressorVersion")

    testImplementation(kotlin("test"))
}

tasks.test {
    maxHeapSize = "2g"
    useJUnitPlatform()
}

tasks.named<JavaExec>("run") {
    outputs.upToDateWhen { false }
}

val buildRustNativeRuntime = tasks.register<Exec>("buildRustNativeRuntime") {
    group = "build"
    description = "Builds the AKEN-R1 Rust native runtime for the selected Windows or Linux target."
    val workspace = rustWorkspaceDir.asFile
    val cargoManifest = rustCargoManifest.asFile
    val artifact = rustLibraryArtifact.asFile
    val targetPlatform = rustRuntimeTarget.platform
    val cargoTarget = rustRuntimeTarget.cargoTarget
    workingDir = workspace
    inputs.files(fileTree(workspace) { exclude("target/**") })
    outputs.file(artifact)
    doFirst {
        if (!cargoManifest.isFile) {
            throw GradleException("AKEN-R1 Rust workspace is missing: $cargoManifest")
        }
    }
    if (targetPlatform == "linux-x64") {
        commandLine("cargo", "zigbuild", "--locked", "--workspace", "--release", "--target", cargoTarget)
    } else {
        commandLine("cargo", "build", "--locked", "--workspace", "--release", "--target", cargoTarget)
    }
}

val packageRustNativeRuntime = tasks.register<Sync>("packageRustNativeRuntime") {
    group = "build"
    description = "Packages exactly one authenticated AKEN-R1 Rust native runtime resource."
    val artifact = rustLibraryArtifact.asFile
    val targetPlatform = rustRuntimeTarget.platform
    val releaseDirectory = rustReleaseDir.asFile
    dependsOn(buildRustNativeRuntime)
    into(rustNativeResourceOutput)
    from(artifact) {
        into("META-INF/jsrt/$targetPlatform")
    }
    doFirst {
        if (!artifact.isFile || artifact.length() == 0L) {
            throw GradleException("AKEN-R1 Rust runtime artifact is missing or empty: $artifact")
        }
        if (artifact.extension.equals("dylib", ignoreCase = true) || artifact.name.contains(".dylib", ignoreCase = true)) {
            throw GradleException("AKEN-R1 rejects Mach-O/.dylib runtime artifacts: $artifact")
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
            throw GradleException("AKEN-R1 Rust runtime artifact has an invalid $targetPlatform image header: $artifact")
        }
        val machOArtifacts = releaseDirectory.listFiles().orEmpty()
            .filter { it.extension.equals("dylib", ignoreCase = true) }
        if (machOArtifacts.isNotEmpty()) {
            throw GradleException("AKEN-R1 release directory contains rejected Mach-O artifacts: ${machOArtifacts.joinToString()}")
        }
    }
}

tasks.named<ProcessResources>("processResources") {
    dependsOn(packageRustNativeRuntime)
    from(packageRustNativeRuntime)
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
