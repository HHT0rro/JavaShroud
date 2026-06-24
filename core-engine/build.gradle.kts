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
val guavaVersion = rootProject.extra["guavaVersion"] as String
val gsonVersion = rootProject.extra["gsonVersion"] as String
val jphantomVersion = rootProject.extra["jphantomVersion"] as String
val dex2jarVersion = rootProject.extra["dex2jarVersion"] as String
val cafed00dVersion = rootProject.extra["cafed00dVersion"] as String
val jlinkerVersion = rootProject.extra["jlinkerVersion"] as String
val aircompressorVersion = rootProject.extra["aircompressorVersion"] as String

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

tasks.processResources {
    from(file("src/main/native")) {
        include("js_kernel.c", "js_helpers.c", "js_native_common.c", "js_native_common.h", "js_crypto.c", "js_crypto.h", "js_antidebug.c", "js_antidebug.h", "js_protected_section.c", "js_protected_section.h", "js_vm_core.c", "js_vm_core.h", "js_vm_resource.c", "js_vm_resource.h", "js_vm_symbol.c", "js_vm_symbol.h", "js_vm_internal.h", "js_jni_runtime.c", "js_jni_runtime.h", "native_secrets.inc")
        into("META-INF/native-src")
    }
    from(file("src/main/native/zstd")) {
        include("**/*")
        into("META-INF/native-src/zstd")
    }
    from(file("src/main/native/cross-compile")) {
        include("jni.h", "jni_md_linux.h")
        into("META-INF/native-src/cross-compile")
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}

tasks.jar {
    archiveBaseName.set("obfuscator-engine")
    manifest {
        attributes["Main-Class"] = application.mainClass.get()
    }
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    from(layout.buildDirectory.dir("classes/kotlin/main"))
    from(layout.buildDirectory.dir("classes/kotlin/main")) {
        include("io/github/hht0rro/javashroud/transforms/protection/**/*.class")
        into("META-INF/javashroud-helpers")
    }
    from(layout.buildDirectory.dir("classes/kotlin/main")) {
        include("io/github/hht0rro/javashroud/transforms/protection/**/*.class")
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
    // Bundle native C source files for runtime recompilation during obfuscation.
    // These are used by NativeRecompilationTransforms to generate per-output
    // diversified native libraries when a zig toolchain is available.
    from(file("src/main/native")) {
        include("js_kernel.c", "js_helpers.c", "js_native_common.c", "js_native_common.h", "js_crypto.c", "js_crypto.h", "js_antidebug.c", "js_antidebug.h", "js_protected_section.c", "js_protected_section.h", "js_vm_core.c", "js_vm_core.h", "js_vm_resource.c", "js_vm_resource.h", "js_vm_symbol.c", "js_vm_symbol.h", "js_vm_internal.h", "js_jni_runtime.c", "js_jni_runtime.h", "native_secrets.inc")
        into("META-INF/native-src")
    }
    from(file("src/main/native/zstd")) {
        include("**/*")
        into("META-INF/native-src/zstd")
    }
    from(file("src/main/native/cross-compile")) {
        include("jni.h", "jni_md_linux.h")
        into("META-INF/native-src/cross-compile")
    }
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}


tasks.register<Exec>("buildNativeKernel") {
    group = "build"
    description = "Compiles the JavaShroud native microkernel (js_kernel) for the current platform."
    workingDir = file("src/main/native")
    if (org.gradle.internal.os.OperatingSystem.current().isWindows) {
        commandLine("cmd", "/c", "build-native-kernel.bat")
    } else {
        commandLine("bash", "build-native-kernel-linux.sh")
    }
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
                    "-H:IncludeResources=META-INF/native-src/.*",
                ),
            )
        }
    }
}
