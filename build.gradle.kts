plugins {
    id("org.jetbrains.kotlin.jvm") version "2.1.21" apply false
    id("org.graalvm.buildtools.native") version "0.11.1" apply false
}

val asmVersion = "9.9"
val jacksonVersion = "2.20.0"
val slf4jVersion = "2.0.17"
val snakeyamlVersion = "2.5"
val commonsIoVersion = "2.20.0"
val commonsCompressVersion = "1.28.0"
val guavaVersion = "33.4.8-jre"
val gsonVersion = "2.13.1"
val jphantomVersion = "1.4.4"
val dex2jarVersion = "2.4.28"
val cafed00dVersion = "2.1.4"
val jlinkerVersion = "1.0.7"
val aircompressorVersion = "0.27"
val javaShroudVersion = "0.9.2-dev"
val javaShroudVbcVersion = "4.55"

allprojects {
    version = javaShroudVersion

    repositories {
        mavenCentral()
        maven("https://jitpack.io")
    }

    extra.apply {
        set("asmVersion", asmVersion)
        set("jacksonVersion", jacksonVersion)
        set("slf4jVersion", slf4jVersion)
        set("snakeyamlVersion", snakeyamlVersion)
        set("commonsIoVersion", commonsIoVersion)
        set("commonsCompressVersion", commonsCompressVersion)
        set("guavaVersion", guavaVersion)
        set("gsonVersion", gsonVersion)
        set("jphantomVersion", jphantomVersion)
        set("dex2jarVersion", dex2jarVersion)
        set("cafed00dVersion", cafed00dVersion)
        set("jlinkerVersion", jlinkerVersion)
        set("aircompressorVersion", aircompressorVersion)
        set("javaShroudVersion", javaShroudVersion)
        set("javaShroudVbcVersion", javaShroudVbcVersion)
    }
}

subprojects {
    layout.buildDirectory.set(rootProject.layout.buildDirectory.dir(project.name))
}
