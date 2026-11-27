package io.github.hht0rro.javashroud.apk

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.config.parseConfig
import io.github.hht0rro.javashroud.config.validateConfig
import io.github.hht0rro.javashroud.model.config.ApkSigningConfig
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.APPEND
import java.nio.file.StandardOpenOption.CREATE
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.jar.JarOutputStream
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Timeout

/**
 * Owned Android runtime regressions. Enable explicitly with JAVASHROUD_ANDROID_DEVICE_TESTS=true,
 * ANDROID_SERIAL, and ANDROID_HOME or ANDROID_SDK_ROOT. The JNI test additionally requires
 * ANDROID_NDK_HOME. An enabled test fails if its prerequisites are unavailable.
 * JAVASHROUD_ANDROID_EXPECT_API and JAVASHROUD_ANDROID_EXPECT_PAGE_SIZE optionally require exact
 * observed device values before fixture generation, compilation, or installation.
 *
 * Each test creates its own package, sources, disposable signing key, and retained evidence under
 * build/android-runtime-evidence. All adb commands use the explicit serial. Package operations
 * address only that test's package. The device must already be booted and available to adb.
 */
@Timeout(value = 20, unit = TimeUnit.MINUTES, threadMode = Timeout.ThreadMode.SEPARATE_THREAD)
class ApkAndroidDeviceSmokeTest {
    @Test
    fun singleDexResourcesAndShortLayoutCallbackReturn42() = runScenario(Scenario.SINGLE)

    @Test
    fun atLeast66000MethodsRemainMultiDexAndExecuteAcrossClassSplits() = runScenario(Scenario.MULTI)

    @Test
    fun jniAdditionReturns42WithTheSelectedDeviceAbiAndPageSize() = runScenario(Scenario.JNI)

    private fun runScenario(scenario: Scenario) {
        val enabled = System.getenv("JAVASHROUD_ANDROID_DEVICE_TESTS") == "true"
        val reason = "Set JAVASHROUD_ANDROID_DEVICE_TESTS=true to run the owned Android device smoke tests"
        if (!enabled) println("SKIPPED ${scenario.name}: $reason")
        assumeTrue(enabled, reason)
        val root = generateSequence(Path.of("").toAbsolutePath().normalize()) { it.parent }
            .firstOrNull { Files.isRegularFile(it.resolve("settings.gradle.kts")) }
            ?: error("Cannot find the repository root for Android runtime evidence")
        val evidenceRoot = Files.createDirectories(root.resolve("build/android-runtime-evidence"))
        val evidence = Files.createTempDirectory(evidenceRoot, "${scenario.name.lowercase()}-")
        println("Android runtime evidence: $evidence")
        val harness = DeviceHarness(scenario, evidence)
        try {
            harness.exercise()
            harness.note("PASS ${scenario.name}")
        } catch (failure: Throwable) {
            harness.note(failure.stackTraceToString())
            throw failure
        }
    }

    private enum class Scenario { SINGLE, MULTI, JNI }

    private data class Sdk(val adb: Path, val aapt2: Path, val zipalign: Path, val apksigner: Path, val androidJar: Path)
    private data class Device(val api: Int, val abi: String, val pageSize: Int)
    private data class NativeTools(val clang: Path, val readelf: Path, val sysroot: Path, val target: String)
    private data class DexInventory(val classCounts: List<Int>, val definedMethods: Int)

    private class DeviceHarness(private val scenario: Scenario, private val evidence: Path) {
        private val identity = UUID.randomUUID().toString().replace("-", "")
        private val packageName = "io.github.hht0rro.javashroud.smoke.s$identity"
        private val tag = "JS${identity.take(20)}"
        private val windows = System.getProperty("os.name").startsWith("Windows", ignoreCase = true)
        private val jdkBin = Path.of(System.getProperty("java.home"), "bin")
        private var commandIndex = 0
        private lateinit var serial: String
        private lateinit var sdk: Sdk
        private lateinit var device: Device

        fun note(message: String) {
            Files.writeString(evidence.resolve("session.log"), "${Instant.now()} $message\n", CREATE, APPEND)
        }

        fun exercise() {
            note("scenario=$scenario package=$packageName logTag=$tag")
            serial = requiredEnvironment("ANDROID_SERIAL")
            sdk = resolveSdk()
            device = inspectDevice()
            val nativeTools = if (scenario == Scenario.JNI) resolveNativeTools() else null
            val java = requireFile(jdkBin.resolve(executable("java")))
            val javac = requireFile(jdkBin.resolve(executable("javac")))
            val keytool = requireFile(jdkBin.resolve(executable("keytool")))
            val toolchain = ApkToolchainProvisioner.ensure("", "", userHome = evidence.resolve("tool-cache"))
            val signing = createSigningKey(keytool)
            val sources = generateSources()
            val resourceApk = compileResources()
            val classJar = compileJava(javac, sources)
            val dex = ApkD8Runner(COMPILE_TIMEOUT, ::recordProcess).compile(
                toolchain, classJar, evidence.resolve("input-dex"), MIN_API, sdk.androidJar.toString(), ::note,
            )
            val library = nativeTools?.let(::compileNativeLibrary)
            val unsigned = assembleApk(resourceApk, dex, library)
            val original = evidence.resolve("original.apk")
            ApkSignerService.sign(unsigned, original, signing, MIN_API, device.pageSize, ::note)
            val originalSha = sha256(original)
            Files.writeString(evidence.resolve("input.sha256"), "$originalSha  original.apk\n")
            try {
                val originalInventory = inspectDex(original)
                verifyArtifact(java, original, signing, library)
                val protectedApk = protect(original, signing, toolchain)
                val protectedInventory = inspectDex(protectedApk)
                assertEquals(originalInventory.classCounts.sum(), protectedInventory.classCounts.sum(), "Class count changed")
                if (scenario == Scenario.MULTI) {
                    assertEquals(originalInventory.definedMethods, protectedInventory.definedMethods, "Method definitions changed")
                }
                assertEquals(originalSha, sha256(original), "Protection changed the input APK")
                verifyArtifact(java, protectedApk, signing, library)
                assertPackageAbsent()
                exerciseInstalled(original, "original")
                exerciseInstalled(protectedApk, "protected")
            } finally {
                assertEquals(originalSha, sha256(original), "Input APK bytes changed during the smoke test")
            }
        }

        private fun resolveSdk(): Sdk {
            val sdkRoot = System.getenv("ANDROID_HOME")?.trim()?.takeIf { it.isNotEmpty() }
                ?: requiredEnvironment("ANDROID_SDK_ROOT")
            val root = Path.of(sdkRoot).toAbsolutePath().normalize()
            require(Files.isDirectory(root)) { "Android SDK directory does not exist: $root" }
            val buildTools = versionedDirectories(root.resolve("build-tools"))
                .firstOrNull { candidate ->
                    listOf(executable("aapt2"), executable("zipalign"), "lib/apksigner.jar")
                        .all { Files.isRegularFile(candidate.resolve(it)) }
                } ?: error("SDK build-tools must contain aapt2, zipalign, and lib/apksigner.jar: $root")
            val androidJar = versionedDirectories(root.resolve("platforms"))
                .map { it.resolve("android.jar") }.firstOrNull { Files.isRegularFile(it) }
                ?: error("SDK platform android.jar is missing: $root")
            note("SDK=$root buildTools=$buildTools androidJar=$androidJar")
            return Sdk(
                requireFile(root.resolve("platform-tools/${executable("adb")}")),
                buildTools.resolve(executable("aapt2")), buildTools.resolve(executable("zipalign")),
                buildTools.resolve("lib/apksigner.jar"), androidJar,
            )
        }

        private fun inspectDevice(): Device {
            assertEquals("device", adb("device-state", "get-state").trim(), "Explicit Android device is unavailable")
            val apiText = adb("device-api", "shell", "getprop", "ro.build.version.sdk").trim()
            val abi = adb("device-abi", "shell", "getprop", "ro.product.cpu.abi").trim()
            val abiList = adb("device-abilist", "shell", "getprop", "ro.product.cpu.abilist").trim()
            val getconf = recordProcess(adbCommand("shell", "getconf", "PAGE_SIZE"), DEVICE_TIMEOUT)
            val reportedPageSize = getconf.output.trim().toIntOrNull()?.takeIf { getconf.exitCode == 0 && !getconf.timedOut }
            val pageSize = reportedPageSize ?: run {
                // API21's toolbox does not supply getconf. Read the kernel mapping units there.
                val pages = adb("device-kernel-page-size", "shell", "cat", "/proc/self/smaps")
                val observedPages = Regex("(?m)^KernelPageSize:\\s+([0-9]+) kB\\s*$")
                    .findAll(pages).map { it.groupValues[1].toInt() * 1024 }.toSet()
                observedPages.singleOrNull() ?: error("Device has no unambiguous kernel page size: $observedPages")
            }
            note("pageSizeSource=${if (reportedPageSize != null) "getconf" else "smaps"}")
            val selinux = adb("device-selinux", "shell", "getenforce").trim()
            note("serial=$serial api=$apiText abi=$abi abilist=$abiList pageSize=$pageSize SELinux=$selinux")
            val api = apiText.toIntOrNull() ?: error("Device returned an invalid Android API: $apiText")
            require(api >= MIN_API) { "Owned fixtures require Android API $MIN_API or newer, found $api" }
            require(abi.isNotBlank()) { "Device returned an empty primary ABI" }
            require(pageSize == 4096 || pageSize == 16384) { "Unsupported device page size: $pageSize" }
            require(selinux in setOf("Enforcing", "Permissive", "Disabled")) { "Invalid SELinux state: $selinux" }
            System.getenv("JAVASHROUD_ANDROID_EXPECT_API")?.let { expected ->
                val expectedApi = expected.trim().toIntOrNull()
                    ?: error("JAVASHROUD_ANDROID_EXPECT_API must be an integer, found '$expected'")
                assertEquals(expectedApi, api, "Selected device API differs from JAVASHROUD_ANDROID_EXPECT_API")
            }
            System.getenv("JAVASHROUD_ANDROID_EXPECT_PAGE_SIZE")?.let { expected ->
                val expectedPageSize = expected.trim().toIntOrNull()
                    ?: error("JAVASHROUD_ANDROID_EXPECT_PAGE_SIZE must be an integer, found '$expected'")
                assertEquals(
                    expectedPageSize, pageSize,
                    "Selected device page size differs from JAVASHROUD_ANDROID_EXPECT_PAGE_SIZE",
                )
            }
            return Device(api, abi, pageSize)
        }

        private fun resolveNativeTools(): NativeTools {
            val ndk = Path.of(requiredEnvironment("ANDROID_NDK_HOME")).toAbsolutePath().normalize()
            requireFile(ndk.resolve("source.properties"))
            val host = when {
                windows -> "windows-x86_64"
                System.getProperty("os.name").startsWith("Mac") -> "darwin-x86_64"
                else -> "linux-x86_64"
            }
            val llvm = ndk.resolve("toolchains/llvm/prebuilt/$host")
            val sysroot = llvm.resolve("sysroot")
            requireFile(sysroot.resolve("usr/include/jni.h"))
            val triple = when (device.abi) {
                "arm64-v8a" -> "aarch64-linux-android"
                "armeabi-v7a" -> "armv7a-linux-androideabi"
                "x86" -> "i686-linux-android"
                "x86_64" -> "x86_64-linux-android"
                else -> error("JNI fixture has no NDK target for the selected device ABI: ${device.abi}")
            }
            note("NDK=$ndk host=$host target=$triple$MIN_API pageSize=${device.pageSize}")
            return NativeTools(
                requireFile(llvm.resolve("bin/${executable("clang")}")),
                requireFile(llvm.resolve("bin/${executable("llvm-readelf")}")), sysroot, "$triple$MIN_API",
            )
        }

        private fun createSigningKey(keytool: Path): ApkSigningConfig {
            val key = evidence.resolve("owned-test-key.p12")
            command("keytool", listOf(
                keytool.toString(), "-genkeypair", "-storetype", "PKCS12", "-keystore", key.toString(),
                "-alias", "owned", "-storepass", TEST_PASSWORD, "-keypass", TEST_PASSWORD,
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "2",
                "-dname", "CN=JavaShroud Owned Android Smoke", "-noprompt",
            ))
            return ApkSigningConfig(key.toString(), TEST_PASSWORD, "owned", TEST_PASSWORD)
        }

        private fun generateSources(): List<Path> {
            val sourceRoot = Files.createDirectories(evidence.resolve("src"))
            val sources = mutableListOf<Path>()
            fun source(name: String, text: String) {
                sources.add(Files.writeString(sourceRoot.resolve(name), text.trimIndent() + "\n"))
            }
            Files.createDirectories(evidence.resolve("res/layout"))
            Files.createDirectories(evidence.resolve("res/values"))
            Files.writeString(evidence.resolve("AndroidManifest.xml"), """
                <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="$packageName">
                    <uses-sdk android:minSdkVersion="$MIN_API" android:targetSdkVersion="${device.api}" />
                    <application android:label="Owned smoke" android:allowBackup="false"
                        android:extractNativeLibs="false" android:theme="@android:style/Theme.Material.Light.NoActionBar">
                        <activity android:name="$packageName.SmokeActivity" android:exported="true">
                            <intent-filter>
                                <action android:name="android.intent.action.MAIN" />
                                <category android:name="android.intent.category.LAUNCHER" />
                            </intent-filter>
                        </activity>
                    </application>
                </manifest>
            """.trimIndent())
            Files.writeString(evidence.resolve("res/values/values.xml"), """
                <resources><integer name="answer">42</integer><string name="action">Exercise callback</string></resources>
            """.trimIndent())
            Files.writeString(evidence.resolve("res/layout/main.xml"), """
                <$packageName.AnswerView xmlns:android="http://schemas.android.com/apk/res/android"
                    android:id="@+id/action" android:layout_width="match_parent" android:layout_height="match_parent"
                    android:text="@string/action" android:onClick="go" />
            """.trimIndent())
            source("AnswerView.java", """
                package $packageName;
                public final class AnswerView extends OwnedBaseButton {
                    public AnswerView(android.content.Context context, android.util.AttributeSet attributes) {
                        super(context, attributes);
                    }
                    @Override public OwnedAnswerSpec createSpec(android.content.Context context, android.util.AttributeSet attributes) {
                        return new OwnedAnswerSpec();
                    }
                }
            """)
            source("OwnedBaseButton.java", """
                package $packageName;
                public abstract class OwnedBaseButton extends android.widget.Button {
                    private final int checkedAnswer;
                    public OwnedBaseButton(android.content.Context context, android.util.AttributeSet attributes) {
                        super(context, attributes);
                        checkedAnswer = createSpec(context, attributes).answer;
                        if (checkedAnswer != 42) throw new AssertionError("Inherited factory returned " + checkedAnswer);
                    }
                    abstract OwnedBaseSpec createSpec(android.content.Context context, android.util.AttributeSet attributes);
                    public final int checkedAnswer() { return checkedAnswer; }
                }
            """)
            source("OwnedBaseSpec.java", """
                package $packageName;
                public class OwnedBaseSpec {
                    public final int answer;
                    public OwnedBaseSpec(int answer) { this.answer = answer; }
                }
            """)
            source("OwnedAnswerSpec.java", """
                package $packageName;
                public final class OwnedAnswerSpec extends OwnedBaseSpec {
                    public OwnedAnswerSpec() { super(42); }
                }
            """)
            source("OwnedParcel.java", """
                package $packageName;
                public final class OwnedParcel implements android.os.Parcelable {
                    public final int answer;
                    public OwnedParcel(int answer) { this.answer = answer; }
                    public int describeContents() { return 0; }
                    public void writeToParcel(android.os.Parcel output, int flags) { output.writeInt(answer); }
                    public static final android.os.Parcelable.Creator<OwnedParcel> CREATOR =
                        new android.os.Parcelable.Creator<OwnedParcel>() {
                            public OwnedParcel createFromParcel(android.os.Parcel input) { return new OwnedParcel(input.readInt()); }
                            public OwnedParcel[] newArray(int size) { return new OwnedParcel[size]; }
                        };
                }
            """)
            source("OwnedWebBridge.java", """
                package $packageName;
                public final class OwnedWebBridge {
                    @android.webkit.JavascriptInterface public int answer() { return 42; }
                }
            """)
            source("SmokeActivity.java", """
                package $packageName;
                public final class SmokeActivity extends android.app.Activity {
                    private String invocation;
                    private android.webkit.WebView web;
                    @Override public void onCreate(android.os.Bundle state) {
                        super.onCreate(state);
                        invocation = getIntent().getStringExtra("invocation");
                        setContentView(R.layout.main);
                        final int factory = ((AnswerView) findViewById(R.id.action)).checkedAnswer();
                        if (factory != 42) throw new AssertionError("Inherited dispatch failed");
                        android.util.Log.i("$tag", "token=" + invocation + " factory=42");
                        final int result = Calculation.value();
                        final int resource = getResources().getInteger(R.integer.answer);
                        if (result != 42 || resource != 42) throw new AssertionError("Unexpected fixture answer");
                        android.util.Log.i("$tag", "token=" + invocation + " result=" + result + " resource=" + resource);
                        final android.os.Parcel parcel = android.os.Parcel.obtain();
                        try {
                            parcel.writeParcelable(new OwnedParcel(42), 0);
                            parcel.setDataPosition(0);
                            final OwnedParcel restored = parcel.readParcelable(OwnedParcel.class.getClassLoader());
                            if (restored.answer != 42) throw new AssertionError("Parcelable round trip failed");
                            android.util.Log.i("$tag", "token=" + invocation + " parcel=42");
                        } finally { parcel.recycle(); }
                        web = new android.webkit.WebView(this);
                        web.getSettings().setJavaScriptEnabled(true);
                        web.addJavascriptInterface(new OwnedWebBridge(), "owned");
                        web.setWebViewClient(new android.webkit.WebViewClient() {
                            @Override public void onPageFinished(android.webkit.WebView view, String url) {
                                view.evaluateJavascript("owned.answer()", new android.webkit.ValueCallback<String>() {
                                    @Override public void onReceiveValue(String value) {
                                        if (!"42".equals(value)) throw new AssertionError("Javascript interface returned " + value);
                                        android.util.Log.i("$tag", "token=" + invocation + " web=42");
                                    }
                                });
                            }
                        });
                        web.loadDataWithBaseURL("https://owned.invalid/", "<html><body>Owned fixture</body></html>", "text/html", "UTF-8", null);
                        final android.view.View button = findViewById(R.id.action);
                        button.post(new Runnable() {
                            @Override public void run() {
                                if (!button.performClick()) throw new AssertionError("Layout callback was not invoked");
                            }
                        });
                    }
                    public void go(android.view.View view) {
                        final int result = Calculation.value();
                        if (result != 42) throw new AssertionError("Unexpected callback answer");
                        android.util.Log.i("$tag", "token=" + invocation + " click=" + result);
                    }
                    @Override public void onDestroy() {
                        if (web != null) web.destroy();
                        super.onDestroy();
                    }
                }
            """)
            val calculation = StringBuilder("package $packageName;\npublic final class Calculation {\n")
            calculation.append("    public static int value() {\n")
            if (scenario == Scenario.MULTI) {
                repeat(BULK_CLASSES) { index ->
                    val name = "Bulk${index.toString().padStart(3, '0')}"
                    val bulk = StringBuilder("package $packageName;\npublic final class $name {\n")
                    repeat(METHODS_PER_CLASS) { method ->
                        bulk.append("    public static int m$method(int value) { return value + $method; }\n")
                    }
                    bulk.append("}\n")
                    source("$name.java", bulk.toString())
                    calculation.append("        if ($name.m0(42) != 42) throw new AssertionError(\"$name\");\n")
                }
            }
            if (scenario == Scenario.JNI) {
                source("NativeMath.java", """
                    package $packageName;
                    public final class NativeMath {
                        static { System.loadLibrary("owned_smoke"); }
                        public static native int add(int left, int right);
                    }
                """)
                calculation.append("        return NativeMath.add(19, 23);\n")
            } else {
                calculation.append("        return 20 + 22;\n")
            }
            calculation.append("    }\n}\n")
            source("Calculation.java", calculation.toString())
            return sources
        }

        private fun compileResources(): Path {
            val compiled = evidence.resolve("compiled-resources.zip")
            command("aapt2-compile", listOf(
                sdk.aapt2.toString(), "compile", "--dir", evidence.resolve("res").toString(), "-o", compiled.toString(),
            ))
            val resourceApk = evidence.resolve("resources.apk")
            val generated = Files.createDirectories(evidence.resolve("generated"))
            command("aapt2-link", listOf(
                sdk.aapt2.toString(), "link", "-o", resourceApk.toString(),
                "--manifest", evidence.resolve("AndroidManifest.xml").toString(),
                "-I", sdk.androidJar.toString(), "--java", generated.toString(), compiled.toString(),
            ))
            return resourceApk
        }

        private fun compileJava(javac: Path, sources: List<Path>): Path {
            val generated = Files.walk(evidence.resolve("generated")).use { paths ->
                paths.filter { it.toString().endsWith(".java") }.toList()
            }
            assertTrue(generated.isNotEmpty(), "aapt2 generated no R.java")
            val classes = Files.createDirectories(evidence.resolve("classes"))
            val arguments = evidence.resolve("javac.args")
            Files.writeString(arguments, (sources + generated).joinToString("\n") { source ->
                "\"${source.toString().replace('\\', '/')}\""
            })
            command("javac", listOf(
                javac.toString(), "-encoding", "UTF-8", "-source", "8", "-target", "8",
                "-classpath", sdk.androidJar.toString(), "-d", classes.toString(), "@$arguments",
            ), COMPILE_TIMEOUT)
            val jar = evidence.resolve("fixture-classes.jar")
            JarOutputStream(Files.newOutputStream(jar)).use { output ->
                Files.walk(classes).use { paths ->
                    paths.filter { Files.isRegularFile(it) && it.toString().endsWith(".class") }.sorted().forEach { file ->
                        output.putNextEntry(ZipEntry(classes.relativize(file).toString().replace('\\', '/')))
                        Files.copy(file, output)
                        output.closeEntry()
                    }
                }
            }
            return jar
        }

        private fun compileNativeLibrary(tools: NativeTools): Path {
            val source = evidence.resolve("owned-smoke.c")
            Files.writeString(source, """
                #include <jni.h>
                JNIEXPORT jint JNICALL Java_${packageName.replace('.', '_')}_NativeMath_add(
                        JNIEnv *environment, jclass owner, jint left, jint right) {
                    (void)environment;
                    (void)owner;
                    return left + right;
                }
            """.trimIndent() + "\n")
            val library = evidence.resolve("libowned_smoke.so")
            command("ndk-clang", listOf(
                tools.clang.toString(), "--target=${tools.target}", "--sysroot=${tools.sysroot}",
                "-shared", "-fPIC", "-O2", "-Wl,-z,max-page-size=${device.pageSize}",
                "-Wl,-z,common-page-size=${device.pageSize}", source.toString(), "-o", library.toString(),
            ), COMPILE_TIMEOUT)
            val headers = command("native-program-headers", listOf(
                tools.readelf.toString(), "--program-headers", "--wide", library.toString(),
            )).output
            val loads = headers.lineSequence().map(String::trim).filter { it.startsWith("LOAD ") }.toList()
            assertTrue(loads.isNotEmpty(), "NDK library has no ELF LOAD segments")
            for (load in loads) {
                val alignment = load.split(Regex("\\s+")).last().removePrefix("0x").toLong(16)
                assertTrue(
                    alignment >= device.pageSize && alignment % device.pageSize == 0L,
                    "Incorrect ELF alignment: $load",
                )
            }
            return library
        }

        private fun assembleApk(resourceApk: Path, dex: List<Pair<String, ByteArray>>, library: Path?): Path {
            val unaligned = evidence.resolve("unsigned-unaligned.apk")
            ZipOutputStream(Files.newOutputStream(unaligned)).use { output ->
                ZipFile(resourceApk.toFile()).use { resources ->
                    for (entry in resources.entries()) {
                        val bytes = resources.getInputStream(entry).use { it.readBytes() }
                        addEntry(output, entry.name, bytes, entry.method)
                    }
                }
                for ((name, bytes) in dex) addEntry(output, name, bytes, ZipEntry.DEFLATED)
                if (library != null) {
                    addEntry(output, "lib/${device.abi}/libowned_smoke.so", Files.readAllBytes(library), ZipEntry.STORED)
                }
            }
            val aligned = evidence.resolve("unsigned-aligned.apk")
            command("zipalign-input", listOf(
                sdk.zipalign.toString(), "-P", (device.pageSize / 1024).toString(), "-f", "4", unaligned.toString(), aligned.toString(),
            ))
            return aligned
        }

        private fun addEntry(output: ZipOutputStream, name: String, bytes: ByteArray, method: Int) {
            val entry = ZipEntry(name)
            entry.method = method
            if (method == ZipEntry.STORED) {
                entry.size = bytes.size.toLong()
                entry.crc = CRC32().apply { update(bytes) }.value
            }
            output.putNextEntry(entry)
            output.write(bytes)
            output.closeEntry()
        }

        private fun protect(
            original: Path,
            signing: ApkSigningConfig,
            toolchain: ApkToolchainProvisioner.ApkToolchain,
        ): Path {
            val protectedApk = evidence.resolve("protected.apk")
            val config = evidence.resolve("protection.toml")
            val mapper = ObjectMapper()
            fun literal(path: Path): String = mapper.writeValueAsString(path.toString())
            Files.writeString(config, """
                inputJarPath = ${literal(original)}
                outputJarPath = ${literal(protectedApk)}
                artifactFormat = 'apk'
                protectionProfile = 'minimal'
                allowOptInPasses = true
                logFilePath = ${literal(evidence.resolve("pipeline.log"))}
                [ruleSet]
                rules = []
                [apk]
                minApi = $MIN_API
                androidJarPath = ${literal(sdk.androidJar)}
                dex2jarDirPath = ${literal(toolchain.dex2jarDirectory)}
                d8JarPath = ${literal(toolchain.d8Jar)}
                soPageSize = ${device.pageSize}
                [apk.signing]
                keystorePath = ${literal(Path.of(signing.keystorePath))}
                storePassword = '$TEST_PASSWORD'
                keyAlias = 'owned'
                keyPassword = '$TEST_PASSWORD'
                v1Enabled = true
                v2Enabled = true
            """.trimIndent() + "\n" + listOf(
                "rename-packages", "rename-classes", "rename-methods", "rename-fields", "strip-compile-debug-info",
            ).joinToString("\n") { pass -> "[[passes]]\nid = '$pass'\nenabled = true\n" })
            val validated = validateConfig(parseConfig(config), config)
            ApkPipelineRunner(
                dexToClassConverter = ApkDex2JarRunner(COMPILE_TIMEOUT, ::recordProcess),
                classToDexCompiler = ApkD8Runner(COMPILE_TIMEOUT, ::recordProcess),
            ).run(validated, config) { event -> note("engine $event") }
            return requireFile(protectedApk)
        }

        private fun inspectDex(apk: Path): DexInventory {
            val dexes = ZipFile(apk.toFile()).use { archive ->
                archive.entries().asSequence().filter { ApkOutputPacker.isDexEntry(it.name) }
                    .sortedBy { ApkOutputPacker.dexIndex(it.name) }
                    .map { entry -> entry.name to archive.getInputStream(entry).use { it.readBytes() } }.toList()
            }
            ApkValidation.validateDisjointDexClasses(dexes)
            val counts = mutableListOf<Int>()
            var definedMethods = 0
            for ((name, bytes) in dexes) {
                ApkValidation.validateDexHeader(name, bytes)
                val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
                val classCount = buffer.getInt(0x60)
                val classOffset = buffer.getInt(0x64)
                val methodIds = buffer.getInt(0x58)
                assertTrue(classCount > 0 && methodIds in 1..65536, "Invalid DEX class/method counts in $name")
                counts += classCount
                for (index in 0 until classCount) {
                    val dataOffset = buffer.getInt(classOffset + index * 32 + 24)
                    if (dataOffset == 0) continue
                    buffer.position(dataOffset)
                    readUleb128(buffer) // static fields
                    readUleb128(buffer) // instance fields
                    definedMethods += readUleb128(buffer) + readUleb128(buffer)
                }
                note("${apk.fileName}/$name classes=$classCount methodIds=$methodIds")
            }
            if (scenario == Scenario.MULTI) {
                assertTrue(counts.size >= 2, "Persistent multidex fixture collapsed to ${counts.size} DEX file(s)")
                assertTrue(
                    definedMethods >= BULK_CLASSES * METHODS_PER_CLASS,
                    "Expected at least 66000 method definitions, found $definedMethods",
                )
                assertTrue(counts.all { it < counts.sum() }, "Classes did not split across DEX files")
            } else {
                assertEquals(1, counts.size, "Small owned fixture must contain a single DEX")
            }
            note("${apk.fileName} dexCount=${counts.size} classCounts=$counts definedMethods=$definedMethods sha256=${sha256(apk)}")
            return DexInventory(counts, definedMethods)
        }

        private fun readUleb128(buffer: ByteBuffer): Int {
            var value = 0
            for (shift in 0..28 step 7) {
                val next = buffer.get().toInt() and 0xff
                if (shift == 28) require(next and 0xf0 == 0) { "Invalid DEX ULEB128" }
                value = value or ((next and 0x7f) shl shift)
                if (next and 0x80 == 0) return value
            }
            error("Unterminated DEX ULEB128")
        }

        private fun verifyArtifact(java: Path, apk: Path, signing: ApkSigningConfig, library: Path?) {
            ZipFile(apk.toFile()).use { archive ->
                val manifest = archive.getEntry("AndroidManifest.xml") ?: error("Missing fixture manifest in $apk")
                val info = ApkBinaryXmlReader.parse(archive.getInputStream(manifest).use { it.readBytes() })
                assertEquals(packageName, info.packageName, "Only this test's unique owned package may be installed")
            }
            ApkSignerService.verify(apk, signing, MIN_API, ::note)
            val signature = command("${apk.fileName}-apksigner", listOf(
                java.toString(), "-jar", sdk.apksigner.toString(), "verify", "--verbose", "--print-certs", apk.toString(),
            )).output
            assertTrue(signature.contains("Verified using v1 scheme (JAR signing): true"), "Independent v1 signature verification failed")
            assertTrue(signature.contains("Verified using v2 scheme (APK Signature Scheme v2): true"), "Independent v2 signature verification failed")
            command("${apk.fileName}-zipalign", listOf(
                sdk.zipalign.toString(), "-c", "-P", (device.pageSize / 1024).toString(), "-v", "4", apk.toString(),
            ))
            if (library != null) {
                org.apache.commons.compress.archivers.zip.ZipFile.builder().setPath(apk).get().use { archive ->
                    val entry = archive.getEntry("lib/${device.abi}/libowned_smoke.so")
                        ?: error("JNI payload is missing from $apk")
                    assertEquals(ZipEntry.STORED, entry.method, "JNI library must remain uncompressed")
                    assertEquals(0L, entry.dataOffset % device.pageSize, "JNI ZIP payload has incorrect page alignment")
                    val bytes = archive.getInputStream(entry).use { it.readBytes() }
                    assertTrue(bytes.contentEquals(Files.readAllBytes(library)), "JNI library bytes changed")
                }
            }
        }

        private fun assertPackageAbsent() {
            val result = recordProcess(adbCommand("shell", "pm", "path", packageName), DEVICE_TIMEOUT)
            assertTrue(!result.timedOut, "Package collision check timed out")
            assertTrue(result.exitCode in 0..1, "Unable to establish fixture package absence: ${result.output}")
            assertTrue(!result.output.contains("package:"), "Unique fixture package already exists: $packageName")
        }

        private fun exerciseInstalled(apk: Path, label: String) {
            var failure: Throwable? = null
            try {
                val install = adb("$label-install", "install", "--no-streaming", "-t", apk.toString())
                assertTrue(install.lineSequence().any { it.trim() == "Success" }, "Fixture installation failed: $install")
                val token = UUID.randomUUID().toString()
                val launch = adb("$label-start", "shell", "am", "start", "-W", "-n", "$packageName/.SmokeActivity", "--es", "invocation", token)
                assertTrue(launch.lineSequence().any { it.trim() == "Status: ok" }, "Fixture launch failed: $launch")
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30)
                var observed = false
                while (System.nanoTime() < deadline) {
                    val log = adb("$label-logcat", "logcat", "-d", "-v", "brief", "-s", "$tag:I", "*:S")
                    val lines = log.lineSequence().filter { it.contains("token=$token ") }.toList()
                    if (lines.any { it.endsWith(" result=42 resource=42") } && lines.any { it.endsWith(" click=42") } &&
                        lines.any { it.endsWith(" parcel=42") } && lines.any { it.endsWith(" web=42") } &&
                        lines.any { it.endsWith(" factory=42") }) {
                        observed = true
                        break
                    }
                    Thread.sleep(500)
                }
                assertTrue(observed, "Expected result=42 resource=42 click=42 parcel=42 web=42 factory=42 for $label; evidence=$evidence")
                val firstPid = packagePid("$label-first-pid")
                assertTrue(firstPid.matches(Regex("[0-9]+")), "Fixture process is missing: $firstPid")
                Thread.sleep(2_000)
                assertEquals(firstPid, packagePid("$label-later-pid"), "Fixture process did not survive")
                val runtime = adb("$label-process-logcat", "logcat", "-d", "-v", "threadtime", "-s", "AndroidRuntime:E", "*:S")
                assertTrue(!runtime.contains("Process: $packageName, PID: $firstPid"), "Fixture crashed: $runtime")
                note("$label runtime PASS result=42 resource=42 click=42 parcel=42 web=42 factory=42 pid=$firstPid token=$token")
            } catch (error: Throwable) {
                failure = error
                // Capture native tombstones before uninstall removes the package identity.
                // A missing PID can precede the normal AndroidRuntime log inspection.
                try {
                    adb("$label-failure-crash-logcat", "logcat", "-b", "crash", "-d", "-v", "threadtime")
                    adb("$label-failure-exit-info", "shell", "dumpsys", "activity", "exit-info", packageName)
                } catch (diagnosticFailure: Throwable) {
                    error.addSuppressed(diagnosticFailure)
                    note("Failure diagnostics: ${diagnosticFailure.stackTraceToString()}")
                }
                throw error
            } finally {
                // Timeout interruption must still allow bounded cleanup of this unique package.
                val interrupted = Thread.interrupted()
                try {
                    val uninstall = adb("$label-uninstall", "uninstall", packageName)
                    assertTrue(uninstall.lineSequence().any { it.trim() == "Success" }, "Fixture cleanup failed: $uninstall")
                } catch (cleanup: Throwable) {
                    if (failure == null) throw cleanup
                    failure.addSuppressed(cleanup)
                    note("Cleanup failure: ${cleanup.stackTraceToString()}")
                } finally {
                    if (interrupted) Thread.currentThread().interrupt()
                }
            }
        }

        private fun packagePid(label: String): String {
            val lines = adb(label, "shell", "ps").lineSequence().filter { it.isNotBlank() }.toList()
            val header = lines.firstOrNull()?.trim()?.split(Regex("\\s+")).orEmpty()
            val pidIndex = header.indexOf("PID")
            require(pidIndex >= 0) { "Device process list has no PID column" }
            return lines.drop(1).map { it.trim().split(Regex("\\s+")) }
                .filter { it.lastOrNull() == packageName }.singleOrNull()?.getOrNull(pidIndex).orEmpty()
        }

        private fun adb(label: String, vararg arguments: String): String = command(label, adbCommand(*arguments), DEVICE_TIMEOUT).output

        private fun adbCommand(vararg arguments: String): List<String> = listOf(sdk.adb.toString(), "-s", serial) + arguments

        private fun command(label: String, arguments: List<String>, timeout: Long = DEVICE_TIMEOUT): ApkProcessSupport.ProcessResult {
            note("$label")
            val result = recordProcess(arguments, timeout)
            ApkProcessSupport.requireSuccess(label, arguments, result)
            return result
        }

        private fun recordProcess(arguments: List<String>, timeout: Long): ApkProcessSupport.ProcessResult {
            val prefix = (++commandIndex).toString().padStart(4, '0')
            val output = evidence.resolve("$prefix-output.log")
            Files.writeString(evidence.resolve("$prefix-command.txt"), arguments.joinToString("\n") + "\ntimeoutMillis=$timeout\n")
            val process = ProcessBuilder(arguments).directory(evidence.toFile()).redirectErrorStream(true).redirectOutput(output.toFile()).start()
            val started = System.nanoTime()
            try {
                val finished = process.waitFor(timeout, TimeUnit.MILLISECONDS)
                if (!finished) terminate(process)
                val result = ApkProcessSupport.ProcessResult(
                    if (finished) process.exitValue() else -1, Files.readString(output), !finished,
                )
                val elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
                note("command=$prefix exit=${result.exitCode} timedOut=${result.timedOut} elapsedMillis=$elapsed")
                return result
            } catch (interrupted: InterruptedException) {
                terminate(process)
                Thread.currentThread().interrupt()
                throw interrupted
            }
        }

        private fun terminate(process: Process) {
            process.descendants().use { children -> children.forEach { it.destroyForcibly() } }
            process.destroyForcibly()
            process.waitFor(5, TimeUnit.SECONDS)
        }

        private fun versionedDirectories(root: Path): List<Path> {
            require(Files.isDirectory(root)) { "Missing SDK directory: $root" }
            return Files.list(root).use { children ->
                children.filter { Files.isDirectory(it) }.toList().sortedWith { left, right ->
                    val leftVersion = Regex("[0-9]+").findAll(left.fileName.toString()).map { it.value.toInt() }.toList()
                    val rightVersion = Regex("[0-9]+").findAll(right.fileName.toString()).map { it.value.toInt() }.toList()
                    var comparison = 0
                    for (index in 0 until maxOf(leftVersion.size, rightVersion.size)) {
                        comparison = (rightVersion.getOrElse(index) { 0 }).compareTo(leftVersion.getOrElse(index) { 0 })
                        if (comparison != 0) break
                    }
                    comparison
                }
            }
        }

        private fun executable(name: String): String = if (windows) "$name.exe" else name

        private fun requiredEnvironment(name: String): String = System.getenv(name)?.trim()?.takeIf { it.isNotEmpty() }
            ?: error("JAVASHROUD_ANDROID_DEVICE_TESTS=true requires $name${if (name == "ANDROID_NDK_HOME") " for the JNI scenario" else ""}")

        private fun requireFile(path: Path): Path {
            require(Files.isRegularFile(path)) { "Required Android smoke-test tool or input does not exist: $path" }
            return path
        }

        private fun sha256(path: Path): String = MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(path)).joinToString("") { "%02x".format(it.toInt() and 0xff) }

        private companion object {
            const val MIN_API = 21
            const val BULK_CLASSES = 66
            const val METHODS_PER_CLASS = 1000
            const val COMPILE_TIMEOUT = 180_000L
            const val DEVICE_TIMEOUT = 60_000L
            const val TEST_PASSWORD = "owned-smoke-test"
        }
    }
}
