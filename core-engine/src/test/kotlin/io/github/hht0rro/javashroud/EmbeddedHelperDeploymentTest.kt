package io.github.hht0rro.javashroud

import com.fasterxml.jackson.databind.ObjectMapper
import io.github.hht0rro.javashroud.adapters.protocol.EngineCommand
import io.github.hht0rro.javashroud.adapters.protocol.buildCommandRequest
import io.github.hht0rro.javashroud.adapters.protocol.dispatchRequest
import io.github.hht0rro.javashroud.kernel.EngineKernel
import io.github.hht0rro.javashroud.model.analysis.JarAnalysisSummary
import io.github.hht0rro.javashroud.model.analysis.RenamePlan
import io.github.hht0rro.javashroud.model.artifact.BytecodeArtifact
import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.transforms.protection.EmbeddedHelperDeployment
import io.github.hht0rro.javashroud.transforms.protection.NativeKernelShellPacker
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Focused helper deployment regression coverage for the remaining live helper-backed passes.
 */
class EmbeddedHelperDeploymentTest {
    private val objectMapper = ObjectMapper()

    @Test
    fun jni_microkernel_loader_embeds_all_helper_inner_classes() {
        val updated = EmbeddedHelperDeployment.injectRequiredHelpers(
            artifact = emptyArtifact(),
            executedPassIds = listOf("jni-microkernel-loader"),
        )
        val entries = updated.jarEntries.map { it.name }.toSet()

        for (entryName in listOf(
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}RuntimeResourceMetadata.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}SealedNativeLibrary.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}TypeParseResult.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}SamLambdaOptions.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}SamInvocationHandler.class",
        )) {
            assertTrue(entryName in entries, "JNI microkernel helper dependency must be embedded: $entryName")
        }
    }


    @Test
    fun overlay_marker_alone_does_not_satisfy_max_stub_abi_probe() {
        val shellPackedBytes = "loadable-native-prefix-${NativeKernelShellPacker.LOADER_MARKER}".toByteArray(Charsets.US_ASCII)

        assertFalse(
            EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(shellPackedBytes),
            "standard overlay marker alone must not be accepted as max stub shell evidence.",
        )
    }

    @Test
    fun max_stub_markers_and_jni_onload_satisfy_jni_vm_abi_probe() {
        val maxStubBytes = "native-prefix-JNI_OnLoad-${NativeKernelShellPacker.MAX_STUB_MARKER}-${NativeKernelShellPacker.MAX_PAYLOAD_MARKER}".toByteArray(Charsets.US_ASCII)

        assertTrue(
            EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(maxStubBytes),
            "max stub artifacts must carry JNI_OnLoad plus stub and payload markers.",
        )
    }

    @Test
    fun jni_microkernel_helper_loads_outer_stub_without_java_max_payload_decoder() {
        val helperSource = Files.readString(resolveWorkspacePath("core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))

        assertTrue(helperSource.contains("System.load(tempLib.getAbsolutePath())"), "Bundled native loading must still delegate to the extracted outer stub library.")
        assertFalse(helperSource.contains("System.loadLibrary("), "A bundled verification failure must not fall back to a stale system-path library.")
        assertTrue(helperSource.contains("decodeSealedNativeResource"), "Java may only decode the sealed outer native resource before System.load.")

        for (forbiddenToken in listOf(
            NativeKernelShellPacker.MAX_STUB_MARKER,
            NativeKernelShellPacker.MAX_PAYLOAD_MARKER,
            "js_shell_payload",
            "js_shell_stream_key",
            "js_shell_payload_mac",
            "js_shell_payload.inc",
            "NativeKernelShellPacker",
            "buildMaxPayloadBundle",
            "renderMaxPayloadHeader",
        )) {
            assertFalse(
                helperSource.contains(forbiddenToken),
                "JniMicrokernelHelper must not parse, decrypt, or fallback-load max shell payload material in Java: $forbiddenToken",
            )
        }
    }

    @Test
    fun jni_microkernel_helper_parses_boot_kek_without_trimmed_text_copies() {
        val helperSource = Files.readString(resolveWorkspacePath("core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val bootSecretStart = helperSource.indexOf("private static byte[] loadBootSecret(byte[] bootEnvelope)")
        val bootSecretEnd = helperSource.indexOf("private static byte[] decryptBootMaterial", bootSecretStart)
        assertTrue(bootSecretStart >= 0 && bootSecretEnd > bootSecretStart, "Boot KEK loader must remain locatable.")
        val bootSecretLoader = helperSource.substring(bootSecretStart, bootSecretEnd)

        assertFalse(bootSecretLoader.contains("encoded.trim()"), "Runtime boot KEK parsing must match the strict native environment contract.")
        assertFalse(bootSecretLoader.contains("new String(bytes, StandardCharsets.US_ASCII)"), "Boot KEK files must be decoded directly from the wipeable byte buffer.")
        assertTrue(bootSecretLoader.contains("return hexToBytes(bytes);"), "Runtime boot KEK files must use direct byte-array hex decoding.")
    }

    @Test
    fun bundle_native_libraries_replaces_existing_kernel_resources_with_recompiled_outputs() {
        val deploymentSource = Files.readString(resolveWorkspacePath("core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/EmbeddedHelperDeployment.kt"))
        val bundleStart = deploymentSource.indexOf("internal fun bundleNativeLibrariesIfAvailable")
        val bundleEnd = deploymentSource.indexOf("internal fun nativeLibraryContainsRequiredJniVmAbi", bundleStart)
        assertTrue(bundleStart >= 0 && bundleEnd > bundleStart, "Native bundling function must remain locatable.")
        val bundleSource = deploymentSource.substring(bundleStart, bundleEnd)
        val retainedFilter = "val retainedJarEntries = artifact.jarEntries.filterNot { entry ->"
        val rejectedNativeEntries = "isNativeKernelResource(entry.name)"
        val legacyBootCleanup = "entry.name in legacyBootResourcePaths"
        val appendRecompiled = "val updatedJarEntries = retainedJarEntries + newEntries"

        assertTrue(
            bundleSource.contains(retainedFilter),
            "Native bundling must remove pre-existing js_kernel resources before adding max outer stubs.",
        )
        assertTrue(
            bundleSource.contains(rejectedNativeEntries) && bundleSource.contains(legacyBootCleanup),
            "Native bundling must remove pre-existing kernels and legacy boot resources before packaging recompiled outputs.",
        )
        for (legacyProducer in listOf("BootMaterialEnvelope", "BootKekSidecar", "bootKeyDelivery", "embeddedBootKekBytes")) {
            assertFalse(
                bundleSource.contains(legacyProducer),
                "Native bundling must not emit or select legacy boot-key material: $legacyProducer",
            )
        }
        assertTrue(
            bundleSource.contains(appendRecompiled),
            "Native bundling must package only retained non-kernel resources plus freshly recompiled native outputs.",
        )
        assertTrue(
            bundleSource.indexOf(retainedFilter) < bundleSource.indexOf(appendRecompiled),
            "Existing native kernel resources must be filtered before the final JAR entry list is assembled.",
        )
    }

    @Test
    fun jni_microkernel_loader_removes_legacy_boot_resources_during_helper_injection() {
        val updated = EmbeddedHelperDeployment.injectRequiredHelpers(
            artifact = emptyArtifact().copy(
                jarEntries = listOf(
                    JarEntryData("META-INF/.r/boot.dat", byteArrayOf(0x01)),
                    JarEntryData("META-INF/.r/kek.dat", byteArrayOf(0x02)),
                    JarEntryData("META-INF/app/retained.bin", byteArrayOf(0x03)),
                ),
            ),
            executedPassIds = listOf("jni-microkernel-loader"),
        )
        val entries = updated.jarEntries.map { it.name }.toSet()

        assertFalse("META-INF/.r/boot.dat" in entries, "AKEN deployment must drop the legacy JSBM boot resource")
        assertFalse("META-INF/.r/kek.dat" in entries, "AKEN deployment must drop the legacy JSBK sidecar resource")
        assertTrue("META-INF/app/retained.bin" in entries, "AKEN cleanup must preserve unrelated resources")
        assertTrue(
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class" in entries,
            "AKEN cleanup must not prevent required JNI helper injection",
        )
    }

    @Test
    fun jni_microkernel_loader_removes_legacy_boot_resources_when_helpers_are_already_present() {
        val firstPass = EmbeddedHelperDeployment.injectRequiredHelpers(
            artifact = emptyArtifact(),
            executedPassIds = listOf("jni-microkernel-loader"),
        )
        val secondPass = EmbeddedHelperDeployment.injectRequiredHelpers(
            artifact = firstPass.copy(
                jarEntries = firstPass.jarEntries + listOf(
                    JarEntryData("META-INF/.r/boot.dat", byteArrayOf(0x01)),
                    JarEntryData("META-INF/.r/kek.dat", byteArrayOf(0x02)),
                    JarEntryData("META-INF/app/retained.bin", byteArrayOf(0x03)),
                ),
            ),
            executedPassIds = listOf("jni-microkernel-loader"),
        )
        val entries = secondPass.jarEntries.map { it.name }.toSet()

        assertFalse("META-INF/.r/boot.dat" in entries, "AKEN cleanup must run even when every helper is already present")
        assertFalse("META-INF/.r/kek.dat" in entries, "AKEN cleanup must remove a reintroduced embedded boot-KEK resource")
        assertTrue("META-INF/app/retained.bin" in entries, "AKEN cleanup must preserve unrelated resources on repeat deployment")
        assertEquals(firstPass.classArtifacts.size, secondPass.classArtifacts.size, "Repeat deployment must not duplicate helper class artifacts")
        assertEquals(firstPass.analysisSummary.resourceCount + 1, secondPass.analysisSummary.resourceCount, "Resource analysis must reflect only the retained reintroduced resource")
        assertEquals(firstPass.analysisSummary.classCount, secondPass.analysisSummary.classCount, "Repeat deployment must keep the class count stable")
    }

    @Test
    fun string_encryption_embeds_native_decode_helper() {
        val updated = withVbc4BuildContext(defaultVbc4BuildContext()) {
            EmbeddedHelperDeployment.injectRequiredHelpers(
                artifact = emptyArtifact(),
                executedPassIds = listOf("string-encryption"),
            )
        }
        val entries = updated.jarEntries.map { it.name }.toSet()

        assertTrue(
            "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper.class" in entries,
            "string-encryption must embed its native decode helper.",
        )
        assertTrue(
            "io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper${"$"}CachePolicy.class" in entries,
            "string-encryption must embed StringEncryptionHelper${"$"}CachePolicy because the helper links to this nested enum at runtime.",
        )
    }
    @Test
    fun class_encryption_loader_embeds_aken_class_page_runtime_helpers() {
        val updated = withVbc4BuildContext(defaultVbc4BuildContext()) {
            EmbeddedHelperDeployment.injectRequiredHelpers(
                artifact = emptyArtifact(),
                executedPassIds = listOf("class-encryption-loader"),
            )
        }
        val entries = updated.jarEntries.map { it.name }.toSet()

        for (entryName in listOf(
            "io/github/hht0rro/javashroud/transforms/protection/AkenClassPageRuntimeDescriptor.class",
            "io/github/hht0rro/javashroud/transforms/protection/AkenClassPageRuntimeDescriptor" + '$' + "PageBinding.class",
            "io/github/hht0rro/javashroud/transforms/protection/AkenClassPageRuntimeDescriptor" + '$' + "DescriptorReader.class",
            "io/github/hht0rro/javashroud/transforms/protection/AkenClassPageRuntimeDescriptor" + '$' + "WipableByteAccumulator.class",
        )) {
            assertTrue(
                entryName in entries,
                "class-encryption-loader must embed the AKEN ClassPage runtime dependency: $entryName",
            )
        }
    }

    @Test
    fun class_encryption_loader_seals_runtime_helpers_without_exposing_legacy_helper_names() {
        val inputJar = buildDiverseFixtureJar(Files.createTempFile("javashroud-helper-deploy", ".jar"))
        try {
            val outputJar = runEngine(inputJar, listOf("strip-compile-debug-info", "class-encryption-loader"))
            try {
                assertTrue(Files.exists(outputJar), "Output JAR should exist")

                val entries = loadJarEntryNames(outputJar)
                assertTrue(
                    entries.any { it.startsWith("r/") && it.endsWith(".class") },
                    "Class encryption runtime helpers should be sealed into neutral entries. Entries: $entries",
                )
                assertFalse(
                    entries.any { it.contains("ClassEncryptionLoaderHelper") },
                    "Relocated loader helpers must not expose fixed helper names. Entries: $entries",
                )
                for (legacyHelperName in listOf(
                    "HiddenClassDeployerHelper",
                    "PersonaSwitchHelper",
                    "ThreadContextKeyHelper",
                    "CrossClassCouplingHelper",
                    "InterfaceProxyHelper",
                    "VmBlockDispatcherHelper",
                )) {
                    assertFalse(
                        entries.any { it.contains(legacyHelperName) },
                        "Deleted helper '$legacyHelperName' must not be injected anymore. Entries: $entries",
                    )
                }
            } finally {
                Files.deleteIfExists(outputJar)
            }
        } finally {
            Files.deleteIfExists(inputJar)
        }
    }


    private fun defineHelper(helperBytes: ByteArray): Class<*> = object : ClassLoader(javaClass.classLoader) {
        fun define(): Class<*> = defineClass(
            "io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper",
            helperBytes,
            0,
            helperBytes.size,
        )
    }.define()

    private fun resolveWorkspacePath(relativePath: String): Path {
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val candidate = current.resolve(relativePath)
            if (Files.exists(candidate)) return candidate
            current = current.parent ?: break
        }
        error("Unable to locate workspace file: $relativePath")
    }

    private fun emptyArtifact(): BytecodeArtifact = BytecodeArtifact(
        jarEntries = emptyList(),
        classArtifacts = emptyList(),
        classArtifactIndex = emptyMap(),
        analysisSummary = JarAnalysisSummary(
            classCount = 0,
            resourceCount = 0,
            manifestPresent = false,
            classSummaries = emptyList(),
            classNameIndex = emptyMap(),
            ruleMatches = emptyList(),
            renamePlan = RenamePlan(emptyList()),
        ),
    )

    private fun runEngine(inputJar: Path, passIds: List<String>): Path {
        val tag = safeTag(passIds.joinToString("-"), "javashroud-helper-")
        val outputJar = inputJar.resolveSibling("javashroud-helper-out-$tag.jar")
        val configPath = inputJar.resolveSibling("javashroud-helper-cfg-$tag.toml")
        writeRunConfig(configPath, inputJar, outputJar, passIds)
        try {
            captureStdout {
                dispatchRequest(
                    buildCommandRequest(EngineCommand.Run, arrayOf("-config", configPath.toString())),
                    EngineKernel(),
                )
            }
        } finally {
            Files.deleteIfExists(configPath)
        }
        return outputJar
    }

    private fun writeRunConfig(configPath: Path, inputJar: Path, outputJar: Path, passIds: List<String>) {
        writeTestRunConfigToml(configPath, inputJar, outputJar, passIds)
    }

    private fun loadJarEntryNames(jarPath: Path): List<String> {
        val entries = mutableListOf<String>()
        JarInputStream(Files.newInputStream(jarPath)).use { jar ->
            while (true) {
                val entry = jar.nextJarEntry ?: break
                if (!entry.isDirectory) {
                    entries += entry.name
                }
                jar.closeEntry()
            }
        }
        return entries
    }

    private fun captureStdout(block: () -> Unit): String {
        val original = System.out
        val buffer = ByteArrayOutputStream()
        System.setOut(PrintStream(buffer, true, Charsets.UTF_8))
        return try {
            block()
            buffer.toString(Charsets.UTF_8)
        } finally {
            System.setOut(original)
        }
    }

    private fun safeTag(raw: String, prefix: String): String {
        val clean = raw.replace(Regex("[^a-zA-Z0-9._-]"), "_")
        val maxLen = 180 - prefix.length
        return if (clean.length > maxLen) clean.substring(0, maxLen) else clean
    }
}
