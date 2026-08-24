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
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Opcodes
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
    fun jni_microkernel_loader_embeds_only_aken_runtime_helper_closure() {
        val updated = EmbeddedHelperDeployment.injectRequiredHelpers(
            artifact = emptyArtifact(),
            executedPassIds = listOf("jni-microkernel-loader"),
        )
        val entries = updated.jarEntries.map { it.name }.toSet()

        for (entryName in listOf(
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}AkenNativeLibrary.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}TypeParseResult.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}SamLambdaOptions.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}SamInvocationHandler.class",
        )) {
            assertTrue(entryName in entries, "AKEN JNI helper dependency must be embedded: $entryName")
        }
        for (legacyEntry in listOf(
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}RuntimeResourceMetadata.class",
            "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper${"$"}SealedNativeLibrary.class",
        )) {
            assertFalse(legacyEntry in entries, "AKEN deployment must not embed legacy runtime helper: $legacyEntry")
        }
    }

@Test
    fun jni_microkernel_loader_emits_aken_only_outer_helper_without_legacy_boot_surface() {
        val updated = EmbeddedHelperDeployment.injectRequiredHelpers(
            artifact = emptyArtifact(),
            executedPassIds = listOf("jni-microkernel-loader"),
        )
        val helperBytes = updated.jarEntries
            .first { it.name == "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class" }
            .bytes
        val helperText = helperBytes.toString(Charsets.ISO_8859_1)

        for (legacyMarker in listOf(
            "kek.dat",
            "JSBK1",
            "JSBM",
            "JAVASHROUD_BOOT_SECRET_",
            "META-INF/.r/boot.dat",
            "BootMaterialEnvelope",
            "BootKekSidecar",
            "nativeInstallBootMaterial",
            "nativeInstallBootEnvelope",
            "nativeDecodeRuntimeResource",
            "decodeRuntimeResourceForNative",
            "nativeExecuteVmResource",
            "executeVmResource",
        )) {
            assertFalse(helperText.contains(legacyMarker), "AKEN outer helper must omit legacy marker: $legacyMarker")
        }
    }

    @Test
    fun jni_microkernel_loader_emits_only_typed_page_native_surface() {
        val updated = EmbeddedHelperDeployment.injectRequiredHelpers(
            artifact = emptyArtifact(),
            executedPassIds = listOf("jni-microkernel-loader"),
        )
        val helperBytes = updated.jarEntries
            .first { it.name == "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class" }
            .bytes
        val methods = linkedSetOf<String>()
        val nativeMethods = linkedSetOf<String>()

        ClassReader(helperBytes).accept(object : ClassVisitor(Opcodes.ASM9) {
            override fun visitMethod(
                access: Int,
                name: String,
                descriptor: String,
                signature: String?,
                exceptions: Array<out String>?,
            ): org.objectweb.asm.MethodVisitor? {
                val method = "$name$descriptor"
                methods += method
                if (access and Opcodes.ACC_NATIVE != 0) nativeMethods += method
                return null
            }
        }, ClassReader.SKIP_CODE or ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)

        val requiredNativeMethods = linkedSetOf(
            "nativeInit(Ljava/lang/String;)I",
            "nativeHeartbeat()I",
            "nativeInstallAkenSessionNonce([B)Z",
            "nativeExecuteAkenVmPage(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;",
            "nativeOpenAkenString([BI[B)Ljava/lang/String;",
            "nativeReadAkenClassPage([BI[B)[B",
            "nativeConsumeAkenNativeChunk([BI[B)V",
        )
        assertEquals(requiredNativeMethods, nativeMethods, "Emitted helper must expose exactly seven R1 native registrations")

        val requiredTypedMethods = setOf(
            "nativeInit(Ljava/lang/String;)I",
            "nativeHeartbeat()I",
            "nativeInstallAkenSessionNonce([B)Z",
            "nativeExecuteAkenVmPage(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;",
            "nativeOpenAkenString([BI[B)Ljava/lang/String;",
            "nativeReadAkenClassPage([BI[B)[B",
            "nativeConsumeAkenNativeChunk([BI[B)V",
            "executeAkenVmPage(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;",
            "openAkenString([BI[B)Ljava/lang/String;",
            "readAkenClassPage([BI[B)[B",
            "consumeAkenNativeChunk([BI[B)V",
        )
        assertTrue(
            methods.containsAll(requiredTypedMethods),
            "AKEN helper must retain the complete typed page ABI: ${requiredTypedMethods - methods}",
        )

        val forbiddenNativeOrGenericMethods = setOf(
            "nativeVerify",
            "nativeGetVersion",
            "nativeGetBootToken",
            "nativeInstallBootMaterial",
            "nativeInstallBootEnvelope",
            "nativeIsBootMaterialReady",
            "nativeAbortBootMaterial",
            "nativePreloadRuntimeResources",
            "nativeDecodeRuntimeResource",
            "nativeDecryptAes",
            "nativeDeriveClassEncryptionKey",
            "nativeDecryptClassBytes",
            "nativeSealedBindingKey",
            "nativeGetMachineFingerprint",
            "nativeExecuteVmResource",
            "nativeExecuteVmResourceByToken",
            "nativeExecuteVmResourceVoid",
            "nativeExecuteVmResourceInt",
            "nativeExecuteVmResourceIntInt",
            "nativeExecuteVmResourceIntVoid",
            "decodeRuntimeResourceEnvelope",
            "decodeRuntimeResourceForNative",
            "deriveClassEncryptionKey",
            "decryptClassBytes",
            "reconstructKey",
            "nativeReconstructKey",
        )
        val leakedMethods = methods.map { it.substringBefore('(') }.toSet().intersect(forbiddenNativeOrGenericMethods)
        assertTrue(leakedMethods.isEmpty(), "AKEN helper must not emit generic or key-returning methods: $leakedMethods")
    }


    @Test
    fun incomplete_r1_exports_do_not_satisfy_the_native_abi_probe() {
        val incomplete = "JNI_OnLoad-JNI_OnUnload-jsrt_r1_runtime_binding_digest".toByteArray(Charsets.US_ASCII)

        assertFalse(
            EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(incomplete),
            "R1 artifacts must expose the complete typed jsrt_r1 export set.",
        )
    }

    @Test
    fun r1_exports_and_jni_lifecycle_satisfy_the_native_abi_probe() {
        val r1Bytes = listOf(
            "JNI_OnLoad",
            "JNI_OnUnload",
            "jsrt_r1_runtime_binding_digest",
            "jsrt_r1_open_frame",
        ).joinToString("-").toByteArray(Charsets.US_ASCII)

        assertTrue(
            EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(r1Bytes),
            "Rust R1 artifacts must carry the typed jsrt_r1 exports and JNI lifecycle.",
        )
        assertFalse(
            EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(
                (r1Bytes.decodeToString() + "-nativeExecuteVmResource").toByteArray(Charsets.US_ASCII),
            ),
            "legacy generic native routes must remain rejected.",
        )
    }

    @Test
    fun jni_microkernel_helper_validates_r1_images_before_system_load() {
        val helperSource = Files.readString(resolveWorkspacePath("core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))

        assertTrue(helperSource.contains("validateR1NativeImage(platformTarget, nativeBytes)"), "R1 images must be validated before extraction.")
        assertTrue(helperSource.contains("System.load(tempLib.getAbsolutePath())"), "Bundled native loading must use the authenticated extracted R1 image.")
        assertFalse(helperSource.contains("System.loadLibrary("), "A bundled verification failure must not fall back to a system-path library.")
        assertFalse(helperSource.contains("decodeSealedNativeResource"), "R1 Java must not decode a retired native wrapper.")
        assertFalse(helperSource.contains("nativeExecuteVmResource"), "R1 Java must not retain the generic native VM route.")
        assertFalse(helperSource.contains("nativeInstallBootMaterial"), "R1 Java must not retain boot-material JNI calls.")
    }

    @Test
    fun jni_microkernel_helper_retains_only_fail_closed_java_compatibility_wrappers() {
        val helperSource = Files.readString(resolveWorkspacePath("core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))

        assertTrue(helperSource.contains("public static byte[] deriveClassEncryptionKey"))
        assertTrue(helperSource.contains("class-encryption key derivation is not part of the R1 Java helper"))
        assertTrue(helperSource.contains("public static byte[] decryptClassBytes"))
        assertTrue(helperSource.contains("class-encryption decryption is not part of the R1 Java helper"))
        assertFalse(helperSource.contains("nativeDeriveClassEncryptionKey"))
        assertFalse(helperSource.contains("nativeDecryptClassBytes"))
        assertFalse(helperSource.contains("loadBootSecret"))
        assertFalse(helperSource.contains("decryptBootMaterial"))
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
            "Native bundling must remove pre-existing native resources before adding R1 Rust runtimes.",
        )
        assertTrue(
            bundleSource.contains(rejectedNativeEntries) && bundleSource.contains(legacyBootCleanup),
            "Native bundling must remove pre-existing native and legacy boot resources before packaging Rust outputs.",
        )
        for (legacyProducer in listOf("BootMaterialEnvelope", "BootKekSidecar", "bootKeyDelivery", "embeddedBootKekBytes")) {
            assertFalse(
                bundleSource.contains(legacyProducer),
                "Native bundling must not emit or select legacy boot-key material: $legacyProducer",
            )
        }
        assertTrue(
            bundleSource.contains(appendRecompiled),
            "Native bundling must package only retained non-runtime resources plus freshly compiled Rust outputs.",
        )
        assertTrue(
            bundleSource.indexOf(retainedFilter) < bundleSource.indexOf(appendRecompiled),
            "Existing native resources must be filtered before the final JAR entry list is assembled.",
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
    fun string_encryption_embeds_native_string_terminal_without_plaintext_cache_helper() {
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
        assertFalse(
            entries.any { it.startsWith("io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper${"$"}CachePolicy") },
            "string-encryption must not embed a plaintext cache-policy helper class.",
        )
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
