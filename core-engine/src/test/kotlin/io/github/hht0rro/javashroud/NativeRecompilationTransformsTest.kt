package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.NativeToolchainProvisioner
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.currentVbc4BuildContextOrNull
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class NativeRecompilationTransformsTest {

    @Test
    fun native_recompilation_defaults_to_o2_when_js_vbc4_opt_is_unset() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"))
        val optBody = source.substringAfter("private fun nativeCompileOptLevel()").substringBefore("private fun nativeCompileExtraFlags")
        val compileBody = source.substringAfter("private fun compileWithZig(").substringBefore("internal fun generateDiversifiedSecrets")

        assertTrue(optBody.contains("System.getenv(\"JS_VBC4_OPT\")"), "JS_VBC4_OPT must remain the native optimization override")
        assertTrue(optBody.contains("else \"-O2\""), "Native compile optimization must default to -O2 when JS_VBC4_OPT is unset")
        assertFalse(compileBody.contains("\"-O0\""), "Default native compile command must not select -O0 when JS_VBC4_OPT is unset")
        assertFalse(compileBody.contains("rng.nextInt") && compileBody.contains("optLevel"), "Default optimization must not be randomized")
    }
    @Test
    fun generateDiversifiedSecrets_produces_different_output_for_different_seeds() {
        val rng1 = java.util.Random(12345L)
        val rng2 = java.util.Random(67890L)
        val secrets1 = NativeRecompilationTransforms.generateDiversifiedSecrets(12345L, rng1, defaultVbc4BuildContext())
        val secrets2 = NativeRecompilationTransforms.generateDiversifiedSecrets(67890L, rng2, defaultVbc4BuildContext())
        assertNotEquals(secrets1, secrets2, "Different seeds should produce different secrets")
    }

    @Test
    fun generateDiversifiedSecrets_contains_required_markers() {
        val rng = java.util.Random(42L)
        val secrets = NativeRecompilationTransforms.generateDiversifiedSecrets(42L, rng, defaultVbc4BuildContext())
        assertTrue(secrets.contains("JS_SECRET_SEED"), "Should contain JS_SECRET_SEED define")
        assertTrue(secrets.contains("js_secret_SECURITY_EXCEPTION_CLASS"), "Should contain class name constant")
        assertTrue(secrets.contains("js_secret_RUNTIME_CLASS"), "Should contain Runtime class constant")
        assertTrue(secrets.contains("JS_SECRET_AES_KEY"), "Should contain AES key material for generated native strings")
        assertTrue(secrets.contains("JS_SECRET_AES_IV"), "Should contain AES IV material for generated native strings")
        assertTrue(secrets.contains("JS_SECRET_DECRYPT"), "Should contain the native string decode macro")
        assertFalse(secrets.contains("js_secret_keystream"), "Generated native secrets must not retain the old XOR keystream helper")
        assertTrue(secrets.contains("#endif"), "Should be properly closed")
    }

    @Test
    fun generateDiversifiedSecrets_decrypts_with_generated_aes_ctr_material() {
        val secrets = NativeRecompilationTransforms.generateDiversifiedSecrets(42L, java.util.Random(42L), defaultVbc4BuildContext())
        val key = parseCByteArray(secrets, "JS_SECRET_AES_KEY")
        val iv = parseCByteArray(secrets, "JS_SECRET_AES_IV")
        val index = Regex("""#define JS_SECRET_INDEX_SYSTEM_CLASS (\d+)""").find(secrets)!!.groupValues[1].toInt()
        val encryptedSystemClass = parseCByteArray(secrets, "js_secret_SYSTEM_CLASS")

        assertEquals("java/lang/System", decryptNativeSecret(encryptedSystemClass, key, iv, index))
    }

    @Test
    fun generateAntiReverseGuards_contains_debug_detection() {
        val rng = java.util.Random(42L)
        val guards = NativeRecompilationTransforms.generateAntiReverseGuards(rng)
        assertTrue(guards.contains("_js_guard_is_debugged"), "Should contain debug check function")
        assertTrue(guards.contains("IsDebuggerPresent") || guards.contains("ptrace"), "Should contain platform debug API")
        assertTrue(guards.contains("_js_guard_timing_anomaly"), "Should contain timing check")
        assertTrue(guards.contains("_js_guard_hw_breakpoints"), "Should contain HW breakpoint check")
    }

    @Test
    fun generateAntiReverseGuards_contains_vm_detection() {
        val rng = java.util.Random(42L)
        val guards = NativeRecompilationTransforms.generateAntiReverseGuards(rng)
        assertTrue(guards.contains("_js_guard_vm_detected"), "Should contain VM detection")
        assertTrue(guards.contains("_js_guard_integrity_check"), "Should contain integrity check")
        assertTrue(guards.contains("_js_guard_all"), "Should contain composite guard")
    }


    @Test
    fun applySourceDiversification_preserves_source_structure() {
        val source = """
            #include <jni.h>
            #include <string.h>
            static int test_func(int x) {
                return x + 1;
            }
        """.trimIndent()
        val rng = java.util.Random(42L)
        val result = NativeRecompilationTransforms.applySourceDiversification(source, rng)
        assertTrue(result.contains("#include <jni.h>"), "Should preserve includes")
        assertTrue(result.contains("test_func"), "Should preserve original functions")
    }

    @Test
    fun applySourceDiversification_appends_after_final_preprocessor_block() {
        val source = """
            #include <jni.h>
            #if defined(__linux__)
            static int linux_only(void) {
                return 1;
            }
            #endif
        """.trimIndent()
        val result = NativeRecompilationTransforms.applySourceDiversification(source, java.util.Random(42L))
        val finalEndif = result.indexOf("#endif")
        val firstJunk = result.indexOf("static int _junk_")
        assertTrue(firstJunk > finalEndif, "Junk functions must be appended after preprocessor blocks")
    }

    @Test
    fun generateAntiReverseGuards_keeps_ptrace_linux_only() {
        val guards = NativeRecompilationTransforms.generateAntiReverseGuards(java.util.Random(42L))
        assertTrue(guards.contains("#elif defined(__linux__) || defined(__ANDROID__)"), "ptrace branch should be Linux-gated")
        assertFalse(guards.contains("#else\n#include <sys/ptrace.h>"), "macOS targets must not include Linux ptrace header")
    }

    @Test
    fun generateDiversifiedSecrets_embeds_matching_vbc4_build_key_shares() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 7 + 3).toByte() },
            nativeSeed = 0x13572468L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (0xA0 + index).toByte() },
        )

        val secrets = NativeRecompilationTransforms.generateDiversifiedSecrets(42L, java.util.Random(42L), context)
        val shareA = parseCByteArray(secrets, "JS_VBC4_BUILD_KEY_SHARE_A")
        val shareB = parseCByteArray(secrets, "JS_VBC4_BUILD_KEY_SHARE_B")
        val reconstructed = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (shareA[index].toInt() xor shareB[index].toInt()).toByte() }

        assertTrue(secrets.contains("JS_VBC4_BUILD_KEY_GENERATED"), "Native VBC4 build key marker must be generated")
        assertTrue(context.masterKey.contentEquals(reconstructed), "Generated native VBC4 key shares must reconstruct the Kotlin build master key")
        assertTrue(secrets.contains("static const unsigned char JS_VBC4_LAYOUT_DIGEST[32] = { ${cBytesForTest(context.jarLayoutDigest)} };"), "Native VBC4 layout digest must match the Kotlin build context")
        assertTrue(secrets.contains("#define JS_VBC4_DISPATCH_MIX_A"), "Native VBC4 dispatch mix must be generated per build")
    }
    @Test
    fun generateDiversifiedSecrets_does_not_emit_flat_vbc4_master_material() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (0x40 + index).toByte() },
            nativeSeed = 0x2468ACE0L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (0x10 + index * 3).toByte() },
        )

        val secrets = NativeRecompilationTransforms.generateDiversifiedSecrets(99L, java.util.Random(99L), context)
        val shareA = parseCByteArray(secrets, "JS_VBC4_BUILD_KEY_SHARE_A")
        val shareB = parseCByteArray(secrets, "JS_VBC4_BUILD_KEY_SHARE_B")
        val reconstructed = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (shareA[index].toInt() xor shareB[index].toInt()).toByte() }

        assertTrue(context.masterKey.contentEquals(reconstructed), "Split shares must reconstruct the scoped build master only when combined")
        assertFalse(shareA.contentEquals(context.masterKey), "Share A must not be the flat VBC4 master key")
        assertFalse(shareB.contentEquals(context.masterKey), "Share B must not be the flat VBC4 master key")
        assertFalse(secrets.contains("JS_VBC4_MASTER_KEY"), "Generated native secrets must not expose a flat VBC4 master key symbol")
        assertFalse(secrets.contains("g_vbc4_inner_pad") || secrets.contains("g_vbc4_outer_pad"), "Generated native secrets must not expose long-lived VBC4 HMAC pads")
        assertFalse(secrets.contains(cBytesForTest(context.masterKey)), "Generated native secrets must not contain the contiguous flat VBC4 master key bytes")
    }

    @Test
    fun vbc4BuildContext_scope_uses_wiped_copy_without_mutating_caller_context() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index + 1).toByte() },
            nativeSeed = 0x10203040L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (0x7F - index).toByte() },
        )
        val originalMaster = context.masterKey.copyOf()
        var scopedContext: Vbc4BuildContext? = null
        var scopedMasterCopy: ByteArray? = null

        withVbc4BuildContext(context) {
            scopedContext = currentVbc4BuildContextOrNull()
            scopedMasterCopy = scopedContext!!.copyMasterKey()
            assertFalse(scopedContext === context, "Thread-local VBC4 context must be a scoped copy, not the caller-owned key holder")
            assertTrue(originalMaster.contentEquals(scopedMasterCopy!!), "Scoped VBC4 context must start with equivalent build key material")
        }

        assertTrue(context.masterKey.contentEquals(originalMaster), "Caller-owned context must remain usable after the scoped copy is wiped")
        assertTrue(scopedContext!!.masterKey.all { it.toInt() == 0 }, "Scoped VBC4 master key copy must be wiped on scope exit")
        assertTrue(scopedContext!!.runtimeResourceKey.all { it.toInt() == 0 }, "Scoped VBC4 runtime resource key copy must be wiped on scope exit")
    }

    @Test
    fun nativeToolchainProvisioner_cacheDirectory_is_consistent() {
        val dir = NativeToolchainProvisioner.cacheDirectory()
        assertNotNull(dir, "Cache directory should not be null")
        assertTrue(dir.toString().contains("javashroud"), "Should contain javashroud in path")
        assertTrue(dir.toString().contains("zig"), "Should contain zig in path")
    }

    @Test
    fun zigTargets_contains_all_platforms() {
        val targets = NativeRecompilationTransforms.ZIG_TARGETS
        assertTrue(targets.containsKey("windows-x64"), "Should have windows-x64 target")
        assertTrue(targets.containsKey("linux-x64"), "Should have linux-x64 target")
        assertTrue(targets.containsKey("macos-x64"), "Should have macos-x64 target")
        assertTrue(targets.containsKey("macos-arm64"), "Should have macos-arm64 target")
    }
    @Test
    fun target_platform_auto_still_expands_to_every_zig_target() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/EmbeddedHelperDeployment.kt"))
        val autoBranch = source.substringAfter("val targetPlatforms = if (targetPlatformParam == \"auto\") {").substringBefore("} else {")

        assertTrue(autoBranch.contains("NativeRecompilationTransforms.ZIG_TARGETS.keys"), "targetPlatform=auto must keep compiling every supported Zig target")
    }

    @Test
    fun native_artifact_cache_key_covers_security_sensitive_inputs() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"))
        val keyBody = source.substringAfter("internal fun nativeArtifactCacheKey(").substringBefore("private fun digestNativeSourceTree")

        assertTrue(keyBody.contains("taskPlatform"), "Cache key must include the requested platform")
        assertTrue(keyBody.contains("zigTarget"), "Cache key must include the Zig target")
        assertTrue(keyBody.contains("outputName"), "Cache key must include the native output name")
        assertTrue(keyBody.contains("nativeCompileOptLevel()"), "Cache key must include compile optimization level")
        assertTrue(keyBody.contains("nativeCompileExtraFlags()"), "Cache key must include compile hardening flags")
        assertTrue(keyBody.contains("sourceDigest"), "Cache key must include generated native source content")
        assertTrue(keyBody.contains("toolchainIdentity"), "Cache key must include Zig toolchain identity")
        assertTrue(keyBody.contains("vbc4BuildContext.nativeSeed"), "Cache key must include VBC4 native seed")
        assertTrue(keyBody.contains("vbc4BuildContext.jarLayoutDigest"), "Cache key must include layout digest")
        assertTrue(keyBody.contains("vbc4BuildContext.masterKey"), "Cache key must include VBC4 build key material")
        assertTrue(keyBody.contains("vbc4BuildContext.runtimeResourceKey"), "Cache key must include runtime resource key material")
        assertTrue(keyBody.contains("protectedSectionKey"), "Cache key must include protected-section sealing material")
    }

    @Test
    fun native_artifact_cache_hit_requires_sealed_jni_abi_validation() {
        val source = java.nio.file.Files.readString(resolveSource("src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/NativeRecompilationTransforms.kt"))
        val readCacheBody = source.substringAfter("private fun readNativeArtifactCache(").substringBefore("private fun writeNativeArtifactCache")
        val writeCacheGate = source.substringAfter("if (!compileResult.fromCache &&").substringBefore("results.add")

        assertTrue(readCacheBody.contains("EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(bytes)"), "Cache hits must validate sealed JNI ABI before reuse")
        assertTrue(readCacheBody.contains("Files.deleteIfExists(cachePath)"), "Invalid cache entries must be discarded before recompilation")
        assertTrue(writeCacheGate.contains("EmbeddedHelperDeployment.nativeLibraryContainsRequiredJniVmAbi(rawBytes)"), "Only ABI-valid native artifacts should be written to cache")
    }


    private fun parseCByteArray(source: String, name: String): ByteArray {
        val pattern = Regex("static const unsigned char $name\\[(?:\\d+)?] = \\{ ([^}]*) };")
        val values = pattern.find(source)?.groupValues?.get(1)
            ?: error("Missing C byte array $name")
        return values.split(",")
            .map { token -> token.trim().removePrefix("0x").removeSuffix("u").toInt(16).toByte() }
            .toByteArray()
    }

    private fun cBytesForTest(bytes: ByteArray): String = bytes.joinToString(", ") { byte ->
        "0x%02Xu".format(byte.toInt() and 0xFF)
    }


}

private fun resolveSource(relativePath: String): java.nio.file.Path {
    val direct = java.nio.file.Path.of(relativePath)
    if (java.nio.file.Files.exists(direct)) return direct
    return java.nio.file.Path.of("core-engine").resolve(relativePath)
}
private fun decryptNativeSecret(encrypted: ByteArray, key: ByteArray, iv: ByteArray, index: Int): String {
    val counter = iv.copyOf()
    var carry = index
    var pos = counter.lastIndex
    while (pos >= 0 && carry != 0) {
        val total = (counter[pos].toInt() and 0xFF) + (carry and 0xFF)
        counter[pos] = total.toByte()
        carry = (carry ushr 8) + (total ushr 8)
        pos--
    }
    val cipher = Cipher.getInstance("AES/CTR/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(counter))
    return cipher.doFinal(encrypted).toString(Charsets.UTF_8)
}
