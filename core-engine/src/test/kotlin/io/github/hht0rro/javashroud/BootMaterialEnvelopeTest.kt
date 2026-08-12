package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.BootMaterialEnvelope
import io.github.hht0rro.javashroud.transforms.protection.RuntimeKeyPartitions
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import java.nio.file.Files
import java.nio.file.Path
import java.lang.reflect.InvocationTargetException
import java.util.Arrays
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class BootMaterialEnvelopeTest {
    private val bootSecret = ByteArray(32) { index -> (index * 17 + 3).toByte() }

    @Test
    fun correct_kek_recovers_exact_boot_material_without_plaintext_leakage() {
        val context = context()
        val shellBinding = ByteArray(32) { index -> (index * 19 + 5).toByte() }
        val envelope = BootMaterialEnvelope.encode(context, bootSecret, mapOf("linux-x64" to shellBinding))
        val plain = decode(envelope, bootSecret)

        assertContentEquals(byteArrayOf(0x4A, 0x53, 0x42, 0x4D), envelope.copyOfRange(0, 4))
        assertEquals(2, plain[0].toInt() and 0xFF)
        assertEquals(1, plain[3].toInt() and 0xFF)
        assertContentEquals(context.masterKey, plain.copyOfRange(4, 36))
        assertContentEquals(context.jarLayoutDigest, plain.copyOfRange(36, 68))
        val bindingOffset = 68 + context.runtimeKeyPartitions.totalSlots * 32
        assertEquals(2, plain[bindingOffset].toInt() and 0xFF)
        assertContentEquals(shellBinding, plain.copyOfRange(bindingOffset + 1, bindingOffset + 33))
        assertFalse(containsSlice(envelope, context.masterKey), "envelope must not contain the plaintext master key")
        assertFalse(containsSlice(envelope, context.jarLayoutDigest), "envelope must not contain the plaintext layout digest")
        assertFalse(containsSlice(envelope, shellBinding), "envelope must not expose the platform shell binding commitment")
        for (slot in 0 until context.runtimeKeyPartitions.totalSlots) {
            val key = context.runtimeKeyPartitions.copyKeyForSlot(slot)
            try {
                assertFalse(containsSlice(envelope, key), "envelope must not expose slot $slot")
            } finally {
                Arrays.fill(key, 0)
            }
        }
    }

    @Test
    fun wrong_kek_and_authenticated_bytes_tampering_fail_closed() {
        val envelope = BootMaterialEnvelope.encode(context(), bootSecret)
        assertFails { decode(envelope, bootSecret.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }) }
        for (offset in listOf(0, 4, 6, envelope.size / 2, envelope.lastIndex)) {
            val tampered = envelope.copyOf().also { it[offset] = (it[offset].toInt() xor 0x5A).toByte() }
            assertFails("tampering offset $offset must fail") { decode(tampered, bootSecret) }
        }
    }

    @Test
    fun runtime_contract_is_one_shot_ready_gated_and_abort_wipes_both_sides() {
        val helper = Files.readString(resolveSource("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java"))
        val core = Files.readString(resolveSource("src/main/native/js_vm_core.c"))
        val shell = Files.readString(resolveSource("src/main/native/js_shell_stub.c"))
        val abi = Files.readString(resolveSource("src/main/native/js_jni_runtime.h"))
        assertTrue(helper.contains("nativeInstallBootMaterial") && helper.contains("nativeIsBootMaterialReady") && helper.contains("nativeAbortBootMaterial"))
        assertTrue(helper.contains("clearJavaBootMaterial();") && helper.contains("nativeAbortBootMaterial();"), "failed load paths must wipe Java and native material")
        assertTrue(core.contains("js_runtime_boot_material_state != 0") && core.contains("js_runtime_boot_material_state = 2"), "native install must be one shot")
        assertTrue(core.contains("js_vm_abort_preload_state(env);") && core.contains("js_runtime_boot_material_clear();"), "native abort must wipe derived preload state and root material")
        assertTrue(core.contains("raw[0] == 2") && core.contains("binding_count * 33"), "native install must validate the v2 binding extension")
        assertTrue(helper.contains("takeExpectedShellBindingCommitment") && helper.contains("clearExpectedShellBindingCommitment"), "Java must expose and wipe the one-shot shell expectation")
        val onLoad = shell.substring(shell.indexOf("jint JNICALL JNI_OnLoad"))
        assertTrue(onLoad.indexOf("js_shell_take_expected_binding_commitment") < onLoad.indexOf("js_shell_extract_meta"), "JNI_OnLoad must fetch the boot.dat expectation before payload acceptance")
        assertFalse(shell.contains("js_shell_expected_binding_commitment"), "the expected commitment must not be compiled into the shell")
        assertTrue(abi.contains("JS_NATIVE_ABI_TABLE_VERSION 9u") && abi.indexOf("native_is_boot_material_ready") < abi.indexOf("native_abort_boot_material"))
        assertTrue(helper.contains("nativeInstallBootEnvelope") && shell.contains("js_shell_open_boot_kek_sidecar"), "hardened boot material must be finally opened by the native shell")
        assertTrue(helper.contains("nativeDecodeRuntimeResource") && abi.contains("native_decode_runtime_resource"), "runtime resource keys must remain usable after Java copies are wiped")
    }

    @Test
    fun shell_binding_handoff_is_thread_owned_one_shot_and_requires_consumption() {
        val helper = Class.forName("io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper")
        val validate = helper.getDeclaredMethod("validateAndPublishJavaBootMaterial", ByteArray::class.java).apply { isAccessible = true }
        val take = helper.getDeclaredMethod("takeExpectedShellBindingCommitment").apply { isAccessible = true }
        val verify = helper.getDeclaredMethod("verifyShellBindingHandoffAfterLoad").apply { isAccessible = true }
        val clear = helper.getDeclaredMethod("clearJavaBootMaterial").apply { isAccessible = true }
        val commitment = ByteArray(32) { index -> (index * 23 + 7).toByte() }
        val material = decode(BootMaterialEnvelope.encode(context(), bootSecret, mapOf(currentPlatform() to commitment)), bootSecret)
        try {
            validate.invoke(null, material)
            val wrongThreadResult = AtomicReference<Any?>()
            Thread { wrongThreadResult.set(take.invoke(null)) }.apply { start(); join() }
            assertNull(wrongThreadResult.get(), "a different thread must not consume the load handoff")
            assertContentEquals(commitment, take.invoke(null) as ByteArray)
            assertNull(take.invoke(null), "the load handoff must be consumable only once")
            verify.invoke(null)

            clear.invoke(null)
            validate.invoke(null, material)
            val failure = assertFailsWith<InvocationTargetException> { verify.invoke(null) }
            assertTrue(failure.cause is SecurityException, "an unconsumed MAX binding must reject the loaded library")
        } finally {
            clear.invoke(null)
            Arrays.fill(material, 0)
        }
    }

    private fun context(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 5 + 11).toByte() },
        nativeSeed = 0x1020_3040L,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 7 + 13).toByte() },
        runtimeResourceKey = ByteArray(32) { index -> (index * 9 + 17).toByte() },
        runtimeKeyPartitions = RuntimeKeyPartitions.generate(),
    )

    private fun containsSlice(haystack: ByteArray, needle: ByteArray): Boolean =
        needle.isNotEmpty() && haystack.indices.any { start ->
            start + needle.size <= haystack.size && needle.indices.all { offset -> haystack[start + offset] == needle[offset] }
        }

    private fun currentPlatform(): String {
        val os = System.getProperty("os.name", "").lowercase()
        val arch = System.getProperty("os.arch", "").lowercase()
        val x64 = arch == "amd64" || arch == "x86_64" || arch == "x64"
        val arm64 = arch == "aarch64" || arch == "arm64"
        return when {
            os.startsWith("windows") && x64 -> "windows-x64"
            os == "linux" && x64 -> "linux-x64"
            "mac" in os && arm64 -> "macos-arm64"
            "mac" in os && x64 -> "macos-x64"
            else -> error("unsupported test platform: $os/$arch")
        }
    }

    private fun decode(envelope: ByteArray, secret: ByteArray): ByteArray {
        require(envelope.size >= 38 && envelope.copyOfRange(0, 4).contentEquals(byteArrayOf(0x4A, 0x53, 0x42, 0x4D)))
        require((envelope[4].toInt() and 0xFF) == 2 && (envelope[5].toInt() and 0xFF) == 12)
        val nonce = envelope.copyOfRange(6, 18)
        val sealedLength = (envelope[18].toInt() and 0xFF) or
            ((envelope[19].toInt() and 0xFF) shl 8) or
            ((envelope[20].toInt() and 0xFF) shl 16) or
            ((envelope[21].toInt() and 0xFF) shl 24)
        require(sealedLength >= 16 && sealedLength + 22 == envelope.size)
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(secret, "AES"), GCMParameterSpec(128, nonce))
            updateAAD("javashroud-boot-material-v2".toByteArray(Charsets.US_ASCII))
            doFinal(envelope, 22, sealedLength)
        }
    }

    private fun resolveSource(relative: String): Path {
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val direct = current.resolve(relative)
            if (Files.exists(direct)) return direct
            val nested = current.resolve("core-engine").resolve(relative)
            if (Files.exists(nested)) return nested
            current = current.parent ?: error("Unable to locate $relative")
        }
    }
}
