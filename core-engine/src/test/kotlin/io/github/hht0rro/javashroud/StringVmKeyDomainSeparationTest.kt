package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.bytecode.decodeStringPayload
import io.github.hht0rro.javashroud.bytecode.deriveStringEncryptionRoot
import io.github.hht0rro.javashroud.bytecode.deriveStringClassIdentity
import io.github.hht0rro.javashroud.bytecode.encodeStringPayload
import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse

class StringVmKeyDomainSeparationTest {
    @Test
    fun string_and_vm_roots_are_domain_separated_and_string_payload_round_trips() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { (it * 13 + 1).toByte() },
            nativeSeed = 0x24681357L,
            jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { (it * 17 + 9).toByte() },
        )
        val stringRoot = deriveStringEncryptionRoot(context)
        val vmRoot = context.deriveVmBuildKey()
        assertFalse(stringRoot.contentEquals(vmRoot), "string and VM roots must use independent HKDF domains")

        withVbc4BuildContext(context) {
            val plain = "domain-separated".toByteArray()
            val firstClass = deriveStringClassIdentity("example/First")
            val secondClass = deriveStringClassIdentity("example/Second")
            val encrypted = encodeStringPayload(plain.decodeToString(), 0x13572468, 0x24681357, firstClass)
            val secondEncrypted = encodeStringPayload(plain.decodeToString(), 0x13572468, 0x24681357, secondClass)
            assertFalse(encrypted.contentEquals(plain))
            assertFalse(encrypted.contentEquals(secondEncrypted), "identical literals in different classes must use different child keys")
            assertContentEquals(plain, decodeStringPayload(encrypted, 0x13572468, 0x24681357, firstClass))
            assertFalse(
                plain.contentEquals(decodeStringPayload(encrypted, 0x13572468, 0x24681357, secondClass)),
                "a class identity mismatch must not recover the plaintext",
            )
        }
        stringRoot.fill(0)
        vmRoot.fill(0)
    }
}
