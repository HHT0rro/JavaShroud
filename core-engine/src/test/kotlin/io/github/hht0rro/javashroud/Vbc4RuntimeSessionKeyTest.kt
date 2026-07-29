package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse

class Vbc4RuntimeSessionKeyTest {
    @Test
    fun build_method_and_runtime_session_domains_are_stable_and_diverge_at_the_expected_boundary() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { (it * 7 + 3).toByte() },
            nativeSeed = 0x102030405060708L,
            jarLayoutDigest = ByteArray(32) { (it * 5 + 11).toByte() },
        )
        val identity = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8) + "META-INF/r/method".toByteArray()
        val methodNonce = ByteArray(16) { (it * 13 + 1).toByte() }
        val firstStartup = ByteArray(32) { (it + 1).toByte() }
        val secondStartup = ByteArray(32) { (it + 2).toByte() }

        assertContentEquals(context.deriveVmBuildKey(), context.deriveVmBuildKey())
        assertContentEquals(
            context.deriveVmMethodKey(identity, methodNonce),
            context.deriveVmMethodKey(identity, methodNonce),
        )
        val first = context.deriveVmRuntimeSessionLeaf(firstStartup, identity, methodNonce)
        assertContentEquals(first, context.deriveVmRuntimeSessionLeaf(firstStartup, identity, methodNonce))
        assertFalse(first.contentEquals(context.deriveVmRuntimeSessionLeaf(secondStartup, identity, methodNonce)))
        assertFalse(first.contentEquals(context.deriveVmRuntimeSessionLeaf(firstStartup, identity + 9, methodNonce)))
        assertFalse(first.contentEquals(context.deriveVmRuntimeSessionLeaf(firstStartup, identity, methodNonce.copyOf().also { it[0] = 99 })))
    }
}
