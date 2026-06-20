package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.RuntimeResourceKind
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

/**
 * Phase 0 / SEC-004 gate: production key-fetch paths must fail closed when no
 * Vbc4BuildContext is initialized, instead of silently falling back to a random
 * standalone context. The runtime resource codec fetches the per-build root key
 * via requireVbc4BuildContext(), so encoding outside a build scope must throw.
 */
class ProductionContextRequiredTest {

    private fun freshContext(): Vbc4BuildContext {
        val random = SecureRandom()
        val master = ByteArray(32).also { random.nextBytes(it) }
        val layout = ByteArray(32).also { random.nextBytes(it) }
        return Vbc4BuildContext(masterKey = master, nativeSeed = 0x4242L, jarLayoutDigest = layout)
    }

    @Test
    fun runtime_resource_encode_fails_closed_without_build_context() {
        val payload = ByteArray(64) { it.toByte() }
        assertFailsWith<IllegalStateException>("encode must fail closed outside a build context") {
            RuntimeResourceCodec.encode(
                bytes = payload,
                kind = RuntimeResourceKind.Manifest,
                seed = 7,
                variantId = 1,
                layerCount = 1,
            )
        }
    }

    @Test
    fun runtime_resource_encode_succeeds_within_build_context() {
        val payload = ByteArray(64) { it.toByte() }
        val encoded = withVbc4BuildContext(freshContext()) {
            RuntimeResourceCodec.encode(
                bytes = payload,
                kind = RuntimeResourceKind.Manifest,
                seed = 7,
                variantId = 1,
                layerCount = 1,
            )
        }
        assertNotNull(encoded)
    }
}
