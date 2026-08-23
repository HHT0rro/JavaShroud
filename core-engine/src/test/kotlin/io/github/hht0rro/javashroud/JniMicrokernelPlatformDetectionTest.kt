package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class JniMicrokernelPlatformDetectionTest {
    private val detectPlatform = JniMicrokernelHelper::class.java.getDeclaredMethod(
        "detectPlatform",
        String::class.java,
        String::class.java,
    ).apply { isAccessible = true }

    @Test
    fun `platform detection returns only locked R1 target triples`() {
        for (arch in listOf("amd64", "x86_64", "x64")) {
            assertEquals("x86_64-pc-windows-gnu", detect("Windows 11", arch))
            assertEquals("x86_64-unknown-linux-gnu.2.17", detect("Linux", arch))
        }
    }

    @Test
    fun `platform detection rejects every other os and architecture`() {
        assertNull(detect("Windows 11", "aarch64"))
        assertNull(detect("Windows 11", "ia64"))
        assertNull(detect("Linux", "arm64"))
        assertNull(detect("Darwin", "amd64"))
        assertNull(detect("Mac OS X", "x86_64"))
        assertNull(detect("macOS", "arm64"))
        assertNull(detect("FreeBSD", "amd64"))
    }

    private fun detect(osName: String, osArch: String): String? =
        detectPlatform.invoke(null, osName, osArch) as String?
}
