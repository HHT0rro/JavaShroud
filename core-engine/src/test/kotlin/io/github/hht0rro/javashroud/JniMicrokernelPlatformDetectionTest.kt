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
    fun `platform detection accepts only explicit supported aliases`() {
        for (arch in listOf("amd64", "x86_64", "x64")) {
            assertEquals("windows-x64", detect("Windows 11", arch))
            assertEquals("linux-x64", detect("Linux", arch))
            assertEquals("macos-x64", detect("Mac OS X", arch))
        }
        for (arch in listOf("aarch64", "arm64")) {
            assertEquals("macos-arm64", detect("macOS", arch))
        }
    }

    @Test
    fun `platform detection rejects misleading os and architecture names`() {
        assertNull(detect("Windows 11", "aarch64"))
        assertNull(detect("Windows 11", "ia64"))
        assertNull(detect("Linux", "arm64"))
        assertNull(detect("Darwin", "amd64"))
        assertNull(detect("Mac OS X", "riscv64"))
    }

    private fun detect(osName: String, osArch: String): String? =
        detectPlatform.invoke(null, osName, osArch) as String?
}
