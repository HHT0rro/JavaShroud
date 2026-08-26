package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeExtractDirectoryFailClosedTest {
    @Test
    fun unwritable_or_non_directory_extract_paths_are_skipped() {
        val method = JniMicrokernelHelper::class.java.getDeclaredMethod("ensureNativeExtractDirectory", File::class.java)
        method.isAccessible = true
        assertFalse(method.invoke(null, null) as Boolean)

        val file = Files.createTempFile("js-native-extract", ".tmp").toFile()
        try {
            assertFalse(method.invoke(null, file) as Boolean)
        } finally {
            file.delete()
        }

        val dir = Files.createTempDirectory("js-native-extract-dir").toFile()
        try {
            dir.setWritable(false, false)
            val accepted = method.invoke(null, dir) as Boolean
            if (!dir.canWrite()) {
                assertFalse(accepted, "read-only extract directory must be skipped")
            } else {
                assertTrue(accepted == dir.canWrite())
            }
        } finally {
            dir.setWritable(true, false)
            dir.delete()
        }
    }

    @Test
    fun loader_fail_closes_when_no_extract_directory_is_usable() {
        val path = Path.of("src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java")
        val source = Files.readString(if (Files.exists(path)) path else Path.of("core-engine").resolve(path))
        assertTrue(source.contains("if (!ensureNativeExtractDirectory(extractDirectory)) continue;"))
        assertTrue(source.contains("aken:native-extract-unavailable"))
        assertTrue(source.contains("aken:native-resource-missing"))
        assertTrue(source.contains("aken:native-extract-digest-mismatch"))
        assertTrue(source.contains("aken:native-loaded-digest-mismatch"))
    }
}
