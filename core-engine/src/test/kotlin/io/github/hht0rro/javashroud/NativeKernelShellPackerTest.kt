package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.QpPackingLevel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class NativeKernelShellPackerTest {
    @Test
    fun r1_packing_policy_has_only_locked_configuration_values() {
        assertEquals(
            listOf("off", "standard", "max", "max-hardening"),
            QpPackingLevel.entries.map { it.configValue },
        )
        assertEquals(QpPackingLevel.MAX, QpPackingLevel.parse(" MAX "))
        assertEquals(QpPackingLevel.MAX_HARDENING, QpPackingLevel.parse("max-hardening"))
    }

    @Test
    fun retired_shell_profiles_are_not_accepted_as_platform_or_artifact_values() {
        assertFailsWith<IllegalArgumentException> {
            QpPackingLevel.parse("macos-dylib")
        }
        assertFailsWith<IllegalArgumentException> {
            QpPackingLevel.parse("native-shell")
        }
    }
}
