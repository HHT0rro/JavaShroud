package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.AkenR1PackingLevel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class NativeKernelShellPackerTest {
    @Test
    fun r1_packing_policy_has_only_locked_configuration_values() {
        assertEquals(
            listOf("off", "standard", "max", "max-hardening"),
            AkenR1PackingLevel.entries.map { it.configValue },
        )
        assertEquals(AkenR1PackingLevel.MAX, AkenR1PackingLevel.parse(" MAX "))
        assertEquals(AkenR1PackingLevel.MAX_HARDENING, AkenR1PackingLevel.parse("max-hardening"))
    }

    @Test
    fun retired_shell_profiles_are_not_accepted_as_platform_or_artifact_values() {
        assertFailsWith<IllegalArgumentException> {
            AkenR1PackingLevel.parse("macos-dylib")
        }
        assertFailsWith<IllegalArgumentException> {
            AkenR1PackingLevel.parse("native-shell")
        }
    }
}
