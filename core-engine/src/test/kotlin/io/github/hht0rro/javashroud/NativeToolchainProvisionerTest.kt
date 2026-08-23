package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.RustToolchainProvisioner
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RustOnlyToolchainBoundaryTest {
    @Test
    fun r1_accepts_only_locked_windows_and_linux_runtime_targets() {
        assertEquals(
            "x86_64-pc-windows-gnu",
            RustToolchainProvisioner.target("windows-x64").rustupTarget,
        )
        assertEquals(
            "2.17",
            RustToolchainProvisioner.target("x86_64-unknown-linux-gnu.2.17").glibcFloor,
        )
        assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
            RustToolchainProvisioner.target("x86_64-unknown-linux-gnu")
        }
        assertFailsWith<RustToolchainProvisioner.RustToolchainException> {
            RustToolchainProvisioner.hostPlatform("Darwin", "x86_64")
        }
    }
}
