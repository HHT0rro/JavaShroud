package io.github.hht0rro.javashroud

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NativeVmExecutionFrameTest {
    @Test
    fun c_vm_execution_frame_probe_is_retired_in_favor_of_rust_vm_frames() {
        assertFalse(Files.exists(resolveSource("src/main/native")))
        assertFalse(Files.exists(resolveSource("src/test/native/vm_execution_frame_probe.c")))
        val vm = Files.readString(resolveSource("src/main/rust/crates/jsrt-vm/src/lib.rs"))
        val executor = Files.readString(resolveSource("src/main/rust/crates/jsrt-vm/src/executor.rs"))
        assertTrue(vm.contains("VBC4_MAX_FRAME_SIZE"))
        assertTrue(executor.contains("fn execute") || executor.contains("execute("))
    }

    private fun resolveSource(relativePath: String): Path {
        val direct = Path.of(relativePath)
        return if (Files.exists(direct)) direct else Path.of("core-engine").resolve(relativePath)
    }
}
