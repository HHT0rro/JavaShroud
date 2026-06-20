package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.transforms.protection.VBC4_LAYOUT_DIGEST_SIZE
import io.github.hht0rro.javashroud.transforms.protection.VBC4_MASTER_KEY_SIZE
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.nio.file.Files
import java.nio.file.Path
import org.objectweb.asm.Opcodes
import kotlin.system.measureNanoTime
import kotlin.test.Test
import kotlin.test.assertTrue

class PerfBaselineProbeTest {
    @Test
    fun perf_baseline_probe_records_vm_resource_size_and_serializer_cost() {
        val metrics = listOf(16, 64, 160).map { instructionPairs ->
            var payloadSize = 0
            val nanos = measureNanoTime {
                payloadSize = serializeFixture(instructionPairs).size
            }
            ProbeMetric(
                instructionPairs = instructionPairs,
                vmResourceBytes = payloadSize,
                serializerNanos = nanos,
            )
        }

        assertTrue(metrics.all { it.vmResourceBytes > 0 }, "probe must record VMBC resource sizes")
        assertTrue(metrics.all { it.serializerNanos > 0 }, "probe must record serializer timing")
        val json = metrics.toJson()
        val baselineDir = repoRoot().resolve("plan").resolve("baseline")
        Files.createDirectories(baselineDir)
        Files.writeString(baselineDir.resolve("perf-uplift-serializer-baseline.json"), json + System.lineSeparator())
        println("PERF_BASELINE_PROBE_JSON=$json")
    }

    private fun repoRoot(): Path {
        val cwd = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
        return if (Files.exists(cwd.resolve("settings.gradle.kts"))) cwd else cwd.parent
    }

    private fun serializeFixture(instructionPairs: Int): ByteArray = withVbc4BuildContext(fixedContext()) {
        val serializer = VmBytecodeSerializer(
            buildSeed = 0x5150_0000 + instructionPairs,
            stateBinding = "perf-baseline-probe",
            buildContext = fixedContext(),
        )
        serializer.visitCode()
        repeat(instructionPairs) { index ->
            serializer.visitLdcInsn(index * 31)
            serializer.visitInsn(Opcodes.POP)
        }
        serializer.visitInsn(Opcodes.ICONST_1)
        serializer.visitInsn(Opcodes.IRETURN)
        serializer.visitMaxs(8, 8)
        serializer.visitEnd()
        serializer.serialize()
    }

    private fun fixedContext(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(VBC4_MASTER_KEY_SIZE) { index -> (index * 13 + 7).toByte() },
        nativeSeed = 0x5150_600DL,
        jarLayoutDigest = ByteArray(VBC4_LAYOUT_DIGEST_SIZE) { index -> (index * 17 + 5).toByte() },
    )

    private data class ProbeMetric(
        val instructionPairs: Int,
        val vmResourceBytes: Int,
        val serializerNanos: Long,
    )

    private fun List<ProbeMetric>.toJson(): String = joinToString(prefix = "[", postfix = "]") { metric ->
        "{\"instructionPairs\":${metric.instructionPairs},\"vmResourceBytes\":${metric.vmResourceBytes},\"serializerNanos\":${metric.serializerNanos}}"
    }
}
