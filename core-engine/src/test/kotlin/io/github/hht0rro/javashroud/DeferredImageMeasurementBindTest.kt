package io.github.hht0rro.javashroud

import io.github.hht0rro.javashroud.qp.testSecretPackDraft
import io.github.hht0rro.javashroud.transforms.protection.QpNativeCompilerPass
import io.github.hht0rro.javashroud.transforms.protection.qp.IMAGE_MEASUREMENT_MAGIC
import io.github.hht0rro.javashroud.transforms.protection.qp.NativeImageMeasurement
import io.github.hht0rro.javashroud.transforms.protection.qp.NativeSecretPackLiterals
import io.github.hht0rro.javashroud.transforms.protection.qp.NativeVmSecretPack
import io.github.hht0rro.javashroud.transforms.protection.qp.QpResourceKind
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Deferred JSIM bind: when nativeshroud packing is enabled, measurement is
 * written against the packed disk image rather than the unbound compile product.
 */
class DeferredImageMeasurementBindTest {
    @Test
    fun unbound_compile_product_has_no_commitment_slot() {
        withPreparedLiterals(seed = 41) { literals, _ ->
            val unbound = samplePeWithJsmsAndJsmk(literals, mutatePayload = 0x00)
            val magic = IMAGE_MEASUREMENT_MAGIC
            val slot = NativeImageMeasurement.locateMeasurementSlot(unbound)
            for (i in 0 until 32) {
                assertTrue(unbound[slot + magic.size + i] == 0.toByte(), "unbound .jsms commitment must be zero")
            }
            assertTrue(literals.blobByPlatform().isEmpty(), "seal must not run before bind")
        }
    }

    @Test
    fun post_pack_bind_commitment_matches_digest_of_returned_bytes() {
        withPreparedLiterals(seed = 77) { literals, _ ->
            val unbound = samplePeWithJsmsAndJsmk(literals, mutatePayload = 0x00)
            // Simulate NativeShroud rewriting .text while preserving .jsms/.jsmk.
            val packed = samplePeWithJsmsAndJsmk(literals, mutatePayload = 0xCC)
            assertFalse(unbound.contentEquals(packed), "packed image must differ from unbound compile product")

            QpNativeCompilerPass.bindImageMeasurement(packed, literals, "windows-x64")

            val magic = IMAGE_MEASUREMENT_MAGIC
            val slot = NativeImageMeasurement.locateMeasurementSlot(packed)
            val written = packed.copyOfRange(slot + magic.size, slot + magic.size + 32)
            val expected = NativeImageMeasurement.hmacCommitment(
                literals.measurementKey,
                NativeImageMeasurement.digest(packed),
            )
            assertContentEquals(expected, written)
            assertTrue(literals.blobByPlatform().containsKey("windows-x64"))
            assertFalse(
                written.contentEquals(
                    NativeImageMeasurement.hmacCommitment(
                        literals.measurementKey,
                        NativeImageMeasurement.digest(unbound),
                    ),
                ),
                "commitment must bind the packed image, not the unbound compile product",
            )
        }
    }

    @Test
    fun missing_jsms_fail_closed_zeros_bytes() {
        withPreparedLiterals(seed = 99) { literals, _ ->
            val broken = samplePeWithJsmsAndJsmk(literals, mutatePayload = 0x00)
            // Strip measurement magic so locateMeasurementSlot cannot find .jsms.
            val magic = IMAGE_MEASUREMENT_MAGIC
            val slot = NativeImageMeasurement.locateMeasurementSlot(broken)
            Arrays.fill(broken, slot, slot + magic.size + 32, 0)
            // Also clear the section name so locateJsmsSection fails.
            val peOffset = 0x80
            val optionalSize = 0xF0
            val sectionTable = peOffset + 24 + optionalSize
            Arrays.fill(broken, sectionTable, sectionTable + 8, 0)

            assertFailsWith<Exception> {
                QpNativeCompilerPass.bindImageMeasurement(broken, literals, "windows-x64")
            }
            assertTrue(broken.all { it == 0.toByte() }, "bind failure must zero the Windows image")
        }
    }

    private fun withPreparedLiterals(
        seed: Long,
        block: (NativeSecretPackLiterals, NativeVmSecretPack) -> Unit,
    ) {
        val draft = testSecretPackDraft()
        try {
            val slotId = draft.registerSlot()
            draft.pageKey(
                slotId = slotId,
                resourceKind = QpResourceKind.QpMethod,
                pageIndex = 0,
                encodedHandle = ByteArray(24) { it.toByte() },
                locatorToken = ByteArray(16) { it.toByte() },
                pageNonce = ByteArray(12) { it.toByte() },
                preNativeCommitment = ByteArray(32) { 0x40 },
            )
            val sealed = draft.sealedCopyForSpecialization()
            val literals = NativeSecretPackLiterals.prepare(
                pack = sealed,
                random = java.util.Random(seed),
                cryptoDomain = ByteArray(32) { 0x11 },
                layoutDigest = ByteArray(32) { 0x22 },
            )
            try {
                block(literals, sealed)
            } finally {
                literals.wipe()
                sealed.wipe()
            }
        } finally {
            draft.wipe()
        }
    }

    /**
     * Minimal PE64 DLL with `.jsms` (magic + zero commitment) and `.jsmk`
     * (cm^R pre-mask rows) so [QpNativeCompilerPass.bindImageMeasurement] can run.
     */
    private fun samplePeWithJsmsAndJsmk(
        literals: NativeSecretPackLiterals,
        mutatePayload: Int,
    ): ByteArray {
        val shardCount = literals.shardCount()
        val jsmkSize = shardCount * 32
        val jsmsSize = IMAGE_MEASUREMENT_MAGIC.size + 32
        val dataStart = 0x400
        val jsmsRaw = dataStart
        val jsmkRaw = dataStart + 0x80
        val payloadRaw = dataStart + 0x200
        val bytes = ByteArray(payloadRaw + 0x40)

        bytes[0] = 'M'.code.toByte()
        bytes[1] = 'Z'.code.toByte()
        bytes[0x3C] = 0x80.toByte()
        bytes[0x80] = 'P'.code.toByte()
        bytes[0x81] = 'E'.code.toByte()
        // Machine = AMD64, NumberOfSections = 2
        bytes[0x84] = 0x64
        bytes[0x85] = 0x86.toByte()
        bytes[0x86] = 2
        // SizeOfOptionalHeader = 0xF0
        bytes[0x94] = 0xF0.toByte()
        // Optional magic PE32+
        bytes[0x98] = 0x0B
        bytes[0x99] = 0x02
        // NumberOfRvaAndSizes = 16
        bytes[0x80 + 24 + 108] = 16

        val sectionTable = 0x80 + 24 + 0xF0
        writePeSection(
            bytes = bytes,
            section = sectionTable,
            name = ".jsms",
            virtualSize = jsmsSize,
            virtualAddress = 0x1000,
            rawSize = 0x80,
            rawOffset = jsmsRaw,
        )
        writePeSection(
            bytes = bytes,
            section = sectionTable + 40,
            name = ".jsmk",
            virtualSize = jsmkSize,
            virtualAddress = 0x2000,
            rawSize = ((jsmkSize + 0x1F) / 0x20) * 0x20,
            rawOffset = jsmkRaw,
        )

        val magic = IMAGE_MEASUREMENT_MAGIC
        magic.copyInto(bytes, jsmsRaw)
        // Commitment slot stays zero until bind.

        val maskRMaster = literals.maskRMaster()
        try {
            for (shard in 0 until shardCount) {
                val cm = literals.cmKeyAt(shard)
                val mask = NativeImageMeasurement.shardMask(maskRMaster, shard)
                val rowOff = jsmkRaw + shard * 32
                for (j in 0 until 32) {
                    bytes[rowOff + j] = (cm[j].toInt() xor mask[j].toInt()).toByte()
                }
                Arrays.fill(cm, 0)
                Arrays.fill(mask, 0)
            }
        } finally {
            Arrays.fill(maskRMaster, 0)
        }

        // Simulated .text payload that packing may rewrite.
        for (i in 0 until 0x20) {
            bytes[payloadRaw + i] = (mutatePayload and 0xFF).toByte()
        }
        return bytes
    }

    private fun writePeSection(
        bytes: ByteArray,
        section: Int,
        name: String,
        virtualSize: Int,
        virtualAddress: Int,
        rawSize: Int,
        rawOffset: Int,
    ) {
        val nameBytes = name.toByteArray(Charsets.US_ASCII)
        nameBytes.copyInto(bytes, section, endIndex = minOf(nameBytes.size, 8))
        writeU32(bytes, section + 8, virtualSize)
        writeU32(bytes, section + 12, virtualAddress)
        writeU32(bytes, section + 16, rawSize)
        writeU32(bytes, section + 20, rawOffset)
    }

    private fun writeU32(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xFF).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xFF).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xFF).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xFF).toByte()
    }
}
