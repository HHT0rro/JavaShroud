package io.github.hht0rro.javashroud.aken.r1

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.r1.*
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class R1ArtifactDirectoryTest {
    @Test
    fun rust_directory_parser_uses_the_current_jsr1dir_contract() {
        val rust = java.nio.file.Files.readString(
            java.nio.file.Path.of("src/main/rust/crates/jsrt-page/src/directory.rs"),
        )
        assertTrue(rust.contains("JSR1DIR"), "Rust directory parser must use the current magic")
        assertTrue(rust.contains("JavaShroud/AKEN-R1/ArtifactDirectory/RuntimeBindingDigest"))
        assertTrue(rust.contains("JavaShroud/AKEN-R1/ArtifactDirectory/RecordBinding"))
        assertTrue(rust.contains("JavaShroud/AKEN-R1/ArtifactDirectory/RootBinding"))
        assertTrue(rust.contains("x86_64-unknown-linux-gnu.2.17"))
        assertTrue(rust.contains("x86_64-apple-darwin"))
    }

    @Test
    fun hard_coded_golden_vector_is_stable() {
        val runtime = sampleRuntime()
        val page = samplePage(runtime, 0, AkenResourceKind.StringPage)
        val directory = R1ArtifactDirectory.create(runtime, listOf(page))
        try {
            val encoded = directory.encode()
            println("R1-GOLDEN=" + encoded.joinToString("") { "%02x".format(it.toInt() and 0xFF) })
            assertContentEquals(hex(GOLDEN_HEX), encoded)
        } finally {
            directory.wipe()
            page.wipe()
            runtime.wipe()
        }
    }

    @Test
    fun round_trip_reconstructs_only_after_authentication() {
        val runtime = sampleRuntime()
        val pages = samplePages(runtime)
        val directory = R1ArtifactDirectory.create(runtime, pages)
        try {
            val encoded = directory.encode()
            val decoded = R1ArtifactDirectoryParser.decode(encoded, runtime)
            try {
                assertEquals(directory.size, decoded.size)
                assertEquals(directory.rootDigest.toList(), decoded.rootDigest.toList())
                assertEquals(directory.entries.map { it.key }, decoded.entries.map { it.key })
                directory.entries.zip(decoded.entries).forEach { (expected, actual) ->
                    assertEquals(expected.relativePath, actual.relativePath)
                    assertEquals(expected.offset, actual.offset)
                    assertEquals(expected.storedLength, actual.storedLength)
                    assertContentEquals(expected.descriptor, actual.descriptor)
                    assertContentEquals(expected.envelope, actual.envelope)
                    assertContentEquals(expected.bindingDigest, actual.bindingDigest)
                }
            } finally {
                decoded.wipe()
            }
        } finally {
            directory.wipe()
            pages.forEach { it.wipe() }
            runtime.wipe()
        }
    }

    @Test
    fun canonical_order_is_independent_of_input_permutation() {
        val runtime = sampleRuntime()
        val pages = samplePages(runtime)
        try {
            val baseline = R1ArtifactDirectorySerializer.encode(runtime, pages)
            val permutations = listOf(
                intArrayOf(0, 1, 2),
                intArrayOf(0, 2, 1),
                intArrayOf(1, 0, 2),
                intArrayOf(1, 2, 0),
                intArrayOf(2, 0, 1),
                intArrayOf(2, 1, 0),
            )
            repeat(12) { round ->
                val order = permutations[round % permutations.size]
                val candidate = R1ArtifactDirectorySerializer.encode(
                    runtime,
                    order.map { pages[it] },
                )
                assertContentEquals(baseline, candidate)
            }
        } finally {
            pages.forEach { it.wipe() }
            runtime.wipe()
        }
    }

    @Test
    fun accessors_are_defensive_and_close_wipes_owned_material() {
        val runtime = sampleRuntime()
        val page = samplePage(runtime, 0, AkenResourceKind.StringPage)
        val directory = R1ArtifactDirectory.create(runtime, listOf(page))
        val entry = directory.entries.single()
        try {
            val descriptor = entry.descriptor
            val envelope = entry.envelope
            val key = entry.key
            val keyBytes = key.asBytes()
            descriptor[0] = 0
            envelope[0] = 0
            keyBytes[0] = 0
            assertEquals(1, entry.descriptor[0].toInt())
            assertEquals(9, entry.envelope[0].toInt())
            assertEquals(AkenResourceKind.StringPage, entry.key.resourceKind)

            directory.wipe()
            assertFailsWith<IllegalStateException> { entry.descriptor }
            assertFailsWith<IllegalStateException> { directory.rootDigest }
        } finally {
            directory.wipe()
            page.wipe()
            runtime.wipe()
        }
    }

    @Test
    fun header_key_order_framed_payload_digest_and_legacy_mutations_fail() {
        val runtime = sampleRuntime()
        val pages = samplePages(runtime)
        val directory = R1ArtifactDirectory.create(runtime, pages)
        try {
            val encoded = directory.encode()
            val layout = layout(encoded, pages.size)
            val headerMutations = listOf(
                encoded.copyOf().also { it[0] = 'X'.code.toByte() },
                encoded.copyOf().also { it[layout.artifactOffset] = (it[layout.artifactOffset].toInt() xor 1).toByte() },
                encoded.copyOf().also { it[layout.targetOffset] = 'z'.code.toByte() },
                encoded.copyOf().also { it[layout.profileOffset] = 'z'.code.toByte() },
                encoded.copyOf().also { it[layout.runtimeDigestOffset] = (it[layout.runtimeDigestOffset].toInt() xor 1).toByte() },
                encoded.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
                encoded.copyOf().also { it[0] = 'A'.code.toByte() },
            )
            headerMutations.forEach { assertReject(it, runtime) }

            val keyMutation = encoded.copyOf().also {
                it[layout.recordStarts[0] + 5] = (it[layout.recordStarts[0] + 5].toInt() xor 1).toByte()
            }
            assertReject(keyMutation, runtime)

            val descriptorMutation = encoded.copyOf().also {
                it[layout.descriptorDataOffsets[0]] = (it[layout.descriptorDataOffsets[0]].toInt() xor 1).toByte()
            }
            assertReject(descriptorMutation, runtime)

            val envelopeMutation = encoded.copyOf().also {
                it[layout.envelopeDataOffsets[0]] = (it[layout.envelopeDataOffsets[0]].toInt() xor 1).toByte()
            }
            assertReject(envelopeMutation, runtime)

            listOf(
                layout.pathLengthOffsets[0],
                layout.descriptorLengthOffsets[0],
                layout.envelopeLengthOffsets[0],
            ).forEach { lengthOffset ->
                val mutation = encoded.copyOf()
                mutation[lengthOffset] = 0x7F
                mutation[lengthOffset + 1] = 0xFF.toByte()
                mutation[lengthOffset + 2] = 0xFF.toByte()
                mutation[lengthOffset + 3] = 0xFF.toByte()
                assertReject(mutation, runtime)
            }

            val swapped = swapRecords(encoded, layout)
            assertReject(swapped, runtime)

            val concatenated = encoded + encoded
            assertReject(concatenated, runtime)

            for (end in encoded.indices) {
                assertReject(encoded.copyOf(end), runtime)
            }
        } finally {
            directory.wipe()
            pages.forEach { it.wipe() }
            runtime.wipe()
        }
    }

    @Test
    fun duplicate_unsupported_target_and_legacy_magic_fail_closed() {
        val runtime = sampleRuntime()
        val pages = samplePages(runtime)
        val directory = R1ArtifactDirectory.create(runtime, pages)
        try {
            val encoded = directory.encode()
            val layout = layout(encoded, pages.size)

            val duplicate = encoded.copyOf()
            encoded.copyInto(
                duplicate,
                destinationOffset = layout.recordStarts[1],
                startIndex = layout.recordStarts[0],
                endIndex = layout.recordStarts[0] + PageKeySize,
            )
            assertReject(duplicate, runtime)

            val unsupported = encoded.copyOf()
            unsupported[layout.targetOffset + 1] = 'z'.code.toByte()
            assertReject(unsupported, runtime)

            val legacy = encoded.copyOf()
            "AKENOLD".encodeToByteArray().copyInto(legacy, 0)
            assertReject(legacy, runtime)
        } finally {
            directory.wipe()
            pages.forEach { it.wipe() }
            runtime.wipe()
        }
    }

    private fun assertReject(encoded: ByteArray, runtime: RuntimeBindingDigest) {
        assertFailsWith<R1ArtifactDirectoryException> {
            R1ArtifactDirectoryParser.decode(encoded, runtime)
        }
    }

    private fun sampleRuntime(): RuntimeBindingDigest = RuntimeBindingDigest.create(
        artifactCommitment = ByteArray(32) { it.toByte() },
        nativeSha256 = ByteArray(32) { (it + 32).toByte() },
        abiDigest = ByteArray(32) { (it + 64).toByte() },
        targetTriple = RuntimeBindingDigest.TARGET_WINDOWS_GNU,
        specializationDigest = ByteArray(32) { (it + 96).toByte() },
        payloadProfile = "golden-profile",
    )

    private fun samplePages(runtime: RuntimeBindingDigest): List<R1ArtifactPage> = listOf(
        samplePage(runtime, 0, AkenResourceKind.StringPage),
        samplePage(runtime, 1, AkenResourceKind.StringPage),
        samplePage(runtime, 2, AkenResourceKind.NativeChunk),
    )

    private fun samplePage(
        runtime: RuntimeBindingDigest,
        pageIndex: Int,
        kind: AkenResourceKind,
    ): R1ArtifactPage {
        val handle = ByteArray(24) { (pageIndex * 24 + it).toByte() }
        val locator = ByteArray(16) { (0xA0 + pageIndex * 16 + it).toByte() }
        val key = PageKey(kind, pageIndex, handle, locator)
        return R1ArtifactPage.create(
            key = key,
            relativePath = "pages/page-$pageIndex.bin",
            offset = 17 + pageIndex,
            storedLength = 99 + pageIndex,
            descriptor = byteArrayOf(1, 2, 3, pageIndex.toByte()),
            envelope = byteArrayOf(9, 8, 7, pageIndex.toByte()),
            runtimeBindingDigest = runtime,
        ).also {
            key.wipe()
        }
    }

    private data class Layout(
        val artifactOffset: Int,
        val targetOffset: Int,
        val profileOffset: Int,
        val runtimeDigestOffset: Int,
        val recordStarts: List<Int>,
        val recordEnds: List<Int>,
        val pathLengthOffsets: List<Int>,
        val descriptorLengthOffsets: List<Int>,
        val descriptorDataOffsets: List<Int>,
        val envelopeLengthOffsets: List<Int>,
        val envelopeDataOffsets: List<Int>,
    )

    private fun layout(encoded: ByteArray, count: Int): Layout {
        var cursor = 7 + 4
        val artifactOffset = cursor
        cursor += 32 * 3
        val targetLengthOffset = cursor
        val targetLength = readU32(encoded, targetLengthOffset)
        val targetOffset = targetLengthOffset + 4
        cursor += 4 + targetLength
        cursor += 32
        val profileLengthOffset = cursor
        val profileLength = readU32(encoded, profileLengthOffset)
        val profileOffset = profileLengthOffset + 4
        cursor += 4 + profileLength
        val runtimeDigestOffset = cursor
        cursor += 32

        val starts = ArrayList<Int>(count)
        val ends = ArrayList<Int>(count)
        val pathLengths = ArrayList<Int>(count)
        val descriptorLengths = ArrayList<Int>(count)
        val descriptorOffsets = ArrayList<Int>(count)
        val envelopeLengths = ArrayList<Int>(count)
        val envelopeOffsets = ArrayList<Int>(count)
        repeat(count) {
            starts += cursor
            cursor += PageKeySize
            pathLengths += cursor
            val pathLength = readU32(encoded, cursor)
            cursor += 4 + pathLength
            cursor += 8
            descriptorLengths += cursor
            val descriptorLength = readU32(encoded, cursor)
            descriptorOffsets += cursor + 4
            cursor += 4 + descriptorLength
            envelopeLengths += cursor
            val envelopeLength = readU32(encoded, cursor)
            envelopeOffsets += cursor + 4
            cursor += 4 + envelopeLength
            cursor += 32
            ends += cursor
        }
        assertEquals(encoded.size - 32, cursor)
        return Layout(
            artifactOffset,
            targetOffset,
            profileOffset,
            runtimeDigestOffset,
            starts,
            ends,
            pathLengths,
            descriptorLengths,
            descriptorOffsets,
            envelopeLengths,
            envelopeOffsets,
        )
    }

    private fun swapRecords(encoded: ByteArray, layout: Layout): ByteArray {
        val first = encoded.copyOfRange(layout.recordStarts[0], layout.recordEnds[0])
        val second = encoded.copyOfRange(layout.recordStarts[1], layout.recordEnds[1])
        return encoded.copyOfRange(0, layout.recordStarts[0]) +
            second + first +
            encoded.copyOfRange(layout.recordEnds[1], encoded.size)
    }

    private fun readU32(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)

    private fun hex(value: String): ByteArray {
        val clean = value.filterNot(Char::isWhitespace)
        require(clean.length % 2 == 0)
        return ByteArray(clean.length / 2) { index ->
            clean.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private companion object {
        const val PageKeySize: Int = 45
        const val GOLDEN_HEX: String =
            "4a53523144495200000001000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f000000157838365f36342d70632d77696e646f77732d676e75606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000e676f6c64656e2d70726f66696c65641e4457e0214b7f2a7c28cb37615df8b0d76ca12c61cccfb3b58eb7a07706200200000000000102030405060708090a0b0c0d0e0f1011121314151617a0a1a2a3a4a5a6a7a8a9aaabacadaeaf0000001070616765732f706167652d302e62696e000000110000006300000004010203000000000409080700503a3ce9d1dae1566b4f130472b3f162c96c3ae92582e0bc767022cfde7419c4e34db6d8067cc0808989f0afc16da7014d1be887737353bbf0affcd56c4dc3cd"
    }
}
