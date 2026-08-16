package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptorPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import java.util.Arrays
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AkenClassPageDescriptorTest {
    @Test
    fun descriptor_defensively_owns_one_class_page_set_and_round_trips_strictly() {
        val handleZero = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 7 + 3).toByte() }
        val proofZero = ByteArray(37) { index -> (index * 11 + 5).toByte() }
        val handleOne = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 13 + 9).toByte() }
        val proofOne = ByteArray(73) { index -> (index * 17 + 1).toByte() }
        var pageZero: AkenClassPageDescriptorPage? = null
        var pageOne: AkenClassPageDescriptorPage? = null
        var descriptor: AkenClassPageDescriptor? = null
        var decoded: AkenClassPageDescriptor? = null
        var encoded: ByteArray? = null
        try {
            pageZero = AkenClassPageDescriptorPage.create(0, handleZero, proofZero)
            pageOne = AkenClassPageDescriptorPage.create(1, handleOne, proofOne)
            descriptor = AkenClassPageDescriptor.create(
                internalName = "fixture/DescriptorOwner",
                pages = listOf(pageZero, pageOne),
            )
            Arrays.fill(handleZero, 0)
            Arrays.fill(proofZero, 0)
            Arrays.fill(handleOne, 0)
            Arrays.fill(proofOne, 0)

            assertEquals(2, descriptor.pageCount)
            val route = descriptor.resourcePathForBuild()
            assertTrue(route.startsWith("META-INF/") || route.startsWith("assets/"), route)
            assertTrue(route.substringAfterLast('/').contains('.'), route)
            assertTrue(descriptor.markerForBuild().matches(Regex("[A-Za-z0-9_-]{43}")), "marker must be opaque Base64URL binding material")

            encoded = descriptor.copyEncodedForBuild()
            decoded = AkenClassPageDescriptor.decodeForBuild(encoded)
            assertEquals("fixture/DescriptorOwner", decoded.internalName)
            assertEquals(2, decoded.pageCount)
            decoded.withPagesForBuild { pages ->
                assertEquals(listOf(0, 1), pages.map { it.pageIndex })
                val copiedHandleZero = pages[0].copyEncodedHandleForBuild()
                val copiedProofZero = pages[0].copyCallSiteProofForBuild()
                val copiedHandleOne = pages[1].copyEncodedHandleForBuild()
                val copiedProofOne = pages[1].copyCallSiteProofForBuild()
                try {
                    assertContentEquals(ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 7 + 3).toByte() }, copiedHandleZero)
                    assertContentEquals(ByteArray(37) { index -> (index * 11 + 5).toByte() }, copiedProofZero)
                    assertContentEquals(ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 13 + 9).toByte() }, copiedHandleOne)
                    assertContentEquals(ByteArray(73) { index -> (index * 17 + 1).toByte() }, copiedProofOne)
                } finally {
                    Arrays.fill(copiedHandleZero, 0)
                    Arrays.fill(copiedProofZero, 0)
                    Arrays.fill(copiedHandleOne, 0)
                    Arrays.fill(copiedProofOne, 0)
                }
            }
        } finally {
            encoded?.let { Arrays.fill(it, 0) }
            decoded?.wipe()
            descriptor?.wipe()
            pageZero?.wipe()
            pageOne?.wipe()
            Arrays.fill(handleZero, 0)
            Arrays.fill(proofZero, 0)
            Arrays.fill(handleOne, 0)
            Arrays.fill(proofOne, 0)
        }
    }

    @Test
    fun descriptor_chunks_preserve_exact_binary_encoding_and_routes_are_class_local() {
        val pages = mutableListOf<AkenClassPageDescriptorPage>()
        var descriptorA: AkenClassPageDescriptor? = null
        var descriptorB: AkenClassPageDescriptor? = null
        var encoded: ByteArray? = null
        var decodedFromChunks: ByteArray? = null
        try {
            repeat(8) { pageIndex ->
                val handle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (pageIndex * 19 + index * 3).toByte() }
                val proof = ByteArray(191 + pageIndex) { index -> (pageIndex * 23 + index * 5).toByte() }
                try {
                    pages += AkenClassPageDescriptorPage.create(pageIndex, handle, proof)
                } finally {
                    Arrays.fill(handle, 0)
                    Arrays.fill(proof, 0)
                }
            }
            descriptorA = AkenClassPageDescriptor.create("fixture/ChunkedDescriptor", pages)
            descriptorB = AkenClassPageDescriptor.create("fixture/OtherDescriptor", pages)
            val chunks = descriptorA.copyBase64UrlChunksForBuild(maxChunkChars = 31)
            assertTrue(chunks.size > 1, "fixture must exercise bounded descriptor chunks")
            assertTrue(chunks.all { it.length in 1..31 }, chunks.joinToString(","))
            encoded = descriptorA.copyEncodedForBuild()
            decodedFromChunks = Base64.getUrlDecoder().decode(chunks.joinToString(separator = ""))
            assertContentEquals(encoded, decodedFromChunks)
            assertNotEquals(descriptorA.resourcePathForBuild(), descriptorB.resourcePathForBuild())
            assertNotEquals(descriptorA.markerForBuild(), descriptorB.markerForBuild())
        } finally {
            encoded?.let { Arrays.fill(it, 0) }
            decodedFromChunks?.let { Arrays.fill(it, 0) }
            descriptorA?.wipe()
            descriptorB?.wipe()
            pages.forEach { it.wipe() }
        }
    }

    @Test
    fun descriptor_rejects_trailing_bytes_holes_and_wiped_access() {
        val handle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 29 + 7).toByte() }
        val proof = ByteArray(41) { index -> (index * 31 + 11).toByte() }
        var page: AkenClassPageDescriptorPage? = null
        var descriptor: AkenClassPageDescriptor? = null
        var encoded: ByteArray? = null
        var trailing: ByteArray? = null
        var hole: ByteArray? = null
        try {
            page = AkenClassPageDescriptorPage.create(0, handle, proof)
            descriptor = AkenClassPageDescriptor.create("fixture/StrictDescriptor", listOf(page))
            encoded = descriptor.copyEncodedForBuild()

            trailing = encoded.copyOf(encoded.size + 1)
            trailing[trailing.lastIndex] = 0x5A
            assertFailsWith<IllegalArgumentException> { AkenClassPageDescriptor.decodeForBuild(trailing) }

            hole = encoded.copyOf()
            val pageIndexOffset = Short.SIZE_BYTES + "fixture/StrictDescriptor".encodeToByteArray().size + Short.SIZE_BYTES
            hole[pageIndexOffset + Int.SIZE_BYTES - 1] = 1
            assertFailsWith<IllegalArgumentException> { AkenClassPageDescriptor.decodeForBuild(hole) }

            descriptor.wipe()
            assertTrue(descriptor.isWiped)
            assertFailsWith<IllegalStateException> { descriptor.copyEncodedForBuild() }
        } finally {
            encoded?.let { Arrays.fill(it, 0) }
            trailing?.let { Arrays.fill(it, 0) }
            hole?.let { Arrays.fill(it, 0) }
            descriptor?.wipe()
            page?.wipe()
            Arrays.fill(handle, 0)
            Arrays.fill(proof, 0)
        }
    }
}
