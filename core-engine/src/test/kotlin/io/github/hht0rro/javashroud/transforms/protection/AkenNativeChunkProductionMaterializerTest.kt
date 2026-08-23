package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkCandidate
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenNativeChunkProductionMaterializerTest {
    @Test
    fun native_chunk_only_candidates_materialize_before_native_compilation() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 1).toByte() },
            nativeSeed = 0x414B_454E_0000_3074L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 3).toByte() },
        )
        val identity = ByteArray(32) { index -> (index * 13 + 5).toByte() }
        val plaintext = "production native handler chunk".encodeToByteArray()
        val proof = ByteArray(32) { index -> (index * 17 + 7).toByte() }
        val handle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 19 + 9).toByte() }
        val expectedProof = proof.copyOf()
        val expectedHandle = handle.copyOf()
        val candidate = AkenNativeChunkCandidate.create(
            logicalIdentity = identity,
            plaintext = plaintext,
            pageIndex = 0,
            callSiteProof = proof,
            encodedHandle = handle,
            logicalBindingPath = "META-INF/.logical/native/production-materializer.bin",
            targetPageSize = 1024,
        )

        try {
            withVbc4BuildContext(context) {
                val scoped = requireVbc4BuildContext()
                scoped.registerAkenNativeChunkCandidates(listOf(candidate))
                candidate.wipe()
                Arrays.fill(identity, 0)
                Arrays.fill(plaintext, 0)
                Arrays.fill(proof, 0)
                Arrays.fill(handle, 0)

                val input = testAttachedArtifact(
                    classArtifacts = emptyList(),
                    jarEntries = listOf(JarEntryData("META-INF/existing.bin", byteArrayOf(1, 2, 3))),
                )
                assertTrue(
                    RuntimeArtifactSealing.reserveAkenNativeChunkPreSealRoutesIfNeeded(
                        artifact = input,
                        seed = scoped.nativeSeed,
                    ),
                )

                val output = AkenVbc4ProductionMaterializer.materializeBeforeNativeCompilation(
                    artifact = input,
                    seed = scoped.nativeSeed,
                )
                val routePath = buildList {
                    scoped.requireAkenNativeChunkPreSealRouteReservation().withRoutesForBuild { routes ->
                        assertEquals(1, routes.size)
                        add(routes.single().futureResourcePath)
                    }
                }.single()

                assertTrue(output.jarEntries.any { entry -> entry.name == routePath })
                assertEquals(input.jarEntries.size + 1, output.jarEntries.size)

                val layout = scoped.requireAkenVbc4FinalizationLayout()
                assertTrue(
                    layout.verifyWriterEquivalentArtifactForBuild(
                        output.jarEntries.map { entry -> AkenArtifactEntry(entry.name, entry.bytes) },
                    ),
                )
                scoped.withAkenNativeLocatorRecordsForBuild { records ->
                    assertEquals(1, records.size)
                    assertTrue(records.single().isNotEmpty())
                }
                layout.withPageZeroDispatchBindingsForBuild { bindings ->
                    assertTrue(bindings.isEmpty())
                }

                val tamperedEntries = output.jarEntries.map { entry ->
                    val bytes = entry.bytes.copyOf()
                    try {
                        if (entry.name == routePath) {
                            bytes[0] = (bytes[0].toInt() xor 0x4D).toByte()
                        }
                        AkenArtifactEntry(entry.name, bytes)
                    } finally {
                        Arrays.fill(bytes, 0)
                    }
                }
                assertFalse(layout.verifyWriterEquivalentArtifactForBuild(tamperedEntries))

                val retainedHandle = scoped.withAkenNativeChunkCandidatesForBuild { candidates ->
                    candidates.single().copyEncodedHandleForBuild()
                }
                try {
                    assertContentEquals(expectedHandle, retainedHandle)
                } finally {
                    Arrays.fill(retainedHandle, 0)
                }
            }
        } finally {
            candidate.wipe()
            context.wipe()
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(handle, 0)
            Arrays.fill(expectedProof, 0)
            Arrays.fill(expectedHandle, 0)
        }
    }
}
