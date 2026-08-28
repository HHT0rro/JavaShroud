package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpTextPageCandidate
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpStringPageProductionMaterializerTest {
    @Test
    fun string_page_only_candidates_materialize_before_native_compilation() {
        val context = QpBuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 1).toByte() },
            nativeSeed = 0x414B_454E_0000_3073L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 3).toByte() },
        )
        val identity = ByteArray(32) { index -> (index * 13 + 5).toByte() }
        val plaintext = "production typed string materialization".encodeToByteArray()
        val proof = ByteArray(32) { index -> (index * 17 + 7).toByte() }
        val handle = ByteArray(QpHandle.ENCODED_HANDLE_SIZE) { index -> (index * 19 + 9).toByte() }
        val candidate = QpTextPageCandidate.create(
            logicalIdentity = identity,
            plaintext = plaintext,
            pageIndex = 0,
            callSiteProof = proof,
            encodedHandle = handle,
            logicalBindingPath = "META-INF/.logical/string/production-materializer.bin",
            targetPageSize = 128,
        )

        try {
            withQpBuildContext(context) {
                val scoped = requireQpBuildContext()
                scoped.registerQpTextPageCandidates(listOf(candidate))
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
                    RuntimeArtifactSealing.reserveQpTextRoutesIfNeeded(
                        artifact = input,
                        seed = scoped.nativeSeed,
                    ),
                )

                val output = QpMethodProductionMaterializer.materializeBeforeNativeCompilation(
                    artifact = input,
                    seed = scoped.nativeSeed,
                )
                val routePath = buildList {
                    scoped.requireQpTextRouteReservation().withRoutesForBuild { routes ->
                        assertEquals(1, routes.size)
                        add(routes.single().futureResourcePath)
                    }
                }.single()

                assertTrue(output.jarEntries.any { entry -> entry.name == routePath })
                assertEquals(input.jarEntries.size + 1, output.jarEntries.size)

                val layout = scoped.requireQpFinalizationLayout()
                assertTrue(
                    layout.verifyWriterEquivalentArtifactForBuild(
                        output.jarEntries.map { entry -> QpArtifactEntry(entry.name, entry.bytes) },
                    ),
                )
                scoped.withQpLocatorRecordsForBuild { records ->
                    assertEquals(1, records.size)
                    assertTrue(records.single().isNotEmpty())
                }
                layout.withPageZeroDispatchBindingsForBuild { bindings ->
                    assertTrue(bindings.isEmpty())
                }
            }
        } finally {
            candidate.wipe()
            context.wipe()
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(proof, 0)
            Arrays.fill(handle, 0)
        }
    }
}
