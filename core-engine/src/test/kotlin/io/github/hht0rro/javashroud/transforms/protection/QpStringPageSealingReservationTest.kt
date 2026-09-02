package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.qp.QpHandle
import io.github.hht0rro.javashroud.transforms.protection.qp.QpTextPageCandidate
import io.github.hht0rro.javashroud.transforms.protection.qp.QpMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.qp.QpMethodCandidate
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class QpStringPageSealingReservationTest {
    @Test
    fun production_sealing_reserves_string_page_routes_in_the_same_namespace_as_native_routes() {
        val context = QpBuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 1).toByte() },
            nativeSeed = 0x414B_454E_0000_0073L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 3).toByte() },
        )
        val stringIdentity = ByteArray(32) { index -> (index * 13 + 5).toByte() }
        val stringPlaintext = "production string route".encodeToByteArray()
        val stringProof = ByteArray(32) { index -> (index * 17 + 7).toByte() }
        val stringHandle = ByteArray(QpHandle.ENCODED_HANDLE_SIZE) { index -> (index * 19 + 9).toByte() }
        val vmIdentity = ByteArray(32) { index -> (index * 23 + 11).toByte() }
        val vmProgram = ByteArray(96) { index -> (index * 29 + 13).toByte() }
        val stringCandidate = QpTextPageCandidate.create(
            logicalIdentity = stringIdentity,
            plaintext = stringPlaintext,
            pageIndex = 0,
            callSiteProof = stringProof,
            encodedHandle = stringHandle,
            logicalBindingPath = "META-INF/.logical/string/production.bin",
            targetPageSize = 128,
        )
        val vmCandidate = QpMethodCandidate.create(
            entryToken = 0x414B_454E_0000_0074L,
            logicalMethod = QpMethodIdentity.create(
                dispatchClassToken = "fixture/Sealing",
                dispatchMethodToken = "run",
                descriptor = "()V",
                logicalVmResourcePath = "META-INF/qp/production.bin",
            ),
            logicalIdentity = vmIdentity,
            serializedProgram = vmProgram,
        )
        try {
            withQpBuildContext(context) {
                val scoped = requireQpBuildContext()
                scoped.registerQpTextPageCandidates(listOf(stringCandidate))
                scoped.registerQpMethodCandidates(listOf(vmCandidate))
                stringCandidate.wipe()
                vmCandidate.wipe()
                Arrays.fill(stringIdentity, 0)
                Arrays.fill(stringPlaintext, 0)
                Arrays.fill(stringProof, 0)
                Arrays.fill(stringHandle, 0)
                Arrays.fill(vmIdentity, 0)
                Arrays.fill(vmProgram, 0)

                val artifact = testAttachedArtifact(
                    classArtifacts = emptyList(),
                    jarEntries = listOf(JarEntryData("META-INF/existing.bin", byteArrayOf(1, 2, 3))),
                )

                // Call StringPage reservation first to prove the native VM path also
                // consumes any already-published StringPage route namespace.
                assertTrue(RuntimeArtifactSealing.reserveQpTextRoutesIfNeeded(artifact, scoped.nativeSeed))
                assertTrue(RuntimeArtifactSealing.reserveQpPreSealRoutesIfNeeded(artifact, scoped.nativeSeed))
                assertTrue(RuntimeArtifactSealing.reserveQpTextRoutesIfNeeded(artifact, scoped.nativeSeed))
                assertTrue(RuntimeArtifactSealing.reserveQpPreSealRoutesIfNeeded(artifact, scoped.nativeSeed))

                val stringPaths = mutableListOf<String>()
                scoped.requireQpTextRouteReservation().withRoutesForBuild { routes ->
                    assertEquals(1, routes.size)
                    stringPaths += routes.single().futureResourcePath
                }
                val vmPaths = mutableListOf<String>()
                scoped.requireQpPreSealRouteReservation().withRoutesForBuild { routes ->
                    assertEquals(1, routes.size)
                    vmPaths += routes.single().futureContainerPath
                }

                val allPaths = stringPaths + vmPaths
                assertEquals(allPaths.size, allPaths.distinct().size)
                assertFalse("META-INF/existing.bin" in allPaths)
            }
        } finally {
            stringCandidate.wipe()
            vmCandidate.wipe()
            context.wipe()
            Arrays.fill(stringIdentity, 0)
            Arrays.fill(stringPlaintext, 0)
            Arrays.fill(stringProof, 0)
            Arrays.fill(stringHandle, 0)
            Arrays.fill(vmIdentity, 0)
            Arrays.fill(vmProgram, 0)
        }
    }
}
