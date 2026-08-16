package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4LogicalMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4MethodCandidate
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenClassPageSealingReservationTest {
    @Test
    fun production_sealing_reserves_class_page_routes_in_the_same_namespace_as_vbc4_routes() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 1).toByte() },
            nativeSeed = 0x414B_454E_0000_0073L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 3).toByte() },
        )
        val stringIdentity = ByteArray(32) { index -> (index * 13 + 5).toByte() }
        val stringPlaintext = "production class route".encodeToByteArray()
        val stringProof = ByteArray(32) { index -> (index * 17 + 7).toByte() }
        val stringHandle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 19 + 9).toByte() }
        val vbc4Identity = ByteArray(32) { index -> (index * 23 + 11).toByte() }
        val vbc4Program = ByteArray(96) { index -> (index * 29 + 13).toByte() }
        val stringCandidate = AkenClassPageCandidate.create(
            logicalIdentity = stringIdentity,
            plaintext = stringPlaintext,
            pageIndex = 0,
            callSiteProof = stringProof,
            encodedHandle = stringHandle,
            logicalBindingPath = "META-INF/.logical/class/production.bin",
            targetPageSize = 512,
        )
        val vbc4Candidate = AkenVbc4MethodCandidate.create(
            entryToken = 0x414B_454E_0000_0074L,
            logicalMethod = AkenVbc4LogicalMethodIdentity.create(
                dispatchClassToken = "fixture/Sealing",
                dispatchMethodToken = "run",
                descriptor = "()V",
                logicalVmResourcePath = "META-INF/vbc4/production.bin",
            ),
            logicalIdentity = vbc4Identity,
            serializedProgram = vbc4Program,
        )
        try {
            withVbc4BuildContext(context) {
                val scoped = requireVbc4BuildContext()
                scoped.registerAkenClassPageCandidates(listOf(stringCandidate))
                scoped.registerAkenVbc4MethodCandidates(listOf(vbc4Candidate))
                stringCandidate.wipe()
                vbc4Candidate.wipe()
                Arrays.fill(stringIdentity, 0)
                Arrays.fill(stringPlaintext, 0)
                Arrays.fill(stringProof, 0)
                Arrays.fill(stringHandle, 0)
                Arrays.fill(vbc4Identity, 0)
                Arrays.fill(vbc4Program, 0)

                val artifact = testAttachedArtifact(
                    classArtifacts = emptyList(),
                    jarEntries = listOf(JarEntryData("META-INF/existing.bin", byteArrayOf(1, 2, 3))),
                )

                // Call ClassPage reservation first to prove the VBC4 path also
                // consumes any already-published ClassPage route namespace.
                assertTrue(RuntimeArtifactSealing.reserveAkenClassPagePreSealRoutesIfNeeded(artifact, scoped.nativeSeed))
                assertTrue(RuntimeArtifactSealing.reserveAkenVbc4PreSealRoutesIfNeeded(artifact, scoped.nativeSeed))
                assertTrue(RuntimeArtifactSealing.reserveAkenClassPagePreSealRoutesIfNeeded(artifact, scoped.nativeSeed))
                assertTrue(RuntimeArtifactSealing.reserveAkenVbc4PreSealRoutesIfNeeded(artifact, scoped.nativeSeed))

                val stringPaths = mutableListOf<String>()
                scoped.requireAkenClassPagePreSealRouteReservation().withRoutesForBuild { routes ->
                    assertEquals(1, routes.size)
                    stringPaths += routes.single().futureResourcePath
                }
                val vbc4Paths = mutableListOf<String>()
                scoped.requireAkenVbc4PreSealRouteReservation().withRoutesForBuild { routes ->
                    assertEquals(1, routes.size)
                    vbc4Paths += routes.single().futureContainerPath
                }

                val allPaths = stringPaths + vbc4Paths
                assertEquals(allPaths.size, allPaths.distinct().size)
                assertFalse("META-INF/existing.bin" in allPaths)
            }
        } finally {
            stringCandidate.wipe()
            vbc4Candidate.wipe()
            context.wipe()
            Arrays.fill(stringIdentity, 0)
            Arrays.fill(stringPlaintext, 0)
            Arrays.fill(stringProof, 0)
            Arrays.fill(stringHandle, 0)
            Arrays.fill(vbc4Identity, 0)
            Arrays.fill(vbc4Program, 0)
        }
    }
}
