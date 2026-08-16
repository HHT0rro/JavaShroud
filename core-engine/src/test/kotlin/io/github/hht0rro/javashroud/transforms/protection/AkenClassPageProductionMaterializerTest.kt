package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageCandidate
import java.util.Arrays
import java.util.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenClassPageProductionMaterializerTest {
    @Test
    fun string_page_only_candidates_materialize_before_native_compilation() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 1).toByte() },
            nativeSeed = 0x414B_454E_0000_3073L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 3).toByte() },
        )
        val identity = ByteArray(32) { index -> (index * 13 + 5).toByte() }
        val plaintext = "production typed class materialization".encodeToByteArray()
        val proof = ByteArray(32) { index -> (index * 17 + 7).toByte() }
        val handle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 19 + 9).toByte() }
        val candidate = AkenClassPageCandidate.create(
            logicalIdentity = identity,
            plaintext = plaintext,
            pageIndex = 0,
            callSiteProof = proof,
            encodedHandle = handle,
            logicalBindingPath = "META-INF/.logical/class/production-materializer.bin",
            targetPageSize = 512,
        )

        try {
            withVbc4BuildContext(context) {
                val scoped = requireVbc4BuildContext()
                scoped.registerAkenClassPageCandidatesForClass(
                    internalName = "fixture/ProductionMaterializer",
                    candidates = listOf(candidate),
                )
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
                    RuntimeArtifactSealing.reserveAkenClassPagePreSealRoutesIfNeeded(
                        artifact = input,
                        seed = scoped.nativeSeed,
                    ),
                )

                val output = AkenVbc4ProductionMaterializer.materializeBeforeNativeCompilation(
                    artifact = input,
                    seed = scoped.nativeSeed,
                )
                val routePath = buildList {
                    scoped.requireAkenClassPagePreSealRouteReservation().withRoutesForBuild { routes ->
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
                val nativeLocatorInclude = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(
                    vbc4BuildContext = scoped,
                    rng = Random(0xA4EEL),
                )
                assertTrue(nativeLocatorInclude.contains("#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_COUNT 1u"))
                assertFalse(nativeLocatorInclude.contains("production typed class materialization"))
                layout.withPageZeroDispatchBindingsForBuild { bindings ->
                    assertTrue(bindings.isEmpty())
                }
                scoped.withAkenClassPageDescriptorSourcesForBuild { sources ->
                    assertEquals(1, sources.size)
                    assertEquals("fixture/ProductionMaterializer", sources.single().internalName)
                    layout.withClassPageBindingsForBuild { bindings ->
                        assertEquals(1, bindings.size)
                        assertTrue(sources.single().matchesBindingForBuild(bindings.single()))
                    }
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
