package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenClassPageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import java.util.Arrays
import java.util.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
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
        val expectedProof = proof.copyOf()
        val expectedHandle = handle.copyOf()
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

                val descriptorPath =
                    AkenClassPageDescriptor.resourcePathForInternalNameForBuild(
                        "fixture/ProductionMaterializer",
                    )
                assertTrue(output.jarEntries.any { entry -> entry.name == routePath })
                assertTrue(output.jarEntries.any { entry -> entry.name == descriptorPath })
                assertEquals(input.jarEntries.size + 2, output.jarEntries.size)

                val descriptorBytes = output.jarEntries.single { entry -> entry.name == descriptorPath }.bytes.copyOf()
                var descriptor: AkenClassPageDescriptor? = null
                try {
                    descriptor = AkenClassPageDescriptor.decodeForBuild(descriptorBytes)
                    assertEquals("fixture/ProductionMaterializer", descriptor.internalName)
                    descriptor.withPagesForBuild { pages ->
                        assertEquals(1, pages.size)
                        val descriptorHandle = pages.single().copyEncodedHandleForBuild()
                        val descriptorProof = pages.single().copyCallSiteProofForBuild()
                        try {
                            assertContentEquals(expectedHandle, descriptorHandle)
                            assertContentEquals(expectedProof, descriptorProof)
                        } finally {
                            Arrays.fill(descriptorHandle, 0)
                            Arrays.fill(descriptorProof, 0)
                        }
                    }
                } finally {
                    descriptor?.wipe()
                    Arrays.fill(descriptorBytes, 0)
                }

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
                val descriptorTamperedEntries = output.jarEntries.map { entry ->
                    val bytes = entry.bytes.copyOf()
                    try {
                        if (entry.name == descriptorPath) {
                            bytes[0] = (bytes[0].toInt() xor 0x4D).toByte()
                        }
                        AkenArtifactEntry(entry.name, bytes)
                    } finally {
                        Arrays.fill(bytes, 0)
                    }
                }
                assertFalse(layout.verifyWriterEquivalentArtifactForBuild(descriptorTamperedEntries))
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
