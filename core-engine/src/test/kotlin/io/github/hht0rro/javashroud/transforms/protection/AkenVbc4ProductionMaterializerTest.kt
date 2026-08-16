package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4LogicalMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4MethodCandidate
import java.io.ByteArrayOutputStream
import java.util.Arrays
import java.util.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AkenVbc4ProductionMaterializerTest {
    @Test
    fun production_hook_materializes_page_entries_before_native_locator_generation() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 3).toByte() },
            nativeSeed = 0x4A4B_454E_0000_0021L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 5).toByte() },
        )
        val logicalPath = "META-INF/vbc4/production-materializer.bin"
        val plaintext = framedVbc4(blockLength = 640)
        val identity = ByteArray(32) { index -> (index * 13 + 9).toByte() }
        val candidate = AkenVbc4MethodCandidate.create(
            entryToken = 0x414B_454E_0000_0021L,
            logicalMethod = AkenVbc4LogicalMethodIdentity.create(
                dispatchClassToken = "fixture/ProductionMaterializer",
                dispatchMethodToken = "dispatch",
                descriptor = "()I",
                logicalVmResourcePath = logicalPath,
            ),
            logicalIdentity = identity,
            serializedProgram = plaintext,
        )
        val artifact = testAttachedArtifact(
            classArtifacts = emptyList(),
            jarEntries = listOf(JarEntryData("META-INF/existing.bin", byteArrayOf(1, 2, 3))),
        )
        try {
            withVbc4BuildContext(context) {
                val scoped = requireVbc4BuildContext()
                scoped.registerAkenVbc4MethodCandidates(listOf(candidate))
                candidate.wipe()

                assertTrue(
                    RuntimeArtifactSealing.reserveAkenVbc4PreSealRoutesIfNeeded(
                        artifact = artifact,
                        seed = scoped.nativeSeed,
                    ),
                )
                val materialized = RuntimeArtifactSealing.materializeAkenVbc4PagesForNativeCompilation(
                    artifact = artifact,
                    seed = scoped.nativeSeed,
                )
                val layout = assertNotNull(scoped.akenVbc4FinalizationLayoutOrNull())
                val pageEntry = layout.entriesForBuild().single { it.name != "META-INF/existing.bin" }
                val pageBytes = pageEntry.copyBytesForBuild()
                try {
                    assertTrue(materialized.jarEntries.any { it.name == pageEntry.name })
                    assertFalse(pageBytes.contentEquals(plaintext))
                } finally {
                    Arrays.fill(pageBytes, 0)
                }

                val include = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(
                    scoped,
                    Random(0xA4E1),
                )
                assertTrue(include.contains("#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_COUNT 1u"))
                assertFalse(include.contains(plaintext.decodeToString()))
            }
        } finally {
            candidate.wipe()
            context.wipe()
            Arrays.fill(identity, 0)
            Arrays.fill(plaintext, 0)
        }
    }

    @Test
    fun production_hook_keeps_all_preseal_route_snapshots_live_until_planning_completes() {
        val context = Vbc4BuildContext(
            masterKey = ByteArray(32) { index -> (index * 5 + 11).toByte() },
            nativeSeed = 0x4A4B_454E_0000_0042L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 9 + 7).toByte() },
        )
        val primaryProgram = framedVbc4(blockLength = 640)
        val secondaryProgram = framedVbc4(blockLength = 704)
        val primaryIdentity = ByteArray(32) { index -> (index * 13 + 3).toByte() }
        val secondaryIdentity = ByteArray(32) { index -> (index * 19 + 5).toByte() }
        val primary = AkenVbc4MethodCandidate.create(
            entryToken = 0x414B_454E_0000_0042L,
            logicalMethod = AkenVbc4LogicalMethodIdentity.create(
                dispatchClassToken = "fixture/RouteSnapshotPrimary",
                dispatchMethodToken = "dispatch",
                descriptor = "()I",
                logicalVmResourcePath = "META-INF/vbc4/route-snapshot-primary.bin",
            ),
            logicalIdentity = primaryIdentity,
            serializedProgram = primaryProgram,
        )
        val secondary = AkenVbc4MethodCandidate.create(
            entryToken = 0x414B_454E_0000_0043L,
            logicalMethod = AkenVbc4LogicalMethodIdentity.create(
                dispatchClassToken = "fixture/RouteSnapshotSecondary",
                dispatchMethodToken = "dispatch",
                descriptor = "()I",
                logicalVmResourcePath = "META-INF/vbc4/route-snapshot-secondary.bin",
            ),
            logicalIdentity = secondaryIdentity,
            serializedProgram = secondaryProgram,
        )
        val artifact = testAttachedArtifact(
            classArtifacts = emptyList(),
            jarEntries = listOf(JarEntryData("META-INF/existing.bin", byteArrayOf(7, 8, 9))),
        )
        try {
            withVbc4BuildContext(context) {
                val scoped = requireVbc4BuildContext()
                scoped.registerAkenVbc4MethodCandidates(listOf(primary, secondary))
                primary.wipe()
                secondary.wipe()

                assertTrue(
                    RuntimeArtifactSealing.reserveAkenVbc4PreSealRoutesIfNeeded(
                        artifact = artifact,
                        seed = scoped.nativeSeed,
                    ),
                )
                val materialized = RuntimeArtifactSealing.materializeAkenVbc4PagesForNativeCompilation(
                    artifact = artifact,
                    seed = scoped.nativeSeed,
                )
                val layout = assertNotNull(scoped.akenVbc4FinalizationLayoutOrNull())
                val pageEntries = layout.entriesForBuild().filter { entry -> entry.name != "META-INF/existing.bin" }
                assertEquals(
                    2,
                    pageEntries.size,
                    "each independently reserved VBC4 method must retain a live route until all candidates are planned",
                )
                assertTrue(
                    pageEntries.all { pageEntry -> materialized.jarEntries.any { entry -> entry.name == pageEntry.name } },
                    "materialization must publish every page container selected from the scoped route snapshot",
                )

                val include = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(
                    scoped,
                    Random(0xA4E2),
                )
                assertTrue(include.contains("#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_COUNT 2u"))
                assertFalse(include.contains(primaryProgram.decodeToString()))
                assertFalse(include.contains(secondaryProgram.decodeToString()))
            }
        } finally {
            primary.wipe()
            secondary.wipe()
            context.wipe()
            Arrays.fill(primaryIdentity, 0)
            Arrays.fill(secondaryIdentity, 0)
            Arrays.fill(primaryProgram, 0)
            Arrays.fill(secondaryProgram, 0)
        }
    }

    private fun framedVbc4(blockLength: Int): ByteArray {
        val out = ByteArrayOutputStream()
        out.write("VBC4".encodeToByteArray())
        writeU2(out, 4)
        out.write(ByteArray(16))
        writeU4(out, 0xAABBCCDDL)
        out.write(ByteArray(16))
        writeU2(out, 0)
        writeU2(out, 1)
        writeU4(out, 0)
        writeU4(out, 4)
        out.write(byteArrayOf(1, 2, 3, 4))
        writeU2(out, 7)
        writeU4(out, 1)
        writeU4(out, 101)
        writeU4(out, blockLength.toLong())
        writeU4(out, blockLength.toLong())
        writeU4(out, blockLength.toLong())
        out.write(ByteArray(blockLength) { index -> (index * 17 + 3).toByte() })
        writeU4(out, 0)
        writeU4(out, 0)
        writeU4(out, 0)
        writeU4(out, 0)
        out.write(ByteArray(32))
        out.write(32)
        return out.toByteArray()
    }

    private fun writeU2(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU4(out: ByteArrayOutputStream, value: Long) {
        out.write(((value ushr 24) and 0xFF).toInt())
        out.write(((value ushr 16) and 0xFF).toInt())
        out.write(((value ushr 8) and 0xFF).toInt())
        out.write((value and 0xFF).toInt())
    }
}
