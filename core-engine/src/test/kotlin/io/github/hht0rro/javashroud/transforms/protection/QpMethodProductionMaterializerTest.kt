package io.github.hht0rro.javashroud.transforms.protection

import io.github.hht0rro.javashroud.model.artifact.JarEntryData
import io.github.hht0rro.javashroud.testAttachedArtifact
import io.github.hht0rro.javashroud.transforms.protection.qp.QpMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.qp.QpMethodCandidate
import io.github.hht0rro.javashroud.transforms.protection.qp.QpNameSchedule
import io.github.hht0rro.javashroud.transforms.protection.qp.derivedVmMagic
import java.io.ByteArrayOutputStream
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class QpMethodProductionMaterializerTest {
    @Test
    fun production_hook_materializes_page_entries_before_native_locator_generation() {
        val context = QpBuildContext(
            masterKey = ByteArray(32) { index -> (index * 7 + 3).toByte() },
            nativeSeed = 0x4A4B_454E_0000_0021L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 5).toByte() },
            nameSeed = QpNameSchedule.TEST_NAME_SEED.copyOf(),
        )
        val logicalPath = "META-INF/qp/production-materializer.bin"
        val plaintext = framedQp(blockLength = 640)
        val identity = ByteArray(32) { index -> (index * 13 + 9).toByte() }
        val candidate = QpMethodCandidate.create(
            entryToken = 0x414B_454E_0000_0021L,
            logicalMethod = QpMethodIdentity.create(
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
            withQpBuildContext(context) {
                val scoped = requireQpBuildContext()
                scoped.registerQpMethodCandidates(listOf(candidate))
                candidate.wipe()

                assertTrue(
                    RuntimeArtifactSealing.reserveQpPreSealRoutesIfNeeded(
                        artifact = artifact,
                        seed = scoped.nativeSeed,
                    ),
                )
                val materialized = RuntimeArtifactSealing.materializeQpPagesForNativeCompilation(
                    artifact = artifact,
                    seed = scoped.nativeSeed,
                )
                val layout = assertNotNull(scoped.qpFinalizationLayoutOrNull())
                val pageEntry = layout.entriesForBuild().single { it.name != "META-INF/existing.bin" }
                val pageBytes = pageEntry.copyBytesForBuild()
                try {
                    assertTrue(materialized.jarEntries.any { it.name == pageEntry.name })
                    assertFalse(pageBytes.contentEquals(plaintext))
                } finally {
                    Arrays.fill(pageBytes, 0)
                }

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
        val context = QpBuildContext(
            masterKey = ByteArray(32) { index -> (index * 5 + 11).toByte() },
            nativeSeed = 0x4A4B_454E_0000_0042L,
            jarLayoutDigest = ByteArray(32) { index -> (index * 9 + 7).toByte() },
            nameSeed = QpNameSchedule.TEST_NAME_SEED.copyOf(),
        )
        val primaryProgram = framedQp(blockLength = 640)
        val secondaryProgram = framedQp(blockLength = 704)
        val primaryIdentity = ByteArray(32) { index -> (index * 13 + 3).toByte() }
        val secondaryIdentity = ByteArray(32) { index -> (index * 19 + 5).toByte() }
        val primary = QpMethodCandidate.create(
            entryToken = 0x414B_454E_0000_0042L,
            logicalMethod = QpMethodIdentity.create(
                dispatchClassToken = "fixture/RouteSnapshotPrimary",
                dispatchMethodToken = "dispatch",
                descriptor = "()I",
                logicalVmResourcePath = "META-INF/qp/route-snapshot-primary.bin",
            ),
            logicalIdentity = primaryIdentity,
            serializedProgram = primaryProgram,
        )
        val secondary = QpMethodCandidate.create(
            entryToken = 0x414B_454E_0000_0043L,
            logicalMethod = QpMethodIdentity.create(
                dispatchClassToken = "fixture/RouteSnapshotSecondary",
                dispatchMethodToken = "dispatch",
                descriptor = "()I",
                logicalVmResourcePath = "META-INF/qp/route-snapshot-secondary.bin",
            ),
            logicalIdentity = secondaryIdentity,
            serializedProgram = secondaryProgram,
        )
        val artifact = testAttachedArtifact(
            classArtifacts = emptyList(),
            jarEntries = listOf(JarEntryData("META-INF/existing.bin", byteArrayOf(7, 8, 9))),
        )
        try {
            withQpBuildContext(context) {
                val scoped = requireQpBuildContext()
                scoped.registerQpMethodCandidates(listOf(primary, secondary))
                primary.wipe()
                secondary.wipe()

                assertTrue(
                    RuntimeArtifactSealing.reserveQpPreSealRoutesIfNeeded(
                        artifact = artifact,
                        seed = scoped.nativeSeed,
                    ),
                )
                val materialized = RuntimeArtifactSealing.materializeQpPagesForNativeCompilation(
                    artifact = artifact,
                    seed = scoped.nativeSeed,
                )
                val layout = assertNotNull(scoped.qpFinalizationLayoutOrNull())
                val pageEntries = layout.entriesForBuild().filter { entry -> entry.name != "META-INF/existing.bin" }
                assertEquals(
                    2,
                    pageEntries.size,
                    "each independently reserved native VM method must retain a live route until all candidates are planned",
                )
                assertTrue(
                    pageEntries.all { pageEntry -> materialized.jarEntries.any { entry -> entry.name == pageEntry.name } },
                    "materialization must publish every page container selected from the scoped route snapshot",
                )

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

    private fun framedQp(blockLength: Int): ByteArray {
        val out = ByteArrayOutputStream()
        val currentMagic = derivedVmMagic()
        try {
            out.write(currentMagic)
        } finally {
            Arrays.fill(currentMagic, 0)
        }
        out.write(ByteArray(16))
        out.write(ByteArray(32))
        writeU4(out, 0xAABBCCDDL)
        out.write(ByteArray(16))
        writeU2(out, 0)
        writeU2(out, 1)
        writeU4(out, 4)
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
