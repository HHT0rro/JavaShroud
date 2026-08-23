package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.AkenVbc4InnerMaterial
import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.NativeVmBuildProfile
import io.github.hht0rro.javashroud.transforms.protection.Vbc4EntryMetadata
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativeChunkHandlerDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativePageLocatorCompileInput
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativePageEnvelope
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPageMaterialization
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPageMaterializationInput
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenPageMaterializer
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimePageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenTypedPageEntryToken
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4LogicalMethodIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4MethodCandidate
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPagePlanner
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PreSealRoute
import io.github.hht0rro.javashroud.transforms.protection.defaultVbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.vmStateBinding
import io.github.hht0rro.javashroud.transforms.protection.withVbc4BuildContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Comparator
import java.util.Random
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.objectweb.asm.Label
import org.objectweb.asm.Opcodes

class AkenNativePageLocatorResolverNativeTest {
    @Test
    fun temporary_native_locator_fixture_resolves_and_rejects_invalid_generated_tables() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the native AKEN locator probe")

        val sourceNativeDir = resolveSource("src/main/native/js_jni_runtime.c").parent
        val probeSource = resolveSource("src/test/native/aken_native_page_locator_probe.c")
        val sourceInclude = sourceNativeDir.resolve("js_aken_page_locator.inc")
        val originalInclude = Files.readAllBytes(sourceInclude)
        val rawProof = "AKEN-PROOF-A".toByteArray(StandardCharsets.US_ASCII)
        val handleA = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (0x10 + index).toByte() }
        val handleB = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (0x80 + index).toByte() }
        val tempDir = Files.createTempDirectory("javashroud-aken-native-locator-")
        var records: List<ByteArray> = emptyList()
        var validBlob: ByteArray? = null
        try {
            val recordA = fixtureRecord(
                entryToken = 0x1122_3344_5566_7788L,
                pageIndex = 7,
                encodedHandle = handleA,
                rawProof = rawProof,
                seed = 0x2A,
                resourcePath = "META-INF/.aken/native-probe/a.bin",
                requireInlineEnvelope = true,
            )
            val recordB1 = fixtureRecord(
                entryToken = 0x8877_6655_4433_2211uL.toLong(),
                pageIndex = 9,
                encodedHandle = handleB,
                rawProof = rawProof,
                seed = 0x3B,
                resourcePath = "META-INF/.aken/native-probe/b-one.bin",
                requireInlineEnvelope = true,
            )
            val recordB2 = fixtureRecord(
                entryToken = 0x8877_6655_4433_2211uL.toLong(),
                pageIndex = 9,
                encodedHandle = handleB,
                rawProof = rawProof,
                seed = 0x4C,
                resourcePath = "META-INF/.aken/native-probe/b-two.bin",
                requireInlineEnvelope = true,
            )
            records = listOf(recordA, recordB1, recordB2)
            assertFalse(recordB1.contentEquals(recordB2), "duplicate lookup identities retain independently bound records")

            val compiled = compileProbe(
                zig = checkNotNull(zig),
                root = tempDir,
                sourceNativeDir = sourceNativeDir,
                probeSource = probeSource,
                include = renderInclude(records),
            )
            val valid = runProbe(compiled, "valid")
            assertEquals(0, valid.exitCode, "valid native locator fixture must pass:\n${valid.output}")
            assertTrue(valid.output.contains("AKEN native page locator probe: PASS"), valid.output)
            validBlob = concatenate(records)

            val bindingTampered = records.map { it.copyOf() }
            try {
                bindingTampered.first()[bindingTampered.first().lastIndex] =
                    (bindingTampered.first().last().toInt() xor 0x01).toByte()
                val tamperedBlob = concatenate(bindingTampered)
                val tamperedExecutable = compiled.directory.resolve(if (isWindows()) "record-binding-tamper.exe" else "record-binding-tamper")
                try {
                    patchGeneratedTable(compiled.executable, tamperedExecutable, checkNotNull(validBlob), tamperedBlob)
                    assertFailClosed("record-binding tamper", runProbe(CompiledProbe(compiled.directory, tamperedExecutable), "record-binding-tamper"))
                } finally {
                    Arrays.fill(tamperedBlob, 0)
                }
            } finally {
                bindingTampered.forEach { Arrays.fill(it, 0) }
            }

            val contiguousOffsets = contiguousOffsets(records)
            val nonContiguousOffsets = contiguousOffsets.copyOf().also { it[1] += 1 }
            val contiguousOffsetBytes = encodeNativeUnsignedInts(contiguousOffsets)
            val nonContiguousOffsetBytes = encodeNativeUnsignedInts(nonContiguousOffsets)
            try {
                val tamperedExecutable = compiled.directory.resolve(if (isWindows()) "non-contiguous-offset.exe" else "non-contiguous-offset")
                patchGeneratedTable(
                    compiled.executable,
                    tamperedExecutable,
                    contiguousOffsetBytes,
                    nonContiguousOffsetBytes,
                )
                assertFailClosed(
                    "non-contiguous record offsets",
                    runProbe(CompiledProbe(compiled.directory, tamperedExecutable), "non-contiguous-offset"),
                )
            } finally {
                Arrays.fill(contiguousOffsets, 0)
                Arrays.fill(nonContiguousOffsets, 0)
                Arrays.fill(contiguousOffsetBytes, 0)
                Arrays.fill(nonContiguousOffsetBytes, 0)
            }
        } finally {
            try {
                assertContentEquals(
                    originalInclude,
                    Files.readAllBytes(sourceInclude),
                    "the repository's default empty locator include must remain untouched",
                )
            } finally {
                records.forEach { Arrays.fill(it, 0) }
                validBlob?.let { Arrays.fill(it, 0) }
                Arrays.fill(originalInclude, 0)
                Arrays.fill(rawProof, 0)
                Arrays.fill(handleA, 0)
                Arrays.fill(handleB, 0)
                deleteTree(tempDir)
            }
        }
    }

    @Test
    fun published_finalization_layout_production_include_compiles_and_resolves_one_current_page() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the production AKEN locator probe")

        val sourceNativeDir = resolveSource("src/main/native/js_jni_runtime.c").parent
        val sourceInclude = sourceNativeDir.resolve("js_aken_page_locator.inc")
        val originalInclude = Files.readAllBytes(sourceInclude)
        val identity0 = "fixture:aken-native-production-resolver:first".encodeToByteArray()
        val identity1 = "fixture:aken-native-production-resolver:second".encodeToByteArray()
        val identity2 = "fixture:aken-native-production-resolver:third".encodeToByteArray()
        val plaintext0 = "first production renderer plaintext must not enter native include".encodeToByteArray()
        val plaintext1 = "second production renderer plaintext must not enter native include".encodeToByteArray()
        val plaintext2 = "third production renderer plaintext must not enter native include".encodeToByteArray()
        val proof0 = ByteArray(37) { index -> (index * 5 + 3).toByte() }
        val proof1 = ByteArray(41) { index -> (index * 7 + 11).toByte() }
        val proof2 = ByteArray(43) { index -> (index * 13 + 17).toByte() }
        val firstToken = 0x414B_454E_0000_1001L
        val secondToken = 0x414B_454E_0000_1002L
        val thirdToken = 0x414B_454E_0000_1003L
        val page0 = AkenVbc4PendingPage.create(
            entryToken = firstToken,
            logicalIdentity = identity0,
            plaintext = plaintext0,
            resourcePath = "META-INF/.aken/vbc4/production-renderer.bin",
            pageIndex = 0,
            targetPageSize = 512,
            callSiteProof = proof0,
            random = SecureRandom(),
        )
        val page1Offset = page0.expectedStoredLength + 19
        val page1 = AkenVbc4PendingPage.create(
            entryToken = secondToken,
            logicalIdentity = identity1,
            plaintext = plaintext1,
            resourcePath = "META-INF/.aken/vbc4/production-renderer.bin",
            resourceOffset = page1Offset,
            pageIndex = 0,
            targetPageSize = 768,
            callSiteProof = proof1,
            random = SecureRandom(),
        )
        val page2 = AkenVbc4PendingPage.create(
            entryToken = thirdToken,
            logicalIdentity = identity2,
            plaintext = plaintext2,
            resourcePath = "META-INF/.aken/vbc4/production-renderer.bin",
            resourceOffset = page1Offset + page1.expectedStoredLength + 23,
            pageIndex = 0,
            targetPageSize = 1024,
            callSiteProof = proof2,
            random = SecureRandom(),
        )
        val tempDir = Files.createTempDirectory("javashroud-aken-production-native-locator-")
        var context: Vbc4BuildContext? = null
        var layout: AkenVbc4FinalizationLayout? = null
        var compilerRecords: List<ByteArray> = emptyList()
        var currentPage: ProductionCurrentPage? = null
        var generatedIncludeBytes: ByteArray? = null
        var validBlob: ByteArray? = null
        var generatedOffsets: IntArray? = null
        var generatedLengths: IntArray? = null
        var generatedProbeBytes: ByteArray? = null
        try {
            val commitment = AkenVbc4FinalizationLayout.reserve(
                pendingPages = listOf(page0, page1, page2),
                fixedEntries = emptyList(),
            )
            val buildContext = defaultVbc4BuildContext()
            context = buildContext
            val planCommitment = commitment.copyBytes()
            val plan = try {
                buildContext.initializeAkenBuildPlan(planCommitment)
            } finally {
                Arrays.fill(planCommitment, 0)
            }
            val finalized = AkenVbc4FinalizationLayout.materializeAndWipe(
                plan = plan,
                commitment = commitment,
                pendingPages = listOf(page0, page1, page2),
                fixedEntries = emptyList(),
                vbc4StateBindingLayoutDigest = AkenVbc4InnerMaterial.copyStateBindingLayoutDigest(context),
            )
            layout = finalized
            buildContext.publishAkenVbc4FinalizationLayout(finalized)
            compilerRecords = buildContext.withAkenNativeLocatorRecordsForBuild { records ->
                records.map { record -> record.copyOf() }
            }
            assertEquals(3, compilerRecords.size)

            for (record in compilerRecords) {
                val candidate = parseProductionCurrentPage(record)
                if (
                    candidate.entryToken == firstToken &&
                    candidate.resourceKind == AkenResourceKind.Vbc4Method &&
                    candidate.pageIndex == 0
                ) {
                    check(currentPage == null) {
                        "production compiler records must have one exact first-page request identity"
                    }
                    currentPage = candidate
                } else {
                    candidate.wipe()
                }
            }
            val selectedPage = checkNotNull(currentPage)
            assertEquals(AkenResourceKind.Vbc4Method, selectedPage.resourceKind)
            assertEquals(0, selectedPage.pageIndex)

            val include = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(
                buildContext,
                Random(0xA4E1),
            )
            generatedIncludeBytes = include.toByteArray(StandardCharsets.US_ASCII)
            assertFalse(include.contains(plaintext0.decodeToString()))
            assertFalse(include.contains(plaintext1.decodeToString()))
            assertFalse(include.contains(plaintext2.decodeToString()))

            val renderedBlob = parseGeneratedUnsignedByteArray(include, "js_aken_native_page_locator_blob")
            val renderedOffsets = parseGeneratedUnsignedIntArray(include, "js_aken_native_page_locator_record_offsets")
            val renderedLengths = parseGeneratedUnsignedIntArray(include, "js_aken_native_page_locator_record_lengths")
            validBlob = renderedBlob
            generatedOffsets = renderedOffsets
            generatedLengths = renderedLengths
            assertEquals(3, renderedOffsets.size)
            assertEquals(3, renderedLengths.size)
            var expectedOffset = 0
            for (index in renderedOffsets.indices) {
                assertEquals(expectedOffset, renderedOffsets[index], "production renderer must emit a contiguous native table")
                assertTrue(renderedLengths[index] > 0)
                expectedOffset += renderedLengths[index]
            }
            assertEquals(renderedBlob.size, expectedOffset)

            val matchedRecordIndexes = ArrayList<Int>()
            for (index in renderedOffsets.indices) {
                val offset = renderedOffsets[index]
                val length = renderedLengths[index]
                val record = renderedBlob.copyOfRange(offset, offset + length)
                try {
                    val candidate = parseProductionCurrentPage(record)
                    try {
                        if (
                            candidate.entryToken == selectedPage.entryToken &&
                            candidate.resourceKind == selectedPage.resourceKind &&
                            candidate.pageIndex == selectedPage.pageIndex &&
                            MessageDigest.isEqual(candidate.encodedHandle, selectedPage.encodedHandle)
                        ) {
                            matchedRecordIndexes += index
                        }
                    } finally {
                        candidate.wipe()
                    }
                } finally {
                    Arrays.fill(record, 0)
                }
            }
            assertEquals(1, matchedRecordIndexes.size, "production include must retain exactly one current-page record")
            val selectedRecordIndex = matchedRecordIndexes.single()

            generatedProbeBytes = productionRendererProbeSource(selectedPage, proof0)
                .toByteArray(StandardCharsets.US_ASCII)
            val generatedProbeSource = tempDir.resolve("production-current-page-probe.c")
            Files.write(generatedProbeSource, checkNotNull(generatedProbeBytes))
            val compiled = compileProbe(
                zig = checkNotNull(zig),
                root = tempDir,
                sourceNativeDir = sourceNativeDir,
                probeSource = generatedProbeSource,
                include = include,
            )
            val valid = runProbe(compiled, "production-valid")
            assertEquals(0, valid.exitCode, "production generated locator must resolve its current page:\n${valid.output}")
            assertTrue(valid.output.contains("AKEN native page locator probe: PASS"), valid.output)

            val bindingTamperedBlob = renderedBlob.copyOf()
            try {
                val bindingByteOffset = renderedOffsets[selectedRecordIndex] + renderedLengths[selectedRecordIndex] - 1
                bindingTamperedBlob[bindingByteOffset] =
                    (bindingTamperedBlob[bindingByteOffset].toInt() xor 0x01).toByte()
                val tamperedExecutable = compiled.directory.resolve(
                    if (isWindows()) "production-record-binding-tamper.exe" else "production-record-binding-tamper",
                )
                patchGeneratedTable(compiled.executable, tamperedExecutable, renderedBlob, bindingTamperedBlob)
                assertFailClosed(
                    "production renderer record-binding tamper",
                    runProbe(CompiledProbe(compiled.directory, tamperedExecutable), "production-record-binding-tamper"),
                )
            } finally {
                Arrays.fill(bindingTamperedBlob, 0)
            }

            val originalOffsetBytes = encodeNativeUnsignedInts(renderedOffsets)
            val nonContiguousOffsets = renderedOffsets.copyOf().also { it[1] += 1 }
            val nonContiguousOffsetBytes = encodeNativeUnsignedInts(nonContiguousOffsets)
            try {
                val tamperedExecutable = compiled.directory.resolve(
                    if (isWindows()) "production-non-contiguous-offset.exe" else "production-non-contiguous-offset",
                )
                patchGeneratedTable(
                    compiled.executable,
                    tamperedExecutable,
                    originalOffsetBytes,
                    nonContiguousOffsetBytes,
                )
                assertFailClosed(
                    "production renderer non-contiguous offsets",
                    runProbe(CompiledProbe(compiled.directory, tamperedExecutable), "production-non-contiguous-offset"),
                )
            } finally {
                Arrays.fill(originalOffsetBytes, 0)
                Arrays.fill(nonContiguousOffsets, 0)
                Arrays.fill(nonContiguousOffsetBytes, 0)
            }

            buildContext.wipe()
            assertTrue(finalized.isWiped)
        } finally {
            try {
                assertContentEquals(
                    originalInclude,
                    Files.readAllBytes(sourceInclude),
                    "the repository's default empty locator include must remain untouched",
                )
            } finally {
                compilerRecords.forEach { Arrays.fill(it, 0) }
                currentPage?.wipe()
                generatedIncludeBytes?.let { Arrays.fill(it, 0) }
                validBlob?.let { Arrays.fill(it, 0) }
                generatedOffsets?.fill(0)
                generatedLengths?.fill(0)
                generatedProbeBytes?.let { Arrays.fill(it, 0) }
                layout?.wipe()
                context?.wipe()
                Arrays.fill(originalInclude, 0)
                Arrays.fill(identity0, 0)
                Arrays.fill(identity1, 0)
                Arrays.fill(identity2, 0)
                Arrays.fill(plaintext0, 0)
                Arrays.fill(plaintext1, 0)
                Arrays.fill(plaintext2, 0)
                Arrays.fill(proof0, 0)
                Arrays.fill(proof1, 0)
                Arrays.fill(proof2, 0)
                page0.wipe()
                page1.wipe()
                page2.wipe()
                deleteTree(tempDir)
            }
        }
    }

    @Test
    fun production_vbc4_page_opens_only_from_its_bound_native_payload_context() {
        val zig = findZig()
        assumeTrue(zig != null, "Zig is required to compile the AKEN bound-payload opener probe")

        val sourceNativeDir = resolveSource("src/main/native/js_jni_runtime.c").parent
        val sourceInclude = sourceNativeDir.resolve("js_aken_page_locator.inc")
        val probeSource = resolveSource("src/test/native/aken_native_bound_payload_probe.c")
        val originalInclude = Files.readAllBytes(sourceInclude)
        val identity = "fixture:aken-native-bound-payload".encodeToByteArray()
        val plaintext = ByteArray(733) { index -> ((index * 29 + 17) and 0xFF).toByte() }
        val rawProof = ByteArray(67) { index -> ((index * 11 + 5) and 0xFF).toByte() }
        val entryToken = 0x414B_454E_0000_2001L
        val page = AkenVbc4PendingPage.create(
            entryToken = entryToken,
            logicalIdentity = identity,
            plaintext = plaintext,
            resourcePath = "META-INF/.aken/vbc4/bound-payload.bin",
            pageIndex = 0,
            targetPageSize = 768,
            callSiteProof = rawProof,
            random = SecureRandom(),
        )
        val tempDir = Files.createTempDirectory("javashroud-aken-native-bound-payload-")
        var context: Vbc4BuildContext? = null
        var layout: AkenVbc4FinalizationLayout? = null
        var currentPage: ProductionCurrentPage? = null
        var compilerRecord: ByteArray? = null
        var entryBytes: ByteArray? = null
        var payload: ByteArray? = null
        var generatedIncludeBytes: ByteArray? = null
        var generatedFixtureBytes: ByteArray? = null
        try {
            val commitment = AkenVbc4FinalizationLayout.reserve(
                pendingPages = listOf(page),
                fixedEntries = emptyList(),
            )
            val buildContext = defaultVbc4BuildContext()
            context = buildContext
            val planCommitment = commitment.copyBytes()
            val plan = try {
                buildContext.initializeAkenBuildPlan(planCommitment)
            } finally {
                Arrays.fill(planCommitment, 0)
            }
            val finalized = AkenVbc4FinalizationLayout.materializeAndWipe(
                plan = plan,
                commitment = commitment,
                pendingPages = listOf(page),
                fixedEntries = emptyList(),
                vbc4StateBindingLayoutDigest = AkenVbc4InnerMaterial.copyStateBindingLayoutDigest(context),
            )
            layout = finalized
            buildContext.publishAkenVbc4FinalizationLayout(finalized)
            compilerRecord = buildContext.withAkenNativeLocatorRecordsForBuild { records ->
                assertEquals(1, records.size)
                records.single().copyOf()
            }
            val selectedPage = parseProductionCurrentPage(checkNotNull(compilerRecord))
            currentPage = selectedPage
            assertEquals(entryToken, selectedPage.entryToken)
            assertEquals(AkenResourceKind.Vbc4Method, selectedPage.resourceKind)
            assertEquals(0, selectedPage.pageIndex)

            val descriptor = decodeProductionCurrentPageDescriptor(checkNotNull(compilerRecord))
            assertEquals(selectedPage.resourceKind, descriptor.resourceKind)
            assertEquals(selectedPage.pageIndex, descriptor.pageIndex)
            val route = descriptor.route
            val entry = finalized.entriesForBuild().single { it.name == route.resourcePath }
            entryBytes = entry.copyBytesForBuild()
            val endExclusive = route.resourceOffset.toLong() + route.storedLength.toLong()
            require(endExclusive <= checkNotNull(entryBytes).size.toLong()) {
                "production AKEN route exceeds its final entry"
            }
            payload = checkNotNull(entryBytes).copyOfRange(route.resourceOffset, endExclusive.toInt())
            assertEquals(route.storedLength, checkNotNull(payload).size)

            val include = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(
                buildContext,
                Random(0xA4E2),
            )
            generatedIncludeBytes = include.toByteArray(StandardCharsets.US_ASCII)
            assertFalse(include.contains(plaintext.decodeToString()), "native locator include must not contain plaintext")

            val fixtureInclude = productionBoundPayloadFixtureInclude(
                currentPage = selectedPage,
                rawCallSiteProof = rawProof,
                descriptor = descriptor,
                encodedPayload = checkNotNull(payload),
                expectedPlaintext = plaintext,
            )
            generatedFixtureBytes = fixtureInclude.toByteArray(StandardCharsets.US_ASCII)
            val compiled = compileProbe(
                zig = checkNotNull(zig),
                root = tempDir,
                sourceNativeDir = sourceNativeDir,
                probeSource = probeSource,
                include = include,
                additionalNativeFiles = mapOf(
                    "aken_native_bound_payload_fixture.inc" to checkNotNull(generatedFixtureBytes),
                ),
            )
            val result = runProbe(compiled, "bound-payload")
            assertEquals(0, result.exitCode, "production AKEN bound-payload opener must pass:\n${result.output}")
            assertTrue(result.output.contains("AKEN native bound payload probe: PASS"), result.output)

            buildContext.wipe()
            assertTrue(finalized.isWiped)
        } finally {
            try {
                assertContentEquals(
                    originalInclude,
                    Files.readAllBytes(sourceInclude),
                    "the repository's default empty locator include must remain untouched",
                )
            } finally {
                compilerRecord?.let { Arrays.fill(it, 0) }
                currentPage?.wipe()
                entryBytes?.let { Arrays.fill(it, 0) }
                payload?.let { Arrays.fill(it, 0) }
                generatedIncludeBytes?.let { Arrays.fill(it, 0) }
                generatedFixtureBytes?.let { Arrays.fill(it, 0) }
                layout?.wipe()
                context?.wipe()
                Arrays.fill(originalInclude, 0)
                Arrays.fill(identity, 0)
                Arrays.fill(plaintext, 0)
                Arrays.fill(rawProof, 0)
                page.wipe()
                deleteTree(tempDir)
            }
        }
    }

    @Test
    fun production_single_page_vbc4_executes_and_authenticates_through_real_jni() {
        val zig = findZig()
        val platform = currentAkenHostPlatform()
        assumeTrue(zig != null, "Zig is required to compile the real AKEN JNI current-page fixture")
        assumeTrue(platform != null, "The real AKEN JNI current-page fixture supports release-gate host platforms only")

        val sourceNativeDir = resolveSource("src/main/native/js_jni_runtime.c").parent
        val sourceInclude = sourceNativeDir.resolve("js_aken_page_locator.inc")
        val originalInclude = Files.readAllBytes(sourceInclude)
        val identity = "fixture:aken-real-jni-current-page".encodeToByteArray()
        val rawProof = ByteArray(71) { index -> ((index * 13 + 9) and 0xFF).toByte() }
        val entryToken = 0x414B_454E_0000_3001L
        val logicalBindingPath = "META-INF/vm/aken-real-jni-current-page.vbc4"
        val tempDir = Files.createTempDirectory("javashroud-aken-real-jni-current-page-")
        var context: Vbc4BuildContext? = null
        var pendingPage: AkenVbc4PendingPage? = null
        var layout: AkenVbc4FinalizationLayout? = null
        var currentPage: ProductionCurrentPage? = null
        var compilerRecord: ByteArray? = null
        var entryBytes: ByteArray? = null
        var generatedIncludeBytes: ByteArray? = null
        var tamperedEntryBytes: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            val buildContext = akenVbc4ExecutorContext()
            context = buildContext
            plaintext = withVbc4BuildContext(buildContext) {
                val serializer = VmBytecodeSerializer(
                    buildSeed = 0x2468_1357,
                    stateBinding = vmStateBinding(entryToken, logicalBindingPath),
                    entryMetadata = Vbc4EntryMetadata(
                        entryToken = entryToken,
                        returnDescriptor = "I",
                        methodIdentity = "11".repeat(32),
                        ownerIdentity = "22".repeat(32),
                        resourcePath = logicalBindingPath,
                        isStatic = true,
                    ),
                    buildContext = buildContext,
                    structureEntropy = ByteArray(32) { index -> (index * 17 + 3).toByte() },
                )
                serializer.visitCode()
                serializer.visitInsn(Opcodes.ICONST_2)
                serializer.visitInsn(Opcodes.IRETURN)
                serializer.visitMaxs(1, 0)
                serializer.visitEnd()
                serializer.serialize()
            }
            pendingPage = AkenVbc4PendingPage.create(
                entryToken = entryToken,
                logicalIdentity = identity,
                plaintext = checkNotNull(plaintext),
                resourcePath = "META-INF/.aken/vbc4/real-jni-current-page.bin",
                pageIndex = 0,
                targetPageSize = 2048,
                callSiteProof = rawProof,
                random = SecureRandom(),
                logicalBindingPath = logicalBindingPath,
            )

            val commitment = AkenVbc4FinalizationLayout.reserve(
                pendingPages = listOf(checkNotNull(pendingPage)),
                fixedEntries = emptyList(),
            )
            val planCommitment = commitment.copyBytes()
            val plan = try {
                buildContext.initializeAkenBuildPlan(planCommitment)
            } finally {
                Arrays.fill(planCommitment, 0)
            }
            val finalized = AkenVbc4FinalizationLayout.materializeAndWipe(
                plan = plan,
                commitment = commitment,
                pendingPages = listOf(checkNotNull(pendingPage)),
                fixedEntries = emptyList(),
                vbc4StateBindingLayoutDigest = AkenVbc4InnerMaterial.copyStateBindingLayoutDigest(context),
            )
            layout = finalized
            buildContext.publishAkenVbc4FinalizationLayout(finalized)
            compilerRecord = buildContext.withAkenNativeLocatorRecordsForBuild { records ->
                assertEquals(1, records.size)
                records.single().copyOf()
            }
            val selectedPage = parseProductionCurrentPage(checkNotNull(compilerRecord))
            currentPage = selectedPage
            assertEquals(entryToken, selectedPage.entryToken)
            assertEquals(AkenResourceKind.Vbc4Method, selectedPage.resourceKind)
            assertEquals(0, selectedPage.pageIndex)

            val descriptor = decodeProductionCurrentPageDescriptor(checkNotNull(compilerRecord))
            val route = descriptor.route
            assertEquals(logicalBindingPath, route.logicalBindingPath)
            val entry = finalized.entriesForBuild().single { it.name == route.resourcePath }
            entryBytes = entry.copyBytesForBuild()
            val endExclusive = route.resourceOffset.toLong() + route.storedLength.toLong()
            require(endExclusive <= checkNotNull(entryBytes).size.toLong()) {
                "production AKEN real JNI route exceeds its final entry"
            }

            val include = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(
                buildContext,
                Random(0xA4E3),
            )
            generatedIncludeBytes = include.toByteArray(StandardCharsets.US_ASCII)
            assertFalse(
                include.contains(checkNotNull(plaintext).decodeToString()),
                "real JNI locator include must not contain plaintext",
            )

            val nativeLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir,
                sourceNativeDir = sourceNativeDir,
                include = include,
                platform = checkNotNull(platform),
            )
            val runtimeRoot = prepareAkenJniRuntimeFixture(
                root = tempDir,
                platform = platform,
                nativeLibrary = nativeLibrary,
                pageResourcePath = route.resourcePath,
                pageResourceBytes = checkNotNull(entryBytes),
                entryToken = selectedPage.entryToken,
                encodedHandle = selectedPage.encodedHandle,
                pageIndex = selectedPage.pageIndex,
                callSiteProof = rawProof,
            )

            val authenticated = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-good"),
                expectedOutcome = "result:2",
                label = "jni-executed",
            )
            assertEquals(0, authenticated.exitCode, "real JNI authenticated complete VBC4 page must execute:\n${authenticated.output}")
            assertTrue(
                authenticated.output.contains("AKEN real JNI current page fixture: PASS:executed"),
                authenticated.output,
            )
            assertFalse(authenticated.output.contains("WARNING in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("FATAL ERROR in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("JNI DETECTED ERROR IN APPLICATION"), authenticated.output)
            val benchmarkWarmup = System.getenv("JS_AKEN_PAGE_OPEN_BENCH_WARMUP")
                ?.toIntOrNull()
                ?.takeIf { it in 0..100_000 }
                ?: 16
            val benchmarkTimeoutSeconds = pageOpenBenchmarkTimeoutSeconds()

            /* The benchmark executes the same production-bound page through
             * the real JNI bridge after the one-shot semantic assertion above.
             * Samples are configurable for the required 100/1,000/10,000/
             * 100,000 profiles while the default test remains bounded. */
            pageOpenBenchmarkProfiles().forEach { benchmarkSamples ->
                val benchmark = runAkenJniRuntimeFixture(
                    runtimeRoot = runtimeRoot,
                    extractDirectory = tempDir.resolve("extract-benchmark-$benchmarkSamples"),
                    expectedOutcome = "bench:$benchmarkSamples:$benchmarkWarmup",
                    label = "jni-page-open-benchmark-$benchmarkSamples",
                    timeoutSeconds = benchmarkTimeoutSeconds,
                )
                assertEquals(0, benchmark.exitCode, "production AKEN page-open benchmark must pass:\n${benchmark.output}")
                val benchmarkLine = requireSingleAkenPhaseLine(
                    result = benchmark,
                    label = "production AKEN page-open benchmark",
                )
                /* The phase line contains only latency, counter deltas, and the
                 * deterministic result digest.  Persist it in the JUnit XML so
                 * a benchmark run remains auditable without exposing fixture
                 * plaintext, handles, proofs, routes, or temp paths. */
                /* Use the Java stdout stream explicitly so Gradle's JUnit
                 * report captures one sanitized phase line for every profile
                 * even when the fixture subprocess itself is long-running. */
                System.out.println(benchmarkLine)
                System.out.flush()
                val benchmarkFields = benchmarkLine.split(' ')
                    .mapNotNull { token ->
                        val separator = token.indexOf('=')
                        if (separator <= 0 || separator == token.lastIndex) null
                        else token.substring(0, separator) to token.substring(separator + 1)
                    }
                    .toMap()
                assertEquals("production", benchmarkFields["phase_mode"], benchmark.output)
                assertEquals("pass", benchmarkFields["phase_status"], benchmark.output)
                assertEquals(benchmarkSamples.toString(), benchmarkFields["samples"], benchmark.output)
                assertEquals(benchmarkWarmup.toString(), benchmarkFields["warmup"], benchmark.output)
                listOf("p50", "p95", "p99", "max").forEach { field ->
                    assertTrue(benchmarkFields[field]?.toLongOrNull()?.let { it >= 0L } == true, benchmark.output)
                }
                listOf(
                    "auth_check_count",
                    "digest_check_count",
                    "tag_check_count",
                    "length_check_count",
                    "structure_check_count",
                    "jni_abi_check_count",
                    "wipe_count",
                ).forEach { field ->
                    assertTrue(benchmarkFields[field]?.toLongOrNull()?.let { it > 0L } == true, benchmark.output)
                }
                listOf(
                    "auth_failure_count",
                    "wipe_failure_count",
                    "plaintext_persistence_bytes",
                    "fallback_count",
                    "legacy_path_hits",
                    "exception_count",
                    "security_checks_skipped",
                ).forEach { field ->
                    assertEquals("0", benchmarkFields[field], benchmark.output)
                }
                assertTrue(benchmarkFields["output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true, benchmark.output)
            }

            tamperedEntryBytes = checkNotNull(entryBytes).copyOf()
            val tamperOffset = route.resourceOffset + (route.storedLength / 2)
            require(tamperOffset in tamperedEntryBytes.indices) { "real JNI tamper offset is outside the current page entry" }
            tamperedEntryBytes[tamperOffset] = (tamperedEntryBytes[tamperOffset].toInt() xor 0x5A).toByte()
            writeClasspathResource(runtimeRoot, route.resourcePath, tamperedEntryBytes)

            val tampered = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-tampered"),
                expectedOutcome = "error:AKEN VM page authentication failed",
                label = "jni-tampered",
            )
            assertEquals(0, tampered.exitCode, "real JNI tampered current-page route must fail closed at authentication:\n${tampered.output}")
            assertTrue(
                tampered.output.contains("AKEN real JNI current page fixture: PASS:tampered"),
                tampered.output,
            )
            assertFalse(tampered.output.contains("WARNING in native method"), tampered.output)
            assertFalse(tampered.output.contains("FATAL ERROR in native method"), tampered.output)
            assertFalse(tampered.output.contains("JNI DETECTED ERROR IN APPLICATION"), tampered.output)

            buildContext.wipe()
            assertTrue(finalized.isWiped)
        } finally {
            try {
                assertContentEquals(
                    originalInclude,
                    Files.readAllBytes(sourceInclude),
                    "the repository's default empty locator include must remain untouched",
                )
            } finally {
                compilerRecord?.let { Arrays.fill(it, 0) }
                currentPage?.wipe()
                entryBytes?.let { Arrays.fill(it, 0) }
                generatedIncludeBytes?.let { Arrays.fill(it, 0) }
                tamperedEntryBytes?.let { Arrays.fill(it, 0) }
                plaintext?.let { Arrays.fill(it, 0) }
                layout?.wipe()
                context?.wipe()
                Arrays.fill(originalInclude, 0)
                Arrays.fill(identity, 0)
                Arrays.fill(rawProof, 0)
                pendingPage?.wipe()
                deleteTree(tempDir)
            }
        }
    }

    @Test
    fun typed_string_page_decodes_through_real_jni_and_fails_closed_on_locator_envelope_proof_and_payload_tampering() {
        val zig = findZig()
        val platform = currentAkenHostPlatform()
        assumeTrue(zig != null, "Zig is required to compile the real AKEN typed string-page fixture")
        assumeTrue(platform != null, "The real AKEN typed string-page fixture supports release-gate host platforms only")

        val sourceNativeDir = resolveSource("src/main/native/js_jni_runtime.c").parent
        val sourceInclude = sourceNativeDir.resolve("js_aken_page_locator.inc")
        val originalInclude = Files.readAllBytes(sourceInclude)
        val artifactCommitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (index * 19 + 23).toByte() }
        val logicalIdentity = "fixture:aken-real-jni-string-page".encodeToByteArray()
        val plaintextText = "AKEN-v4-typed-StringPage-cache-wrapper-fixture".padEnd(383, 'x')
        val plaintext = plaintextText.encodeToByteArray()
        val rawProof = ByteArray(73) { index -> ((index * 17 + 11) and 0xFF).toByte() }
        val pageResourcePath = "META-INF/.aken/string/real-jni-page.bin"
        val logicalBindingPath = "strings/fixture/real-jni-page"
        val tempDir = Files.createTempDirectory("javashroud-aken-real-jni-string-page-")
        var plan: AkenBuildPlan? = null
        var materialization: AkenPageMaterialization? = null
        var compileInput: AkenNativePageLocatorCompileInput? = null
        var compilerRecord: ByteArray? = null
        var currentPage: ProductionCurrentPage? = null
        var encodedHandle: ByteArray? = null
        var descriptorHandle: AkenHandle? = null
        var encodedPayload: ByteArray? = null
        var tamperedPayload: ByteArray? = null
        var invalidProof: ByteArray? = null
        var nativeEnvelope: ByteArray? = null
        var descriptorEncoding: ByteArray? = null
        var routeEncoding: ByteArray? = null
        var pageBindingDigest: ByteArray? = null
        var tamperedEnvelope: ByteArray? = null
        var tamperedEnvelopeRecord: ByteArray? = null
        var tamperedRecord: ByteArray? = null
        try {
            val buildPlan = AkenBuildPlan.create(artifactCommitment, SecureRandom())
            plan = buildPlan
            val page = buildPlan.registerPage(
                kind = AkenResourceKind.StringPage,
                identity = logicalIdentity,
                pageIndex = 3,
                targetPageSize = 384,
            )
            val materializationInput = AkenPageMaterializationInput.create(
                page = page,
                plaintext = plaintext,
                resourcePath = pageResourcePath,
                resourceOffset = 0,
                callSiteProof = rawProof,
                logicalBindingPath = logicalBindingPath,
            )
            val generatedMaterialization = AkenPageMaterializer.materializeAndWipe(
                plan = buildPlan,
                inputs = listOf(materializationInput),
            )
            materialization = generatedMaterialization
            plan = null

            val generatedPage = generatedMaterialization.pagesForBuild().single()
            val descriptor = generatedPage.descriptorForBuild
            assertEquals(AkenResourceKind.StringPage, descriptor.resourceKind)
            assertEquals(3, descriptor.pageIndex)
            assertEquals(pageResourcePath, descriptor.route.resourcePath)
            assertEquals(0, descriptor.route.resourceOffset)
            encodedPayload = generatedPage.copyEncodedPayloadForBuild()
            assertEquals(descriptor.route.storedLength, checkNotNull(encodedPayload).size)

            compileInput = AkenNativePageLocatorCompileInput.fromTypedPage(
                descriptor = descriptor,
                rawCallSiteProof = rawProof,
            )
            compilerRecord = checkNotNull(compileInput).copyNativeLocatorRecordForCompiler()
            nativeEnvelope = checkNotNull(compileInput).copyNativeEnvelopeForCompiler()
            descriptorEncoding = checkNotNull(compileInput).copyResolvedDescriptorForCompiler()
            routeEncoding = checkNotNull(compileInput).copyRouteEncodingForCompiler()
            pageBindingDigest = checkNotNull(compileInput).copyPageBindingDigestForCompiler()
            currentPage = parseProductionCurrentPage(checkNotNull(compilerRecord))
            assertEquals(AkenResourceKind.StringPage, checkNotNull(currentPage).resourceKind)
            assertEquals(descriptor.pageIndex, checkNotNull(currentPage).pageIndex)
            descriptorHandle = descriptor.handle
            encodedHandle = checkNotNull(descriptorHandle).encoded
            assertEquals(
                AkenTypedPageEntryToken.derive(
                    resourceKind = AkenResourceKind.StringPage,
                    pageIndex = descriptor.pageIndex,
                    encodedHandle = checkNotNull(encodedHandle),
                ),
                checkNotNull(currentPage).entryToken,
                "the generic compiler record must use the exact token derived by the native typed string bridge",
            )

            val include = renderInclude(listOf(checkNotNull(compilerRecord)))
            val nativeLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir.resolve("native-good"),
                sourceNativeDir = sourceNativeDir,
                include = include,
                platform = checkNotNull(platform),
            )
            val runtimeRoot = prepareAkenStringJniRuntimeFixture(
                root = tempDir.resolve("runtime-good"),
                platform = platform,
                nativeLibrary = nativeLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = rawProof,
            )
            val authenticated = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-good"),
                expectedOutcome = "result:$plaintextText",
                label = "jni-string-decoded",
            )
            assertEquals(0, authenticated.exitCode, "real JNI AKEN string page must decode:\n${authenticated.output}")
            assertTrue(authenticated.output.contains("AKEN real JNI string page fixture: PASS:decoded"), authenticated.output)
            assertFalse(authenticated.output.contains("WARNING in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("FATAL ERROR in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("JNI DETECTED ERROR IN APPLICATION"), authenticated.output)

            val repeatedOpen = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-repeated-open"),
                expectedOutcome = "string:$plaintextText",
                label = "jni-string-terminal-repeated-open",
            )
            assertEquals(0, repeatedOpen.exitCode, "AKEN String terminal must reopen through the authenticated JNI route:\n${repeatedOpen.output}")
            assertTrue(repeatedOpen.output.contains("AKEN real JNI string page fixture: PASS:reopened"), repeatedOpen.output)
            assertFalse(repeatedOpen.output.contains("WARNING in native method"), repeatedOpen.output)
            assertFalse(repeatedOpen.output.contains("FATAL ERROR in native method"), repeatedOpen.output)
            assertFalse(repeatedOpen.output.contains("JNI DETECTED ERROR IN APPLICATION"), repeatedOpen.output)

            tamperedPayload = checkNotNull(encodedPayload).copyOf()
            val payloadTamperOffset = tamperedPayload.lastIndex / 2
            tamperedPayload[payloadTamperOffset] = (tamperedPayload[payloadTamperOffset].toInt() xor 0x5A).toByte()
            writeClasspathResource(runtimeRoot, descriptor.route.resourcePath, tamperedPayload)
            val payloadFailure = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-payload-tampered"),
                expectedOutcome = "error:AKEN string page authentication failed",
                label = "jni-string-payload-tampered",
            )
            assertEquals(0, payloadFailure.exitCode, "tampered AKEN string ciphertext must fail closed:\n${payloadFailure.output}")
            assertTrue(payloadFailure.output.contains("AKEN real JNI string page fixture: PASS:tampered"), payloadFailure.output)

            invalidProof = rawProof.copyOf()
            invalidProof[invalidProof.lastIndex] = (invalidProof[invalidProof.lastIndex].toInt() xor 0x35).toByte()
            val proofRuntimeRoot = prepareAkenStringJniRuntimeFixture(
                root = tempDir.resolve("runtime-proof-tampered"),
                platform = platform,
                nativeLibrary = nativeLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = invalidProof,
            )
            val proofFailure = runAkenJniRuntimeFixture(
                runtimeRoot = proofRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-proof-tampered"),
                expectedOutcome = "error:AKEN string page route is invalid",
                label = "jni-string-proof-tampered",
            )
            assertEquals(0, proofFailure.exitCode, "tampered AKEN string proof must fail closed:\n${proofFailure.output}")
            assertTrue(proofFailure.output.contains("AKEN real JNI string page fixture: PASS:tampered"), proofFailure.output)

            tamperedEnvelope = checkNotNull(nativeEnvelope).copyOf()
            tamperedEnvelope[tamperedEnvelope.lastIndex] = (tamperedEnvelope[tamperedEnvelope.lastIndex].toInt() xor 0x6B).toByte()
            tamperedEnvelopeRecord = encodeCompilerRecord(
                entryToken = checkNotNull(currentPage).entryToken,
                resourceKind = AkenResourceKind.StringPage,
                pageIndex = descriptor.pageIndex,
                encodedHandle = checkNotNull(encodedHandle),
                nativeEnvelope = tamperedEnvelope,
                descriptor = checkNotNull(descriptorEncoding),
                route = checkNotNull(routeEncoding),
                vbc4StateBindingLayoutDigest = checkNotNull(pageBindingDigest),
            )
            val envelopeTamperedLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir.resolve("native-envelope-tampered"),
                sourceNativeDir = sourceNativeDir,
                include = renderInclude(listOf(checkNotNull(tamperedEnvelopeRecord))),
                platform = platform,
            )
            val envelopeRuntimeRoot = prepareAkenStringJniRuntimeFixture(
                root = tempDir.resolve("runtime-envelope-tampered"),
                platform = platform,
                nativeLibrary = envelopeTamperedLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = rawProof,
            )
            val envelopeFailure = runAkenJniRuntimeFixture(
                runtimeRoot = envelopeRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-envelope-tampered"),
                expectedOutcome = "error:AKEN string page route is invalid",
                label = "jni-string-envelope-tampered",
            )
            assertEquals(0, envelopeFailure.exitCode, "tampered AKEN string envelope must fail closed:\n${envelopeFailure.output}")
            assertTrue(envelopeFailure.output.contains("AKEN real JNI string page fixture: PASS:tampered"), envelopeFailure.output)

            tamperedRecord = checkNotNull(compilerRecord).copyOf()
            tamperedRecord[tamperedRecord.lastIndex] = (tamperedRecord[tamperedRecord.lastIndex].toInt() xor 0x44).toByte()
            val locatorTamperedLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir.resolve("native-locator-tampered"),
                sourceNativeDir = sourceNativeDir,
                include = renderInclude(listOf(tamperedRecord)),
                platform = platform,
            )
            val locatorRuntimeRoot = prepareAkenStringJniRuntimeFixture(
                root = tempDir.resolve("runtime-locator-tampered"),
                platform = platform,
                nativeLibrary = locatorTamperedLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = rawProof,
            )
            val locatorFailure = runAkenJniRuntimeFixture(
                runtimeRoot = locatorRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-locator-tampered"),
                expectedOutcome = "error:AKEN string page route is unavailable",
                label = "jni-string-locator-tampered",
            )
            assertEquals(0, locatorFailure.exitCode, "tampered AKEN string locator binding must fail closed:\n${locatorFailure.output}")
            assertTrue(locatorFailure.output.contains("AKEN real JNI string page fixture: PASS:tampered"), locatorFailure.output)
        } finally {
            try {
                assertContentEquals(
                    originalInclude,
                    Files.readAllBytes(sourceInclude),
                    "the repository's default empty locator include must remain untouched",
                )
            } finally {
                compilerRecord?.let { Arrays.fill(it, 0) }
                currentPage?.wipe()
                encodedHandle?.let { Arrays.fill(it, 0) }
                encodedPayload?.let { Arrays.fill(it, 0) }
                tamperedPayload?.let { Arrays.fill(it, 0) }
                invalidProof?.let { Arrays.fill(it, 0) }
                nativeEnvelope?.let { Arrays.fill(it, 0) }
                descriptorEncoding?.let { Arrays.fill(it, 0) }
                routeEncoding?.let { Arrays.fill(it, 0) }
                pageBindingDigest?.let { Arrays.fill(it, 0) }
                tamperedEnvelope?.let { Arrays.fill(it, 0) }
                tamperedEnvelopeRecord?.let { Arrays.fill(it, 0) }
                tamperedRecord?.let { Arrays.fill(it, 0) }
                descriptorHandle?.wipe()
                compileInput?.wipe()
                materialization?.wipe()
                plan?.wipe()
                Arrays.fill(originalInclude, 0)
                Arrays.fill(artifactCommitment, 0)
                Arrays.fill(logicalIdentity, 0)
                Arrays.fill(plaintext, 0)
                Arrays.fill(rawProof, 0)
                deleteTree(tempDir)
            }
        }
    }

    @Test
    fun typed_class_page_reads_through_real_jni_and_fails_closed_on_locator_envelope_proof_and_payload_tampering() {
        val zig = findZig()
        val platform = currentAkenHostPlatform()
        assumeTrue(zig != null, "Zig is required to compile the real AKEN typed class-page fixture")
        assumeTrue(platform != null, "The real AKEN typed class-page fixture supports release-gate host platforms only")

        val sourceNativeDir = resolveSource("src/main/native/js_jni_runtime.c").parent
        val sourceInclude = sourceNativeDir.resolve("js_aken_page_locator.inc")
        val originalInclude = Files.readAllBytes(sourceInclude)
        val artifactCommitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (index * 19 + 23).toByte() }
        val logicalIdentity = "fixture:aken-real-jni-class-page".encodeToByteArray()
        val plaintext = ByteArray(511) { index -> ((index * 29 + 7) and 0xFF).toByte() }
        val rawProof = ByteArray(73) { index -> ((index * 17 + 11) and 0xFF).toByte() }
        val pageResourcePath = "META-INF/.aken/class/real-jni-page.bin"
        val logicalBindingPath = "classes/fixture/real-jni-page"
        val tempDir = Files.createTempDirectory("javashroud-aken-real-jni-class-page-")
        var plan: AkenBuildPlan? = null
        var materialization: AkenPageMaterialization? = null
        var compileInput: AkenNativePageLocatorCompileInput? = null
        var compilerRecord: ByteArray? = null
        var currentPage: ProductionCurrentPage? = null
        var encodedHandle: ByteArray? = null
        var descriptorHandle: AkenHandle? = null
        var encodedPayload: ByteArray? = null
        var tamperedPayload: ByteArray? = null
        var invalidProof: ByteArray? = null
        var nativeEnvelope: ByteArray? = null
        var descriptorEncoding: ByteArray? = null
        var routeEncoding: ByteArray? = null
        var pageBindingDigest: ByteArray? = null
        var tamperedEnvelope: ByteArray? = null
        var tamperedEnvelopeRecord: ByteArray? = null
        var tamperedRecord: ByteArray? = null
        try {
            val buildPlan = AkenBuildPlan.create(artifactCommitment, SecureRandom())
            plan = buildPlan
            val page = buildPlan.registerPage(
                kind = AkenResourceKind.EncryptedClassPage,
                identity = logicalIdentity,
                pageIndex = 5,
                targetPageSize = 512,
            )
            val materializationInput = AkenPageMaterializationInput.create(
                page = page,
                plaintext = plaintext,
                resourcePath = pageResourcePath,
                resourceOffset = 0,
                callSiteProof = rawProof,
                logicalBindingPath = logicalBindingPath,
            )
            val generatedMaterialization = AkenPageMaterializer.materializeAndWipe(
                plan = buildPlan,
                inputs = listOf(materializationInput),
            )
            materialization = generatedMaterialization
            plan = null

            val generatedPage = generatedMaterialization.pagesForBuild().single()
            val descriptor = generatedPage.descriptorForBuild
            assertEquals(AkenResourceKind.EncryptedClassPage, descriptor.resourceKind)
            assertEquals(5, descriptor.pageIndex)
            assertEquals(pageResourcePath, descriptor.route.resourcePath)
            assertEquals(0, descriptor.route.resourceOffset)
            encodedPayload = generatedPage.copyEncodedPayloadForBuild()
            assertEquals(descriptor.route.storedLength, checkNotNull(encodedPayload).size)

            compileInput = AkenNativePageLocatorCompileInput.fromTypedPage(
                descriptor = descriptor,
                rawCallSiteProof = rawProof,
            )
            compilerRecord = checkNotNull(compileInput).copyNativeLocatorRecordForCompiler()
            nativeEnvelope = checkNotNull(compileInput).copyNativeEnvelopeForCompiler()
            descriptorEncoding = checkNotNull(compileInput).copyResolvedDescriptorForCompiler()
            routeEncoding = checkNotNull(compileInput).copyRouteEncodingForCompiler()
            pageBindingDigest = checkNotNull(compileInput).copyPageBindingDigestForCompiler()
            currentPage = parseProductionCurrentPage(checkNotNull(compilerRecord))
            assertEquals(AkenResourceKind.EncryptedClassPage, checkNotNull(currentPage).resourceKind)
            assertEquals(descriptor.pageIndex, checkNotNull(currentPage).pageIndex)
            descriptorHandle = descriptor.handle
            encodedHandle = checkNotNull(descriptorHandle).encoded
            assertEquals(
                AkenTypedPageEntryToken.derive(
                    resourceKind = AkenResourceKind.EncryptedClassPage,
                    pageIndex = descriptor.pageIndex,
                    encodedHandle = checkNotNull(encodedHandle),
                ),
                checkNotNull(currentPage).entryToken,
                "the generic compiler record must use the exact token derived by the native typed class bridge",
            )

            val include = renderInclude(listOf(checkNotNull(compilerRecord)))
            val nativeLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir.resolve("native-good"),
                sourceNativeDir = sourceNativeDir,
                include = include,
                platform = checkNotNull(platform),
            )
            val runtimeRoot = prepareAkenClassJniRuntimeFixture(
                root = tempDir.resolve("runtime-good"),
                platform = platform,
                nativeLibrary = nativeLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = rawProof,
            )
            val authenticated = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-good"),
                expectedOutcome = "result:${hexLower(plaintext)}",
                label = "jni-class-read",
            )
            assertEquals(0, authenticated.exitCode, "real JNI AKEN class page must read:\n${authenticated.output}")
            assertTrue(authenticated.output.contains("AKEN real JNI class page fixture: PASS:read"), authenticated.output)
            assertFalse(authenticated.output.contains("WARNING in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("FATAL ERROR in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("JNI DETECTED ERROR IN APPLICATION"), authenticated.output)

            tamperedPayload = checkNotNull(encodedPayload).copyOf()
            val payloadTamperOffset = tamperedPayload.lastIndex / 2
            tamperedPayload[payloadTamperOffset] = (tamperedPayload[payloadTamperOffset].toInt() xor 0x5A).toByte()
            writeClasspathResource(runtimeRoot, descriptor.route.resourcePath, tamperedPayload)
            val payloadFailure = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-payload-tampered"),
                expectedOutcome = "error:AKEN class page authentication failed",
                label = "jni-class-payload-tampered",
            )
            assertEquals(0, payloadFailure.exitCode, "tampered AKEN class ciphertext must fail closed:\n${payloadFailure.output}")
            assertTrue(payloadFailure.output.contains("AKEN real JNI class page fixture: PASS:tampered"), payloadFailure.output)

            invalidProof = rawProof.copyOf()
            invalidProof[invalidProof.lastIndex] = (invalidProof[invalidProof.lastIndex].toInt() xor 0x35).toByte()
            val proofRuntimeRoot = prepareAkenClassJniRuntimeFixture(
                root = tempDir.resolve("runtime-proof-tampered"),
                platform = platform,
                nativeLibrary = nativeLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = invalidProof,
            )
            val proofFailure = runAkenJniRuntimeFixture(
                runtimeRoot = proofRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-proof-tampered"),
                expectedOutcome = "error:AKEN class page route is invalid",
                label = "jni-class-proof-tampered",
            )
            assertEquals(0, proofFailure.exitCode, "tampered AKEN class proof must fail closed:\n${proofFailure.output}")
            assertTrue(proofFailure.output.contains("AKEN real JNI class page fixture: PASS:tampered"), proofFailure.output)

            tamperedEnvelope = checkNotNull(nativeEnvelope).copyOf()
            tamperedEnvelope[tamperedEnvelope.lastIndex] = (tamperedEnvelope[tamperedEnvelope.lastIndex].toInt() xor 0x6B).toByte()
            tamperedEnvelopeRecord = encodeCompilerRecord(
                entryToken = checkNotNull(currentPage).entryToken,
                resourceKind = AkenResourceKind.EncryptedClassPage,
                pageIndex = descriptor.pageIndex,
                encodedHandle = checkNotNull(encodedHandle),
                nativeEnvelope = tamperedEnvelope,
                descriptor = checkNotNull(descriptorEncoding),
                route = checkNotNull(routeEncoding),
                vbc4StateBindingLayoutDigest = checkNotNull(pageBindingDigest),
            )
            val envelopeTamperedLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir.resolve("native-envelope-tampered"),
                sourceNativeDir = sourceNativeDir,
                include = renderInclude(listOf(checkNotNull(tamperedEnvelopeRecord))),
                platform = platform,
            )
            val envelopeRuntimeRoot = prepareAkenClassJniRuntimeFixture(
                root = tempDir.resolve("runtime-envelope-tampered"),
                platform = platform,
                nativeLibrary = envelopeTamperedLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = rawProof,
            )
            val envelopeFailure = runAkenJniRuntimeFixture(
                runtimeRoot = envelopeRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-envelope-tampered"),
                expectedOutcome = "error:AKEN class page route is invalid",
                label = "jni-class-envelope-tampered",
            )
            assertEquals(0, envelopeFailure.exitCode, "tampered AKEN class envelope must fail closed:\n${envelopeFailure.output}")
            assertTrue(envelopeFailure.output.contains("AKEN real JNI class page fixture: PASS:tampered"), envelopeFailure.output)

            tamperedRecord = checkNotNull(compilerRecord).copyOf()
            tamperedRecord[tamperedRecord.lastIndex] = (tamperedRecord[tamperedRecord.lastIndex].toInt() xor 0x44).toByte()
            val locatorTamperedLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir.resolve("native-locator-tampered"),
                sourceNativeDir = sourceNativeDir,
                include = renderInclude(listOf(tamperedRecord)),
                platform = platform,
            )
            val locatorRuntimeRoot = prepareAkenClassJniRuntimeFixture(
                root = tempDir.resolve("runtime-locator-tampered"),
                platform = platform,
                nativeLibrary = locatorTamperedLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = rawProof,
            )
            val locatorFailure = runAkenJniRuntimeFixture(
                runtimeRoot = locatorRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-locator-tampered"),
                expectedOutcome = "error:AKEN class page route is unavailable",
                label = "jni-class-locator-tampered",
            )
            assertEquals(0, locatorFailure.exitCode, "tampered AKEN class locator binding must fail closed:\n${locatorFailure.output}")
            assertTrue(locatorFailure.output.contains("AKEN real JNI class page fixture: PASS:tampered"), locatorFailure.output)
        } finally {
            try {
                assertContentEquals(
                    originalInclude,
                    Files.readAllBytes(sourceInclude),
                    "the repository's default empty locator include must remain untouched",
                )
            } finally {
                compilerRecord?.let { Arrays.fill(it, 0) }
                currentPage?.wipe()
                encodedHandle?.let { Arrays.fill(it, 0) }
                encodedPayload?.let { Arrays.fill(it, 0) }
                tamperedPayload?.let { Arrays.fill(it, 0) }
                invalidProof?.let { Arrays.fill(it, 0) }
                nativeEnvelope?.let { Arrays.fill(it, 0) }
                descriptorEncoding?.let { Arrays.fill(it, 0) }
                routeEncoding?.let { Arrays.fill(it, 0) }
                pageBindingDigest?.let { Arrays.fill(it, 0) }
                tamperedEnvelope?.let { Arrays.fill(it, 0) }
                tamperedEnvelopeRecord?.let { Arrays.fill(it, 0) }
                tamperedRecord?.let { Arrays.fill(it, 0) }
                descriptorHandle?.wipe()
                compileInput?.wipe()
                materialization?.wipe()
                plan?.wipe()
                Arrays.fill(originalInclude, 0)
                Arrays.fill(artifactCommitment, 0)
                Arrays.fill(logicalIdentity, 0)
                Arrays.fill(plaintext, 0)
                Arrays.fill(rawProof, 0)
                deleteTree(tempDir)
            }
        }
    }

    @Test
    fun typed_native_chunk_is_consumed_natively_through_real_jni_and_fails_closed_on_locator_envelope_proof_and_payload_tampering() {
        val zig = findZig()
        val platform = currentAkenHostPlatform()
        assumeTrue(zig != null, "Zig is required to compile the real AKEN typed native-chunk fixture")
        assumeTrue(platform != null, "The real AKEN typed native-chunk fixture supports release-gate host platforms only")

        val sourceNativeDir = resolveSource("src/main/native/js_jni_runtime.c").parent
        val sourceInclude = sourceNativeDir.resolve("js_aken_page_locator.inc")
        val originalInclude = Files.readAllBytes(sourceInclude)
        val artifactCommitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (index * 37 + 29).toByte() }
        val logicalIdentity = ByteArray(AkenNativeChunkHandlerDescriptor.IDENTITY_SIZE) { index -> (index * 41 + 5).toByte() }
        val rawProof = ByteArray(AkenNativeChunkHandlerDescriptor.CALL_SITE_PROOF_SIZE) { index -> (index * 23 + 3).toByte() }
        val preassignedHandle = ByteArray(AkenHandle.ENCODED_HANDLE_SIZE) { index -> (index * 29 + 7).toByte() }
        val descriptorNonce = ByteArray(AkenNativeChunkHandlerDescriptor.NONCE_SIZE) { index -> (index * 17 + 11).toByte() }
        val plaintext = AkenNativeChunkHandlerDescriptor.createLoaderAttestation(
            logicalIdentity = logicalIdentity,
            encodedHandle = preassignedHandle,
            callSiteProof = rawProof,
            nonce = descriptorNonce,
        )
        val pageResourcePath = "META-INF/.aken/native/real-jni-chunk.bin"
        val logicalBindingPath = "native/fixture/real-jni-chunk"
        val tempDir = Files.createTempDirectory("javashroud-aken-real-jni-native-chunk-")
        var plan: AkenBuildPlan? = null
        var materialization: AkenPageMaterialization? = null
        var compileInput: AkenNativePageLocatorCompileInput? = null
        var compilerRecord: ByteArray? = null
        var currentPage: ProductionCurrentPage? = null
        var encodedHandle: ByteArray? = null
        var descriptorHandle: AkenHandle? = null
        var encodedPayload: ByteArray? = null
        var tamperedPayload: ByteArray? = null
        var invalidProof: ByteArray? = null
        var nativeEnvelope: ByteArray? = null
        var descriptorEncoding: ByteArray? = null
        var routeEncoding: ByteArray? = null
        var pageBindingDigest: ByteArray? = null
        var tamperedEnvelope: ByteArray? = null
        var tamperedEnvelopeRecord: ByteArray? = null
        var tamperedRecord: ByteArray? = null
        try {
            val buildPlan = AkenBuildPlan.create(artifactCommitment, SecureRandom())
            plan = buildPlan
            val page = buildPlan.registerPage(
                kind = AkenResourceKind.NativeChunk,
                identity = logicalIdentity,
                pageIndex = 7,
                targetPageSize = 1024,
                encodedHandleOverride = preassignedHandle,
            )
            val materializationInput = AkenPageMaterializationInput.create(
                page = page,
                plaintext = plaintext,
                resourcePath = pageResourcePath,
                resourceOffset = 0,
                callSiteProof = rawProof,
                logicalBindingPath = logicalBindingPath,
            )
            val generatedMaterialization = AkenPageMaterializer.materializeAndWipe(
                plan = buildPlan,
                inputs = listOf(materializationInput),
            )
            materialization = generatedMaterialization
            plan = null

            val generatedPage = generatedMaterialization.pagesForBuild().single()
            val descriptor = generatedPage.descriptorForBuild
            assertEquals(AkenResourceKind.NativeChunk, descriptor.resourceKind)
            assertEquals(7, descriptor.pageIndex)
            assertEquals(pageResourcePath, descriptor.route.resourcePath)
            assertEquals(0, descriptor.route.resourceOffset)
            encodedPayload = generatedPage.copyEncodedPayloadForBuild()
            assertEquals(descriptor.route.storedLength, checkNotNull(encodedPayload).size)

            compileInput = AkenNativePageLocatorCompileInput.fromTypedPage(
                descriptor = descriptor,
                rawCallSiteProof = rawProof,
            )
            compilerRecord = checkNotNull(compileInput).copyNativeLocatorRecordForCompiler()
            nativeEnvelope = checkNotNull(compileInput).copyNativeEnvelopeForCompiler()
            descriptorEncoding = checkNotNull(compileInput).copyResolvedDescriptorForCompiler()
            routeEncoding = checkNotNull(compileInput).copyRouteEncodingForCompiler()
            pageBindingDigest = checkNotNull(compileInput).copyPageBindingDigestForCompiler()
            currentPage = parseProductionCurrentPage(checkNotNull(compilerRecord))
            assertEquals(AkenResourceKind.NativeChunk, checkNotNull(currentPage).resourceKind)
            assertEquals(descriptor.pageIndex, checkNotNull(currentPage).pageIndex)
            descriptorHandle = descriptor.handle
            encodedHandle = checkNotNull(descriptorHandle).encoded
            assertContentEquals(preassignedHandle, checkNotNull(encodedHandle))
            assertTrue(
                AkenNativeChunkHandlerDescriptor.isLoaderAttestationForBuild(
                    encoded = plaintext,
                    logicalIdentity = logicalIdentity,
                    encodedHandle = checkNotNull(encodedHandle),
                    callSiteProof = rawProof,
                ),
            )
            assertEquals(
                AkenTypedPageEntryToken.derive(
                    resourceKind = AkenResourceKind.NativeChunk,
                    pageIndex = descriptor.pageIndex,
                    encodedHandle = checkNotNull(encodedHandle),
                ),
                checkNotNull(currentPage).entryToken,
                "the generic compiler record must use the exact token derived by the native typed chunk bridge",
            )

            val include = renderInclude(listOf(checkNotNull(compilerRecord)))
            val nativeLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir.resolve("native-good"),
                sourceNativeDir = sourceNativeDir,
                include = include,
                platform = checkNotNull(platform),
            )
            val runtimeRoot = prepareAkenNativeChunkJniRuntimeFixture(
                root = tempDir.resolve("runtime-good"),
                platform = platform,
                nativeLibrary = nativeLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = rawProof,
            )
            val authenticated = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-good"),
                expectedOutcome = "consume",
                label = "jni-native-chunk-consumed",
            )
            assertEquals(0, authenticated.exitCode, "real JNI AKEN native chunk must consume:\n" + authenticated.output)
            assertTrue(authenticated.output.contains("AKEN real JNI native chunk fixture: PASS:consumed"), authenticated.output)
            assertFalse(authenticated.output.contains("WARNING in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("FATAL ERROR in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("JNI DETECTED ERROR IN APPLICATION"), authenticated.output)

            tamperedPayload = checkNotNull(encodedPayload).copyOf()
            val payloadTamperOffset = tamperedPayload.lastIndex / 2
            tamperedPayload[payloadTamperOffset] = (tamperedPayload[payloadTamperOffset].toInt() xor 0x5A).toByte()
            writeClasspathResource(runtimeRoot, descriptor.route.resourcePath, tamperedPayload)
            val payloadFailure = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-payload-tampered"),
                expectedOutcome = "error:AKEN native chunk authentication failed",
                label = "jni-native-chunk-payload-tampered",
            )
            assertEquals(0, payloadFailure.exitCode, "tampered AKEN native chunk ciphertext must fail closed:\n" + payloadFailure.output)
            assertTrue(payloadFailure.output.contains("AKEN real JNI native chunk fixture: PASS:tampered"), payloadFailure.output)

            invalidProof = rawProof.copyOf()
            invalidProof[invalidProof.lastIndex] = (invalidProof[invalidProof.lastIndex].toInt() xor 0x35).toByte()
            val proofRuntimeRoot = prepareAkenNativeChunkJniRuntimeFixture(
                root = tempDir.resolve("runtime-proof-tampered"),
                platform = platform,
                nativeLibrary = nativeLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = invalidProof,
            )
            val proofFailure = runAkenJniRuntimeFixture(
                runtimeRoot = proofRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-proof-tampered"),
                expectedOutcome = "error:AKEN native chunk route is invalid",
                label = "jni-native-chunk-proof-tampered",
            )
            assertEquals(0, proofFailure.exitCode, "tampered AKEN native chunk proof must fail closed:\n" + proofFailure.output)
            assertTrue(proofFailure.output.contains("AKEN real JNI native chunk fixture: PASS:tampered"), proofFailure.output)

            tamperedEnvelope = checkNotNull(nativeEnvelope).copyOf()
            tamperedEnvelope[tamperedEnvelope.lastIndex] = (tamperedEnvelope[tamperedEnvelope.lastIndex].toInt() xor 0x6B).toByte()
            tamperedEnvelopeRecord = encodeCompilerRecord(
                entryToken = checkNotNull(currentPage).entryToken,
                resourceKind = AkenResourceKind.NativeChunk,
                pageIndex = descriptor.pageIndex,
                encodedHandle = checkNotNull(encodedHandle),
                nativeEnvelope = tamperedEnvelope,
                descriptor = checkNotNull(descriptorEncoding),
                route = checkNotNull(routeEncoding),
                vbc4StateBindingLayoutDigest = checkNotNull(pageBindingDigest),
            )
            val envelopeTamperedLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir.resolve("native-envelope-tampered"),
                sourceNativeDir = sourceNativeDir,
                include = renderInclude(listOf(checkNotNull(tamperedEnvelopeRecord))),
                platform = platform,
            )
            val envelopeRuntimeRoot = prepareAkenNativeChunkJniRuntimeFixture(
                root = tempDir.resolve("runtime-envelope-tampered"),
                platform = platform,
                nativeLibrary = envelopeTamperedLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = rawProof,
            )
            val envelopeFailure = runAkenJniRuntimeFixture(
                runtimeRoot = envelopeRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-envelope-tampered"),
                expectedOutcome = "error:AKEN native chunk route is invalid",
                label = "jni-native-chunk-envelope-tampered",
            )
            assertEquals(0, envelopeFailure.exitCode, "tampered AKEN native chunk envelope must fail closed:\n" + envelopeFailure.output)
            assertTrue(envelopeFailure.output.contains("AKEN real JNI native chunk fixture: PASS:tampered"), envelopeFailure.output)

            tamperedRecord = checkNotNull(compilerRecord).copyOf()
            tamperedRecord[tamperedRecord.lastIndex] = (tamperedRecord[tamperedRecord.lastIndex].toInt() xor 0x44).toByte()
            val locatorTamperedLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir.resolve("native-locator-tampered"),
                sourceNativeDir = sourceNativeDir,
                include = renderInclude(listOf(tamperedRecord)),
                platform = platform,
            )
            val locatorRuntimeRoot = prepareAkenNativeChunkJniRuntimeFixture(
                root = tempDir.resolve("runtime-locator-tampered"),
                platform = platform,
                nativeLibrary = locatorTamperedLibrary,
                pageResourcePath = descriptor.route.resourcePath,
                pageResourceBytes = checkNotNull(encodedPayload),
                encodedHandle = checkNotNull(encodedHandle),
                pageIndex = descriptor.pageIndex,
                callSiteProof = rawProof,
            )
            val locatorFailure = runAkenJniRuntimeFixture(
                runtimeRoot = locatorRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-locator-tampered"),
                expectedOutcome = "error:AKEN native chunk route is unavailable",
                label = "jni-native-chunk-locator-tampered",
            )
            assertEquals(0, locatorFailure.exitCode, "tampered AKEN native chunk locator binding must fail closed:\n" + locatorFailure.output)
            assertTrue(locatorFailure.output.contains("AKEN real JNI native chunk fixture: PASS:tampered"), locatorFailure.output)
        } finally {
            try {
                assertContentEquals(
                    originalInclude,
                    Files.readAllBytes(sourceInclude),
                    "the repository's default empty locator include must remain untouched",
                )
            } finally {
                compilerRecord?.let { Arrays.fill(it, 0) }
                currentPage?.wipe()
                encodedHandle?.let { Arrays.fill(it, 0) }
                encodedPayload?.let { Arrays.fill(it, 0) }
                tamperedPayload?.let { Arrays.fill(it, 0) }
                invalidProof?.let { Arrays.fill(it, 0) }
                nativeEnvelope?.let { Arrays.fill(it, 0) }
                descriptorEncoding?.let { Arrays.fill(it, 0) }
                routeEncoding?.let { Arrays.fill(it, 0) }
                pageBindingDigest?.let { Arrays.fill(it, 0) }
                tamperedEnvelope?.let { Arrays.fill(it, 0) }
                tamperedEnvelopeRecord?.let { Arrays.fill(it, 0) }
                tamperedRecord?.let { Arrays.fill(it, 0) }
                descriptorHandle?.wipe()
                compileInput?.wipe()
                materialization?.wipe()
                plan?.wipe()
                Arrays.fill(originalInclude, 0)
                Arrays.fill(artifactCommitment, 0)
                Arrays.fill(logicalIdentity, 0)
                Arrays.fill(plaintext, 0)
                Arrays.fill(rawProof, 0)
                Arrays.fill(preassignedHandle, 0)
                Arrays.fill(descriptorNonce, 0)
                deleteTree(tempDir)
            }
        }
    }

    @Test
    fun production_multi_page_vbc4_assembles_executes_and_authenticates_through_real_jni() {
        val zig = findZig()
        val platform = currentAkenHostPlatform()
        assumeTrue(zig != null, "Zig is required to compile the real AKEN JNI multi-page fixture")
        assumeTrue(platform != null, "The real AKEN JNI multi-page fixture supports release-gate host platforms only")

        val sourceNativeDir = resolveSource("src/main/native/js_jni_runtime.c").parent
        val sourceInclude = sourceNativeDir.resolve("js_aken_page_locator.inc")
        val originalInclude = Files.readAllBytes(sourceInclude)
        val identity = ByteArray(32) { index -> (index * 19 + 7).toByte() }
        val pageZeroProof = akenVbc4PageProof(0)
        val entryToken = 0x414B_454E_0000_4001L
        val logicalBindingPath = "META-INF/vm/aken-real-jni-multi-page.vbc4"
        val containerPath = "META-INF/.aken/vbc4/real-jni-multi-page.bin"
        val tempDir = Files.createTempDirectory("javashroud-aken-real-jni-multi-page-")
        var context: Vbc4BuildContext? = null
        var layout: AkenVbc4FinalizationLayout? = null
        var compilerRecords: List<ByteArray>? = null
        var currentPages: List<ProductionCurrentPage>? = null
        var entryBytes: ByteArray? = null
        var generatedIncludeBytes: ByteArray? = null
        var tamperedEntryBytes: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            val buildContext = akenVbc4ExecutorContext()
            context = buildContext
            plaintext = withVbc4BuildContext(buildContext) {
                val serializer = VmBytecodeSerializer(
                    buildSeed = 0x1357_2468,
                    stateBinding = vmStateBinding(entryToken, logicalBindingPath),
                    entryMetadata = Vbc4EntryMetadata(
                        entryToken = entryToken,
                        returnDescriptor = "I",
                        methodIdentity = "33".repeat(32),
                        ownerIdentity = "44".repeat(32),
                        resourcePath = logicalBindingPath,
                        isStatic = true,
                    ),
                    buildContext = buildContext,
                    structureEntropy = ByteArray(32) { index -> (index * 23 + 5).toByte() },
                )
                val blocks = Array(32) { Label() }
                serializer.visitCode()
                blocks.forEachIndexed { blockIndex, label ->
                    serializer.visitLabel(label)
                    repeat(96) {
                        serializer.visitInsn(Opcodes.NOP)
                    }
                    if (blockIndex < blocks.lastIndex) {
                        serializer.visitJumpInsn(Opcodes.GOTO, blocks[blockIndex + 1])
                    } else {
                        serializer.visitInsn(Opcodes.ICONST_2)
                        serializer.visitInsn(Opcodes.IRETURN)
                    }
                }
                serializer.visitMaxs(1, 0)
                serializer.visitEnd()
                serializer.serialize()
            }

            val logicalMethod = AkenVbc4LogicalMethodIdentity.create(
                dispatchClassToken = "fixture/AkenCurrentPage",
                dispatchMethodToken = "dispatch",
                descriptor = "()I",
                logicalVmResourcePath = logicalBindingPath,
            )
            val candidate = AkenVbc4MethodCandidate.create(
                entryToken = entryToken,
                logicalMethod = logicalMethod,
                logicalIdentity = identity,
                serializedProgram = checkNotNull(plaintext),
            )
            val route = AkenVbc4PreSealRoute.create(
                entryToken = entryToken,
                logicalVmResourcePath = logicalBindingPath,
                futureContainerPath = containerPath,
            )
            try {
                val batch = AkenVbc4PendingPagePlanner.partitionAndWipe(
                    candidate = candidate,
                    route = route,
                    callSiteProofForPage = ::akenVbc4PageProof,
                    targetSizeForPage = { 512 },
                    random = SecureRandom(),
                )
                assertTrue(candidate.isWiped)
                val partitions = batch.partitionsForBuild()
                assertTrue(partitions.size >= 2, "real JNI multi-page fixture must produce at least two VBC4 pages")
                assertEquals(partitions.indices.toList(), partitions.map { it.pageIndex })

                batch.consumePendingPagesForBuild { pages ->
                    assertEquals(partitions.size, pages.size)
                    assertEquals(partitions.indices.toList(), pages.map { it.pageIndex })
                    assertEquals(List(pages.size) { containerPath }, pages.map { it.resourcePath })
                    assertEquals(List(pages.size) { logicalBindingPath }, pages.map { it.logicalBindingPath })

                    val commitment = AkenVbc4FinalizationLayout.reserve(
                        pendingPages = pages,
                        fixedEntries = emptyList(),
                    )
                    val planCommitment = commitment.copyBytes()
                    val plan = try {
                        buildContext.initializeAkenBuildPlan(planCommitment)
                    } finally {
                        Arrays.fill(planCommitment, 0)
                    }
                    val finalized = AkenVbc4FinalizationLayout.materializeAndWipe(
                        plan = plan,
                        commitment = commitment,
                        pendingPages = pages,
                        fixedEntries = emptyList(),
                        vbc4StateBindingLayoutDigest = AkenVbc4InnerMaterial.copyStateBindingLayoutDigest(context),
                    )
                    layout = finalized
                    buildContext.publishAkenVbc4FinalizationLayout(finalized)
                }
                assertTrue(batch.isWiped)
            } finally {
                candidate.wipe()
                route.wipe()
            }

            compilerRecords = buildContext.withAkenNativeLocatorRecordsForBuild { records ->
                records.map { it.copyOf() }
            }
            val records = checkNotNull(compilerRecords)
            val parsedPages = records.map(::parseProductionCurrentPage)
            currentPages = parsedPages
            val sortedPages = parsedPages.sortedBy { it.pageIndex }
            assertTrue(sortedPages.size >= 2)
            assertEquals(sortedPages.indices.toList(), sortedPages.map { it.pageIndex })
            assertTrue(sortedPages.all { it.entryToken == entryToken })
            assertTrue(sortedPages.all { it.resourceKind == AkenResourceKind.Vbc4Method })

            val pageZero = sortedPages.first()
            val pageZeroRecord = records[parsedPages.indexOf(pageZero)]
            val pageZeroDescriptor = decodeProductionCurrentPageDescriptor(pageZeroRecord)
            val pageZeroRoute = pageZeroDescriptor.route
            assertEquals(logicalBindingPath, pageZeroRoute.logicalBindingPath)
            assertEquals(containerPath, pageZeroRoute.resourcePath)

            val finalized = checkNotNull(layout)
            val entry = finalized.entriesForBuild().single { it.name == pageZeroRoute.resourcePath }
            entryBytes = entry.copyBytesForBuild()

            val include = NativeRecompilationTransforms.generateAkenNativePageLocatorInclude(
                buildContext,
                Random(0xB5F4),
            )
            generatedIncludeBytes = include.toByteArray(StandardCharsets.US_ASCII)
            val nativeLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir,
                sourceNativeDir = sourceNativeDir,
                include = include,
                platform = checkNotNull(platform),
            )
            val runtimeRoot = prepareAkenJniRuntimeFixture(
                root = tempDir,
                platform = platform,
                nativeLibrary = nativeLibrary,
                pageResourcePath = pageZeroRoute.resourcePath,
                pageResourceBytes = checkNotNull(entryBytes),
                entryToken = pageZero.entryToken,
                encodedHandle = pageZero.encodedHandle,
                pageIndex = pageZero.pageIndex,
                callSiteProof = pageZeroProof,
            )
            /* Build a second copy of the same current-format artifact with
             * the authoritative software crypto path forced at compile time.
             * The generated locator include, page bytes, bindings and JNI
             * harness are deliberately identical; only AES/GHASH dispatch is
             * different.  This keeps the differential scoped to runtime
             * implementation rather than protocol or artifact inputs. */
            val softwareNativeLibrary = compileAkenJniLibrary(
                zig = checkNotNull(zig),
                root = tempDir,
                sourceNativeDir = sourceNativeDir,
                include = include,
                platform = checkNotNull(platform),
                forceSoftware = true,
            )
            val softwareRuntimeRoot = prepareAkenJniRuntimeFixture(
                root = tempDir.resolve("software-runtime"),
                platform = platform,
                nativeLibrary = softwareNativeLibrary,
                pageResourcePath = pageZeroRoute.resourcePath,
                pageResourceBytes = checkNotNull(entryBytes),
                entryToken = pageZero.entryToken,
                encodedHandle = pageZero.encodedHandle,
                pageIndex = pageZero.pageIndex,
                callSiteProof = pageZeroProof,
            )

            val authenticated = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-good"),
                expectedOutcome = "result:2",
                label = "jni-multi-page-executed",
            )
            assertEquals(0, authenticated.exitCode, "real JNI authenticated multi-page VBC4 method must execute:\n${authenticated.output}")
            assertTrue(
                authenticated.output.contains("AKEN real JNI current page fixture: PASS:executed"),
                authenticated.output,
            )
            assertFalse(authenticated.output.contains("WARNING in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("FATAL ERROR in native method"), authenticated.output)
            assertFalse(authenticated.output.contains("JNI DETECTED ERROR IN APPLICATION"), authenticated.output)

            val softwareAuthenticated = runAkenJniRuntimeFixture(
                runtimeRoot = softwareRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-software-good"),
                expectedOutcome = "result:2",
                label = "jni-multi-page-software-executed",
            )
            assertEquals(
                0,
                softwareAuthenticated.exitCode,
                "real JNI authenticated multi-page VBC4 software-path method must execute:\n${softwareAuthenticated.output}",
            )
            assertTrue(
                softwareAuthenticated.output.contains("AKEN real JNI current page fixture: PASS:executed"),
                softwareAuthenticated.output,
            )
            assertFalse(softwareAuthenticated.output.contains("WARNING in native method"), softwareAuthenticated.output)
            assertFalse(softwareAuthenticated.output.contains("FATAL ERROR in native method"), softwareAuthenticated.output)
            assertFalse(softwareAuthenticated.output.contains("JNI DETECTED ERROR IN APPLICATION"), softwareAuthenticated.output)

            /* Compare one bounded production page-open profile through both
             * native libraries.  Larger 100/1,000/10,000/100,000 profiles
             * remain controlled by the existing benchmark environment knobs;
             * this differential always runs so the default regression lane
             * proves identical output and security counters. */
            val differentialSamples = System.getenv("JS_AKEN_PAGE_OPEN_DIFFERENTIAL_SAMPLES")
                ?.toIntOrNull()
                ?.takeIf { it in 100..100_000 }
                ?: 100
            val differentialWarmup = System.getenv("JS_AKEN_PAGE_OPEN_BENCH_WARMUP")
                ?.toIntOrNull()
                ?.takeIf { it in 0..100_000 }
                ?: 16
            val differentialTimeoutSeconds = pageOpenBenchmarkTimeoutSeconds()
            emitAkenStage("differential-hardware", "start")
            val differentialHardware = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-differential-hardware"),
                expectedOutcome = "bench:$differentialSamples:$differentialWarmup",
                label = "jni-multi-page-differential-hardware",
                timeoutSeconds = differentialTimeoutSeconds,
            )
            emitAkenFixturePhase("differential-hardware", differentialHardware)
            emitAkenStage("differential-software", "start")
            val differentialSoftware = runAkenJniRuntimeFixture(
                runtimeRoot = softwareRuntimeRoot,
                extractDirectory = tempDir.resolve("extract-differential-software"),
                expectedOutcome = "bench:$differentialSamples:$differentialWarmup",
                label = "jni-multi-page-differential-software",
                timeoutSeconds = differentialTimeoutSeconds,
            )
            emitAkenFixturePhase("differential-software", differentialSoftware)
            emitAkenStage("differential", "pass")
            assertEquals(0, differentialHardware.exitCode, differentialHardware.output)
            assertEquals(0, differentialSoftware.exitCode, differentialSoftware.output)
            fun differentialPhaseLine(result: ProcessResult, label: String): String =
                requireSingleAkenPhaseLine(result, label)
            fun differentialFields(line: String): Map<String, String> = line.split(' ')
                .mapNotNull { token ->
                    val separator = token.indexOf('=')
                    if (separator <= 0 || separator == token.lastIndex) null
                    else token.substring(0, separator) to token.substring(separator + 1)
                }
                .toMap()
            val differentialHardwareLine = differentialPhaseLine(
                differentialHardware,
                "AKEN page-open hardware differential",
            )
            val differentialSoftwareLine = differentialPhaseLine(
                differentialSoftware,
                "AKEN page-open software differential",
            )
            val differentialHardwareFields = differentialFields(differentialHardwareLine)
            val differentialSoftwareFields = differentialFields(differentialSoftwareLine)
            assertEquals("production", differentialHardwareFields["phase_mode"], differentialHardwareLine)
            assertEquals("production", differentialSoftwareFields["phase_mode"], differentialSoftwareLine)
            assertEquals("pass", differentialHardwareFields["phase_status"], differentialHardwareLine)
            assertEquals("pass", differentialSoftwareFields["phase_status"], differentialSoftwareLine)
            assertEquals(differentialSamples.toString(), differentialHardwareFields["samples"], differentialHardwareLine)
            assertEquals(differentialSamples.toString(), differentialSoftwareFields["samples"], differentialSoftwareLine)
            assertEquals(
                differentialHardwareFields["output_digest"],
                differentialSoftwareFields["output_digest"],
                "AKEN page-open hardware/software paths must produce the same output digest",
            )
            val differentialHardwarePath = differentialHardwareFields["hardware_crypto_path"]?.toLongOrNull()
                ?: error("AKEN page-open hardware differential did not report hardware_crypto_path")
            val differentialHardwareSoftwarePath = differentialHardwareFields["software_crypto_path"]?.toLongOrNull()
                ?: error("AKEN page-open hardware differential did not report software_crypto_path")
            val differentialHardwareAesCapability = differentialHardwareFields["cpu_hardware_aes"]?.toLongOrNull()
                ?: error("AKEN page-open hardware differential did not report cpu_hardware_aes")
            val differentialHardwareGhashCapability = differentialHardwareFields["cpu_hardware_ghash"]?.toLongOrNull()
                ?: error("AKEN page-open hardware differential did not report cpu_hardware_ghash")
            assertTrue(differentialHardwareAesCapability in 0L..1L, differentialHardwareLine)
            assertTrue(differentialHardwareGhashCapability in 0L..1L, differentialHardwareLine)
            /* The default build may legitimately select the software path on a
             * CPU without AES-NI.  Whichever path is selected must be
             * exclusive: a hardware-selected operation must not also be
             * counted as software, and an unsupported CPU must still exercise
             * the authoritative software implementation. */
            assertTrue(
                (differentialHardwarePath > 0L) xor (differentialHardwareSoftwarePath > 0L),
                differentialHardwareLine,
            )
            if (differentialHardwareAesCapability == 1L) {
                assertTrue(differentialHardwarePath > 0L, differentialHardwareLine)
                assertEquals("0", differentialHardwareFields["software_crypto_path"], differentialHardwareLine)
            } else {
                assertTrue(differentialHardwareSoftwarePath > 0L, differentialHardwareLine)
            }
            if (differentialHardwarePath > 0L) {
                assertEquals("0", differentialHardwareFields["software_crypto_path"], differentialHardwareLine)
            }
            assertEquals("0", differentialSoftwareFields["cpu_hardware_aes"], differentialSoftwareLine)
            assertEquals("0", differentialSoftwareFields["cpu_hardware_ghash"], differentialSoftwareLine)
            assertEquals("0", differentialSoftwareFields["hardware_crypto_path"], differentialSoftwareLine)
            assertTrue(
                differentialSoftwareFields["software_crypto_path"]?.toLongOrNull()?.let { it > 0L } == true,
                differentialSoftwareLine,
            )
            listOf(
                "aes_block_count",
                "ghash_block_count",
                "auth_check_count",
                "digest_check_count",
                "tag_check_count",
                "length_check_count",
                "structure_check_count",
                "jni_abi_check_count",
            ).forEach { field ->
                assertEquals(
                    differentialHardwareFields[field],
                    differentialSoftwareFields[field],
                    "AKEN page-open differential counter mismatch for $field",
                )
                assertTrue(
                    differentialHardwareFields[field]?.toLongOrNull()?.let { it > 0L } == true,
                    "AKEN page-open differential counter $field was not exercised",
                )
            }
            listOf("wipe_count").forEach { field ->
                /* Hardware intrinsics and the authoritative software path may
                 * use different, still bounded scratch-wipe counts.  Both
                 * paths must wipe, while the security gate below rejects any
                 * wipe failure or plaintext persistence. */
                assertTrue(
                    differentialHardwareFields[field]?.toLongOrNull()?.let { it > 0L } == true,
                    differentialHardwareLine,
                )
                assertTrue(
                    differentialSoftwareFields[field]?.toLongOrNull()?.let { it > 0L } == true,
                    differentialSoftwareLine,
                )
            }
            listOf(
                "auth_failure_count",
                "wipe_failure_count",
                "plaintext_persistence_bytes",
                "fallback_count",
                "legacy_path_hits",
                "exception_count",
                "security_checks_skipped",
            ).forEach { field ->
                assertEquals("0", differentialHardwareFields[field], differentialHardwareLine)
                assertEquals("0", differentialSoftwareFields[field], differentialSoftwareLine)
            }
            println("phase=aken-page-open-differential phase_mode=production phase_status=pass samples=$differentialSamples " +
                "cpu_hardware_aes=${differentialHardwareFields["cpu_hardware_aes"]} " +
                "cpu_hardware_ghash=${differentialHardwareFields["cpu_hardware_ghash"]} " +
                "hardware_crypto_path=${differentialHardwareFields["hardware_crypto_path"]} " +
                "software_crypto_path=${differentialSoftwareFields["software_crypto_path"]} " +
                "output_digest=${differentialHardwareFields["output_digest"]}")
            println(differentialHardwareLine)
            println(differentialSoftwareLine)
            System.out.flush()

            /* Exercise the same production-bound container through the full
             * multi-page VBC4 route.  The page-zero VM entry reaches sibling
             * pages through the generated locator include; the fixture harness
             * reports only sanitized timing/counter data. */
            val benchmarkWarmup = System.getenv("JS_AKEN_PAGE_OPEN_BENCH_WARMUP")
                ?.toIntOrNull()
                ?.takeIf { it in 0..100_000 }
                ?: 16
            val benchmarkTimeoutSeconds = pageOpenBenchmarkTimeoutSeconds()
            pageOpenBenchmarkProfiles().forEach { benchmarkSamples ->
                emitAkenStage("benchmark-$benchmarkSamples", "start")
                val benchmark = runAkenJniRuntimeFixture(
                    runtimeRoot = runtimeRoot,
                    extractDirectory = tempDir.resolve("extract-multi-page-benchmark-$benchmarkSamples"),
                    expectedOutcome = "bench:$benchmarkSamples:$benchmarkWarmup",
                    label = "jni-multi-page-benchmark-$benchmarkSamples",
                    timeoutSeconds = benchmarkTimeoutSeconds,
                )
                emitAkenFixturePhase("benchmark-$benchmarkSamples", benchmark)
                assertEquals(0, benchmark.exitCode, "production AKEN multi-page benchmark must pass:\n${benchmark.output}")
                val benchmarkLine = requireSingleAkenPhaseLine(
                    result = benchmark,
                    label = "production AKEN multi-page benchmark",
                )
                /* Keep JUnit evidence auditable while excluding handles,
                 * proofs, routes, temp paths, plaintext, and full exceptions. */
                System.out.println(benchmarkLine)
                System.out.flush()
                val benchmarkFields = benchmarkLine.split(' ')
                    .mapNotNull { token ->
                        val separator = token.indexOf('=')
                        if (separator <= 0 || separator == token.lastIndex) null
                        else token.substring(0, separator) to token.substring(separator + 1)
                    }
                    .toMap()
                assertEquals("production", benchmarkFields["phase_mode"], benchmark.output)
                assertEquals("pass", benchmarkFields["phase_status"], benchmark.output)
                assertEquals(benchmarkSamples.toString(), benchmarkFields["samples"], benchmark.output)
                assertEquals(benchmarkWarmup.toString(), benchmarkFields["warmup"], benchmark.output)
                listOf("p50", "p95", "p99", "max").forEach { field ->
                    assertTrue(benchmarkFields[field]?.toLongOrNull()?.let { it >= 0L } == true, benchmark.output)
                }
                listOf(
                    "auth_check_count",
                    "digest_check_count",
                    "tag_check_count",
                    "length_check_count",
                    "structure_check_count",
                    "jni_abi_check_count",
                    "wipe_count",
                ).forEach { field ->
                    assertTrue(benchmarkFields[field]?.toLongOrNull()?.let { it > 0L } == true, benchmark.output)
                }
                listOf(
                    "auth_failure_count",
                    "wipe_failure_count",
                    "plaintext_persistence_bytes",
                    "fallback_count",
                    "legacy_path_hits",
                    "exception_count",
                    "security_checks_skipped",
                ).forEach { field ->
                    assertEquals("0", benchmarkFields[field], benchmark.output)
                }
                assertTrue(benchmarkFields["output_digest"]?.matches(Regex("[0-9a-f]{16}")) == true, benchmark.output)
            }

            val middlePage = sortedPages[sortedPages.size / 2]
            val middleRecord = records[parsedPages.indexOf(middlePage)]
            val middleDescriptor = decodeProductionCurrentPageDescriptor(middleRecord)
            val middleRoute = middleDescriptor.route
            assertEquals(logicalBindingPath, middleRoute.logicalBindingPath)
            assertEquals(containerPath, middleRoute.resourcePath)
            emitAkenStage("final-tamper", "start")
            val finalEntryBytes = requireNotNull(entryBytes) {
                "AKEN multi-page final entry was unavailable before tamper phase"
            }
            tamperedEntryBytes = finalEntryBytes.copyOf()
            val tamperedBytes = requireNotNull(tamperedEntryBytes) {
                "AKEN multi-page tamper copy was unavailable"
            }
            val tamperOffset = middleRoute.resourceOffset + (middleRoute.storedLength / 2)
            require(tamperOffset in tamperedBytes.indices) {
                "real JNI multi-page tamper offset is outside the current method container"
            }
            tamperedBytes[tamperOffset] =
                (tamperedBytes[tamperOffset].toInt() xor 0x5A).toByte()
            writeClasspathResource(runtimeRoot, middleRoute.resourcePath, tamperedBytes)

            val tampered = runAkenJniRuntimeFixture(
                runtimeRoot = runtimeRoot,
                extractDirectory = tempDir.resolve("extract-tampered"),
                expectedOutcome = "error:AKEN VM page authentication failed",
                label = "jni-multi-page-tampered",
            )
            emitAkenFixturePhase("final-tamper", tampered)
            assertEquals(0, tampered.exitCode, "real JNI tampered sibling VBC4 page must fail closed:\n${tampered.output}")
            assertTrue(
                tampered.output.contains("AKEN real JNI current page fixture: PASS:tampered"),
                tampered.output,
            )
            assertFalse(tampered.output.contains("WARNING in native method"), tampered.output)
            assertFalse(tampered.output.contains("FATAL ERROR in native method"), tampered.output)
            assertFalse(tampered.output.contains("JNI DETECTED ERROR IN APPLICATION"), tampered.output)

            emitAkenStage("final-tamper", "pass")
            buildContext.wipe()
            assertTrue(finalized.isWiped)
        } finally {
            emitAkenStage("cleanup", "start")
            try {
                assertContentEquals(
                    originalInclude,
                    Files.readAllBytes(sourceInclude),
                    "the repository's default empty locator include must remain untouched",
                )
            } finally {
                compilerRecords?.forEach { Arrays.fill(it, 0) }
                currentPages?.forEach { it.wipe() }
                entryBytes?.let { Arrays.fill(it, 0) }
                generatedIncludeBytes?.let { Arrays.fill(it, 0) }
                tamperedEntryBytes?.let { Arrays.fill(it, 0) }
                plaintext?.let { Arrays.fill(it, 0) }
                layout?.wipe()
                context?.wipe()
                Arrays.fill(originalInclude, 0)
                Arrays.fill(identity, 0)
                Arrays.fill(pageZeroProof, 0)
                deleteTree(tempDir)
                emitAkenStage("cleanup", "pass")
            }
        }
    }

    private fun productionBoundPayloadFixtureInclude(
        currentPage: ProductionCurrentPage,
        rawCallSiteProof: ByteArray,
        descriptor: AkenRuntimePageDescriptor,
        encodedPayload: ByteArray,
        expectedPlaintext: ByteArray,
    ): String {
        require(currentPage.resourceKind == AkenResourceKind.Vbc4Method)
        require(rawCallSiteProof.isNotEmpty())
        require(encodedPayload.isNotEmpty())
        require(expectedPlaintext.isNotEmpty())

        var logicalIdentity: ByteArray? = null
        var handle: AkenHandle? = null
        var handleEncoding: ByteArray? = null
        var locatorToken: ByteArray? = null
        var evaluatorFingerprint: ByteArray? = null
        var artifactCommitment: ByteArray? = null
        var descriptorProof: ByteArray? = null
        var codecVariant: ByteArray? = null
        var layoutVariant: ByteArray? = null
        var boundPlan: ByteArray? = null
        try {
            logicalIdentity = descriptor.logicalIdentity
            handle = descriptor.handle
            handleEncoding = handle.encoded
            locatorToken = handle.locatorToken
            evaluatorFingerprint = descriptor.evaluatorPlan.fingerprint
            artifactCommitment = descriptor.proof.artifactCanonicalCommitment
            descriptorProof = descriptor.proof.callSiteProof
            codecVariant = descriptor.route.codecVariant.toByteArray(StandardCharsets.UTF_8)
            layoutVariant = descriptor.route.layoutVariant.toByteArray(StandardCharsets.UTF_8)

            require(MessageDigest.isEqual(currentPage.encodedHandle, checkNotNull(handleEncoding))) {
                "AKEN bound-payload fixture handle does not match its native locator record"
            }
            require(MessageDigest.isEqual(rawCallSiteProof, checkNotNull(descriptorProof))) {
                "AKEN bound-payload fixture raw proof does not match descriptor proof"
            }
            val handleFingerprint = handle.evaluatorPlanFingerprint
            try {
                require(MessageDigest.isEqual(handleFingerprint, checkNotNull(evaluatorFingerprint))) {
                    "AKEN bound-payload fixture handle fingerprint does not match evaluator plan"
                }
            } finally {
                Arrays.fill(handleFingerprint, 0)
            }

            val evaluatorPlan = descriptor.evaluatorPlan
            require(!evaluatorPlan.isLegacyAken7) {
                "newly materialized AKEN native payload fixtures must use a bound decryptor plan"
            }
            boundPlan = requireNotNull(evaluatorPlan.copyBoundDecryptorForNative()) {
                "AKEN bound-payload fixture is missing its opaque native plan"
            }
            require(checkNotNull(boundPlan).isNotEmpty()) {
                "AKEN bound-payload fixture opaque native plan is empty"
            }

            val token = currentPage.entryToken.toULong().toString(16).uppercase().padStart(16, '0')
            return buildString {
                appendLine("/* AUTO-GENERATED AKEN v5 bound-decryptor fixture - DO NOT EDIT */")
                appendLine("#ifndef JS_AKEN_NATIVE_BOUND_PAYLOAD_FIXTURE_INC")
                appendLine("#define JS_AKEN_NATIVE_BOUND_PAYLOAD_FIXTURE_INC")
                appendLine("#include <stdint.h>")
                appendLine()
                appendLine("#define TEST_ENTRY_TOKEN UINT64_C(0x$token)")
                appendLine("#define TEST_RESOURCE_KIND ${descriptor.resourceKind.id}u")
                appendLine("#define TEST_PAGE_INDEX ${descriptor.pageIndex}")
                appendLine("#define TEST_TARGET_PAGE_SIZE ${descriptor.targetPageSize}")
                appendLine()
                appendBoundPayloadBytes("TEST_ENCODED_HANDLE", currentPage.encodedHandle)
                appendBoundPayloadBytes("TEST_RAW_CALL_SITE_PROOF", rawCallSiteProof)
                appendBoundPayloadBytes("TEST_LOGICAL_IDENTITY", checkNotNull(logicalIdentity))
                appendBoundPayloadBytes("TEST_CODEC_VARIANT", checkNotNull(codecVariant))
                appendBoundPayloadBytes("TEST_LAYOUT_VARIANT", checkNotNull(layoutVariant))
                appendBoundPayloadBytes("TEST_LOCATOR_TOKEN", checkNotNull(locatorToken))
                appendBoundPayloadBytes("TEST_EVALUATOR_FINGERPRINT", checkNotNull(evaluatorFingerprint))
                appendBoundPayloadBytes("TEST_ARTIFACT_COMMITMENT", checkNotNull(artifactCommitment))
                appendBoundPayloadBytes("TEST_BOUND_PLAN", checkNotNull(boundPlan))
                appendBoundPayloadBytes("TEST_ENCODED_PAYLOAD", encodedPayload)
                appendBoundPayloadBytes("TEST_EXPECTED_PLAINTEXT", expectedPlaintext)
                appendLine("#endif")
            }
        } finally {
            logicalIdentity?.let { Arrays.fill(it, 0) }
            handleEncoding?.let { Arrays.fill(it, 0) }
            locatorToken?.let { Arrays.fill(it, 0) }
            evaluatorFingerprint?.let { Arrays.fill(it, 0) }
            artifactCommitment?.let { Arrays.fill(it, 0) }
            descriptorProof?.let { Arrays.fill(it, 0) }
            codecVariant?.let { Arrays.fill(it, 0) }
            layoutVariant?.let { Arrays.fill(it, 0) }
            boundPlan?.let { Arrays.fill(it, 0) }
            handle?.wipe()
        }
    }

    private fun StringBuilder.appendBoundPayloadBytes(name: String, value: ByteArray) {
        require(value.isNotEmpty()) { "AKEN native bound-payload fixture byte array must not be empty" }
        append("static const unsigned char ").append(name).append('[').append(value.size).appendLine("] = {")
        value.forEachIndexed { index, byte ->
            if (index % 12 == 0) append("    ")
            append("0x%02Xu".format(byte.toInt() and 0xFF))
            if (index != value.lastIndex) append(", ")
            if (index % 12 == 11 || index == value.lastIndex) appendLine()
        }
        appendLine("};")
    }

    private fun parseProductionCurrentPage(record: ByteArray): ProductionCurrentPage {
        require(record.size in 1..(512 * 1024)) {
            "production AKEN compiler record size is invalid"
        }
        val input = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN)
        require(input.remaining() >= Long.SIZE_BYTES + 1 + Int.SIZE_BYTES + Int.SIZE_BYTES) {
            "production AKEN compiler record is truncated"
        }
        val entryToken = input.long
        val resourceKind = requireNotNull(AkenResourceKind.fromId(input.get().toInt() and 0xFF)) {
            "production AKEN compiler record resource kind is unsupported"
        }
        val pageIndex = input.int
        require(pageIndex >= 0) { "production AKEN compiler record page index is invalid" }

        val encodedHandle = readProductionCurrentPageFrame(
            input,
            maxLength = AkenHandle.ENCODED_HANDLE_SIZE,
            label = "encoded handle",
        )
        val nativeEnvelope = readProductionCurrentPageFrame(input, maxLength = 4096, label = "native envelope")
        val descriptor = readProductionCurrentPageFrame(
            input,
            maxLength = 384 * 1024,
            label = "descriptor",
        )
        val route = readProductionCurrentPageFrame(
            input,
            maxLength = 128 * 1024,
            label = "route",
        )
        val vbc4StateBindingLayoutDigest = ByteArray(AkenArtifactCommitment.DIGEST_SIZE)
        val binding = ByteArray(AkenArtifactCommitment.DIGEST_SIZE)
        var retainHandle = false
        try {
            require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) {
                "production AKEN compiler record handle size is invalid"
            }
            require(nativeEnvelope.isNotEmpty())
            require(descriptor.isNotEmpty())
            require(route.isNotEmpty())
            require(input.remaining() == vbc4StateBindingLayoutDigest.size + binding.size) {
                "production AKEN compiler record binding length is invalid"
            }
            input.get(vbc4StateBindingLayoutDigest)
            input.get(binding)
            val expectedBinding = compilerRecordBinding(
                entryToken = entryToken,
                resourceKind = resourceKind,
                pageIndex = pageIndex,
                encodedHandle = encodedHandle,
                nativeEnvelope = nativeEnvelope,
                descriptor = descriptor,
                route = route,
                vbc4StateBindingLayoutDigest = vbc4StateBindingLayoutDigest,
            )
            try {
                require(MessageDigest.isEqual(binding, expectedBinding)) {
                    "production AKEN compiler record binding is invalid"
                }
            } finally {
                Arrays.fill(expectedBinding, 0)
            }
            retainHandle = true
            return ProductionCurrentPage(
                entryToken = entryToken,
                resourceKind = resourceKind,
                pageIndex = pageIndex,
                encodedHandle = encodedHandle,
            )
        } finally {
            if (!retainHandle) Arrays.fill(encodedHandle, 0)
            Arrays.fill(nativeEnvelope, 0)
            Arrays.fill(descriptor, 0)
            Arrays.fill(route, 0)
            Arrays.fill(vbc4StateBindingLayoutDigest, 0)
            Arrays.fill(binding, 0)
        }
    }

    /**
     * Decodes the descriptor portion of a compiler record after
     * [parseProductionCurrentPage] has already verified the record binding.
     * The decoder retains only the immutable descriptor object; every temporary
     * record frame is cleared before returning.
     */
    private fun decodeProductionCurrentPageDescriptor(record: ByteArray): AkenRuntimePageDescriptor {
        require(record.size in 1..(512 * 1024)) {
            "production AKEN compiler record size is invalid"
        }
        val input = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN)
        require(input.remaining() >= Long.SIZE_BYTES + 1 + Int.SIZE_BYTES + Int.SIZE_BYTES) {
            "production AKEN compiler record is truncated"
        }
        input.long
        requireNotNull(AkenResourceKind.fromId(input.get().toInt() and 0xFF)) {
            "production AKEN compiler record resource kind is unsupported"
        }
        require(input.int >= 0) { "production AKEN compiler record page index is invalid" }

        val encodedHandle = readProductionCurrentPageFrame(
            input,
            maxLength = AkenHandle.ENCODED_HANDLE_SIZE,
            label = "encoded handle",
        )
        val nativeEnvelope = readProductionCurrentPageFrame(input, maxLength = 4096, label = "native envelope")
        val descriptorBytes = readProductionCurrentPageFrame(input, maxLength = 384 * 1024, label = "descriptor")
        val route = readProductionCurrentPageFrame(input, maxLength = 128 * 1024, label = "route")
        val vbc4StateBindingLayoutDigest = ByteArray(AkenArtifactCommitment.DIGEST_SIZE)
        val binding = ByteArray(AkenArtifactCommitment.DIGEST_SIZE)
        try {
            require(input.remaining() == vbc4StateBindingLayoutDigest.size + binding.size) {
                "production AKEN compiler record binding length is invalid"
            }
            input.get(vbc4StateBindingLayoutDigest)
            input.get(binding)
            return AkenRuntimePageDescriptor.decode(descriptorBytes)
        } finally {
            Arrays.fill(encodedHandle, 0)
            Arrays.fill(nativeEnvelope, 0)
            Arrays.fill(descriptorBytes, 0)
            Arrays.fill(route, 0)
            Arrays.fill(vbc4StateBindingLayoutDigest, 0)
            Arrays.fill(binding, 0)
        }
    }

    private fun readProductionCurrentPageFrame(
        input: ByteBuffer,
        maxLength: Int,
        label: String,
    ): ByteArray {
        require(input.remaining() >= Int.SIZE_BYTES) { "production AKEN compiler record $label length is truncated" }
        val length = input.int
        require(length in 1..maxLength && length <= input.remaining()) {
            "production AKEN compiler record $label length is invalid"
        }
        return ByteArray(length).also(input::get)
    }

    private fun parseGeneratedUnsignedByteArray(include: String, name: String): ByteArray =
        generatedArrayInitializer(include, name)
            .let { initializer ->
                Regex("0x([0-9A-F]{2})u").findAll(initializer)
                    .map { match -> match.groupValues[1].toInt(16).toByte() }
                    .toList()
                    .toByteArray()
            }

    private fun parseGeneratedUnsignedIntArray(include: String, name: String): IntArray =
        generatedArrayInitializer(include, name)
            .let { initializer ->
                Regex("(\\d+)u").findAll(initializer)
                    .map { match -> match.groupValues[1].toInt() }
                    .toList()
                    .toIntArray()
            }

    private fun generatedArrayInitializer(include: String, name: String): String {
        val start = include.indexOf("$name[")
        require(start >= 0) { "missing generated array $name" }
        val open = include.indexOf('{', start)
        val close = include.indexOf("};", open)
        require(open >= 0 && close > open) { "malformed generated array $name" }
        return include.substring(open + 1, close)
    }

    private fun productionRendererProbeSource(
        currentPage: ProductionCurrentPage,
        rawCallSiteProof: ByteArray,
    ): String {
        require(currentPage.resourceKind == AkenResourceKind.Vbc4Method)
        require(rawCallSiteProof.isNotEmpty())
        val token = currentPage.entryToken.toULong().toString(16).uppercase().padStart(16, '0')
        return buildString {
            appendLine("#include \"js_jni_runtime.h\"")
            appendLine("#include \"js_crypto.h\"")
            appendLine()
            appendLine("#include <stdint.h>")
            appendLine("#include <stdio.h>")
            appendLine("#include <string.h>")
            appendLine()
            appendLine("#define TEST_CHECK(condition) do { \\")
            appendLine("    if (!(condition)) { \\")
            appendLine("        fprintf(stderr, \"AKEN native locator probe failed: %s (%s:%d)\\n\", #condition, __FILE__, __LINE__); \\")
            appendLine("        return 0; \\")
            appendLine("    } \\")
            appendLine("} while (0)")
            appendLine()
            appendProbeUnsignedBytes("TEST_HANDLE", currentPage.encodedHandle)
            appendProbeUnsignedBytes("TEST_PROOF", rawCallSiteProof)
            appendLine()
            appendLine("static int test_current_page(void) {")
            appendLine("    js_aken_native_page_request request;")
            appendLine("    js_aken_native_page_locator_record record;")
            appendLine("    js_aken_native_page_locator_record missing;")
            appendLine("    js_aken_native_page_envelope envelope;")
            appendLine("    js_aken_native_page_resolved_descriptor resolved;")
            appendLine()
            appendLine("    memset(&request, 0, sizeof(request));")
            appendLine("    memset(&record, 0, sizeof(record));")
            appendLine("    memset(&missing, 0, sizeof(missing));")
            appendLine("    memset(&envelope, 0, sizeof(envelope));")
            appendLine("    memset(&resolved, 0, sizeof(resolved));")
            appendLine("    request.entry_token = UINT64_C(0x$token);")
            appendLine("    request.resource_kind = JS_AKEN_NATIVE_PAGE_RESOURCE_KIND_VBC4_METHOD;")
            appendLine("    request.page_index = ${currentPage.pageIndex};")
            appendLine("    request.encoded_handle = TEST_HANDLE;")
            appendLine("    request.encoded_handle_len = sizeof(TEST_HANDLE);")
            appendLine("    request.raw_call_site_proof = TEST_PROOF;")
            appendLine("    request.raw_call_site_proof_len = sizeof(TEST_PROOF);")
            appendLine()
            appendLine("    TEST_CHECK(js_aken_native_page_locator_lookup(&request, &record));")
            appendLine("    TEST_CHECK(record.parsed == 1u);")
            appendLine("    TEST_CHECK(record.entry_token == request.entry_token);")
            appendLine("    TEST_CHECK(record.resource_kind == request.resource_kind);")
            appendLine("    TEST_CHECK(record.page_index == request.page_index);")
            appendLine("    TEST_CHECK(record.native_envelope_len != 0u);")
            appendLine("    TEST_CHECK(record.descriptor_encoding_len != 0u);")
            appendLine("    TEST_CHECK(record.route_encoding_len != 0u);")
            appendLine("    TEST_CHECK(js_aken_native_page_envelope_parse(")
            appendLine("        record.native_envelope, record.native_envelope_len, &request, &envelope));")
            appendLine("    TEST_CHECK(js_aken_native_page_locator_resolve(&record, &envelope, &resolved));")
            appendLine("    TEST_CHECK(resolved.descriptor_encoding == record.descriptor_encoding);")
            appendLine("    TEST_CHECK(resolved.descriptor_encoding_len == record.descriptor_encoding_len);")
            appendLine("    TEST_CHECK(resolved.route_encoding == record.route_encoding);")
            appendLine("    TEST_CHECK(resolved.route_encoding_len == record.route_encoding_len);")
            appendLine()
            appendLine("    envelope.route_binding[0] ^= 0x01u;")
            appendLine("    TEST_CHECK(!js_aken_native_page_locator_resolve(&record, &envelope, &resolved));")
            appendLine("    TEST_CHECK(resolved.descriptor_encoding == NULL);")
            appendLine("    TEST_CHECK(resolved.route_encoding == NULL);")
            appendLine("    js_aken_native_page_envelope_wipe(&envelope);")
            appendLine("    TEST_CHECK(js_aken_native_page_envelope_parse(")
            appendLine("        record.native_envelope, record.native_envelope_len, &request, &envelope));")
            appendLine("    TEST_CHECK(js_aken_native_page_locator_resolve(&record, &envelope, &resolved));")
            appendLine()
            appendLine("    request.page_index += 1;")
            appendLine("    TEST_CHECK(!js_aken_native_page_locator_lookup(&request, &missing));")
            appendLine("    TEST_CHECK(missing.parsed == 0u);")
            appendLine()
            appendLine("    js_vbc4_wipe_volatile(&resolved, sizeof(resolved));")
            appendLine("    js_aken_native_page_envelope_wipe(&envelope);")
            appendLine("    js_aken_native_page_locator_record_wipe(&record);")
            appendLine("    js_aken_native_page_locator_record_wipe(&missing);")
            appendLine("    js_vbc4_wipe_volatile(&request, sizeof(request));")
            appendLine("    return 1;")
            appendLine("}")
            appendLine()
            appendLine("int main(void) {")
            appendLine("    if (!test_current_page()) return 1;")
            appendLine("    puts(\"AKEN native page locator probe: PASS\");")
            appendLine("    return 0;")
            appendLine("}")
        }
    }

    private fun StringBuilder.appendProbeUnsignedBytes(name: String, value: ByteArray) {
        require(value.isNotEmpty())
        appendLine("static const unsigned char $name[${value.size}] = {")
        value.forEachIndexed { index, byte ->
            if (index % 12 == 0) append("    ")
            append("0x%02Xu".format(byte.toInt() and 0xFF))
            if (index != value.lastIndex) append(", ")
            if (index % 12 == 11 || index == value.lastIndex) appendLine()
        }
        appendLine("};")
    }


    private class ProductionCurrentPage(
        val entryToken: Long,
        val resourceKind: AkenResourceKind,
        val pageIndex: Int,
        val encodedHandle: ByteArray,
    ) {
        fun wipe() {
            Arrays.fill(encodedHandle, 0)
        }
    }

    private fun assertFailClosed(scenario: String, result: ProcessResult) {
        assertTrue(result.exitCode != 0, "$scenario must not permit the probe to pass:\n${result.output}")
        assertTrue(result.output.contains("AKEN native locator probe failed"), "$scenario must reach the reject path:\n${result.output}")
        assertFalse(result.output.contains("AKEN native page locator probe: PASS"), "$scenario unexpectedly passed:\n${result.output}")
    }


    private fun compileAkenJniLibrary(
        zig: String,
        root: Path,
        sourceNativeDir: Path,
        include: String,
        platform: AkenHostPlatform,
        forceSoftware: Boolean = false,
    ): Path {
        val scenarioDirName = if (forceSoftware) "jni-native-software" else "jni-native-hardware"
        val scenarioDir = Files.createDirectories(root.resolve(scenarioDirName))
        val nativeDir = scenarioDir.resolve("native")
        copyTree(sourceNativeDir, nativeDir)
        /* The Zig 0.16 MinGW sysroot shipped on the Windows fixture host has
         * an immintrin.h reference to an optional AVX10 header that is absent.
         * Keep the compile-only shim in this isolated copy; AES-NI/PCLMUL
         * intrinsics used by the runtime remain available and no repository
         * header or ABI is changed. */
        Files.writeString(
            nativeDir.resolve("avx10_2satcvtintrin.h"),
            "#ifndef JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#define JS_FIXTURE_AVX10_2SATCVT_INTRIN_H\n#endif\n",
            StandardCharsets.US_ASCII,
        )
        Files.writeString(nativeDir.resolve("js_aken_page_locator.inc"), include, StandardCharsets.UTF_8)
        if (platform.platformId.startsWith("macos-")) {
            Files.writeString(
                nativeDir.resolve("macos-exported-symbols.txt"),
                "_JNI_OnLoad\n_JNI_OnUnload\n_js_native_abi_table_v1\n",
                StandardCharsets.US_ASCII,
            )
        }

        val library = scenarioDir.resolve("aken-current-page${platform.fileSuffix}")
        val command = compileAkenJniLibraryCommand(
            zig = zig,
            nativeDir = nativeDir,
            library = library,
            platform = platform,
            forceSoftware = forceSoftware,
        )
        var compile = run(
            command = command,
            directory = scenarioDir,
            label = "compile-jni-0",
            zigCache = scenarioDir.resolve("zig-cache-0"),
            timeoutSeconds = 300L,
        )
        for (attempt in 1..5) {
            if (compile.exitCode == 0 || !isTransientZigFailure(compile.output)) break
            compile = run(
                command = command,
                directory = scenarioDir,
                label = "compile-jni-$attempt",
                zigCache = scenarioDir.resolve("zig-cache-$attempt"),
                timeoutSeconds = 300L,
            )
        }
        assertEquals(0, compile.exitCode, "real AKEN JNI fixture must compile:\n${compile.output}")
        assertTrue(Files.isRegularFile(library) && Files.size(library) > 0L, "real AKEN JNI fixture library is missing")
        return library
    }

    private fun compileAkenJniLibraryCommand(
        zig: String,
        nativeDir: Path,
        library: Path,
        platform: AkenHostPlatform,
        forceSoftware: Boolean = false,
    ): List<String> = buildList {
        addAll(
            listOf(
                zig,
                "cc",
                "-target",
                platform.zigTarget,
                "-std=c11",
                "-O2",
                "-shared",
                "-fwrapv",
                "-fno-exceptions",
                "-fvisibility=hidden",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-DZSTD_DISABLE_ASM=1",
                "-DZSTDLIB_VISIBLE=",
                "-DZSTDERRORLIB_VISIBLE=",
                "-DXXH_PUBLIC_API=",
                "-DJS_NATIVE_PROTECTION_NONE=1",
                "-DJS_AKEN_TYPED_ONLY_RUNTIME=1",
                "-DJS_AKEN_JNI_FIXTURE_DIAGNOSTICS=1",
                "-o",
                library.toString(),
            ),
        )
        if (forceSoftware) add("-DJS_CRYPTO_FORCE_SOFTWARE=1")
        addAll(FULL_NATIVE_SOURCES.map { name -> nativeDir.resolve(name).toString() })
        addAll(
            listOf(
                "-I",
                nativeDir.toString(),
                "-I",
                nativeDir.resolve("cross-compile").toString(),
                "-I",
                nativeDir.resolve("zstd").toString(),
                "-I",
                nativeDir.resolve("zstd/common").toString(),
                "-I",
                nativeDir.resolve("zstd/decompress").toString(),
            ),
        )
        when {
            platform.platformId == "windows-x64" -> {
                add("-Wl,--no-entry")
                add("-ladvapi32")
            }
            platform.platformId == "linux-x64" -> {
                add("-Wl,-T,${nativeDir.resolve("js_protected_section_linux.ld")}")
            }
            platform.platformId.startsWith("macos-") -> {
                add("-Wl,-exported_symbols_list,${nativeDir.resolve("macos-exported-symbols.txt")}")
            }
        }
    }

    private fun akenVbc4PageProof(pageIndex: Int): ByteArray {
        require(pageIndex >= 0) { "AKEN VBC4 page proof index is invalid" }
        return ByteArray(73) { index -> (pageIndex * 29 + index * 17 + 11).toByte() }
    }

    private fun akenVbc4ExecutorContext(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(32) { index -> (index * 7 + 0x31).toByte() },
        nativeSeed = 0x414B_454E_5634_3001L,
        jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 0x17).toByte() },
        nativeVmProfile = NativeVmBuildProfile(
            parserRowProfile = 0,
            operandAccessProfile = 0,
        ),
    )

    private fun prepareAkenClassJniRuntimeFixture(
        root: Path,
        platform: AkenHostPlatform,
        nativeLibrary: Path,
        pageResourcePath: String,
        pageResourceBytes: ByteArray,
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
    ): Path {
        require(pageResourceBytes.isNotEmpty()) { "real AKEN JNI class page resource must not be empty" }
        require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) { "real AKEN JNI class handle size is invalid" }
        require(pageIndex >= 0) { "real AKEN JNI class page index is invalid" }
        require(callSiteProof.isNotEmpty()) { "real AKEN JNI class call-site proof must not be empty" }

        val runtimeRoot = Files.createDirectories(root.resolve("runtime-classes"))
        val sourceDir = Files.createDirectories(root.resolve("runtime-source"))
        val source = sourceDir.resolve("$AKEN_JNI_FIXTURE_MAIN.java")
        Files.writeString(
            source,
            akenClassJniHarnessSource(
                encodedHandle = encodedHandle,
                pageIndex = pageIndex,
                callSiteProof = callSiteProof,
            ),
            StandardCharsets.UTF_8,
        )

        val helperClasspath = jniHelperClasspathEntry()
        val javac = javaTool("javac")
        val compile = run(
            command = listOf(
                javac.toString(),
                "-source",
                "8",
                "-target",
                "8",
                "-classpath",
                helperClasspath.toString(),
                "-d",
                runtimeRoot.toString(),
                source.toString(),
            ),
            directory = root,
            label = "compile-class-jni-harness",
            timeoutSeconds = 60L,
        )
        assertEquals(0, compile.exitCode, "real AKEN JNI class Java harness must compile:\n${compile.output}")

        val nativeResourcePath = "META-INF/aken/runtime/aken-class-page${platform.fileSuffix}"
        writeAkenNativeRuntimeResources(
            runtimeRoot = runtimeRoot,
            platform = platform,
            nativeLibrary = nativeLibrary,
            nativeResourcePath = nativeResourcePath,
        )
        writeClasspathResource(runtimeRoot, pageResourcePath, pageResourceBytes)
        return runtimeRoot
    }

    private fun prepareAkenNativeChunkJniRuntimeFixture(
        root: Path,
        platform: AkenHostPlatform,
        nativeLibrary: Path,
        pageResourcePath: String,
        pageResourceBytes: ByteArray,
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
    ): Path {
        require(pageResourceBytes.isNotEmpty()) { "real AKEN JNI native chunk resource must not be empty" }
        require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) { "real AKEN JNI native chunk handle size is invalid" }
        require(pageIndex >= 0) { "real AKEN JNI native chunk page index is invalid" }
        require(callSiteProof.isNotEmpty()) { "real AKEN JNI native chunk call-site proof must not be empty" }

        val runtimeRoot = Files.createDirectories(root.resolve("runtime-classes"))
        val sourceDir = Files.createDirectories(root.resolve("runtime-source"))
        val source = sourceDir.resolve(AKEN_JNI_FIXTURE_MAIN + ".java")
        Files.writeString(
            source,
            akenNativeChunkJniHarnessSource(
                encodedHandle = encodedHandle,
                pageIndex = pageIndex,
                callSiteProof = callSiteProof,
            ),
            StandardCharsets.UTF_8,
        )

        val helperClasspath = jniHelperClasspathEntry()
        val javac = javaTool("javac")
        val compile = run(
            command = listOf(
                javac.toString(),
                "-source",
                "8",
                "-target",
                "8",
                "-classpath",
                helperClasspath.toString(),
                "-d",
                runtimeRoot.toString(),
                source.toString(),
            ),
            directory = root,
            label = "compile-native-chunk-jni-harness",
            timeoutSeconds = 60L,
        )
        assertEquals(0, compile.exitCode, "real AKEN JNI native chunk Java harness must compile:\n" + compile.output)

        val nativeResourcePath = "META-INF/aken/runtime/aken-native-chunk" + platform.fileSuffix
        writeAkenNativeRuntimeResources(
            runtimeRoot = runtimeRoot,
            platform = platform,
            nativeLibrary = nativeLibrary,
            nativeResourcePath = nativeResourcePath,
        )
        writeClasspathResource(runtimeRoot, pageResourcePath, pageResourceBytes)
        return runtimeRoot
    }

    private fun prepareAkenStringJniRuntimeFixture(
        root: Path,
        platform: AkenHostPlatform,
        nativeLibrary: Path,
        pageResourcePath: String,
        pageResourceBytes: ByteArray,
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
    ): Path {
        require(pageResourceBytes.isNotEmpty()) { "real AKEN JNI string page resource must not be empty" }
        require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) { "real AKEN JNI string handle size is invalid" }
        require(pageIndex >= 0) { "real AKEN JNI string page index is invalid" }
        require(callSiteProof.isNotEmpty()) { "real AKEN JNI string call-site proof must not be empty" }

        val runtimeRoot = Files.createDirectories(root.resolve("runtime-classes"))
        val sourceDir = Files.createDirectories(root.resolve("runtime-source"))
        val source = sourceDir.resolve("$AKEN_JNI_FIXTURE_MAIN.java")
        Files.writeString(
            source,
            akenStringJniHarnessSource(
                encodedHandle = encodedHandle,
                pageIndex = pageIndex,
                callSiteProof = callSiteProof,
            ),
            StandardCharsets.UTF_8,
        )

        val helperClasspath = jniHelperClasspathEntry()
        val javac = javaTool("javac")
        val compile = run(
            command = listOf(
                javac.toString(),
                "-source",
                "8",
                "-target",
                "8",
                "-classpath",
                helperClasspath.toString(),
                "-d",
                runtimeRoot.toString(),
                source.toString(),
            ),
            directory = root,
            label = "compile-string-jni-harness",
            timeoutSeconds = 60L,
        )
        assertEquals(0, compile.exitCode, "real AKEN JNI string Java harness must compile:\n${compile.output}")

        val nativeResourcePath = "META-INF/aken/runtime/aken-string-page${platform.fileSuffix}"
        writeAkenNativeRuntimeResources(
            runtimeRoot = runtimeRoot,
            platform = platform,
            nativeLibrary = nativeLibrary,
            nativeResourcePath = nativeResourcePath,
        )
        writeClasspathResource(runtimeRoot, pageResourcePath, pageResourceBytes)
        return runtimeRoot
    }

    private fun prepareAkenJniRuntimeFixture(
        root: Path,
        platform: AkenHostPlatform,
        nativeLibrary: Path,
        pageResourcePath: String,
        pageResourceBytes: ByteArray,
        entryToken: Long,
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
    ): Path {
        require(pageResourceBytes.isNotEmpty()) { "real AKEN JNI page resource must not be empty" }
        require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) { "real AKEN JNI handle size is invalid" }
        require(pageIndex >= 0) { "real AKEN JNI page index is invalid" }
        require(callSiteProof.isNotEmpty()) { "real AKEN JNI call-site proof must not be empty" }

        val runtimeRoot = Files.createDirectories(root.resolve("runtime-classes"))
        val sourceDir = Files.createDirectories(root.resolve("runtime-source"))
        val source = sourceDir.resolve("$AKEN_JNI_FIXTURE_MAIN.java")
        Files.writeString(
            source,
            akenJniHarnessSource(
                entryToken = entryToken,
                encodedHandle = encodedHandle,
                pageIndex = pageIndex,
                callSiteProof = callSiteProof,
            ),
            StandardCharsets.UTF_8,
        )

        val helperClasspath = jniHelperClasspathEntry()
        val javac = javaTool("javac")
        val compile = run(
            command = listOf(
                javac.toString(),
                "-source",
                "8",
                "-target",
                "8",
                "-classpath",
                helperClasspath.toString(),
                "-d",
                runtimeRoot.toString(),
                source.toString(),
            ),
            directory = root,
            label = "compile-jni-harness",
            timeoutSeconds = 60L,
        )
        assertEquals(0, compile.exitCode, "real AKEN JNI Java harness must compile:\n${compile.output}")

        val nativeResourcePath = "META-INF/aken/runtime/aken-current-page${platform.fileSuffix}"
        writeAkenNativeRuntimeResources(
            runtimeRoot = runtimeRoot,
            platform = platform,
            nativeLibrary = nativeLibrary,
            nativeResourcePath = nativeResourcePath,
        )
        writeClasspathResource(runtimeRoot, pageResourcePath, pageResourceBytes)
        return runtimeRoot
    }

    private fun writeAkenNativeRuntimeResources(
        runtimeRoot: Path,
        platform: AkenHostPlatform,
        nativeLibrary: Path,
        nativeResourcePath: String,
    ) {
        val nativeBindingsResourcePath = "META-INF/aken/runtime/aken-current-page.bindings"
        val nativeBytes = Files.readAllBytes(nativeLibrary)
        try {
            writeClasspathResource(runtimeRoot, nativeResourcePath, nativeBytes)
                val nativeBindings = "B|fixture|fixture\n".toByteArray(StandardCharsets.US_ASCII)
                try {
                    writeClasspathResource(runtimeRoot, nativeBindingsResourcePath, nativeBindings)
                    val locator = encodeAkenNativeLocator(
                        platform = platform.platformId,
                        nativeResourcePath = nativeResourcePath,
                        nativeBytes = nativeBytes,
                        nativeBindingsResourcePath = nativeBindingsResourcePath,
                        nativeBindings = nativeBindings,
                    )
                    try {
                        writeClasspathResource(runtimeRoot, "META-INF/aken/native.locator", locator)
                    } finally {
                    Arrays.fill(locator, 0)
                }
            } finally {
                Arrays.fill(nativeBindings, 0)
            }
        } finally {
            Arrays.fill(nativeBytes, 0)
        }
    }

    /**
     * Build the current AKEN native locator fixture without going through the
     * production serializer.  This keeps the native resolver test differential:
     * the C/Java parser must accept the exact v2 binary contract independently.
     */
    private fun encodeAkenNativeLocator(
        platform: String,
        nativeResourcePath: String,
        nativeBytes: ByteArray,
        nativeBindingsResourcePath: String,
        nativeBindings: ByteArray,
    ): ByteArray {
        val payload = ByteArrayOutputStream()
        payload.write(AKEN_NATIVE_LOCATOR_MAGIC)
        payload.write(AKEN_NATIVE_LOCATOR_VERSION)
        payload.write(0)
        writeU16(payload, 2)
        writeAkenNativeLocatorRecord(
            out = payload,
            kind = AKEN_NATIVE_LOCATOR_KIND_LIBRARY,
            platformId = akenNativePlatformId(platform),
            resourcePath = nativeResourcePath,
            storedBytes = nativeBytes,
        )
        writeAkenNativeLocatorRecord(
            out = payload,
            kind = AKEN_NATIVE_LOCATOR_KIND_BINDINGS,
            platformId = 0,
            resourcePath = nativeBindingsResourcePath,
            storedBytes = nativeBindings,
        )
        val payloadBytes = payload.toByteArray()
        val commitment = MessageDigest.getInstance("SHA-256").apply {
            update(AKEN_NATIVE_LOCATOR_COMMITMENT_DOMAIN)
            update(payloadBytes)
        }.digest()
        return try {
            ByteArray(payloadBytes.size + commitment.size).also { encoded ->
                payloadBytes.copyInto(encoded)
                commitment.copyInto(encoded, payloadBytes.size)
            }
        } finally {
            Arrays.fill(payloadBytes, 0)
            Arrays.fill(commitment, 0)
        }
    }

    private fun writeAkenNativeLocatorRecord(
        out: ByteArrayOutputStream,
        kind: Int,
        platformId: Int,
        resourcePath: String,
        storedBytes: ByteArray,
    ) {
        val route = resourcePath.toByteArray(StandardCharsets.US_ASCII)
        val digest = MessageDigest.getInstance("SHA-256").digest(storedBytes)
        val maskedRoute = maskAkenNativeLocatorRoute(route, kind, platformId, storedBytes.size, digest)
        try {
            out.write(kind)
            out.write(platformId)
            writeU16(out, route.size)
            writeInt(out, storedBytes.size)
            out.write(digest)
            out.write(maskedRoute)
        } finally {
            Arrays.fill(route, 0)
            Arrays.fill(digest, 0)
            Arrays.fill(maskedRoute, 0)
        }
    }

    private fun maskAkenNativeLocatorRoute(
        route: ByteArray,
        kind: Int,
        platformId: Int,
        storedLength: Int,
        digest: ByteArray,
    ): ByteArray {
        val masked = route.copyOf()
        var offset = 0
        var blockIndex = 0
        while (offset < masked.size) {
            val block = MessageDigest.getInstance("SHA-256").apply {
                update(AKEN_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN)
                update(kind.toByte())
                update(platformId.toByte())
                updateInt(this, storedLength)
                update(digest)
                updateInt(this, blockIndex++)
            }.digest()
            try {
                val count = minOf(block.size, masked.size - offset)
                repeat(count) { index ->
                    masked[offset + index] = (masked[offset + index].toInt() xor block[index].toInt()).toByte()
                }
                offset += count
            } finally {
                Arrays.fill(block, 0)
            }
        }
        return masked
    }

    private fun akenNativePlatformId(platform: String): Int = when (platform) {
        "windows-x64" -> 1
        "linux-x64" -> 2
        "macos-x64" -> 3
        "macos-arm64" -> 4
        else -> error("unsupported AKEN native fixture platform: $platform")
    }

    /**
     * Emit only fixed phase names, exit status, and the benchmark output digest.
     * The child output itself can contain fixture-specific failure text, so it
     * remains confined to the assertion message and is never copied into the
     * persistent phase stream.
     */
    private fun emitAkenFixturePhase(stage: String, result: ProcessResult) {
        require(stage.matches(Regex("[a-z0-9-]+")))
        val digest = result.output.lineSequence()
            .firstOrNull { it.startsWith("phase=aken-page-open ") }
            ?.split(' ')
            ?.firstOrNull { it.startsWith("output_digest=") }
            ?.substringAfter('=')
            ?.takeIf { it.matches(Regex("[0-9a-f]{16}")) }
            ?: "absent"
        println(
            "phase=aken-jni-fixture stage=$stage " +
                "status=${if (result.exitCode == 0) "pass" else "fail"} " +
                "exit_code=${result.exitCode} output_digest=$digest",
        )
        System.out.flush()
    }

    /**
     * Require exactly one sanitized page-open phase line without copying the
     * child process output into a persistent assertion or JUnit report.  A
     * timeout can otherwise leave an empty stream, while a duplicated line can
     * silently select the wrong profile; both cases must remain fail-closed and
     * must expose only bounded diagnostics.
     */
    private fun requireSingleAkenPhaseLine(result: ProcessResult, label: String): String {
        val phaseLines = result.output.lineSequence()
            .filter { it.startsWith("phase=aken-page-open ") }
            .toList()
        check(phaseLines.size == 1) {
            "$label phase-line-count=${phaseLines.size} " +
                "exit_code=${result.exitCode} output_chars=${result.output.length}"
        }
        return phaseLines.single()
    }

    private fun emitAkenStage(stage: String, status: String) {
        require(stage.matches(Regex("[a-z0-9-]+")))
        require(status.matches(Regex("[a-z0-9-]+")))
        println("phase=aken-jni-fixture stage=$stage status=$status")
        System.out.flush()
    }

    private fun runAkenJniRuntimeFixture(
        runtimeRoot: Path,
        extractDirectory: Path,
        expectedOutcome: String,
        label: String,
        timeoutSeconds: Long = 120L,
    ): ProcessResult {
        Files.createDirectories(extractDirectory)
        val isolatedHome = Files.createDirectories(extractDirectory.resolve("home"))
        val helperClasspath = jniHelperClasspathEntry()
        val classpath = runtimeRoot.toAbsolutePath().normalize().toString() +
            File.pathSeparator +
            helperClasspath.toAbsolutePath().normalize().toString()
        return run(
            command = listOf(
                javaTool("java").toString(),
                "-Xverify:all",
                "-Xcheck:jni",
                "-Djavashroud.debugNativeLoad=true",
                "-Djavashroud.native.extract.dir=${extractDirectory.toAbsolutePath().normalize()}",
                "-Djava.io.tmpdir=${extractDirectory.toAbsolutePath().normalize()}",
                "-Duser.home=${isolatedHome.toAbsolutePath().normalize()}",
                "-classpath",
                classpath,
                AKEN_JNI_FIXTURE_MAIN,
                expectedOutcome,
            ),
            directory = runtimeRoot.parent,
            label = label,
            timeoutSeconds = timeoutSeconds,
        )
    }

    private fun akenJniHarnessSource(
        entryToken: Long,
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
    ): String = """
        import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper;
        import java.lang.reflect.Method;
        import java.util.Arrays;

        public final class $AKEN_JNI_FIXTURE_MAIN {
            private static final long ENTRY_TOKEN = ${entryToken}L;
            private static final int PAGE_INDEX = $pageIndex;
            private static final String HANDLE = "${hexLower(encodedHandle)}";
            private static final String PROOF = "${hexLower(callSiteProof)}";

            public static void main(String[] args) throws Exception {
                if (args.length != 1) {
                    System.err.println("expected one outcome argument");
                    System.exit(2);
                }
                byte[] handle = decodeHex(HANDLE);
                byte[] proof = decodeHex(PROOF);
                try {
                    ensureAkenNativeKernel();
                    assertLegacyKernelUntried("AKEN VBC4 page");
                    String expectedOutcome = args[0];
                    if (expectedOutcome.startsWith("bench:")) {
                        runPageOpenBenchmark(expectedOutcome, handle, proof);
                        assertLegacyKernelUntried("AKEN VBC4 page benchmark");
                        return;
                    }
                    if (expectedOutcome.startsWith("result:")) {
                        Object result = JniMicrokernelHelper.executeAkenVmPage(
                            ENTRY_TOKEN,
                            handle,
                            PAGE_INDEX,
                            proof,
                            new Object[0]
                        );
                        String expectedValue = expectedOutcome.substring("result:".length());
                        if (!expectedValue.equals(String.valueOf(result))) {
                            System.err.println("unexpected AKEN real JNI result: " + result);
                            System.exit(3);
                        }
                        assertLegacyKernelUntried("AKEN VBC4 page execution");
                        System.out.println("AKEN real JNI current page fixture: PASS:executed");
                        return;
                    }
                    if (!expectedOutcome.startsWith("error:")) {
                        System.err.println("unsupported outcome: " + expectedOutcome);
                        System.exit(4);
                    }
                    String expectedMessage = expectedOutcome.substring("error:".length());
                    try {
                        JniMicrokernelHelper.executeAkenVmPage(
                            ENTRY_TOKEN,
                            handle,
                            PAGE_INDEX,
                            proof,
                            new Object[0]
                        );
                        System.err.println("AKEN real JNI current-page route unexpectedly returned");
                        System.exit(5);
                    } catch (SecurityException error) {
                        if (!expectedMessage.equals(error.getMessage())) {
                            System.err.println("unexpected AKEN real JNI failure: " + error.getMessage());
                            error.printStackTrace(System.err);
                            System.exit(6);
                        }
                        assertLegacyKernelUntried("AKEN VBC4 page rejection");
                        System.out.println("AKEN real JNI current page fixture: PASS:tampered");
                    }
                } finally {
                    Arrays.fill(handle, (byte) 0);
                    Arrays.fill(proof, (byte) 0);
                }
            }

            private static void runPageOpenBenchmark(String specification, byte[] handle, byte[] proof) throws Exception {
                String[] parts = specification.split(":", -1);
                if (parts.length != 3) {
                    throw new IllegalArgumentException("AKEN page benchmark specification is malformed");
                }
                int samples = parseBoundedPositive(parts[1], "samples");
                int warmup = parseBoundedNonNegative(parts[2], "warmup");
                Object[] arguments = new Object[0];
                long[] timings = new long[samples];
                long digest = 0x243f6a8885a308d3L;
                for (int index = 0; index < warmup; index++) {
                    Object result = JniMicrokernelHelper.executeAkenVmPage(
                        ENTRY_TOKEN, handle, PAGE_INDEX, proof, arguments
                    );
                    if (!"2".equals(String.valueOf(result))) {
                        throw new SecurityException("AKEN page benchmark warmup result mismatch");
                    }
                }
                long[] before = runtimeMetricsSnapshot();
                for (int index = 0; index < samples; index++) {
                    long started = System.nanoTime();
                    Object result = JniMicrokernelHelper.executeAkenVmPage(
                        ENTRY_TOKEN, handle, PAGE_INDEX, proof, arguments
                    );
                    timings[index] = System.nanoTime() - started;
                    if (!"2".equals(String.valueOf(result))) {
                        throw new SecurityException("AKEN page benchmark result mismatch");
                    }
                    digest = mixDigest(digest, ((long) index << 32) ^ 2L);
                }
                long[] after = runtimeMetricsSnapshot();
                long[] delta = subtractMetrics(after, before);
                long[] capabilities = runtimeCryptoCapabilities();
                if ((capabilities[0] != 0L && capabilities[0] != 1L) ||
                    (capabilities[1] != 0L && capabilities[1] != 1L)) {
                    throw new SecurityException("AKEN page benchmark crypto capability flags are invalid");
                }
                if ((capabilities[0] == 1L && delta[0] <= 0L) ||
                    (capabilities[0] == 0L && delta[1] <= 0L)) {
                    throw new SecurityException("AKEN page benchmark crypto dispatch contradicts capability probe");
                }
                Arrays.sort(timings);
                long p50 = percentile(timings, 50);
                long p95 = percentile(timings, 95);
                long p99 = percentile(timings, 99);
                long max = timings[timings.length - 1];
                if (delta[4] <= 0L || delta[8] <= 0L || delta[9] <= 0L || delta[11] <= 0L || delta[12] <= 0L ||
                    delta[13] <= 0L || delta[14] <= 0L || delta[15] <= 0L ||
                    delta[16] <= 0L || delta[10] != 0L || delta[17] != 0L ||
                    delta[18] != 0L || delta[19] != 0L || delta[20] != 0L ||
                    delta[21] != 0L || delta[22] != 0L) {
                    throw new SecurityException("AKEN page benchmark runtime/security counters failed closed");
                }
                System.out.println(
                    "phase=aken-page-open phase_mode=production phase_status=pass " +
                    "timing_unit=ns samples=" + samples + " warmup=" + warmup + " " +
                    "p50=" + p50 + " p95=" + p95 + " p99=" + p99 + " max=" + max + " " +
                    "cpu_hardware_aes=" + capabilities[0] + " cpu_hardware_ghash=" + capabilities[1] + " " +
                    "hardware_crypto_path=" + delta[0] + " software_crypto_path=" + delta[1] + " " +
                    "aes_block_count=" + delta[2] + " ghash_block_count=" + delta[3] + " " +
                    "vm_frame_reuse_count=" + delta[4] + " vm_heap_fallback_count=" + delta[5] + " " +
                    "resource_index_hit_count=" + delta[6] + " decompress_context_reuse_count=" + delta[7] + " " +
                    "jni_cache_hit_count=" + delta[8] + " auth_check_count=" + delta[9] + " " +
                    "auth_failure_count=" + delta[10] + " digest_check_count=" + delta[11] + " " +
                    "tag_check_count=" + delta[12] + " length_check_count=" + delta[13] + " " +
                    "structure_check_count=" + delta[14] + " jni_abi_check_count=" + delta[15] + " " +
                    "wipe_count=" + delta[16] + " wipe_failure_count=" + delta[17] + " " +
                    "plaintext_persistence_bytes=" + delta[18] + " fallback_count=" + delta[19] + " " +
                    "legacy_path_hits=" + delta[20] + " exception_count=" + delta[21] + " " +
                    "security_checks_skipped=" + delta[22] + " output_digest=" +
                    String.format(java.util.Locale.ROOT, "%016x", digest)
                );
            }

            private static long[] runtimeMetricsSnapshot() throws Exception {
                Method method = JniMicrokernelHelper.class.getDeclaredMethod("nativeRuntimeMetricsSnapshot");
                method.setAccessible(true);
                Object value = method.invoke(null);
                if (!(value instanceof long[])) {
                    throw new SecurityException("AKEN page benchmark metrics snapshot is unavailable");
                }
                return (long[]) value;
            }

            private static long[] runtimeCryptoCapabilities() throws Exception {
                Method method = JniMicrokernelHelper.class.getDeclaredMethod("nativeRuntimeCryptoCapabilities");
                method.setAccessible(true);
                Object value = method.invoke(null);
                if (!(value instanceof long[]) || ((long[]) value).length != 2) {
                    throw new SecurityException("AKEN page benchmark crypto capability probe is unavailable");
                }
                return (long[]) value;
            }

            private static long[] subtractMetrics(long[] after, long[] before) {
                if (after == null || before == null || after.length != 26 || before.length != 26) {
                    throw new SecurityException("AKEN page benchmark metrics snapshot length is invalid");
                }
                long[] delta = new long[after.length];
                for (int index = 0; index < delta.length; index++) {
                    if (after[index] < before[index]) {
                        throw new SecurityException("AKEN page benchmark metrics counter regressed");
                    }
                    delta[index] = after[index] - before[index];
                }
                return delta;
            }

            private static long mixDigest(long value, long input) {
                value ^= input + 0x9e3779b97f4a7c15L + (value << 6) + (value >>> 2);
                value ^= value >>> 30;
                value *= 0xbf58476d1ce4e5b9L;
                value ^= value >>> 27;
                value *= 0x94d049bb133111ebL;
                return value ^ (value >>> 31);
            }

            private static long percentile(long[] sorted, int percent) {
                int index = (sorted.length * percent + 99) / 100 - 1;
                if (index < 0) index = 0;
                if (index >= sorted.length) index = sorted.length - 1;
                return sorted[index];
            }

            private static int parseBoundedPositive(String value, String label) {
                int parsed = parseBoundedNonNegative(value, label);
                if (parsed <= 0) throw new IllegalArgumentException(label + " must be positive");
                return parsed;
            }

            private static int parseBoundedNonNegative(String value, String label) {
                try {
                    int parsed = Integer.parseInt(value);
                    if (parsed < 0 || parsed > 100000) throw new NumberFormatException();
                    return parsed;
                } catch (NumberFormatException error) {
                    throw new IllegalArgumentException(label + " must be in 0..100000", error);
                }
            }

            private static void ensureAkenNativeKernel() {
                try {
                    Method method = JniMicrokernelHelper.class.getDeclaredMethod("ensureAkenNativeKernel");
                    method.setAccessible(true);
                    method.invoke(null);
                } catch (ReflectiveOperationException error) {
                    throw new IllegalStateException("AKEN native loader is unavailable", error);
                }
            }

            private static void assertLegacyKernelUntried(String phase) {
                String status = JniMicrokernelHelper.getLoadStatus();
                if (!"untried".equals(status)) {
                    System.err.println(phase + " unexpectedly activated the legacy kernel: " + status);
                    System.exit(7);
                }
            }

            private static byte[] decodeHex(String value) {
                if ((value.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
                byte[] out = new byte[value.length() / 2];
                for (int index = 0; index < out.length; index++) {
                    int high = Character.digit(value.charAt(index * 2), 16);
                    int low = Character.digit(value.charAt(index * 2 + 1), 16);
                    if (high < 0 || low < 0) throw new IllegalArgumentException("invalid hex");
                    out[index] = (byte) ((high << 4) | low);
                }
                return out;
            }
        }
    """.trimIndent()

    private fun akenStringJniHarnessSource(
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
    ): String = """
        import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper;
        import io.github.hht0rro.javashroud.transforms.protection.StringEncryptionHelper;
        import java.lang.reflect.Method;
        import java.util.Arrays;

        public final class $AKEN_JNI_FIXTURE_MAIN {
            private static final int PAGE_INDEX = $pageIndex;
            private static final String HANDLE = "${hexLower(encodedHandle)}";
            private static final String PROOF = "${hexLower(callSiteProof)}";

            public static void main(String[] args) {
                if (args.length != 1) {
                    System.err.println("expected one outcome argument");
                    System.exit(2);
                }
                byte[] handle = decodeHex(HANDLE);
                byte[] proof = decodeHex(PROOF);
                try {
                    String expectedOutcome = args[0];
                    ensureAkenNativeKernel();
                    assertLegacyKernelUntried("AKEN native loader");
                    if (expectedOutcome.startsWith("string:")) {
                        String expected = expectedOutcome.substring("string:".length());
                        String first = invokeStringTerminal(handle, PAGE_INDEX, proof);
                        String second = invokeStringTerminal(handle, PAGE_INDEX, proof);
                        if (!expected.equals(first) || !expected.equals(second)) {
                            System.err.println("unexpected AKEN repeated string result: " + first + " / " + second);
                            System.exit(3);
                        }
                        assertLegacyKernelUntried("AKEN repeated string page open");
                        System.out.println("AKEN real JNI string page fixture: PASS:reopened");
                        return;
                    }
                    if (expectedOutcome.startsWith("result:")) {
                        String expected = expectedOutcome.substring("result:".length());
                        String actual = invokeStringTerminal(handle, PAGE_INDEX, proof);
                        if (!expected.equals(actual)) {
                            System.err.println("unexpected AKEN real JNI string result: " + actual);
                            System.exit(3);
                        }
                        assertLegacyKernelUntried("AKEN String terminal");
                        System.out.println("AKEN real JNI string page fixture: PASS:decoded");
                        return;
                    }
                    if (!expectedOutcome.startsWith("error:")) {
                        System.err.println("unsupported outcome: " + expectedOutcome);
                        System.exit(4);
                    }
                    String expectedMessage = expectedOutcome.substring("error:".length());
                    try {
                        invokeStringTerminal(handle, PAGE_INDEX, proof);
                        System.err.println("AKEN real JNI string-page route unexpectedly returned");
                        System.exit(5);
                    } catch (SecurityException error) {
                        if (!expectedMessage.equals(error.getMessage())) {
                            System.err.println("unexpected AKEN real JNI string failure: " + error.getMessage());
                            error.printStackTrace(System.err);
                            System.exit(6);
                        }
                        System.out.println("AKEN real JNI string page fixture: PASS:tampered");
                    }
                } finally {
                    Arrays.fill(handle, (byte) 0);
                    Arrays.fill(proof, (byte) 0);
                }
            }

            private static String invokeStringTerminal(byte[] handle, int pageIndex, byte[] proof) {
                try {
                    Method method = StringEncryptionHelper.class.getDeclaredMethod(
                        "invokeAkenStringTerminal", byte[].class, int.class, byte[].class);
                    method.setAccessible(true);
                    return (String) method.invoke(null, handle, pageIndex, proof);
                } catch (java.lang.reflect.InvocationTargetException error) {
                    Throwable cause = error.getCause();
                    if (cause instanceof RuntimeException) throw (RuntimeException) cause;
                    if (cause instanceof Error) throw (Error) cause;
                    throw new IllegalStateException("AKEN String terminal invocation failed", cause);
                } catch (ReflectiveOperationException error) {
                    throw new IllegalStateException("AKEN String terminal is unavailable", error);
                }
            }

            private static void ensureAkenNativeKernel() {
                try {
                    Method method = JniMicrokernelHelper.class.getDeclaredMethod("ensureAkenNativeKernel");
                    method.setAccessible(true);
                    method.invoke(null);
                } catch (ReflectiveOperationException error) {
                    throw new IllegalStateException("AKEN native loader is unavailable", error);
                }
            }

            private static void assertLegacyKernelUntried(String phase) {
                String status = JniMicrokernelHelper.getLoadStatus();
                if (!"untried".equals(status)) {
                    System.err.println(phase + " unexpectedly activated the legacy kernel: " + status);
                    System.exit(7);
                }
            }

            private static byte[] decodeHex(String value) {
                if ((value.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
                byte[] out = new byte[value.length() / 2];
                for (int index = 0; index < out.length; index++) {
                    int high = Character.digit(value.charAt(index * 2), 16);
                    int low = Character.digit(value.charAt(index * 2 + 1), 16);
                    if (high < 0 || low < 0) throw new IllegalArgumentException("invalid hex");
                    out[index] = (byte) ((high << 4) | low);
                }
                return out;
            }
        }
    """.trimIndent()

    private fun akenClassJniHarnessSource(
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
    ): String = """
        import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper;
        import java.lang.reflect.Method;
        import java.util.Arrays;

        public final class $AKEN_JNI_FIXTURE_MAIN {
            private static final int PAGE_INDEX = $pageIndex;
            private static final String HANDLE = "${hexLower(encodedHandle)}";
            private static final String PROOF = "${hexLower(callSiteProof)}";

            public static void main(String[] args) {
                if (args.length != 1) {
                    System.err.println("expected one outcome argument");
                    System.exit(2);
                }
                byte[] handle = decodeHex(HANDLE);
                byte[] proof = decodeHex(PROOF);
                try {
                    String expectedOutcome = args[0];
                    ensureAkenNativeKernel();
                    assertLegacyKernelUntried("AKEN native loader");
                    if (expectedOutcome.startsWith("result:")) {
                        byte[] opened = JniMicrokernelHelper.readAkenClassPage(handle, PAGE_INDEX, proof);
                        try {
                            String expected = expectedOutcome.substring("result:".length());
                            String actual = hexLower(opened);
                            if (!expected.equals(actual)) {
                                System.err.println("unexpected AKEN real JNI class result: " + actual);
                                System.exit(3);
                            }
                            assertLegacyKernelUntried("AKEN direct class page");
                            System.out.println("AKEN real JNI class page fixture: PASS:read");
                            return;
                        } finally {
                            Arrays.fill(opened, (byte) 0);
                        }
                    }
                    if (!expectedOutcome.startsWith("error:")) {
                        System.err.println("unsupported outcome: " + expectedOutcome);
                        System.exit(4);
                    }
                    String expectedMessage = expectedOutcome.substring("error:".length());
                    try {
                        byte[] opened = JniMicrokernelHelper.readAkenClassPage(handle, PAGE_INDEX, proof);
                        try {
                            System.err.println("AKEN real JNI class-page route unexpectedly returned");
                            System.exit(5);
                        } finally {
                            Arrays.fill(opened, (byte) 0);
                        }
                    } catch (SecurityException error) {
                        if (!expectedMessage.equals(error.getMessage())) {
                            System.err.println("unexpected AKEN real JNI class failure: " + error.getMessage());
                            error.printStackTrace(System.err);
                            System.exit(6);
                        }
                        System.out.println("AKEN real JNI class page fixture: PASS:tampered");
                    }
                } finally {
                    Arrays.fill(handle, (byte) 0);
                    Arrays.fill(proof, (byte) 0);
                }
            }

            private static String hexLower(byte[] value) {
                char[] chars = new char[value.length * 2];
                char[] alphabet = "0123456789abcdef".toCharArray();
                for (int index = 0; index < value.length; index++) {
                    int current = value[index] & 0xFF;
                    chars[index * 2] = alphabet[current >>> 4];
                    chars[index * 2 + 1] = alphabet[current & 0x0F];
                }
                return new String(chars);
            }

            private static void ensureAkenNativeKernel() {
                try {
                    Method method = JniMicrokernelHelper.class.getDeclaredMethod("ensureAkenNativeKernel");
                    method.setAccessible(true);
                    method.invoke(null);
                } catch (ReflectiveOperationException error) {
                    throw new IllegalStateException("AKEN native loader is unavailable", error);
                }
            }

            private static void assertLegacyKernelUntried(String phase) {
                String status = JniMicrokernelHelper.getLoadStatus();
                if (!"untried".equals(status)) {
                    System.err.println(phase + " unexpectedly activated the legacy kernel: " + status);
                    System.exit(7);
                }
            }

            private static byte[] decodeHex(String value) {
                if ((value.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
                byte[] out = new byte[value.length() / 2];
                for (int index = 0; index < out.length; index++) {
                    int high = Character.digit(value.charAt(index * 2), 16);
                    int low = Character.digit(value.charAt(index * 2 + 1), 16);
                    if (high < 0 || low < 0) throw new IllegalArgumentException("invalid hex");
                    out[index] = (byte) ((high << 4) | low);
                }
                return out;
            }
        }
    """.trimIndent()

    private fun akenNativeChunkJniHarnessSource(
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
    ): String {
        val handle = hexLower(encodedHandle)
        val proof = hexLower(callSiteProof)
        return """
            import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper;
            import java.lang.reflect.Method;
            import java.util.Arrays;

            public final class $AKEN_JNI_FIXTURE_MAIN {
                private static final int PAGE_INDEX = $pageIndex;
                private static final String HANDLE = "$handle";
                private static final String PROOF = "$proof";

                public static void main(String[] args) {
                    if (args.length != 1) {
                        System.err.println("expected one outcome argument");
                        System.exit(2);
                    }
                    byte[] handle = decodeHex(HANDLE);
                    byte[] proof = decodeHex(PROOF);
                    try {
                        String expectedOutcome = args[0];
                        ensureAkenNativeKernel();
                        assertLegacyKernelUntried("AKEN native loader");
                        if ("consume".equals(expectedOutcome)) {
                            JniMicrokernelHelper.consumeAkenNativeChunk(handle, PAGE_INDEX, proof);
                            assertLegacyKernelUntried("AKEN native chunk consumer");
                            System.out.println("AKEN real JNI native chunk fixture: PASS:consumed");
                            return;
                        }
                        if (!expectedOutcome.startsWith("error:")) {
                            System.err.println("unsupported outcome: " + expectedOutcome);
                            System.exit(4);
                        }
                        String expectedMessage = expectedOutcome.substring("error:".length());
                        try {
                            JniMicrokernelHelper.consumeAkenNativeChunk(handle, PAGE_INDEX, proof);
                            System.err.println("AKEN real JNI native chunk route unexpectedly returned");
                            System.exit(5);
                        } catch (SecurityException error) {
                            if (!expectedMessage.equals(error.getMessage())) {
                                System.err.println("unexpected AKEN real JNI native chunk failure: " + error.getMessage());
                                error.printStackTrace(System.err);
                                System.exit(6);
                            }
                            System.out.println("AKEN real JNI native chunk fixture: PASS:tampered");
                        }
                    } finally {
                        Arrays.fill(handle, (byte) 0);
                        Arrays.fill(proof, (byte) 0);
                    }
                }

                private static void ensureAkenNativeKernel() {
                    try {
                        Method method = JniMicrokernelHelper.class.getDeclaredMethod("ensureAkenNativeKernel");
                        method.setAccessible(true);
                        method.invoke(null);
                    } catch (ReflectiveOperationException error) {
                        throw new IllegalStateException("AKEN native loader is unavailable", error);
                    }
                }

                private static void assertLegacyKernelUntried(String phase) {
                    String status = JniMicrokernelHelper.getLoadStatus();
                    if (!"untried".equals(status)) {
                        System.err.println(phase + " unexpectedly activated the legacy kernel: " + status);
                        System.exit(7);
                    }
                }

                private static byte[] decodeHex(String value) {
                    if ((value.length() & 1) != 0) throw new IllegalArgumentException("odd hex length");
                    byte[] out = new byte[value.length() / 2];
                    for (int index = 0; index < out.length; index++) {
                        int high = Character.digit(value.charAt(index * 2), 16);
                        int low = Character.digit(value.charAt(index * 2 + 1), 16);
                        if (high < 0 || low < 0) throw new IllegalArgumentException("invalid hex");
                        out[index] = (byte) ((high << 4) | low);
                    }
                    return out;
                }
            }
        """.trimIndent()
    }

    private fun writeClasspathResource(root: Path, resourcePath: String, bytes: ByteArray) {
        require(bytes.isNotEmpty()) { "classpath fixture resource must not be empty" }
        val segments = resourcePath.split('/')
        require(
            segments.isNotEmpty() &&
                segments.all { segment -> segment.isNotEmpty() && segment != "." && segment != ".." },
        ) {
            "classpath fixture resource path is invalid"
        }
        var target = root.toAbsolutePath().normalize()
        for (segment in segments) target = target.resolve(segment)
        target = target.normalize()
        require(target.startsWith(root.toAbsolutePath().normalize())) { "classpath fixture resource escapes its root" }
        Files.createDirectories(checkNotNull(target.parent))
        Files.write(target, bytes)
    }

    private fun jniHelperClasspathEntry(): Path {
        val helperRelative = "io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.class"
        val helperClass = resolveSource("build/core-engine/classes/java/main/$helperRelative")
        var classesRoot = helperClass
        repeat(7) {
            classesRoot = checkNotNull(classesRoot.parent) { "AKEN fixture helper classes root is unavailable" }
        }
        check(Files.isRegularFile(classesRoot.resolve(helperRelative))) {
            "AKEN fixture must execute the current compiled JniMicrokernelHelper"
        }
        check(Files.isRegularFile(classesRoot.resolve("io/github/hht0rro/javashroud/transforms/protection/StringEncryptionHelper.class"))) {
            "AKEN fixture must execute the current compiled StringEncryptionHelper"
        }
        return classesRoot
    }

    private fun javaTool(name: String): Path {
        val executable = name + if (isWindows()) ".exe" else ""
        val javaHome = Path.of(System.getProperty("java.home")).toAbsolutePath().normalize()
        val candidates = listOf(
            javaHome.resolve("bin").resolve(executable),
            javaHome.parent?.resolve("bin")?.resolve(executable),
        ).filterNotNull()
        return candidates.firstOrNull { Files.isRegularFile(it) }
            ?: error("Unable to locate $executable from java.home=$javaHome")
    }

    private fun currentAkenHostPlatform(): AkenHostPlatform? {
        val osName = System.getProperty("os.name", "").lowercase()
        val osArch = System.getProperty("os.arch", "").lowercase()
        val x64 = osArch == "amd64" || osArch == "x86_64"
        val arm64 = osArch == "aarch64" || osArch == "arm64"
        return when {
            osName.startsWith("windows") && x64 ->
                AkenHostPlatform("windows-x64", "x86_64-windows-gnu", ".dll")
            osName.contains("linux") && x64 ->
                AkenHostPlatform("linux-x64", "x86_64-linux-gnu", ".so")
            osName.contains("mac") && x64 ->
                AkenHostPlatform("macos-x64", "x86_64-macos", ".dylib")
            osName.contains("mac") && arm64 ->
                AkenHostPlatform("macos-arm64", "aarch64-macos", ".dylib")
            else -> null
        }
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return try {
            hexLower(digest)
        } finally {
            Arrays.fill(digest, 0)
        }
    }

    private fun hexLower(bytes: ByteArray): String = buildString(bytes.size * 2) {
        for (value in bytes) append((value.toInt() and 0xFF).toString(16).padStart(2, '0'))
    }

    private fun compileProbe(
        zig: String,
        root: Path,
        sourceNativeDir: Path,
        probeSource: Path,
        include: String,
        additionalNativeFiles: Map<String, ByteArray> = emptyMap(),
    ): CompiledProbe {
        val scenarioDir = Files.createDirectories(root.resolve("valid"))
        val nativeDir = scenarioDir.resolve("native")
        copyTree(sourceNativeDir, nativeDir)
        Files.writeString(nativeDir.resolve("js_aken_page_locator.inc"), include, StandardCharsets.UTF_8)
        additionalNativeFiles.forEach { (name, bytes) ->
            require(name.isNotBlank() && !name.contains('/') && !name.contains('\\')) {
                "additional native fixture file name is invalid"
            }
            Files.write(nativeDir.resolve(name), bytes)
        }

        val probe = scenarioDir.resolve("aken_native_page_locator_probe.c")
        Files.copy(probeSource, probe, StandardCopyOption.REPLACE_EXISTING)
        val executable = scenarioDir.resolve(if (isWindows()) "aken_native_page_locator_probe.exe" else "aken_native_page_locator_probe")
        val command = compileCommand(zig, nativeDir, probe, executable)
        var compile = run(
            command = command,
            directory = scenarioDir,
            label = "compile-0",
            zigCache = scenarioDir.resolve("zig-cache-0"),
            timeoutSeconds = 300L,
        )
        for (attempt in 1..5) {
            if (compile.exitCode == 0 || !isTransientZigFailure(compile.output)) break
            compile = run(
                command = command,
                directory = scenarioDir,
                label = "compile-$attempt",
                zigCache = scenarioDir.resolve("zig-cache-$attempt"),
                timeoutSeconds = 300L,
            )
        }
        assertEquals(0, compile.exitCode, "valid native fixture must compile:\n${compile.output}")
        return CompiledProbe(scenarioDir, executable)
    }

    private fun runProbe(compiled: CompiledProbe, label: String): ProcessResult =
        run(
            command = listOf(compiled.executable.toString()),
            directory = compiled.directory,
            label = "$label-probe",
        )

    private fun patchGeneratedTable(source: Path, target: Path, expected: ByteArray, replacement: ByteArray) {
        require(expected.isNotEmpty() && expected.size == replacement.size)
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING)
        val image = Files.readAllBytes(target)
        try {
            val matches = occurrencesOf(image, expected)
            assertEquals(1, matches.size, "compiled probe must retain one generated-table occurrence")
            replacement.copyInto(image, destinationOffset = matches.single())
            Files.write(target, image)
        } finally {
            Arrays.fill(image, 0)
        }
    }

    private fun concatenate(records: List<ByteArray>): ByteArray {
        val total = records.sumOf { it.size }
        return ByteArray(total).also { blob ->
            var offset = 0
            records.forEach { record ->
                record.copyInto(blob, destinationOffset = offset)
                offset += record.size
            }
        }
    }

    private fun occurrencesOf(haystack: ByteArray, needle: ByteArray): IntArray {
        if (needle.size > haystack.size) return IntArray(0)
        return (0..haystack.size - needle.size)
            .filter { offset -> needle.indices.all { index -> haystack[offset + index] == needle[index] } }
            .toIntArray()
    }

    private fun encodeNativeUnsignedInts(values: IntArray): ByteArray =
        ByteBuffer.allocate(values.size * Int.SIZE_BYTES)
            .order(ByteOrder.nativeOrder())
            .apply { values.forEach(::putInt) }
            .array()

    private fun compileCommand(zig: String, nativeDir: Path, probe: Path, executable: Path): List<String> = buildList {
        addAll(
            listOf(
                zig,
                "cc",
                "-std=c11",
                "-O0",
                "-Wall",
                "-Wextra",
                // This full-linkage probe intentionally excludes -Werror: unrelated kernel warnings are not resolver failures.
                "-fwrapv",
                "-fno-exceptions",
                "-fvisibility=hidden",
                "-fno-unwind-tables",
                "-fno-asynchronous-unwind-tables",
                "-DZSTD_DISABLE_ASM=1",
                "-DZSTDLIB_VISIBLE=",
                "-DZSTDERRORLIB_VISIBLE=",
                "-DXXH_PUBLIC_API=",
                "-DJS_NATIVE_PROTECTION_NONE=1",
                "-o",
                executable.toString(),
            ),
        )
        addAll(FULL_NATIVE_SOURCES.map { name -> nativeDir.resolve(name).toString() })
        add(probe.toString())
        addAll(
            listOf(
                "-I",
                nativeDir.toString(),
                "-I",
                nativeDir.resolve("cross-compile").toString(),
                "-I",
                nativeDir.resolve("zstd").toString(),
                "-I",
                nativeDir.resolve("zstd/common").toString(),
                "-I",
                nativeDir.resolve("zstd/decompress").toString(),
            ),
        )
        when {
            isWindows() -> add("-ladvapi32")
            isLinux() -> {
                add("-Wl,-T,${nativeDir.resolve("js_protected_section_linux.ld")}")
                add("-ldl")
            }
        }
    }

    private fun fixtureRecord(
        entryToken: Long,
        pageIndex: Int,
        encodedHandle: ByteArray,
        rawProof: ByteArray,
        seed: Int,
        resourcePath: String,
        requireInlineEnvelope: Boolean,
    ): ByteArray {
        val kind = AkenResourceKind.Vbc4Method
        val targetPageSize = 512
        val codecVariant = AkenResourceCodec.CANONICAL_CODEC_VARIANT
        val layoutVariant = "aken4-frame1:fixture:12:8:head:AAAAAAAAAAA"
        val logicalIdentity = "fixture:native-locator:$seed".toByteArray(StandardCharsets.US_ASCII)
        val plaintext = ByteArray(128) { index -> (seed * 13 + index * 31 + 7).toByte() }
        val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (seed + index * 19).toByte() }
        val vbc4StateBindingLayoutDigest = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index ->
            (seed * 17 + index * 29 + 11).toByte()
        }
        var plan: AkenBuildPlan? = null
        var materialization: AkenPageMaterialization? = null
        var descriptorHandle: AkenHandle? = null
        var descriptorBytes: ByteArray? = null
        var routeBytes: ByteArray? = null
        var envelopeBytes: ByteArray? = null
        var envelope: AkenNativePageEnvelope? = null
        try {
            val buildPlan = AkenBuildPlan.create(commitment, SecureRandom())
            plan = buildPlan
            val page = buildPlan.registerPage(
                kind = kind,
                identity = logicalIdentity,
                pageIndex = pageIndex,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
                targetPageSize = targetPageSize,
                encodedHandleOverride = encodedHandle,
            )
            val input = AkenPageMaterializationInput.create(
                page = page,
                plaintext = plaintext,
                resourcePath = resourcePath,
                resourceOffset = seed + 17,
                callSiteProof = rawProof,
                logicalBindingPath = "fixture/native-locator/$seed",
            )
            val generated = AkenPageMaterializer.materializeAndWipe(
                plan = buildPlan,
                inputs = listOf(input),
            )
            materialization = generated
            plan = null

            val descriptor = generated.pagesForBuild().single().descriptorForBuild
            val handle = descriptor.handle
            descriptorHandle = handle
            val route = descriptor.route
            require(handle.encoded.contentEquals(encodedHandle)) {
                "materialized AKEN locator fixture did not retain its preassigned handle"
            }
            envelope = AkenNativePageEnvelope.create(
                entryToken = entryToken,
                handle = handle,
                descriptor = descriptor,
                rawCallSiteProof = rawProof,
            )
            assertEquals(requireInlineEnvelope, checkNotNull(envelope).hasInlineDescriptor)
            descriptorBytes = descriptor.encode()
            routeBytes = route.encode()
            envelopeBytes = checkNotNull(envelope).encode()
            return encodeCompilerRecord(
                entryToken = entryToken,
                resourceKind = kind,
                pageIndex = pageIndex,
                encodedHandle = encodedHandle,
                nativeEnvelope = checkNotNull(envelopeBytes),
                descriptor = checkNotNull(descriptorBytes),
                route = checkNotNull(routeBytes),
                vbc4StateBindingLayoutDigest = vbc4StateBindingLayoutDigest,
            )
        } finally {
            Arrays.fill(logicalIdentity, 0)
            Arrays.fill(plaintext, 0)
            Arrays.fill(commitment, 0)
            Arrays.fill(vbc4StateBindingLayoutDigest, 0)
            descriptorBytes?.let { Arrays.fill(it, 0) }
            routeBytes?.let { Arrays.fill(it, 0) }
            envelopeBytes?.let { Arrays.fill(it, 0) }
            envelope?.wipe()
            descriptorHandle?.wipe()
            materialization?.wipe()
            plan?.wipe()
        }
    }

    private fun encodeCompilerRecord(
        entryToken: Long,
        resourceKind: AkenResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
        nativeEnvelope: ByteArray,
        descriptor: ByteArray,
        route: ByteArray,
        vbc4StateBindingLayoutDigest: ByteArray,
    ): ByteArray {
        require(vbc4StateBindingLayoutDigest.size == AkenArtifactCommitment.DIGEST_SIZE) {
            "production AKEN compiler record VBC4 state-binding layout digest is invalid"
        }
        val binding = compilerRecordBinding(
            entryToken = entryToken,
            resourceKind = resourceKind,
            pageIndex = pageIndex,
            encodedHandle = encodedHandle,
            nativeEnvelope = nativeEnvelope,
            descriptor = descriptor,
            route = route,
            vbc4StateBindingLayoutDigest = vbc4StateBindingLayoutDigest,
        )
        try {
            return ByteArrayOutputStream().use { out ->
                writeLong(out, entryToken)
                out.write(resourceKind.id)
                writeInt(out, pageIndex)
                writeFramed(out, encodedHandle)
                writeFramed(out, nativeEnvelope)
                writeFramed(out, descriptor)
                writeFramed(out, route)
                out.write(vbc4StateBindingLayoutDigest)
                out.write(binding)
                out.toByteArray()
            }
        } finally {
            Arrays.fill(binding, 0)
        }
    }

    private fun compilerRecordBinding(
        entryToken: Long,
        resourceKind: AkenResourceKind,
        pageIndex: Int,
        encodedHandle: ByteArray,
        nativeEnvelope: ByteArray,
        descriptor: ByteArray,
        route: ByteArray,
        vbc4StateBindingLayoutDigest: ByteArray,
    ): ByteArray = MessageDigest.getInstance("SHA-256").apply {
        update(COMPILER_RECORD_BINDING_DOMAIN)
        updateLong(this, entryToken)
        update(resourceKind.id.toByte())
        updateInt(this, pageIndex)
        updateFramed(this, encodedHandle)
        updateFramed(this, nativeEnvelope)
        updateFramed(this, descriptor)
        updateFramed(this, route)
        update(vbc4StateBindingLayoutDigest)
    }.digest()

    private fun renderInclude(records: List<ByteArray>, offsets: IntArray = contiguousOffsets(records)): String {
        val actualOffsets = contiguousOffsets(records)
        val lengths = records.map { it.size }.toIntArray()
        val blob = ByteArray(lengths.sum())
        try {
            records.forEachIndexed { index, record -> record.copyInto(blob, destinationOffset = actualOffsets[index]) }
            return buildString {
                appendLine("/* AUTO-GENERATED AKEN v4 native current-page locator - DO NOT EDIT *" + "/")
                appendLine("#ifndef JS_AKEN_PAGE_LOCATOR_INC")
                appendLine("#define JS_AKEN_PAGE_LOCATOR_INC")
                appendLine("#include <stddef.h>")
                appendLine("#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_COUNT ${records.size}u")
                appendLine("#define JS_AKEN_NATIVE_PAGE_LOCATOR_BLOB_SIZE ${blob.size}u")
                appendLine()
                appendUnsignedBytes("js_aken_native_page_locator_blob", blob)
                appendUnsignedInts("js_aken_native_page_locator_record_offsets", offsets)
                appendUnsignedInts("js_aken_native_page_locator_record_lengths", lengths)
                appendLine("#endif")
            }
        } finally {
            Arrays.fill(actualOffsets, 0)
            Arrays.fill(lengths, 0)
            Arrays.fill(blob, 0)
        }
    }

    private fun contiguousOffsets(records: List<ByteArray>): IntArray {
        var offset = 0
        return IntArray(records.size) { index -> offset.also { offset += records[index].size } }
    }

    private fun StringBuilder.appendUnsignedBytes(name: String, value: ByteArray) {
        appendLine("static const volatile unsigned char $name[${maxOf(1, value.size)}] = {")
        if (value.isEmpty()) {
            appendLine("    0u")
        } else {
            value.forEachIndexed { index, byte ->
                if (index % 12 == 0) append("    ")
                append("0x%02Xu".format(byte.toInt() and 0xFF))
                if (index != value.lastIndex) append(", ")
                if (index % 12 == 11 || index == value.lastIndex) appendLine()
            }
        }
        appendLine("};")
    }

    private fun StringBuilder.appendUnsignedInts(name: String, value: IntArray) {
        appendLine("static const volatile unsigned int $name[${maxOf(1, value.size)}] = {")
        if (value.isEmpty()) {
            appendLine("    0u")
        } else {
            value.forEachIndexed { index, entry ->
                if (index % 8 == 0) append("    ")
                append("${entry}u")
                if (index != value.lastIndex) append(", ")
                if (index % 8 == 7 || index == value.lastIndex) appendLine()
            }
        }
        appendLine("};")
    }

    private fun run(
        command: List<String>,
        directory: Path,
        label: String,
        zigCache: Path? = null,
        timeoutSeconds: Long = 180L,
    ): ProcessResult {
        require(timeoutSeconds > 0L) { "process timeout must be positive" }
        val outputFile = directory.resolve("$label.log")
        val builder = ProcessBuilder(command)
            .directory(directory.toFile())
            .redirectErrorStream(true)
            .redirectOutput(outputFile.toFile())
        zigCache?.let { cache ->
            builder.environment()["ZIG_GLOBAL_CACHE_DIR"] = cache.resolve("global").toString()
            builder.environment()["ZIG_LOCAL_CACHE_DIR"] = cache.resolve("local").toString()
        }
        val process = builder.start()
        val completed = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!completed) process.destroyForcibly().waitFor(10, TimeUnit.SECONDS)
        val output = Files.readString(outputFile, StandardCharsets.UTF_8)
        assertTrue(
            completed,
            "process timed out after ${timeoutSeconds}s: ${command.joinToString(" ")}\n$output",
        )
        return ProcessResult(process.exitValue(), output)
    }

    private fun isTransientZigFailure(output: String): Boolean =
        output.isBlank() ||
            output.contains("CacheCheckFailed") ||
            output.contains("file_open Unexpected") ||
            output.contains(":1:1: error: Unexpected") ||
            output.trim() == "Unexpected" ||
            output.contains("sub-compilation of mingw-w64") ||
            (output.contains("avx10_2satcvtintrin.h") && output.contains("cannot open file")) ||
            (output.contains("zig-x86_64-windows") && output.contains("no such file or directory")) ||
            (output.contains("unable to load '") && output.contains("': Unexpected"))

    /**
     * The normal regression run keeps one 100-sample production profile bounded.
     * A dedicated performance machine sets [JS_AKEN_PAGE_OPEN_BENCH_MATRIX] to
     * run the plan's complete 100/1,000/10,000/100,000 profile set using the
     * same generated current-format artifact and attached-JVM page-open path.
     */
    private fun pageOpenBenchmarkProfiles(): List<Int> {
        val matrix = System.getenv("JS_AKEN_PAGE_OPEN_BENCH_MATRIX")
            ?.trim()
            ?.lowercase()
            ?.let { it == "1" || it == "true" || it == "yes" }
            ?: false
        if (matrix) return listOf(100, 1_000, 10_000, 100_000)
        return listOf(
            System.getenv("JS_AKEN_PAGE_OPEN_BENCH_SAMPLES")
                ?.toIntOrNull()
                ?.takeIf { it in 100..100_000 }
            ?: 100,
        )
    }

    private fun pageOpenBenchmarkTimeoutSeconds(): Long {
        val matrix = System.getenv("JS_AKEN_PAGE_OPEN_BENCH_MATRIX")
            ?.trim()
            ?.lowercase()
            ?.let { it == "1" || it == "true" || it == "yes" }
            ?: false
        val configured = System.getenv("JS_AKEN_PAGE_OPEN_BENCH_TIMEOUT_SECONDS")
            ?.toLongOrNull()
            ?.takeIf { it in 120L..86_400L }
        /*
         * A dedicated single-profile lane may set an explicit timeout without
         * enabling the complete 100/1,000/10,000/100,000 matrix.  Honor that
         * bounded value in either mode; otherwise keep normal regression runs
         * at 120 seconds and the full matrix at a finite one-hour default.
         */
        return configured ?: if (matrix) 3_600L else 120L
    }

    private fun findZig(): String? = listOfNotNull(System.getenv("JAVASHROUD_ZIG"), "zig").firstOrNull { candidate ->
        runCatching {
            val process = ProcessBuilder(candidate, "version").redirectErrorStream(true).start()
            process.inputStream.bufferedReader().use { it.readText() }
            process.waitFor(10, TimeUnit.SECONDS) && process.exitValue() == 0
        }.getOrDefault(false)
    }

    private fun resolveSource(relative: String): Path {
        var current = Path.of("").toAbsolutePath()
        while (true) {
            val direct = current.resolve(relative)
            if (Files.exists(direct)) return direct
            val nested = current.resolve("core-engine").resolve(relative)
            if (Files.exists(nested)) return nested
            current = current.parent ?: error("Unable to locate $relative")
        }
    }

    private fun copyTree(source: Path, target: Path) {
        Files.walk(source).use { paths ->
            paths.forEach { path ->
                val destination = target.resolve(source.relativize(path).toString())
                if (Files.isDirectory(path)) {
                    Files.createDirectories(destination)
                } else {
                    Files.createDirectories(destination.parent)
                    Files.copy(path, destination, StandardCopyOption.REPLACE_EXISTING)
                }
            }
        }
    }

    private fun deleteTree(path: Path) {
        var lastFileSystemFailure: java.nio.file.FileSystemException? = null
        repeat(20) { attempt ->
            if (!Files.exists(path)) return
            try {
                Files.walk(path).use { paths ->
                    paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
                }
                return
            } catch (failure: java.nio.file.FileSystemException) {
                lastFileSystemFailure = failure
                Thread.sleep(100L * (attempt + 1L))
            }
        }
        throw checkNotNull(lastFileSystemFailure) {
            "Unable to delete native probe tree after bounded retry"
        }
    }

    private fun isWindows(): Boolean = System.getProperty("os.name").startsWith("Windows", ignoreCase = true)

    private fun isLinux(): Boolean = System.getProperty("os.name").contains("Linux", ignoreCase = true)

    private fun writeInt(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 24) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeU16(out: ByteArrayOutputStream, value: Int) {
        require(value in 0..0xFFFF) { "AKEN locator u16 fixture value is invalid" }
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeLong(out: ByteArrayOutputStream, value: Long) {
        for (shift in 56 downTo 0 step 8) out.write((value ushr shift).toInt() and 0xFF)
    }

    private fun writeFramed(out: ByteArrayOutputStream, value: ByteArray) {
        writeInt(out, value.size)
        out.write(value)
    }

    private fun updateInt(digest: MessageDigest, value: Int) {
        digest.update((value ushr 24).toByte())
        digest.update((value ushr 16).toByte())
        digest.update((value ushr 8).toByte())
        digest.update(value.toByte())
    }

    private fun updateLong(digest: MessageDigest, value: Long) {
        for (shift in 56 downTo 0 step 8) digest.update((value ushr shift).toByte())
    }

    private fun updateFramed(digest: MessageDigest, value: ByteArray) {
        updateInt(digest, value.size)
        digest.update(value)
    }

    private data class AkenHostPlatform(
        val platformId: String,
        val zigTarget: String,
        val fileSuffix: String,
    )

    private data class CompiledProbe(val directory: Path, val executable: Path)

    private data class ProcessResult(val exitCode: Int, val output: String)

    private companion object {
        const val AKEN_JNI_FIXTURE_MAIN = "AkenCurrentPageJniFixtureMain"
        const val AKEN_NATIVE_LOCATOR_VERSION = 2
        const val AKEN_NATIVE_LOCATOR_KIND_LIBRARY = 1
        const val AKEN_NATIVE_LOCATOR_KIND_BINDINGS = 2
        val AKEN_NATIVE_LOCATOR_MAGIC = byteArrayOf(0xD7.toByte(), 0xA4.toByte(), 0x91.toByte(), 0xE3.toByte())
        val AKEN_NATIVE_LOCATOR_COMMITMENT_DOMAIN =
            "javashroud-aken-native-locator-commitment-v2".toByteArray(StandardCharsets.US_ASCII)
        val AKEN_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN =
            "javashroud-aken-native-locator-route-mask-v2".toByteArray(StandardCharsets.US_ASCII)
        val COMPILER_RECORD_BINDING_DOMAIN =
            "native-page-locator-compile-input".toByteArray(StandardCharsets.US_ASCII)
        val FULL_NATIVE_SOURCES = listOf(
            "js_kernel.c",
            "js_helpers.c",
            "js_native_common.c",
            "js_crypto.c",
            "js_antidebug.c",
            "js_protected_section.c",
            "js_vm_core.c",
            "js_vm_resource.c",
            "js_vm_symbol.c",
            "js_jni_runtime.c",
            "js_machine_id.c",
            "zstd/common/debug.c",
            "zstd/common/entropy_common.c",
            "zstd/common/error_private.c",
            "zstd/common/fse_decompress.c",
            "zstd/common/xxhash.c",
            "zstd/common/zstd_common.c",
            "zstd/decompress/huf_decompress.c",
            "zstd/decompress/zstd_ddict.c",
            "zstd/decompress/zstd_decompress.c",
            "zstd/decompress/zstd_decompress_block.c",
        )
    }
}
