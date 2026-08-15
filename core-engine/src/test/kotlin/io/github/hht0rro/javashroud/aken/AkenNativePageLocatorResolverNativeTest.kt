package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.NativeVmBuildProfile
import io.github.hht0rro.javashroud.transforms.protection.Vbc4EntryMetadata
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
import io.github.hht0rro.javashroud.transforms.protection.VmBytecodeSerializer
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHighValueLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativePageEnvelope
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceCodec
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRoutingMetadata
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorFragment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorRole
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimePageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenSealingProofMetadata
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4FinalizationLayout
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PendingPage
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
        var bootMaterial: ByteArray? = null
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
            bootMaterial = runtimeBootMaterial(buildContext)
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
                bootMaterial = checkNotNull(bootMaterial),
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
                bootMaterial?.let { Arrays.fill(it, 0) }
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
        val fragments = ArrayList<BoundPayloadFragmentFixture>()
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
            val sourceFragments = evaluatorPlan.javaFragments + evaluatorPlan.nativeFragments + listOf(evaluatorPlan.terminal)
            require(sourceFragments.size == 7) { "AKEN bound-payload fixture graph must contain seven fragments" }
            sourceFragments.forEach { fragment ->
                fragments += BoundPayloadFragmentFixture(
                    ordinal = fragment.ordinal,
                    family = fragment.family,
                    shape = fragment.shape,
                    callToken = fragment.callToken,
                    tablePermutation = fragment.tablePermutation,
                )
            }
            require(fragments.map { it.ordinal }.sorted() == (0 until 7).toList()) {
                "AKEN bound-payload fixture graph ordinals are incomplete or duplicated"
            }

            val token = currentPage.entryToken.toULong().toString(16).uppercase().padStart(16, '0')
            return buildString {
                appendLine("/* AUTO-GENERATED AKEN v4 native bound-payload fixture - DO NOT EDIT */")
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
                appendBoundPayloadBytes("TEST_ENCODED_PAYLOAD", encodedPayload)
                appendBoundPayloadBytes("TEST_EXPECTED_PLAINTEXT", expectedPlaintext)
                appendLine()
                fragments.forEachIndexed { index, fragment ->
                    appendBoundPayloadBytes("TEST_FRAGMENT_${index}_SHAPE", fragment.shape)
                    appendBoundPayloadBytes("TEST_FRAGMENT_${index}_CALL_TOKEN", fragment.callToken)
                    appendBoundPayloadInts("TEST_FRAGMENT_${index}_TABLE", fragment.tablePermutation)
                    appendLine()
                }
                appendLine("static const js_aken_evaluator_fragment TEST_EVALUATOR_FRAGMENTS[JS_AKEN_EVALUATOR_FRAGMENT_COUNT] = {")
                fragments.forEachIndexed { index, fragment ->
                    appendLine("    {")
                    appendLine("        .ordinal = ${fragment.ordinal},")
                    appendLine("        .family = ${fragment.family},")
                    appendLine("        .shape = TEST_FRAGMENT_${index}_SHAPE,")
                    appendLine("        .shape_len = sizeof(TEST_FRAGMENT_${index}_SHAPE),")
                    appendLine("        .call_token = TEST_FRAGMENT_${index}_CALL_TOKEN,")
                    appendLine("        .call_token_len = sizeof(TEST_FRAGMENT_${index}_CALL_TOKEN),")
                    appendLine("        .table_permutation = TEST_FRAGMENT_${index}_TABLE,")
                    appendLine("        .table_permutation_len = sizeof(TEST_FRAGMENT_${index}_TABLE) / sizeof(TEST_FRAGMENT_${index}_TABLE[0]),")
                    appendLine(if (index == fragments.lastIndex) "    }" else "    },")
                }
                appendLine("};")
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
            fragments.forEach(BoundPayloadFragmentFixture::wipe)
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

    private fun StringBuilder.appendBoundPayloadInts(name: String, value: IntArray) {
        require(value.size == 32) { "AKEN native evaluator permutation must have width 32" }
        append("static const uint32_t ").append(name).append('[').append(value.size).appendLine("] = {")
        value.forEachIndexed { index, entry ->
            if (index % 8 == 0) append("    ")
            append(entry.toUInt()).append('u')
            if (index != value.lastIndex) append(", ")
            if (index % 8 == 7 || index == value.lastIndex) appendLine()
        }
        appendLine("};")
    }

    private fun parseProductionCurrentPage(record: ByteArray): ProductionCurrentPage {
        require(record.size in 1..(512 * 1024)) {
            "production AKEN compiler record size is invalid"
        }
        val input = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN)
        require(input.remaining() >= 1 + Long.SIZE_BYTES + 1 + Int.SIZE_BYTES + Int.SIZE_BYTES) {
            "production AKEN compiler record is truncated"
        }
        require((input.get().toInt() and 0xFF) == 1) {
            "production AKEN compiler record version is unsupported"
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
        val binding = ByteArray(AkenArtifactCommitment.DIGEST_SIZE)
        var retainHandle = false
        try {
            require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) {
                "production AKEN compiler record handle size is invalid"
            }
            require(nativeEnvelope.isNotEmpty())
            require(descriptor.isNotEmpty())
            require(route.isNotEmpty())
            require(input.remaining() == binding.size) {
                "production AKEN compiler record binding length is invalid"
            }
            input.get(binding)
            val expectedBinding = compilerRecordBinding(
                entryToken = entryToken,
                resourceKind = resourceKind,
                pageIndex = pageIndex,
                encodedHandle = encodedHandle,
                nativeEnvelope = nativeEnvelope,
                descriptor = descriptor,
                route = route,
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
        require(input.remaining() >= 1 + Long.SIZE_BYTES + 1 + Int.SIZE_BYTES + Int.SIZE_BYTES) {
            "production AKEN compiler record is truncated"
        }
        require((input.get().toInt() and 0xFF) == COMPILER_RECORD_VERSION) {
            "production AKEN compiler record version is unsupported"
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
        val binding = ByteArray(AkenArtifactCommitment.DIGEST_SIZE)
        try {
            require(input.remaining() == binding.size) {
                "production AKEN compiler record binding length is invalid"
            }
            input.get(binding)
            return AkenRuntimePageDescriptor.decode(descriptorBytes)
        } finally {
            Arrays.fill(encodedHandle, 0)
            Arrays.fill(nativeEnvelope, 0)
            Arrays.fill(descriptorBytes, 0)
            Arrays.fill(route, 0)
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


    private class BoundPayloadFragmentFixture(
        val ordinal: Int,
        val family: Int,
        val shape: ByteArray,
        val callToken: ByteArray,
        val tablePermutation: IntArray,
    ) {
        fun wipe() {
            Arrays.fill(shape, 0)
            Arrays.fill(callToken, 0)
            Arrays.fill(tablePermutation, 0)
        }
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
    ): Path {
        val scenarioDir = Files.createDirectories(root.resolve("jni-native"))
        val nativeDir = scenarioDir.resolve("native")
        copyTree(sourceNativeDir, nativeDir)
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
                "-DJS_AKEN_JNI_FIXTURE_DIAGNOSTICS=1",
                "-o",
                library.toString(),
            ),
        )
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

    private fun akenVbc4ExecutorContext(): Vbc4BuildContext = Vbc4BuildContext(
        masterKey = ByteArray(32) { index -> (index * 7 + 0x31).toByte() },
        nativeSeed = 0x414B_454E_5634_3001L,
        jarLayoutDigest = ByteArray(32) { index -> (index * 11 + 0x17).toByte() },
        nativeVmProfile = NativeVmBuildProfile(
            parserRowProfile = 0,
            operandAccessProfile = 0,
        ),
    )

    /**
     * Transitional test-only material for the still-legacy inner VBC4 parser.
     * The production AKEN route, locator, evaluator and page opener never carry
     * this array; the fixture installs it only inside its isolated child JVM.
     */
    private fun runtimeBootMaterial(context: Vbc4BuildContext): ByteArray {
        val partitions = context.runtimeKeyPartitions
        val material = ByteArray(4 + 64 + partitions.totalSlots * 32)
        return try {
            material[0] = 2
            material[1] = partitions.resourcePartitionCount.toByte()
            material[2] = partitions.totalSlots.toByte()
            material[3] = 0
            context.masterKey.copyInto(material, destinationOffset = 4)
            context.jarLayoutDigest.copyInto(material, destinationOffset = 36)
            for (slot in 0 until partitions.totalSlots) {
                val key = partitions.copyKeyForSlot(slot)
                try {
                    key.copyInto(material, destinationOffset = 68 + slot * 32)
                } finally {
                    Arrays.fill(key, 0)
                }
            }
            material
        } catch (error: Throwable) {
            Arrays.fill(material, 0)
            throw error
        }
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
        bootMaterial: ByteArray,
    ): Path {
        require(pageResourceBytes.isNotEmpty()) { "real AKEN JNI page resource must not be empty" }
        require(encodedHandle.size == AkenHandle.ENCODED_HANDLE_SIZE) { "real AKEN JNI handle size is invalid" }
        require(pageIndex >= 0) { "real AKEN JNI page index is invalid" }
        require(callSiteProof.isNotEmpty()) { "real AKEN JNI call-site proof must not be empty" }
        require(bootMaterial.isNotEmpty()) { "real AKEN JNI transitional VBC4 boot material must not be empty" }

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
                bootMaterial = bootMaterial,
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
        val nativeBytes = Files.readAllBytes(nativeLibrary)
        try {
            writeClasspathResource(runtimeRoot, nativeResourcePath, nativeBytes)
            val locator = buildString {
                append("AKEN_NATIVE_LOCATOR_V1")
                append('|')
                append(platform.platformId)
                append('|')
                append(nativeResourcePath)
                append('|')
                append(platform.fileSuffix)
                append('|')
                append(nativeBytes.size)
                append('|')
                append(sha256Hex(nativeBytes))
            }.toByteArray(StandardCharsets.US_ASCII)
            try {
                writeClasspathResource(runtimeRoot, "META-INF/aken/native.locator", locator)
            } finally {
                Arrays.fill(locator, 0)
            }
        } finally {
            Arrays.fill(nativeBytes, 0)
        }
        writeClasspathResource(runtimeRoot, pageResourcePath, pageResourceBytes)
        return runtimeRoot
    }

    private fun runAkenJniRuntimeFixture(
        runtimeRoot: Path,
        extractDirectory: Path,
        expectedOutcome: String,
        label: String,
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
            timeoutSeconds = 120L,
        )
    }

    private fun akenJniHarnessSource(
        entryToken: Long,
        encodedHandle: ByteArray,
        pageIndex: Int,
        callSiteProof: ByteArray,
        bootMaterial: ByteArray,
    ): String = """
        import io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper;
        import java.lang.reflect.Method;
        import java.util.Arrays;

        public final class $AKEN_JNI_FIXTURE_MAIN {
            private static final long ENTRY_TOKEN = ${entryToken}L;
            private static final int PAGE_INDEX = $pageIndex;
            private static final String HANDLE = "${hexLower(encodedHandle)}";
            private static final String PROOF = "${hexLower(callSiteProof)}";
            private static final String BOOT_MATERIAL = "${hexLower(bootMaterial)}";

            public static void main(String[] args) throws Exception {
                if (args.length != 1) {
                    System.err.println("expected one outcome argument");
                    System.exit(2);
                }
                installBootMaterial();
                String expectedOutcome = args[0];
                if (expectedOutcome.startsWith("result:")) {
                    Object result = JniMicrokernelHelper.executeAkenVmPage(
                        ENTRY_TOKEN,
                        decodeHex(HANDLE),
                        PAGE_INDEX,
                        decodeHex(PROOF),
                        new Object[0]
                    );
                    String expectedValue = expectedOutcome.substring("result:".length());
                    if (!expectedValue.equals(String.valueOf(result))) {
                        System.err.println("unexpected AKEN real JNI result: " + result);
                        System.exit(3);
                    }
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
                        decodeHex(HANDLE),
                        PAGE_INDEX,
                        decodeHex(PROOF),
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
                    System.out.println("AKEN real JNI current page fixture: PASS:tampered");
                }
            }

            private static void installBootMaterial() throws Exception {
                byte[] material = decodeHex(BOOT_MATERIAL);
                try {
                    Method ensureKernel = JniMicrokernelHelper.class.getDeclaredMethod("ensureAkenNativeKernel");
                    ensureKernel.setAccessible(true);
                    ensureKernel.invoke(null);

                    Method method = JniMicrokernelHelper.class.getDeclaredMethod(
                        "nativeInstallBootMaterial",
                        byte[].class
                    );
                    method.setAccessible(true);
                    Object installed = method.invoke(null, (Object) material);
                    if (!Boolean.TRUE.equals(installed)) {
                        throw new IllegalStateException("transitional VBC4 boot material was rejected");
                    }
                } finally {
                    Arrays.fill(material, (byte) 0);
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
        val helper = Class.forName(
            "io.github.hht0rro.javashroud.transforms.protection.JniMicrokernelHelper",
            false,
            javaClass.classLoader,
        )
        val location = checkNotNull(helper.protectionDomain.codeSource?.location) {
            "JniMicrokernelHelper code source is unavailable"
        }
        return Path.of(location.toURI()).toAbsolutePath().normalize()
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
        val locatorToken = ByteArray(AkenHandle.LOCATOR_TOKEN_SIZE) { index -> (seed * 3 + index * 11).toByte() }
        val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (seed + index * 19).toByte() }
        val javaFragments = List(3) { ordinal -> runtimeFragment(AkenRuntimeEvaluatorRole.Java, ordinal, seed) }
        val nativeFragments = List(3) { ordinal -> runtimeFragment(AkenRuntimeEvaluatorRole.Native, ordinal + 3, seed) }
        val terminal = runtimeFragment(AkenRuntimeEvaluatorRole.Terminal, 6, seed)
        var fingerprint: ByteArray? = null
        var handle: AkenHandle? = null
        var descriptorBytes: ByteArray? = null
        var routeBytes: ByteArray? = null
        var envelopeBytes: ByteArray? = null
        var envelope: AkenNativePageEnvelope? = null
        try {
            fingerprint = AkenRuntimeEvaluatorPlan.computeFingerprint(
                resourceKind = kind,
                logicalIdentity = logicalIdentity,
                pageIndex = pageIndex,
                targetPageSize = targetPageSize,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
                handleEncoding = encodedHandle,
                locatorToken = locatorToken,
                javaFragments = javaFragments,
                nativeFragments = nativeFragments,
                terminal = terminal,
            )
            val evaluatorPlan = AkenRuntimeEvaluatorPlan.create(
                javaFragments = javaFragments,
                nativeFragments = nativeFragments,
                terminal = terminal,
                fingerprint = checkNotNull(fingerprint),
            )
            handle = AkenHandle.create(
                resourceKind = kind,
                pageIndex = pageIndex,
                encoded = encodedHandle,
                locatorToken = locatorToken,
                evaluatorFingerprint = checkNotNull(fingerprint),
            )
            val route = AkenRoutingMetadata.fromHandle(
                handle = checkNotNull(handle),
                logicalIdentity = logicalIdentity,
                resourcePath = resourcePath,
                resourceOffset = seed + 17,
                storedLength = 511,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
            )
            val proof = AkenSealingProofMetadata.create(
                leafIdentity = AkenHighValueLeafIdentity.fromHandle(checkNotNull(handle), logicalIdentity),
                artifactCommitment = commitment,
                meshRoot = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { 0x31 },
                leafDigest = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { 0x42 },
                siblings = listOf(ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { 0x53 }),
                siblingIsLeft = listOf(true),
                callSiteProof = rawProof,
                codecVariant = codecVariant,
                layoutVariant = layoutVariant,
            )
            val descriptor = AkenRuntimePageDescriptor.create(
                handle = checkNotNull(handle),
                logicalIdentity = logicalIdentity,
                route = route,
                proof = proof,
                targetPageSize = targetPageSize,
                evaluatorPlan = evaluatorPlan,
            )
            envelope = AkenNativePageEnvelope.create(
                entryToken = entryToken,
                handle = checkNotNull(handle),
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
            )
        } finally {
            Arrays.fill(logicalIdentity, 0)
            Arrays.fill(locatorToken, 0)
            Arrays.fill(commitment, 0)
            fingerprint?.let { Arrays.fill(it, 0) }
            descriptorBytes?.let { Arrays.fill(it, 0) }
            routeBytes?.let { Arrays.fill(it, 0) }
            envelopeBytes?.let { Arrays.fill(it, 0) }
            envelope?.wipe()
            handle?.wipe()
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
    ): ByteArray {
        val binding = compilerRecordBinding(entryToken, resourceKind, pageIndex, encodedHandle, nativeEnvelope, descriptor, route)
        try {
            return ByteArrayOutputStream().use { out ->
                out.write(COMPILER_RECORD_VERSION)
                writeLong(out, entryToken)
                out.write(resourceKind.id)
                writeInt(out, pageIndex)
                writeFramed(out, encodedHandle)
                writeFramed(out, nativeEnvelope)
                writeFramed(out, descriptor)
                writeFramed(out, route)
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
    ): ByteArray = MessageDigest.getInstance("SHA-256").apply {
        update(COMPILER_RECORD_BINDING_DOMAIN)
        updateLong(this, entryToken)
        update(resourceKind.id.toByte())
        updateInt(this, pageIndex)
        updateFramed(this, encodedHandle)
        updateFramed(this, nativeEnvelope)
        updateFramed(this, descriptor)
        updateFramed(this, route)
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
                appendLine("#define JS_AKEN_NATIVE_PAGE_LOCATOR_RECORD_FORMAT_VERSION 1u")
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

    private fun runtimeFragment(role: AkenRuntimeEvaluatorRole, ordinal: Int, seed: Int): AkenRuntimeEvaluatorFragment {
        val shape = ByteArray(65) { index -> (seed + role.id * 41 + ordinal * 17 + index).toByte() }
        val callToken = ByteArray(32) { index -> (seed * 3 + role.id * 23 + ordinal * 13 + index).toByte() }
        val tablePermutation = IntArray(32) { index -> (index + ordinal) and 31 }
        try {
            shape[0] = 1
            return AkenRuntimeEvaluatorFragment.create(
                role = role,
                ordinal = ordinal,
                family = (seed + ordinal * 5) and 0x0F,
                shape = shape,
                callToken = callToken,
                tablePermutation = tablePermutation,
            )
        } finally {
            Arrays.fill(shape, 0)
            Arrays.fill(callToken, 0)
            Arrays.fill(tablePermutation, 0)
        }
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
            output.contains("sub-compilation of mingw-w64") ||
            (output.contains("unable to load '") && output.contains("': Unexpected"))

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
        const val COMPILER_RECORD_VERSION = 1
        val COMPILER_RECORD_BINDING_DOMAIN =
            "AKEN-v4-native-page-locator-compile-input-v1".toByteArray(StandardCharsets.US_ASCII)
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
