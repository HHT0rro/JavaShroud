package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.NativeRecompilationTransforms
import io.github.hht0rro.javashroud.transforms.protection.Vbc4BuildContext
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
import java.io.ByteArrayOutputStream
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

    private fun compileProbe(
        zig: String,
        root: Path,
        sourceNativeDir: Path,
        probeSource: Path,
        include: String,
    ): CompiledProbe {
        val scenarioDir = Files.createDirectories(root.resolve("valid"))
        val nativeDir = scenarioDir.resolve("native")
        copyTree(sourceNativeDir, nativeDir)
        Files.writeString(nativeDir.resolve("js_aken_page_locator.inc"), include, StandardCharsets.UTF_8)

        val probe = scenarioDir.resolve("aken_native_page_locator_probe.c")
        Files.copy(probeSource, probe, StandardCopyOption.REPLACE_EXISTING)
        val executable = scenarioDir.resolve(if (isWindows()) "aken_native_page_locator_probe.exe" else "aken_native_page_locator_probe")
        val command = compileCommand(zig, nativeDir, probe, executable)
        var compile = run(
            command = command,
            directory = scenarioDir,
            label = "compile-0",
            zigCache = scenarioDir.resolve("zig-cache-0"),
        )
        for (attempt in 1..5) {
            if (compile.exitCode == 0 || !isTransientZigFailure(compile.output)) break
            compile = run(
                command = command,
                directory = scenarioDir,
                label = "compile-$attempt",
                zigCache = scenarioDir.resolve("zig-cache-$attempt"),
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

    private fun run(command: List<String>, directory: Path, label: String, zigCache: Path? = null): ProcessResult {
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
        val completed = process.waitFor(180, TimeUnit.SECONDS)
        if (!completed) process.destroyForcibly().waitFor(10, TimeUnit.SECONDS)
        val output = Files.readString(outputFile, StandardCharsets.UTF_8)
        assertTrue(completed, "process timed out: ${command.joinToString(" ")}\n$output")
        return ProcessResult(process.exitValue(), output)
    }

    private fun isTransientZigFailure(output: String): Boolean =
        output.isBlank() ||
            output.contains("CacheCheckFailed") ||
            output.contains("file_open Unexpected") ||
            output.contains("sub-compilation of mingw-w64")

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
        Files.walk(path).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
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

    private data class CompiledProbe(val directory: Path, val executable: Path)

    private data class ProcessResult(val exitCode: Int, val output: String)

    private companion object {
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
