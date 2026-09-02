package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.qp.QpArtifactEntry
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBoundPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpCanonicalExclusionKind
import io.github.hht0rro.javashroud.transforms.protection.qp.QpCanonicalExclusionRange
import io.github.hht0rro.javashroud.transforms.protection.qp.QpCanonicalReservation
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageMaterialization
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageMaterializationInput
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageMaterializer
import io.github.hht0rro.javashroud.transforms.protection.qp.QpResourceKind
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.qp.QpEvaluatorPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpProofMetadata
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class QpPageMaterializationTest {
    private val commitment = ByteArray(QpArtifactCommitment.DIGEST_SIZE) { index ->
        (index * 19 + 7).toByte()
    }

    @Test
    fun materializes_independent_pages_and_consumes_the_build_authority() {
        val plan = QpBuildPlan.create(commitment, DeterministicSecureRandom(1_101))
        val pageA = plan.registerPage(
            kind = QpResourceKind.QpMethod,
            identity = "fixture:materialization:method-a".encodeToByteArray(),
            pageIndex = 0,
        )
        val pageB = plan.registerPage(
            kind = QpResourceKind.StringPage,
            identity = "fixture:materialization:string-b".encodeToByteArray(),
            pageIndex = 1,
        )
        val inputA = inputFor(
            page = pageA,
            plaintext = "first native VM materialized page".encodeToByteArray(),
            resourcePath = "META-INF/.qp/p/first.bin",
            resourceOffset = 0,
            callSiteProof = byteArrayOf(0x11, 0x12, 0x13),
        )
        val inputB = inputFor(
            page = pageB,
            plaintext = "second string materialized page".encodeToByteArray(),
            resourcePath = "META-INF/.qp/p/second.bin",
            resourceOffset = 96,
            callSiteProof = byteArrayOf(0x21, 0x22, 0x23),
        )

        val output = QpPageMaterializer.materializeAndWipe(plan, listOf(inputA, inputB))
        try {
            assertTrue(plan.isWiped())
            assertTrue(inputA.isWiped)
            assertTrue(inputB.isWiped)

            val pages = output.pagesForBuild()
            assertEquals(2, pages.size)
            assertTrue(pages.all(output::verifyPageForBuild))

            val first = pages[0]
            val second = pages[1]
            val firstPayload = first.copyEncodedPayloadForBuild()
            val secondPayload = second.copyEncodedPayloadForBuild()
            val firstDescriptor = first.descriptorForBuild
            val secondDescriptor = second.descriptorForBuild
            val firstLeafDigest = firstDescriptor.proof.currentLeafDigest
            val secondLeafDigest = secondDescriptor.proof.currentLeafDigest
            try {
                assertEquals(firstPayload.size, firstDescriptor.route.storedLength)
                assertEquals(secondPayload.size, secondDescriptor.route.storedLength)
                assertNotEquals(firstDescriptor.route.leafIdentity, secondDescriptor.route.leafIdentity)
                assertFalse(firstLeafDigest.contentEquals(secondLeafDigest))
                assertFalse(firstPayload.contentEquals(secondPayload))
            } finally {
                Arrays.fill(firstPayload, 0)
                Arrays.fill(secondPayload, 0)
                Arrays.fill(firstLeafDigest, 0)
                Arrays.fill(secondLeafDigest, 0)
            }
        } finally {
            output.wipe()
        }
    }

    @Test
    fun writerEquivalentCanonicalReservationAllowsOnePassAadBindingAndStillRejectsPayloadTamper() {
        val payloadPath = "META-INF/.qp/p/one-pass.bin"
        val plaintext = "canonical one-pass materialized page".encodeToByteArray()
        val probePlan = QpBuildPlan.create(commitment, DeterministicSecureRandom(1_151))
        val probePage = probePlan.registerPage(
            kind = QpResourceKind.QpMethod,
            identity = "fixture:materialization:one-pass".encodeToByteArray(),
            pageIndex = 0,
        )
        val payloadLength = try {
            probePage.pageLayout.encodedLength(plaintext.size + 16)
        } finally {
            probePlan.wipe()
        }
        val payloadRange = QpCanonicalExclusionRange(
            entryName = payloadPath,
            offset = 0,
            length = payloadLength,
            kind = QpCanonicalExclusionKind.HighValuePayload,
        )
        val helperBytes = "helper-writer-equivalent-bytes".encodeToByteArray()
        val canonicalCommitment = QpArtifactCommitment.reserve(
            entries = listOf(
                QpCanonicalReservation(
                    entryName = payloadPath,
                    canonicalBytes = ByteArray(payloadLength),
                    selfReferentialRanges = listOf(payloadRange),
                ),
                QpCanonicalReservation(
                    entryName = "io/example/Helper.class",
                    canonicalBytes = helperBytes,
                ),
            ),
        )
        val commitmentBytes = canonicalCommitment.bytes
        val plan = QpBuildPlan.create(commitmentBytes, DeterministicSecureRandom(1_151))
        commitmentBytes.fill(0)
        val page = plan.registerPage(
            kind = QpResourceKind.QpMethod,
            identity = "fixture:materialization:one-pass".encodeToByteArray(),
            pageIndex = 0,
        )
        val input = inputFor(
            page = page,
            plaintext = plaintext,
            resourcePath = payloadPath,
            resourceOffset = 0,
            callSiteProof = byteArrayOf(0x51, 0x52),
        )
        val output = QpPageMaterializer.materializeAndWipe(plan, listOf(input))
        try {
            val materialized = output.pagesForBuild().single()
            val payload = materialized.copyEncodedPayloadForBuild()
            try {
                assertEquals(payloadLength, payload.size)
                val finalEntries = listOf(
                    QpArtifactEntry(payloadPath, payload),
                    QpArtifactEntry("io/example/Helper.class", helperBytes),
                )
                assertTrue(canonicalCommitment.matchesWriterEquivalentEntriesForBuild(finalEntries))
                assertTrue(output.verifyPayloadForBuild(materialized.descriptorForBuild, payload))

                payload[payload.lastIndex] = (payload[payload.lastIndex].toInt() xor 0x3D).toByte()
                assertTrue(
                    canonicalCommitment.matchesWriterEquivalentEntriesForBuild(
                        listOf(
                            QpArtifactEntry(payloadPath, payload),
                            QpArtifactEntry("io/example/Helper.class", helperBytes),
                        ),
                    ),
                )
                assertFalse(output.verifyPayloadForBuild(materialized.descriptorForBuild, payload))
            } finally {
                Arrays.fill(payload, 0)
            }
        } finally {
            output.wipe()
            Arrays.fill(helperBytes, 0)
        }
    }

    @Test
    fun finalWriterEquivalentArtifactVerifierBindsCanonicalRoutePayloadAndMesh() {
        val payloadPath = "META-INF/.qp/p/final-writer.bin"
        val plaintext = "final writer-equivalent page".encodeToByteArray()
        val probePlan = QpBuildPlan.create(commitment, DeterministicSecureRandom(1_177))
        val probePage = probePlan.registerPage(
            kind = QpResourceKind.StringPage,
            identity = "fixture:materialization:final-writer".encodeToByteArray(),
            pageIndex = 0,
        )
        val payloadLength = try {
            probePage.pageLayout.encodedLength(plaintext.size + 16)
        } finally {
            probePlan.wipe()
        }
        val payloadRange = QpCanonicalExclusionRange(
            entryName = payloadPath,
            offset = 4,
            length = payloadLength,
            kind = QpCanonicalExclusionKind.HighValuePayload,
        )
        val entryPlaceholder = byteArrayOf(0x11, 0x12, 0x13, 0x14) + ByteArray(payloadLength) + byteArrayOf(0x15)
        val canonicalCommitment = QpArtifactCommitment.reserve(
            listOf(
                QpCanonicalReservation(
                    entryName = payloadPath,
                    canonicalBytes = entryPlaceholder,
                    selfReferentialRanges = listOf(payloadRange),
                ),
            ),
        )
        val commitmentBytes = canonicalCommitment.bytes
        val plan = QpBuildPlan.create(commitmentBytes, DeterministicSecureRandom(1_177))
        commitmentBytes.fill(0)
        val page = plan.registerPage(
            kind = QpResourceKind.StringPage,
            identity = "fixture:materialization:final-writer".encodeToByteArray(),
            pageIndex = 0,
        )
        val output = QpPageMaterializer.materializeAndWipe(
            plan,
            listOf(
                inputFor(
                    page = page,
                    plaintext = plaintext,
                    resourcePath = payloadPath,
                    resourceOffset = 4,
                    callSiteProof = byteArrayOf(0x61),
                ),
            ),
        )
        try {
            val payload = output.pagesForBuild().single().copyEncodedPayloadForBuild()
            val finalEntry = entryPlaceholder.copyOf()
            val payloadTamperedEntry = entryPlaceholder.copyOf()
            val outsideTamperedEntry = entryPlaceholder.copyOf()
            try {
                payload.copyInto(finalEntry, destinationOffset = 4)
                payload.copyInto(payloadTamperedEntry, destinationOffset = 4)
                payload.copyInto(outsideTamperedEntry, destinationOffset = 4)
                val finalEntries = listOf(QpArtifactEntry(payloadPath, finalEntry))
                assertTrue(output.verifyWriterEquivalentArtifactForBuild(canonicalCommitment, finalEntries))

                payloadTamperedEntry[4 + payload.lastIndex] =
                    (payloadTamperedEntry[4 + payload.lastIndex].toInt() xor 0x0F).toByte()
                assertFalse(
                    output.verifyWriterEquivalentArtifactForBuild(
                        canonicalCommitment,
                        listOf(QpArtifactEntry(payloadPath, payloadTamperedEntry)),
                    ),
                )

                outsideTamperedEntry[0] = (outsideTamperedEntry[0].toInt() xor 0x0F).toByte()
                assertFalse(
                    output.verifyWriterEquivalentArtifactForBuild(
                        canonicalCommitment,
                        listOf(QpArtifactEntry(payloadPath, outsideTamperedEntry)),
                    ),
                )
            } finally {
                Arrays.fill(payload, 0)
                Arrays.fill(finalEntry, 0)
                Arrays.fill(payloadTamperedEntry, 0)
                Arrays.fill(outsideTamperedEntry, 0)
                Arrays.fill(entryPlaceholder, 0)
            }
        } finally {
            output.wipe()
        }
    }

    @Test
    fun payload_proof_and_descriptor_tampering_fail_closed_without_a_java_decode_path() {
        val output = onePageMaterialization(seed = 1_207)
        try {
            val page = output.pagesForBuild().single()
            val descriptor = page.descriptorForBuild
            val payload = page.copyEncodedPayloadForBuild()
            val encodedDescriptor = descriptor.encode()
            val tamperedPayload = payload.copyOf()
            try {
                val decodedDescriptor = QpPageDescriptor.decode(encodedDescriptor)
                assertTrue(output.verifyPayloadForBuild(decodedDescriptor, payload))

                tamperedPayload[tamperedPayload.lastIndex] =
                    (tamperedPayload.last().toInt() xor 0x5A).toByte()
                assertFalse(output.verifyPayloadForBuild(decodedDescriptor, tamperedPayload))

                val badDescriptor = descriptorWithTamperedMeshRoot(descriptor)
                assertFalse(output.verifyPayloadForBuild(badDescriptor, payload))
            } finally {
                Arrays.fill(payload, 0)
                Arrays.fill(encodedDescriptor, 0)
                Arrays.fill(tamperedPayload, 0)
            }
        } finally {
            output.wipe()
        }
    }

    @Test
    fun production_materialization_uses_v2_opaque_bound_plan_without_legacy_fragment_surface() {
        val output = onePageMaterialization(seed = 1_231)
        try {
            val descriptor = output.pagesForBuild().single().descriptorForBuild
            val evaluator = descriptor.evaluatorPlan
            val encoded = evaluator.encode()
            val tampered = encoded.copyOf()
            try {
                assertEquals(0, encoded[0].toInt() and 0xFF)
                tampered[5] = (tampered[5].toInt() xor 0x01).toByte()
                assertFailsWith<IllegalArgumentException> { QpEvaluatorPlan.decode(tampered) }
            } finally {
                Arrays.fill(encoded, 0)
                Arrays.fill(tampered, 0)
            }
        } finally {
            output.wipe()
        }
    }

    @Test
    fun materialization_owner_wipe_invalidates_its_owned_page_records() {
        val output = onePageMaterialization(seed = 1_303)
        val pages = output.pagesForBuild()

        output.wipe()

        assertTrue(output.isWiped)
        assertTrue(pages.all { it.isWiped })
        assertFailsWith<IllegalStateException> { output.pagesForBuild() }
        assertFailsWith<IllegalStateException> { pages.single().copyEncodedPayloadForBuild() }
        assertFailsWith<IllegalStateException> { pages.single().descriptorForBuild }
    }

    @Test
    fun physical_resource_range_overlap_is_rejected_and_still_wipes_inputs_and_plan() {
        val plan = QpBuildPlan.create(commitment, DeterministicSecureRandom(1_409))
        val first = plan.registerPage(
            kind = QpResourceKind.EncryptedClassPage,
            identity = "fixture:materialization:overlap:first".encodeToByteArray(),
            pageIndex = 0,
        )
        val second = plan.registerPage(
            kind = QpResourceKind.NativeChunk,
            identity = "fixture:materialization:overlap:second".encodeToByteArray(),
            pageIndex = 0,
        )
        val firstInput = inputFor(
            page = first,
            plaintext = "overlap first payload".encodeToByteArray(),
            resourcePath = "META-INF/.qp/p/shared.bin",
            resourceOffset = 0,
            callSiteProof = byteArrayOf(0x31),
        )
        val secondInput = inputFor(
            page = second,
            plaintext = "overlap second payload".encodeToByteArray(),
            resourcePath = "META-INF/.qp/p/shared.bin",
            resourceOffset = 0,
            callSiteProof = byteArrayOf(0x32),
        )

        assertFailsWith<IllegalArgumentException> {
            QpPageMaterializer.materializeAndWipe(plan, listOf(firstInput, secondInput))
        }
        assertTrue(plan.isWiped())
        assertTrue(firstInput.isWiped)
        assertTrue(secondInput.isWiped)
    }

    @Test
    fun input_iteration_failure_still_wipes_consumed_inputs_and_build_authority() {
        val plan = QpBuildPlan.create(commitment, DeterministicSecureRandom(1_451))
        val page = plan.registerPage(
            kind = QpResourceKind.NativeChunk,
            identity = "fixture:materialization:iterator-failure".encodeToByteArray(),
            pageIndex = 0,
        )
        val input = inputFor(
            page = page,
            plaintext = "iterator failure payload".encodeToByteArray(),
            resourcePath = "META-INF/.qp/p/iterator-failure.bin",
            resourceOffset = 0,
            callSiteProof = byteArrayOf(0x45, 0x51),
        )
        val throwingInputs = object : Iterable<QpPageMaterializationInput> {
            override fun iterator(): Iterator<QpPageMaterializationInput> = object : Iterator<QpPageMaterializationInput> {
                private var nextCount = 0

                override fun hasNext(): Boolean = nextCount < 2

                override fun next(): QpPageMaterializationInput = when (nextCount++) {
                    0 -> input
                    else -> throw IllegalStateException("fixture Qp input iteration failure")
                }
            }
        }

        assertFailsWith<IllegalStateException> {
            QpPageMaterializer.materializeAndWipe(plan, throwingInputs)
        }
        assertTrue(plan.isWiped())
        assertTrue(input.isWiped)
    }

    @Test
    fun invalid_route_after_page_encoding_still_wipes_input_and_build_authority() {
        val plan = QpBuildPlan.create(commitment, DeterministicSecureRandom(1_467))
        val page = plan.registerPage(
            kind = QpResourceKind.EncryptedClassPage,
            identity = "fixture:materialization:invalid-route".encodeToByteArray(),
            pageIndex = 2,
        )
        val input = inputFor(
            page = page,
            plaintext = "invalid route payload".encodeToByteArray(),
            resourcePath = "../outside-qp.bin",
            resourceOffset = 0,
            callSiteProof = byteArrayOf(0x46, 0x67),
        )

        assertFailsWith<IllegalArgumentException> {
            QpPageMaterializer.materializeAndWipe(plan, listOf(input))
        }
        assertTrue(plan.isWiped())
        assertTrue(input.isWiped)
    }

    private fun onePageMaterialization(seed: Int): QpPageMaterialization {
        val plan = QpBuildPlan.create(commitment, DeterministicSecureRandom(seed))
        val page = plan.registerPage(
            kind = QpResourceKind.QpMethod,
            identity = "fixture:materialization:one:$seed".encodeToByteArray(),
            pageIndex = 3,
        )
        val input = inputFor(
            page = page,
            plaintext = "one materialized page: $seed".encodeToByteArray(),
            resourcePath = "META-INF/.qp/p/one-$seed.bin",
            resourceOffset = 0,
            callSiteProof = byteArrayOf(0x41, 0x42, 0x43),
        )
        return QpPageMaterializer.materializeAndWipe(plan, listOf(input))
    }

    private fun inputFor(
        page: QpBuildPlan.Page,
        plaintext: ByteArray,
        resourcePath: String,
        resourceOffset: Int,
        callSiteProof: ByteArray,
    ): QpPageMaterializationInput = try {
        QpPageMaterializationInput.create(
            page = page,
            plaintext = plaintext,
            resourcePath = resourcePath,
            resourceOffset = resourceOffset,
            callSiteProof = callSiteProof,
        )
    } finally {
        Arrays.fill(plaintext, 0)
        Arrays.fill(callSiteProof, 0)
    }

    private fun descriptorWithTamperedMeshRoot(
        descriptor: QpPageDescriptor,
    ): QpPageDescriptor {
        val proof = descriptor.proof
        val artifactCommitment = proof.artifactCanonicalCommitment
        val badRoot = proof.merkleRoot
        val leafDigest = proof.currentLeafDigest
        val siblings = proof.siblingDigests
        val callSiteProof = proof.callSiteProof
        val logicalIdentity = descriptor.logicalIdentity
        val handle = descriptor.handle
        try {
            badRoot[0] = (badRoot[0].toInt() xor 0x01).toByte()
            val badProof = QpProofMetadata.create(
                leafIdentity = proof.leafIdentity,
                artifactCommitment = artifactCommitment,
                meshRoot = badRoot,
                leafDigest = leafDigest,
                siblings = siblings,
                siblingIsLeft = proof.siblingDirections,
                callSiteProof = callSiteProof,
                codecVariant = proof.codecVariant,
                layoutVariant = proof.layoutVariant,
            )
            return QpPageDescriptor.create(
                handle = handle,
                logicalIdentity = logicalIdentity,
                route = descriptor.route,
                proof = badProof,
                targetPageSize = descriptor.targetPageSize,
                evaluatorPlan = descriptor.evaluatorPlan,
            )
        } finally {
            Arrays.fill(artifactCommitment, 0)
            Arrays.fill(badRoot, 0)
            Arrays.fill(leafDigest, 0)
            siblings.forEach { Arrays.fill(it, 0) }
            Arrays.fill(callSiteProof, 0)
            Arrays.fill(logicalIdentity, 0)
            handle.wipe()
        }
    }

    private class DeterministicSecureRandom(seed: Int) : SecureRandom() {
        private var state: Int = seed

        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { index ->
                bytes[index] = nextValue().toByte()
            }
        }

        override fun nextInt(bound: Int): Int {
            require(bound > 0)
            return Math.floorMod(nextValue(), bound)
        }

        override fun nextBoolean(): Boolean = (nextValue() and 1) == 0

        private fun nextValue(): Int {
            state = state * 1_103_515_245 + 12_345
            return state
        }
    }
}
