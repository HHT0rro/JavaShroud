package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenEvaluatorState
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHandle
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHighValueLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRoutingMetadata
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorFragment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorRole
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimePageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenSealingProofMetadata
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Regression coverage for the build-engine-only AKEN-7 evaluator-state codec.
 *
 * These tests deliberately exercise only the build/sealing verification helpers:
 * they neither add nor rely on a Java-visible runtime decoder or raw-DEK API.
 */
class AkenEvaluatorStateTest {
    private val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index ->
        (index * 19 + 7).toByte()
    }

    @Test
    fun split_dek_uses_seven_non_raw_shares_and_only_the_complete_xor_recovers_it() {
        val dek = ByteArray(AkenEvaluatorState.STATE_WIDTH) { index -> (index * 29 + 11).toByte() }
        val shares = AkenEvaluatorState.splitDek(dek, DeterministicSecureRandom(1_121))
        try {
            assertEquals(7, shares.size)
            assertTrue(shares.all { it.size == AkenEvaluatorState.STATE_WIDTH })
            assertTrue(shares.all { share -> share.any { it != 0.toByte() } })
            assertTrue(shares.none { share -> share.contentEquals(dek) })

            val recovered = xorAll(shares.asIterable())
            try {
                assertContentEquals(dek, recovered)
            } finally {
                recovered.fill(0)
            }

            shares.indices.forEach { omittedIndex ->
                val partial = xorAll(shares.filterIndexed { index, _ -> index != omittedIndex })
                try {
                    assertFalse(
                        partial.contentEquals(dek),
                        "omitting AKEN-7 share $omittedIndex must not reconstruct the page-local DEK",
                    )
                } finally {
                    partial.fill(0)
                }
            }
        } finally {
            dek.fill(0)
            shares.forEach { it.fill(0) }
        }
    }

    @Test
    fun canonical_artifact_commitment_uses_seven_non_raw_shares_and_requires_the_complete_graph() {
        val shares = AkenEvaluatorState.splitArtifactCommitment(commitment, DeterministicSecureRandom(1_177))
        try {
            assertEquals(7, shares.size)
            assertTrue(shares.all { it.size == AkenEvaluatorState.STATE_WIDTH })
            assertTrue(shares.none { share -> share.contentEquals(commitment) })

            val recovered = xorAll(shares.asIterable())
            try {
                assertContentEquals(commitment, recovered)
            } finally {
                recovered.fill(0)
            }

            shares.indices.forEach { omittedIndex ->
                val partial = xorAll(shares.filterIndexed { index, _ -> index != omittedIndex })
                try {
                    assertFalse(
                        partial.contentEquals(commitment),
                        "omitting AKEN-7 commitment share $omittedIndex must not reconstruct the canonical root",
                    )
                } finally {
                    partial.fill(0)
                }
            }
        } finally {
            shares.forEach { it.fill(0) }
        }
    }

    @Test
    fun generated_aken7_graph_recovers_build_only_dek_without_embedding_it_in_any_single_shape() {
        val plan = AkenBuildPlan.create(commitment, DeterministicSecureRandom(1_213))
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.Vbc4Method,
                identity = "fixture:evaluator:seven-state".encodeToByteArray(),
                pageIndex = 2,
            )
            val recovered = AkenEvaluatorState.recoverForBuildVerification(page, commitment)
            try {
                val graph = page.evaluatorPlan
                assertEquals(3, graph.javaFragments.size)
                assertEquals(3, graph.nativeFragments.size)
                assertEquals(7, graph.allFragments.size)
                assertEquals((0 until 7).toSet(), graph.allFragments.map { it.ordinal }.toSet())
                assertTrue(graph.allFragments.all { it.family in 0..15 })

                graph.allFragments.forEach { fragment ->
                    val shape = fragment.shape
                    val encodedShare = shape.copyOfRange(1, 1 + AkenEvaluatorState.STATE_WIDTH)
                    val commitmentShare = shape.copyOfRange(
                        1 + AkenEvaluatorState.STATE_WIDTH,
                        1 + AkenEvaluatorState.STATE_WIDTH * 2,
                    )
                    try {
                        assertTrue(shape.size > recovered.size + commitment.size)
                        assertFalse(shape.contentEquals(recovered))
                        assertFalse(encodedShare.contentEquals(recovered))
                        assertFalse(containsContiguous(shape, recovered))
                        assertFalse(commitmentShare.contentEquals(commitment))
                        assertFalse(containsContiguous(shape, commitment))
                    } finally {
                        encodedShare.fill(0)
                        commitmentShare.fill(0)
                        shape.fill(0)
                    }
                }

                val wrongCommitment = commitment.copyOf()
                try {
                    wrongCommitment[0] = (wrongCommitment[0].toInt() xor 0x73).toByte()
                    assertFailsWith<IllegalArgumentException> {
                        val rejected = AkenEvaluatorState.recoverForBuildVerification(page, wrongCommitment)
                        rejected.fill(0)
                    }
                } finally {
                    wrongCommitment.fill(0)
                }
            } finally {
                recovered.fill(0)
            }
        } finally {
            plan.wipe()
        }
    }

    @Test
    fun serialized_descriptor_preserves_aken7_evaluator_state_and_build_only_recovery_parity() {
        val plan = AkenBuildPlan.create(commitment, DeterministicSecureRandom(1_307))
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.EncryptedClassPage,
                identity = "fixture:evaluator:descriptor-parity".encodeToByteArray(),
                pageIndex = 4,
            )
            val expectedDek = AkenEvaluatorState.recoverForBuildVerification(page, commitment)
            val descriptor = descriptorFor(plan, page)
            val encoded = descriptor.encode()
            try {
                val parsed = AkenRuntimePageDescriptor.decode(encoded)
                val descriptorDek = AkenEvaluatorState.recoverDescriptorForBuildVerification(parsed)
                try {
                    assertEquals(descriptor.evaluatorPlan, parsed.evaluatorPlan)
                    assertContentEquals(expectedDek, descriptorDek)
                    assertContentEquals(page.evaluatorPlan.fingerprint, parsed.evaluatorPlan.fingerprint)
                } finally {
                    descriptorDek.fill(0)
                }
            } finally {
                expectedDek.fill(0)
                encoded.fill(0)
            }
        } finally {
            plan.wipe()
        }
    }

    @Test
    fun every_evaluator_binding_input_mutation_fails_closed_after_a_structurally_valid_rebind() {
        val plan = AkenBuildPlan.create(commitment, DeterministicSecureRandom(1_409))
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.StringPage,
                identity = "fixture:evaluator:tamper".encodeToByteArray(),
                pageIndex = 1,
            )
            val expectedDek = AkenEvaluatorState.recoverForBuildVerification(page, commitment)
            val baseline = descriptorFor(plan, page)
            try {
                val baselineDek = AkenEvaluatorState.recoverDescriptorForBuildVerification(baseline)
                try {
                    assertContentEquals(expectedDek, baselineDek)
                } finally {
                    baselineDek.fill(0)
                }

                TamperTarget.entries.forEach { target ->
                    val tampered = descriptorWithTamperedBinding(plan, page, target)
                    assertFailsWith<IllegalArgumentException>(target.name) {
                        val recovered = AkenEvaluatorState.recoverDescriptorForBuildVerification(tampered)
                        recovered.fill(0)
                    }
                }
            } finally {
                expectedDek.fill(0)
            }
        } finally {
            plan.wipe()
        }
    }

    private fun descriptorFor(
        plan: AkenBuildPlan,
        page: AkenBuildPlan.Page,
        handle: AkenHandle = page.handle,
        evaluatorPlan: AkenRuntimeEvaluatorPlan = runtimePlanFor(page),
    ): AkenRuntimePageDescriptor {
        val identity = page.logicalIdentity
        try {
            return AkenRuntimePageDescriptor.create(
                handle = handle,
                logicalIdentity = identity,
                route = routeFor(page, handle, identity),
                proof = proofFor(plan, page, handle, identity),
                targetPageSize = page.targetSize,
                evaluatorPlan = evaluatorPlan,
            )
        } finally {
            identity.fill(0)
        }
    }

    private fun routeFor(
        page: AkenBuildPlan.Page,
        handle: AkenHandle,
        identity: ByteArray,
    ): AkenRoutingMetadata = AkenRoutingMetadata.fromHandle(
        handle = handle,
        logicalIdentity = identity,
        resourcePath = "META-INF/.aken/evaluator/${page.resourceKind.id}-${page.pageIndex}.bin",
        resourceOffset = 29,
        storedLength = 127,
        codecVariant = page.codecVariant,
        layoutVariant = page.layoutVariant,
    )

    private fun proofFor(
        plan: AkenBuildPlan,
        page: AkenBuildPlan.Page,
        handle: AkenHandle,
        identity: ByteArray,
    ): AkenSealingProofMetadata {
        val artifactCommitment = plan.artifactCanonicalCommitment
        val meshRoot = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { 0x31 }
        val leafDigest = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { 0x42 }
        val sibling = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { 0x53 }
        try {
            return AkenSealingProofMetadata.create(
                leafIdentity = AkenHighValueLeafIdentity.fromHandle(handle, identity),
                artifactCommitment = artifactCommitment,
                meshRoot = meshRoot,
                leafDigest = leafDigest,
                siblings = listOf(sibling),
                siblingIsLeft = listOf(true),
                callSiteProof = byteArrayOf(0x21, 0x34, 0x55, 0x68),
                codecVariant = page.codecVariant,
                layoutVariant = page.layoutVariant,
            )
        } finally {
            artifactCommitment.fill(0)
            meshRoot.fill(0)
            leafDigest.fill(0)
            sibling.fill(0)
        }
    }

    private fun runtimePlanFor(page: AkenBuildPlan.Page): AkenRuntimeEvaluatorPlan {
        val graph = page.evaluatorPlan
        val fingerprint = graph.fingerprint
        try {
            return AkenRuntimeEvaluatorPlan.create(
                javaFragments = graph.javaFragments.map { runtimeFragment(AkenRuntimeEvaluatorRole.Java, it) },
                nativeFragments = graph.nativeFragments.map { runtimeFragment(AkenRuntimeEvaluatorRole.Native, it) },
                terminal = runtimeFragment(AkenRuntimeEvaluatorRole.Terminal, graph.terminal),
                fingerprint = fingerprint,
            )
        } finally {
            fingerprint.fill(0)
        }
    }

    private fun runtimeFragment(
        role: AkenRuntimeEvaluatorRole,
        fragment: AkenBuildPlan.EvaluatorFragment,
    ): AkenRuntimeEvaluatorFragment {
        val shape = fragment.shape
        val callToken = fragment.callToken
        val tablePermutation = fragment.tablePermutation
        return try {
            AkenRuntimeEvaluatorFragment.create(
                role = role,
                ordinal = fragment.ordinal,
                family = fragment.family,
                shape = shape,
                callToken = callToken,
                tablePermutation = tablePermutation,
            )
        } finally {
            shape.fill(0)
            callToken.fill(0)
            tablePermutation.fill(0)
        }
    }

    private fun descriptorWithTamperedBinding(
        plan: AkenBuildPlan,
        page: AkenBuildPlan.Page,
        target: TamperTarget,
    ): AkenRuntimePageDescriptor {
        val basePlan = runtimePlanFor(page)
        val javaFragments = basePlan.javaFragments.toMutableList()
        val nativeFragments = basePlan.nativeFragments
        val terminal = basePlan.terminal
        val originalHandle = page.handle
        val handleEncoding = originalHandle.encoded
        val locatorToken = originalHandle.locatorToken
        try {
            when (target) {
                TamperTarget.Shape,
                TamperTarget.ArtifactCommitmentShare,
                TamperTarget.CallToken,
                TamperTarget.Permutation,
                TamperTarget.Family -> javaFragments[0] = mutateFragment(javaFragments[0], target)

                TamperTarget.Handle -> {
                    handleEncoding[0] = (handleEncoding[0].toInt() xor 0x4D).toByte()
                }

                TamperTarget.Locator -> {
                    locatorToken[0] = (locatorToken[0].toInt() xor 0x6E).toByte()
                }
            }

            val identity = page.logicalIdentity
            var fingerprint: ByteArray? = null
            try {
                fingerprint = AkenRuntimeEvaluatorPlan.computeFingerprint(
                    resourceKind = page.resourceKind,
                    logicalIdentity = identity,
                    pageIndex = page.pageIndex,
                    targetPageSize = page.targetSize,
                    codecVariant = page.codecVariant,
                    layoutVariant = page.layoutVariant,
                    handleEncoding = handleEncoding,
                    locatorToken = locatorToken,
                    javaFragments = javaFragments,
                    nativeFragments = nativeFragments,
                    terminal = terminal,
                )
                val reboundPlan = AkenRuntimeEvaluatorPlan.create(
                    javaFragments = javaFragments,
                    nativeFragments = nativeFragments,
                    terminal = terminal,
                    fingerprint = checkNotNull(fingerprint),
                )
                val reboundHandle = AkenHandle.create(
                    resourceKind = page.resourceKind,
                    pageIndex = page.pageIndex,
                    encoded = handleEncoding,
                    locatorToken = locatorToken,
                    evaluatorFingerprint = checkNotNull(fingerprint),
                )
                return descriptorFor(plan, page, reboundHandle, reboundPlan)
            } finally {
                identity.fill(0)
                fingerprint?.fill(0)
            }
        } finally {
            handleEncoding.fill(0)
            locatorToken.fill(0)
        }
    }

    private fun mutateFragment(
        fragment: AkenRuntimeEvaluatorFragment,
        target: TamperTarget,
    ): AkenRuntimeEvaluatorFragment {
        val shape = fragment.shape
        val callToken = fragment.callToken
        val permutation = fragment.tablePermutation
        var family = fragment.family
        try {
            when (target) {
                TamperTarget.Shape -> {
                    shape[1] = (shape[1].toInt() xor 0x27).toByte()
                }

                TamperTarget.ArtifactCommitmentShare -> {
                    val offset = 1 + AkenEvaluatorState.STATE_WIDTH
                    shape[offset] = (shape[offset].toInt() xor 0x5C).toByte()
                }

                TamperTarget.CallToken -> {
                    callToken[0] = (callToken[0].toInt() xor 0x39).toByte()
                }

                TamperTarget.Permutation -> {
                    val first = permutation[0]
                    permutation[0] = permutation[1]
                    permutation[1] = first
                }

                TamperTarget.Family -> {
                    family = (family + 1) and 0x0F
                }

                TamperTarget.Handle,
                TamperTarget.Locator -> error("fragment mutation is not applicable to $target")
            }
            return AkenRuntimeEvaluatorFragment.create(
                role = fragment.role,
                ordinal = fragment.ordinal,
                family = family,
                shape = shape,
                callToken = callToken,
                tablePermutation = permutation,
            )
        } finally {
            shape.fill(0)
            callToken.fill(0)
            permutation.fill(0)
        }
    }

    private fun xorAll(values: Iterable<ByteArray>): ByteArray {
        val result = ByteArray(AkenEvaluatorState.STATE_WIDTH)
        values.forEach { value ->
            require(value.size == result.size)
            value.indices.forEach { index ->
                result[index] = (result[index].toInt() xor value[index].toInt()).toByte()
            }
        }
        return result
    }

    private fun containsContiguous(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        return (0..haystack.size - needle.size).any { offset ->
            needle.indices.all { index -> haystack[offset + index] == needle[index] }
        }
    }

    private enum class TamperTarget {
        Shape,
        ArtifactCommitmentShare,
        CallToken,
        Permutation,
        Family,
        Handle,
        Locator,
    }

    private class DeterministicSecureRandom(seed: Int) : SecureRandom() {
        private val seedMaterial = ByteArray(Int.SIZE_BYTES) { index ->
            ((seed ushr ((Int.SIZE_BYTES - 1 - index) * Byte.SIZE_BITS)) and 0xFF).toByte()
        }
        private var counter: Long = 0

        override fun nextBytes(bytes: ByteArray) {
            var offset = 0
            while (offset < bytes.size) {
                val block = nextBlock()
                try {
                    val length = minOf(block.size, bytes.size - offset)
                    System.arraycopy(block, 0, bytes, offset, length)
                    offset += length
                } finally {
                    block.fill(0)
                }
            }
        }

        override fun nextInt(bound: Int): Int {
            require(bound > 0)
            val bytes = ByteArray(Int.SIZE_BYTES)
            try {
                nextBytes(bytes)
                val value = ((bytes[0].toInt() and 0xFF) shl 24) or
                    ((bytes[1].toInt() and 0xFF) shl 16) or
                    ((bytes[2].toInt() and 0xFF) shl 8) or
                    (bytes[3].toInt() and 0xFF)
                return (Integer.toUnsignedLong(value) % bound.toLong()).toInt()
            } finally {
                bytes.fill(0)
            }
        }

        override fun nextBoolean(): Boolean = nextInt(2) == 0

        private fun nextBlock(): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(seedMaterial)
            val value = counter++
            for (shift in 56 downTo 0 step 8) {
                digest.update((value ushr shift).toByte())
            }
            return digest.digest()
        }
    }
}
