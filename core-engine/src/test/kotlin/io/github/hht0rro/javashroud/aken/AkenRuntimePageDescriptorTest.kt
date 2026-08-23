package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBoundDecryptorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHighValueLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRoutingMetadata
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorFragment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorRole
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimePageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenSealingProofMetadata
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AkenRuntimePageDescriptorTest {
    private val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index ->
        (index * 13 + 5).toByte()
    }

    @Test
    fun descriptor_round_trips_one_page_and_rechecks_the_aken7_graph_binding() {
        val plan = AkenBuildPlan.create(commitment, DeterministicSecureRandom(701))
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.Vbc4Method,
                identity = "fixture:runtime:descriptor".encodeToByteArray(),
                pageIndex = 4,
            )
            val descriptor = descriptorFor(plan, page)
            val encoded = descriptor.encode()
            try {
                val decoded = AkenRuntimePageDescriptor.decode(encoded)
                assertEquals(page.resourceKind, decoded.resourceKind)
                assertEquals(page.pageIndex, decoded.pageIndex)
                assertEquals(page.targetSize, decoded.targetPageSize)
                assertContentEquals(page.logicalIdentity, decoded.logicalIdentity)
                assertEquals(descriptor.route.resourcePath, decoded.route.resourcePath)
                assertEquals(descriptor.route.resourceOffset, decoded.route.resourceOffset)
                assertEquals(descriptor.route.storedLength, decoded.route.storedLength)
                assertEquals(descriptor.route.logicalBindingPath, decoded.route.logicalBindingPath)
                assertContentEquals(descriptor.proof.callSiteProof, decoded.proof.callSiteProof)
                assertContentEquals(descriptor.evaluatorPlan.fingerprint, decoded.evaluatorPlan.fingerprint)
                assertTrue(!decoded.evaluatorPlan.isLegacyAken7)
                val boundOpaque = decoded.evaluatorPlan.copyBoundDecryptorForNative()
                try {
                    assertTrue(boundOpaque != null && boundOpaque.isNotEmpty())
                } finally {
                    boundOpaque?.fill(0)
                }
                assertTrue(decoded.matches(page.handle))
                assertTrue(decoded.matches(decoded.handle))
            } finally {
                encoded.fill(0)
            }
        } finally {
            plan.wipe()
        }
    }

    @Test
    fun descriptor_is_defensive_and_rejects_mismatched_page_or_graph_metadata() {
        val plan = AkenBuildPlan.create(commitment, DeterministicSecureRandom(811))
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.StringPage,
                identity = "fixture:runtime:one".encodeToByteArray(),
                pageIndex = 1,
            )
            val other = plan.registerPage(
                kind = AkenResourceKind.StringPage,
                identity = "fixture:runtime:two".encodeToByteArray(),
                pageIndex = 1,
            )
            val descriptor = descriptorFor(plan, page)

            val identityCopy = descriptor.logicalIdentity
            val expectedIdentity = identityCopy.copyOf()
            val opaqueCopy = checkNotNull(descriptor.evaluatorPlan.copyBoundDecryptorForNative())
            val expectedOpaque = opaqueCopy.copyOf()
            val handleCopy = descriptor.route.handleEncoding
            val expectedHandle = handleCopy.copyOf()
            try {
                identityCopy.fill(0x31.toByte())
                opaqueCopy.fill(0x32.toByte())
                handleCopy.fill(0x33.toByte())
                assertContentEquals(expectedIdentity, descriptor.logicalIdentity)
                val currentOpaque = checkNotNull(descriptor.evaluatorPlan.copyBoundDecryptorForNative())
                try {
                    assertContentEquals(expectedOpaque, currentOpaque)
                } finally {
                    currentOpaque.fill(0)
                }
                assertContentEquals(expectedHandle, descriptor.route.handleEncoding)
            } finally {
                identityCopy.fill(0)
                expectedIdentity.fill(0)
                opaqueCopy.fill(0)
                expectedOpaque.fill(0)
                handleCopy.fill(0)
                expectedHandle.fill(0)
            }

            val mismatchedRoute = AkenRoutingMetadata.fromHandle(
                handle = other.handle,
                logicalIdentity = other.logicalIdentity,
                resourcePath = "META-INF/.aken/runtime/other.bin",
                resourceOffset = 11,
                storedLength = 71,
                codecVariant = other.codecVariant,
                layoutVariant = other.layoutVariant,
            )
            assertFailsWith<IllegalArgumentException> {
                AkenRuntimePageDescriptor.create(
                    handle = page.handle,
                    logicalIdentity = page.logicalIdentity,
                    route = mismatchedRoute,
                    proof = proofFor(plan, page),
                    targetPageSize = page.targetSize,
                    evaluatorPlan = descriptor.evaluatorPlan,
                )
            }

            val graph = descriptor.evaluatorPlan
            val badFingerprint = graph.fingerprint
            val boundOpaque = checkNotNull(graph.copyBoundDecryptorForNative())
            try {
                badFingerprint[0] = (badFingerprint[0].toInt() xor 0x5A).toByte()
                val mismatchedGraph = AkenRuntimeEvaluatorPlan.createBound(
                    AkenBoundDecryptorPlan.fromOpaque(boundOpaque),
                    badFingerprint,
                )
                assertFailsWith<IllegalArgumentException> {
                    AkenRuntimePageDescriptor.create(
                        handle = page.handle,
                        logicalIdentity = page.logicalIdentity,
                        route = routeFor(page),
                        proof = proofFor(plan, page),
                        targetPageSize = page.targetSize,
                        evaluatorPlan = mismatchedGraph,
                    )
                }
            } finally {
                boundOpaque.fill(0)
                badFingerprint.fill(0)
            }
        } finally {
            plan.wipe()
        }
    }

    @Test
    fun descriptor_parse_rejects_invalid_version_lengths_trailing_bytes_and_invalid_topology() {
        val plan = AkenBuildPlan.create(commitment, DeterministicSecureRandom(919))
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.NativeChunk,
                identity = "fixture:runtime:strict".encodeToByteArray(),
                pageIndex = 0,
            )
            val encoded = descriptorFor(plan, page).encode()
            val badVersion = encoded.copyOf().also { it[0] = 99.toByte() }
            val badRouteLength = encoded.copyOf().also {
                it[1] = 0x7F
                it[2] = 0xFF.toByte()
                it[3] = 0xFF.toByte()
                it[4] = 0xFF.toByte()
            }
            val trailing = encoded.copyOf(encoded.size + 1).also { it[it.lastIndex] = 0x7E }
            try {
                assertFailsWith<IllegalArgumentException> { AkenRuntimePageDescriptor.decode(badVersion) }
                assertFailsWith<IllegalArgumentException> { AkenRuntimePageDescriptor.decode(badRouteLength) }
                assertFailsWith<IllegalArgumentException> { AkenRuntimePageDescriptor.decode(trailing) }
            } finally {
                encoded.fill(0)
                badVersion.fill(0)
                badRouteLength.fill(0)
                trailing.fill(0)
            }

            val invalidJava = AkenRuntimeEvaluatorFragment.create(
                role = AkenRuntimeEvaluatorRole.Java,
                ordinal = 4,
                family = 1,
                shape = byteArrayOf(1),
                callToken = byteArrayOf(2),
                tablePermutation = intArrayOf(0),
            )
            val graph = legacyRuntimePlanFor(page)
            assertFailsWith<IllegalArgumentException> {
                AkenRuntimeEvaluatorPlan.create(
                    javaFragments = listOf(invalidJava) + graph.javaFragments.drop(1),
                    nativeFragments = graph.nativeFragments,
                    terminal = graph.terminal,
                    fingerprint = graph.fingerprint,
                )
            }
        } finally {
            plan.wipe()
        }
    }

    private fun descriptorFor(plan: AkenBuildPlan, page: AkenBuildPlan.Page): AkenRuntimePageDescriptor {
        val route = routeFor(page)
        val proof = proofFor(plan, page)
        return AkenRuntimePageDescriptor.create(
            handle = page.handle,
            logicalIdentity = page.logicalIdentity,
            route = route,
            proof = proof,
            targetPageSize = page.targetSize,
            evaluatorPlan = runtimePlanFor(page, route, proof),
        )
    }

    private fun routeFor(page: AkenBuildPlan.Page): AkenRoutingMetadata = AkenRoutingMetadata.fromHandle(
        handle = page.handle,
        logicalIdentity = page.logicalIdentity,
        resourcePath = "META-INF/.aken/runtime/" + page.resourceKind.id + "-" + page.pageIndex + ".bin",
        resourceOffset = 17,
        storedLength = 113,
        codecVariant = page.codecVariant,
        layoutVariant = page.layoutVariant,
        logicalBindingPath = "META-INF/vbc4/logical-binding-${page.pageIndex}.bin",
    )

    private fun proofFor(plan: AkenBuildPlan, page: AkenBuildPlan.Page): AkenSealingProofMetadata {
        val leaf = AkenHighValueLeafIdentity.fromHandle(page.handle, page.logicalIdentity)
        return AkenSealingProofMetadata.create(
            leafIdentity = leaf,
            artifactCommitment = plan.artifactCanonicalCommitment,
            meshRoot = ByteArray(32) { 0x41 },
            leafDigest = ByteArray(32) { 0x42 },
            siblings = listOf(ByteArray(32) { 0x43 }),
            siblingIsLeft = listOf(true),
            callSiteProof = byteArrayOf(0x10, 0x20, 0x30),
            codecVariant = page.codecVariant,
            layoutVariant = page.layoutVariant,
        )
    }

    private fun runtimePlanFor(
        page: AkenBuildPlan.Page,
        route: AkenRoutingMetadata,
        proof: AkenSealingProofMetadata,
    ): AkenRuntimeEvaluatorPlan {
        val callSiteProof = proof.callSiteProof
        val fingerprint = page.evaluatorPlan.fingerprint
        return try {
            AkenRuntimeEvaluatorPlan.createBound(
                page.evaluatorPlan.boundPlanForRuntime(route, callSiteProof),
                fingerprint,
            )
        } finally {
            callSiteProof.fill(0)
            fingerprint.fill(0)
        }
    }

    private fun legacyRuntimePlanFor(page: AkenBuildPlan.Page): AkenRuntimeEvaluatorPlan {
        val graph = page.evaluatorPlan
        val fingerprint = graph.fingerprint
        return try {
            AkenRuntimeEvaluatorPlan.create(
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

    private class DeterministicSecureRandom(seed: Int) : SecureRandom() {
        private var state = seed

        override fun nextBytes(bytes: ByteArray) {
            bytes.indices.forEach { index -> bytes[index] = nextValue().toByte() }
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
