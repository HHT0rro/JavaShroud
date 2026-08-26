package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBoundDecryptorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHighValueLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRoutingMetadata
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimePageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenSealingProofMetadata
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AkenRuntimePageDescriptorTest {
    private val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index ->
        (index * 13 + 5).toByte()
    }

    @Test
    fun descriptor_round_trips_one_page_and_rechecks_current_vbc4_evaluator_binding() {
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
                val boundOpaque = decoded.evaluatorPlan.copyBoundDecryptorForNative()
                try {
                    assertTrue(boundOpaque != null && boundOpaque.isNotEmpty())
                    assertFalse(opaquePartitionsThirtyTwoByteDek(boundOpaque!!), "descriptor must not carry a 32-byte DEK overlay")
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
    fun descriptor_parse_rejects_invalid_version_lengths_and_trailing_bytes() {
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

        } finally {
            plan.wipe()
        }
    }

    @Test
    fun current_vbc4_evaluator_uses_variable_fragment_dialect_and_no_retired_lane_domains() {
        val plan = AkenBuildPlan.create(commitment, DeterministicSecureRandom(1_013))
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.Vbc4Method,
                identity = "fixture:runtime:current-evaluator".encodeToByteArray(),
                pageIndex = 0,
            )
            val descriptor = descriptorFor(plan, page)
            val opaque = checkNotNull(descriptor.evaluatorPlan.copyBoundDecryptorForNative())
            try {
                assertContentEquals("AKE1".encodeToByteArray(), opaque.copyOfRange(0, 4))
                val fragmentCount = opaque[5].toInt() and 0xFF
                assertTrue(fragmentCount in 4..12)
                val text = opaque.toString(Charsets.ISO_8859_1)
                assertTrue("vbc4-evaluator-dialect" !in text)
                assertTrue("bound-page-lane" !in text)
                assertTrue("bound-page-plan" !in text)
            } finally {
                opaque.fill(0)
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

    private fun opaquePartitionsThirtyTwoByteDek(opaque: ByteArray): Boolean {
        if (opaque.size < 8 || opaque[0] != 'A'.code.toByte() || opaque[1] != 'K'.code.toByte()) return false
        val fragmentCount = opaque[5].toInt() and 0xFF
        if (fragmentCount !in 4..12) return false
        val covered = BooleanArray(32)
        var cursor = 6 + 12 + 16 + 32 + 32 + 32
        repeat(fragmentCount) {
            if (cursor + 5 > opaque.size) return false
            val offset = opaque[cursor].toInt() and 0xFF
            val length = opaque[cursor + 1].toInt() and 0xFF
            cursor += 5
            if (length == 0 || offset + length > 32) return false
            for (index in offset until offset + length) {
                if (covered[index]) return false
                covered[index] = true
            }
            if (cursor + 4 > opaque.size) return false
            val tokenLen = ((opaque[cursor].toInt() and 0xFF) shl 24) or
                ((opaque[cursor + 1].toInt() and 0xFF) shl 16) or
                ((opaque[cursor + 2].toInt() and 0xFF) shl 8) or
                (opaque[cursor + 3].toInt() and 0xFF)
            cursor += 4 + tokenLen + 16
            if (cursor + 4 > opaque.size) return false
            val encodedLen = ((opaque[cursor].toInt() and 0xFF) shl 24) or
                ((opaque[cursor + 1].toInt() and 0xFF) shl 16) or
                ((opaque[cursor + 2].toInt() and 0xFF) shl 8) or
                (opaque[cursor + 3].toInt() and 0xFF)
            cursor += 4 + encodedLen + 16
        }
        return covered.all { it }
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
