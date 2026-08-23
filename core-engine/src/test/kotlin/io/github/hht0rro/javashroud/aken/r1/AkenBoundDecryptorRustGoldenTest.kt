package io.github.hht0rro.javashroud.aken.r1

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBoundDecryptorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenEvaluatorState
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenHighValueLeafIdentity
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRoutingMetadata
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimeEvaluatorPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenRuntimePageDescriptor
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenSealingProofMetadata
import java.nio.file.Files
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue

class AkenBoundDecryptorRustGoldenTest {
    @Test
    fun kotlin_bound_plan_reconstructs_the_same_dek_as_the_evaluator_graph() {
        val commitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index -> (index * 13 + 5).toByte() }
        val plan = AkenBuildPlan.create(commitment, DeterministicSecureRandom(701))
        try {
            val page = plan.registerPage(
                kind = AkenResourceKind.Vbc4Method,
                identity = "fixture:runtime:descriptor".encodeToByteArray(),
                pageIndex = 4,
            )
            val fromGraph = AkenEvaluatorState.recoverForBuildVerification(page)
            val descriptor = descriptorFor(plan, page)
            val opaque = checkNotNull(descriptor.evaluatorPlan.copyBoundDecryptorForNative())
            val fromBound = AkenBoundDecryptorPlan.fromOpaque(opaque).recoverPageKeyForBuildVerification()
            try {
                assertContentEquals(fromGraph, fromBound)
                val dest = resourceRoot().resolve("aken-r1-sidecar")
                Files.createDirectories(dest)
                Files.write(dest.resolve("bound-golden.bin"), opaque)
                Files.write(dest.resolve("bound-golden.dek"), fromBound)
                assertTrue(Files.size(dest.resolve("bound-golden.bin")) > 0)
            } finally {
                fromGraph.fill(0)
                fromBound.fill(0)
                opaque.fill(0)
            }
        } finally {
            plan.wipe()
        }
    }

    private fun descriptorFor(plan: AkenBuildPlan, page: AkenBuildPlan.Page): AkenRuntimePageDescriptor {
        val route = AkenRoutingMetadata.fromHandle(
            handle = page.handle,
            logicalIdentity = page.logicalIdentity,
            resourcePath = "META-INF/.aken/runtime/" + page.resourceKind.id + "-" + page.pageIndex + ".bin",
            resourceOffset = 17,
            storedLength = 113,
            codecVariant = page.codecVariant,
            layoutVariant = page.layoutVariant,
            logicalBindingPath = "META-INF/vbc4/logical-binding-${page.pageIndex}.bin",
        )
        val leaf = AkenHighValueLeafIdentity.fromHandle(page.handle, page.logicalIdentity)
        val proof = AkenSealingProofMetadata.create(
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
        val fingerprint = page.evaluatorPlan.fingerprint
        return AkenRuntimePageDescriptor.create(
            handle = page.handle,
            logicalIdentity = page.logicalIdentity,
            route = route,
            proof = proof,
            targetPageSize = page.targetSize,
            evaluatorPlan = AkenRuntimeEvaluatorPlan.createBound(
                page.evaluatorPlan.boundPlanForRuntime(route, proof.callSiteProof),
                fingerprint,
            ),
        )
    }

    private fun resourceRoot() = java.nio.file.Path.of("src/test/resources").let { path ->
        if (Files.isDirectory(path)) path else java.nio.file.Path.of("core-engine").resolve(path)
    }

    private class DeterministicSecureRandom(seed: Int) : SecureRandom() {
        private var state = seed
        override fun nextBytes(bytes: ByteArray) {
            for (index in bytes.indices) {
                state = state * 1103515245 + 12345
                bytes[index] = ((state ushr 16) and 0xFF).toByte()
            }
        }
    }
}
