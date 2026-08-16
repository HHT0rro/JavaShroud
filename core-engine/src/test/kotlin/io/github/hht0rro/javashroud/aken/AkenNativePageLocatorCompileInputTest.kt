package io.github.hht0rro.javashroud.aken

import io.github.hht0rro.javashroud.transforms.protection.aken.AkenArtifactCommitment
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenNativePageLocatorCompileInput
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenResourceKind
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PageEmissionRequest
import io.github.hht0rro.javashroud.transforms.protection.aken.AkenVbc4PageEmitter
import java.security.SecureRandom
import java.util.Arrays
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AkenNativePageLocatorCompileInputTest {
    @Test
    fun vbc4_emission_compiles_to_one_exact_native_current_page_record_and_wipes() {
        val artifactCommitment = ByteArray(AkenArtifactCommitment.DIGEST_SIZE) { index ->
            (0xA7 xor (index * 13)).toByte()
        }
        val logicalIdentity = "fixture:aken-native-page-locator:method".encodeToByteArray()
        val expectedEntryToken = 0x4A4B_454E_0000_0BEEuL.toLong()
        val originalPlaintext = "vbc4 page compiler locator input".encodeToByteArray()
        val rawProof = ByteArray(65) { index -> (index * 29 + 7).toByte() }
        val plan = AkenBuildPlan.create(artifactCommitment, SecureRandom())
        artifactCommitment.fill(0)
        val page = plan.registerPage(AkenResourceKind.Vbc4Method, logicalIdentity, pageIndex = 0)
        logicalIdentity.fill(0)

        val request = try {
            AkenVbc4PageEmissionRequest.create(
                page = page,
                entryToken = expectedEntryToken,
                logicalIdentity = page.logicalIdentity,
                plaintext = originalPlaintext,
                resourcePath = "META-INF/.aken/vbc4/native-locator-0.bin",
                callSiteProof = rawProof,
            )
        } finally {
            Arrays.fill(originalPlaintext, 0)
        }

        val output = AkenVbc4PageEmitter.emitAndWipe(plan, listOf(request))
        var compileInput: AkenNativePageLocatorCompileInput? = null
        var handleBytes: ByteArray? = null
        var callSiteProof: ByteArray? = null
        try {
            val emission = output.pagesForBuild().single()
            assertEquals(expectedEntryToken, emission.entryToken)

            compileInput = AkenNativePageLocatorCompileInput.fromVbc4Emission(
                emission = emission,
                vbc4StateBindingLayoutDigest = ByteArray(32) { index -> (index * 23 + 7).toByte() },
            )
            val input = checkNotNull(compileInput)
            handleBytes = emission.copyHandleForBuild().let { handle ->
                try {
                    handle.encoded
                } finally {
                    handle.wipe()
                }
            }
            callSiteProof = emission.copyCallSiteProofForBuild()

            assertTrue(
                input.matchesCurrentPageForBuild(
                    entryToken = expectedEntryToken,
                    encodedHandle = checkNotNull(handleBytes),
                    pageIndex = 0,
                    rawCallSiteProof = checkNotNull(callSiteProof),
                ),
            )
            assertFalse(
                input.matchesCurrentPageForBuild(
                    entryToken = expectedEntryToken + 1,
                    encodedHandle = checkNotNull(handleBytes),
                    pageIndex = 0,
                    rawCallSiteProof = checkNotNull(callSiteProof),
                ),
            )

            val wrongHandle = checkNotNull(handleBytes).copyOf().also {
                it[0] = (it[0].toInt() xor 0x5A).toByte()
            }
            val wrongProof = checkNotNull(callSiteProof).copyOf().also {
                it[it.lastIndex] = (it[it.lastIndex].toInt() xor 0x6C).toByte()
            }
            try {
                assertFalse(
                    input.matchesCurrentPageForBuild(
                        entryToken = expectedEntryToken,
                        encodedHandle = wrongHandle,
                        pageIndex = 0,
                        rawCallSiteProof = checkNotNull(callSiteProof),
                    ),
                )
                assertFalse(
                    input.matchesCurrentPageForBuild(
                        entryToken = expectedEntryToken,
                        encodedHandle = checkNotNull(handleBytes),
                        pageIndex = 1,
                        rawCallSiteProof = checkNotNull(callSiteProof),
                    ),
                )
                assertFalse(
                    input.matchesCurrentPageForBuild(
                        entryToken = expectedEntryToken,
                        encodedHandle = checkNotNull(handleBytes),
                        pageIndex = 0,
                        rawCallSiteProof = wrongProof,
                    ),
                )
            } finally {
                Arrays.fill(wrongHandle, 0)
                Arrays.fill(wrongProof, 0)
            }

            val nativeEnvelope = input.copyNativeEnvelopeForCompiler()
            val descriptor = input.copyResolvedDescriptorForCompiler()
            val route = input.copyRouteEncodingForCompiler()
            val compilerRecord = input.copyNativeLocatorRecordForCompiler()
            try {
                assertTrue(nativeEnvelope.isNotEmpty() && nativeEnvelope.size <= 4096)
                assertTrue(descriptor.isNotEmpty())
                assertTrue(route.isNotEmpty())
                assertTrue(compilerRecord.size > nativeEnvelope.size)
                assertEquals(AkenResourceKind.Vbc4Method, input.resourceKind)
                assertEquals(emission.resourcePath, input.resourcePath)
                assertEquals(emission.resourceOffset, input.resourceOffset)
                assertEquals(emission.storedLength, input.storedLength)

                compilerRecord[0] = (compilerRecord[0].toInt() xor 0x7F).toByte()
                val retained = input.copyNativeLocatorRecordForCompiler()
                try {
                    assertFalse(compilerRecord.contentEquals(retained))
                } finally {
                    Arrays.fill(retained, 0)
                }
            } finally {
                Arrays.fill(nativeEnvelope, 0)
                Arrays.fill(descriptor, 0)
                Arrays.fill(route, 0)
                Arrays.fill(compilerRecord, 0)
            }

            output.wipe()
            assertTrue(output.isWiped)
            assertTrue(
                input.matchesCurrentPageForBuild(
                    entryToken = expectedEntryToken,
                    encodedHandle = checkNotNull(handleBytes),
                    pageIndex = 0,
                    rawCallSiteProof = checkNotNull(callSiteProof),
                ),
                "compiler input must own its own current-page copies after the emission owner is wiped",
            )

            input.wipe()
            assertTrue(input.isWiped)
            assertFalse(
                input.matchesCurrentPageForBuild(
                    entryToken = expectedEntryToken,
                    encodedHandle = checkNotNull(handleBytes),
                    pageIndex = 0,
                    rawCallSiteProof = checkNotNull(callSiteProof),
                ),
            )
            assertFailsWith<IllegalStateException> { input.copyNativeLocatorRecordForCompiler() }
        } finally {
            compileInput?.wipe()
            output.wipe()
            handleBytes?.let { Arrays.fill(it, 0) }
            callSiteProof?.let { Arrays.fill(it, 0) }
            Arrays.fill(rawProof, 0)
        }
    }
}
