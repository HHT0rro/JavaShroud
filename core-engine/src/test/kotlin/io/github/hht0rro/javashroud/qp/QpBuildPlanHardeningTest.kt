package io.github.hht0rro.javashroud.qp

import io.github.hht0rro.javashroud.transforms.protection.qp.QpBuildPlan
import io.github.hht0rro.javashroud.transforms.protection.qp.QpIntegrityTree
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageSizePolicy
import io.github.hht0rro.javashroud.transforms.protection.qp.QpPageCodec
import io.github.hht0rro.javashroud.transforms.protection.qp.QpResourceKind
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class QpBuildPlanHardeningTest {
    private val commitment = ByteArray(32) { index -> (index * 11 + 3).toByte() }

    @Test
    fun page_round_trip_binds_every_codec_input_and_tamper_fails_closed() {
        val plan = QpBuildPlan.create(commitment, DeterministicSecureRandom(17))
        try {
            val page = plan.registerPage(
                kind = QpResourceKind.QpMethod,
                identity = "fixture:qp:method".encodeToByteArray(),
                pageIndex = 7,
            )
            val alternate = plan.registerPage(
                kind = QpResourceKind.StringPage,
                identity = "fixture:string:page".encodeToByteArray(),
                pageIndex = 8,
            )
            val plaintext = "Qp page payload".encodeToByteArray()
            val encoded = plan.encodeForMaterialization(page.handle, plaintext)
            val layout = page.pageLayout
            val alternateLayout = alternate.pageLayout
            val fingerprint = page.evaluatorPlan.fingerprint
            val locator = page.handle.locatorToken
            val identity = page.logicalIdentity
            val wrongCommitment = commitment.copyOf().also { it[0] = (it[0].toInt() xor 0x2A).toByte() }
            val wrongFingerprint = fingerprint.copyOf().also { it[0] = (it[0].toInt() xor 0x2A).toByte() }
            val wrongLocator = locator.copyOf().also { it[0] = (it[0].toInt() xor 0x2A).toByte() }
            val wrongIdentity = identity.copyOf().also { it[0] = (it[0].toInt() xor 0x2A).toByte() }
            val codecProbeDek = ByteArray(32) { index -> (index * 17 + 9).toByte() }
            try {
                // The plan exposes only a boolean AEAD verifier; plaintext is
                // never returned from the plan or materialization API.
                assertTrue(plan.verifyEncodedPayloadForMaterialization(page.handle, encoded))

                val codecProbe = QpPageCodec.encode(
                    plain = plaintext,
                    dek = codecProbeDek,
                    commitment = commitment,
                    identity = identity,
                    pageIndex = page.pageIndex,
                    kind = page.resourceKind,
                    fingerprint = fingerprint,
                    codec = page.codecVariant,
                    layout = layout,
                    locator = locator,
                    random = DeterministicSecureRandom(53),
                    nonceOverride = ByteArray(QpPageCodec.NONCE_SIZE) { index -> (index + 53).toByte() },
                )
                try {
                    val decodedProbe = QpPageCodec.decode(
                        codecProbe,
                        codecProbeDek,
                        commitment,
                        identity,
                        page.pageIndex,
                        page.resourceKind,
                        fingerprint,
                        page.codecVariant,
                        layout,
                        locator,
                    )
                    try {
                        assertContentEquals(plaintext, requireNotNull(decodedProbe))
                    } finally {
                        decodedProbe?.fill(0)
                    }
                    assertNull(
                        QpPageCodec.decode(
                            codecProbe,
                            codecProbeDek,
                            wrongCommitment,
                            identity,
                            page.pageIndex,
                            page.resourceKind,
                            fingerprint,
                            page.codecVariant,
                            layout,
                            locator,
                        ),
                    )
                    assertNull(
                        QpPageCodec.decode(
                            codecProbe,
                            codecProbeDek,
                            commitment,
                            wrongIdentity,
                            page.pageIndex,
                            page.resourceKind,
                            fingerprint,
                            page.codecVariant,
                            layout,
                            locator,
                        ),
                    )
                    assertNull(
                        QpPageCodec.decode(
                            codecProbe,
                            codecProbeDek,
                            commitment,
                            identity,
                            page.pageIndex + 1,
                            page.resourceKind,
                            fingerprint,
                            page.codecVariant,
                            layout,
                            locator,
                        ),
                    )
                    assertNull(
                        QpPageCodec.decode(
                            codecProbe,
                            codecProbeDek,
                            commitment,
                            identity,
                            page.pageIndex,
                            QpResourceKind.NativeChunk,
                            fingerprint,
                            page.codecVariant,
                            layout,
                            locator,
                        ),
                    )
                    assertNull(
                        QpPageCodec.decode(
                            codecProbe,
                            codecProbeDek,
                            commitment,
                            identity,
                            page.pageIndex,
                            page.resourceKind,
                            wrongFingerprint,
                            page.codecVariant,
                            layout,
                            locator,
                        ),
                    )
                    assertNull(
                        QpPageCodec.decode(
                            codecProbe,
                            codecProbeDek,
                            commitment,
                            identity,
                            page.pageIndex,
                            page.resourceKind,
                            fingerprint,
                            "unknown-codec",
                            layout,
                            locator,
                        ),
                    )
                    assertNull(
                        QpPageCodec.decode(
                            codecProbe,
                            codecProbeDek,
                            commitment,
                            identity,
                            page.pageIndex,
                            page.resourceKind,
                            fingerprint,
                            page.codecVariant,
                            alternateLayout,
                            locator,
                        ),
                    )
                    assertNull(
                        QpPageCodec.decode(
                            codecProbe,
                            codecProbeDek,
                            commitment,
                            identity,
                            page.pageIndex,
                            page.resourceKind,
                            fingerprint,
                            page.codecVariant,
                            layout,
                            wrongLocator,
                        ),
                    )
                } finally {
                    codecProbe.fill(0)
                }

                val headerOffset = layout.headerOffset(encoded.size)
                val tamperedCommitment = encoded.copyOf().also {
                    it[headerOffset + QpPageCodec.OFFSET_COMMITMENT] =
                        (it[headerOffset + QpPageCodec.OFFSET_COMMITMENT].toInt() xor 0x41).toByte()
                }
                val tamperedDeclaredPlainLength = encoded.copyOf().also {
                    it[headerOffset + QpPageCodec.OFFSET_PLAINTEXT_LENGTH + 3] =
                        (it[headerOffset + QpPageCodec.OFFSET_PLAINTEXT_LENGTH + 3].toInt() xor 0x01).toByte()
                }
                val tamperedDeclaredBodyLength = encoded.copyOf().also {
                    it[headerOffset + QpPageCodec.OFFSET_CIPHERTEXT_LENGTH + 3] =
                        (it[headerOffset + QpPageCodec.OFFSET_CIPHERTEXT_LENGTH + 3].toInt() xor 0x01).toByte()
                }
                val tamperedNonce = encoded.copyOf().also {
                    it[headerOffset + QpPageCodec.OFFSET_NONCE] =
                        (it[headerOffset + QpPageCodec.OFFSET_NONCE].toInt() xor 0x41).toByte()
                }
                val tamperedBody = encoded.copyOf().also {
                    it[layout.bodyOffset() + plaintext.size] =
                        (it[layout.bodyOffset() + plaintext.size].toInt() xor 0x41).toByte()
                }
                try {
                    assertFalse(plan.verifyEncodedPayloadForMaterialization(page.handle, tamperedCommitment))
                    assertFalse(plan.verifyEncodedPayloadForMaterialization(page.handle, tamperedDeclaredPlainLength))
                    assertFalse(plan.verifyEncodedPayloadForMaterialization(page.handle, tamperedDeclaredBodyLength))
                    assertFalse(plan.verifyEncodedPayloadForMaterialization(page.handle, tamperedNonce))
                    assertFalse(plan.verifyEncodedPayloadForMaterialization(page.handle, tamperedBody))
                } finally {
                    tamperedCommitment.fill(0)
                    tamperedDeclaredPlainLength.fill(0)
                    tamperedDeclaredBodyLength.fill(0)
                    tamperedNonce.fill(0)
                    tamperedBody.fill(0)
                }
            } finally {
                fingerprint.fill(0)
                locator.fill(0)
                identity.fill(0)
                wrongCommitment.fill(0)
                wrongFingerprint.fill(0)
                wrongLocator.fill(0)
                wrongIdentity.fill(0)
                codecProbeDek.fill(0)
                layout.wipe()
                alternateLayout.wipe()
                encoded.fill(0)
                plaintext.fill(0)
            }
        } finally {
            plan.wipe()
        }
    }

    @Test
    fun current_native_evaluator_is_fingerprint_bound_polymorphic_and_defensive() {
        val plan = QpBuildPlan.create(commitment, DeterministicSecureRandom(23))
        try {
            val page = plan.registerPage(
                QpResourceKind.EncryptedClassPage,
                "fixture:class".encodeToByteArray(),
                3,
            )
            val evaluator = page.evaluatorPlan
            assertContentEquals(evaluator.fingerprint, page.handle.evaluatorPlanFingerprint)

            val returnedIdentity = page.logicalIdentity
            val returnedFingerprint = evaluator.fingerprint
            val returnedHandle = page.handle.encoded
            val returnedLocator = page.handle.locatorToken
            try {
                returnedIdentity.fill(0x11)
                returnedFingerprint.fill(0x22)
                returnedHandle.fill(0x55)
                returnedLocator.fill(0x66)
                val encoded = plan.encodeForMaterialization(page.handle, "defensive-copy".encodeToByteArray())
                try {
                    assertTrue(plan.verifyEncodedPayloadForMaterialization(page.handle, encoded))
                } finally {
                    encoded.fill(0)
                }
            } finally {
                returnedIdentity.fill(0)
                returnedFingerprint.fill(0)
                returnedHandle.fill(0)
                returnedLocator.fill(0)
            }

            assertFailsWith<IllegalArgumentException> {
                plan.registerPage(QpResourceKind.EncryptedClassPage, "fixture:class".encodeToByteArray(), 3)
            }
            val publicMethodNames = QpBuildPlan.EvaluatorPlan::class.java.methods.map { it.name.lowercase() }
            assertFalse(
                publicMethodNames.any { name ->
                    name.contains("fragment") ||
                        name.contains("terminal") ||
                        name.contains("execution") ||
                        name.contains("recover") ||
                        name.contains("dek")
                },
            )
            assertFalse(
                QpBuildPlan::class.java.declaredClasses.any { nested ->
                    nested.simpleName == "EvaluatorFragment"
                },
            )
        } finally {
            plan.wipe()
        }

        val encodings = LinkedHashSet<String>()
        val locators = LinkedHashSet<String>()
        val fingerprints = LinkedHashSet<String>()
        val targetSizes = LinkedHashSet<Int>()
        repeat(10) { seed ->
            val build = QpBuildPlan.create(commitment, DeterministicSecureRandom(seed + 101))
            try {
                val page = build.registerPage(QpResourceKind.StringPage, "fixture:poly".encodeToByteArray(), 1)
                val fingerprint = page.evaluatorPlan.fingerprint
                val encoding = page.handle.encoded
                val locator = page.handle.locatorToken
                try {
                    encodings += encoding.joinToString(separator = ",")
                    locators += locator.joinToString(separator = ",")
                    fingerprints += fingerprint.joinToString(separator = ",")
                    targetSizes += page.targetSize
                } finally {
                    fingerprint.fill(0)
                    encoding.fill(0)
                    locator.fill(0)
                }
            } finally {
                build.wipe()
            }
        }
        assertEquals(10, encodings.size)
        assertEquals(10, locators.size)
        assertEquals(10, fingerprints.size)
        assertTrue(targetSizes.size > 1)
    }

    @Test
    fun build_only_page_api_has_no_java_decoder_or_dek_lease_and_wipes_after_close() {
        val plan = QpBuildPlan.create(commitment, DeterministicSecureRandom(41))
        val page = plan.registerPage(QpResourceKind.NativeChunk, "fixture:native".encodeToByteArray(), 2)
        val handle = page.handle
        val payload = plan.encodeForMaterialization(handle, byteArrayOf(1))
        try {
            assertTrue(plan.verifyEncodedPayloadForMaterialization(handle, payload))
        } finally {
            payload.fill(0)
        }

        plan.wipe()
        assertTrue(plan.isWiped())
        assertFailsWith<IllegalStateException> {
            plan.encodeForMaterialization(handle, byteArrayOf(1))
        }
        assertFalse(plan.verifyEncodedPayloadForMaterialization(handle, byteArrayOf(1)))
        assertFailsWith<IllegalStateException> {
            plan.artifactCanonicalCommitment
        }

        val publicMethodNames = QpBuildPlan::class.java.methods.map { method -> method.name.lowercase() }
        assertFalse(
            publicMethodNames.any { name ->
                name.contains("decode") || name.contains("borrow") || name.contains("dek")
            },
        )
        assertFalse(
            QpBuildPlan::class.java.declaredClasses.any { nested ->
                java.lang.reflect.Modifier.isPublic(nested.modifiers) && nested.simpleName.contains("Lease")
            },
        )
    }

    @Test
    fun integrity_mesh_proofs_are_defensive_and_cover_full_leaf_payloads() {
        val leaves = listOf(
            QpIntegrityTree.Leaf("one".encodeToByteArray(), byteArrayOf(1, 2, 3)),
            QpIntegrityTree.Leaf("two".encodeToByteArray(), byteArrayOf(4, 5, 6)),
            QpIntegrityTree.Leaf("three".encodeToByteArray(), byteArrayOf(7, 8, 9)),
        )
        val mesh = QpIntegrityTree.build(leaves)
        assertEquals(3, mesh.leafCount)
        assertTrue(mesh.verify("one".encodeToByteArray(), byteArrayOf(1, 2, 3)))
        assertTrue(mesh.verify("two".encodeToByteArray(), byteArrayOf(4, 5, 6)))
        assertTrue(mesh.verify("three".encodeToByteArray(), byteArrayOf(7, 8, 9)))
        assertFalse(mesh.verify("one".encodeToByteArray(), byteArrayOf(1, 2, 99)))
        assertFalse(mesh.verify("other".encodeToByteArray(), byteArrayOf(1, 2, 3)))

        val proof = mesh.proofFor("two".encodeToByteArray())!!
        val originalDigest = proof.leafDigest
        val originalSiblings = proof.siblings
        val originalDirections = proof.siblingIsLeft
        val originalRoot = proof.root
        try {
            originalDigest[0] = (originalDigest[0].toInt() xor 0x01).toByte()
            originalSiblings.first()[0] = (originalSiblings.first()[0].toInt() xor 0x01).toByte()
            originalRoot[0] = (originalRoot[0].toInt() xor 0x01).toByte()
            assertTrue(mesh.verify(proof, "two".encodeToByteArray(), byteArrayOf(4, 5, 6)))
        } finally {
            originalDigest.fill(0)
            originalSiblings.forEach { it.fill(0) }
            originalRoot.fill(0)
        }

        val siblingTamper = proof.siblings
        val rootTamper = proof.root
        val digestTamper = proof.leafDigest
        val directionTamper = proof.siblingIsLeft.toMutableList()
        try {
            siblingTamper.first()[0] = (siblingTamper.first()[0].toInt() xor 0x01).toByte()
            assertFalse(
                mesh.verify(
                    QpIntegrityTree.MerkleProof(
                        proof.leafIndex,
                        proof.leafDigest,
                        siblingTamper,
                        proof.siblingIsLeft,
                        proof.root,
                    ),
                    "two".encodeToByteArray(),
                    byteArrayOf(4, 5, 6),
                ),
            )

            rootTamper[0] = (rootTamper[0].toInt() xor 0x01).toByte()
            assertFalse(
                mesh.verify(
                    QpIntegrityTree.MerkleProof(
                        proof.leafIndex,
                        proof.leafDigest,
                        proof.siblings,
                        proof.siblingIsLeft,
                        rootTamper,
                    ),
                    "two".encodeToByteArray(),
                    byteArrayOf(4, 5, 6),
                ),
            )

            digestTamper[0] = (digestTamper[0].toInt() xor 0x01).toByte()
            assertFalse(
                mesh.verify(
                    QpIntegrityTree.MerkleProof(
                        proof.leafIndex,
                        digestTamper,
                        proof.siblings,
                        proof.siblingIsLeft,
                        proof.root,
                    ),
                    "two".encodeToByteArray(),
                    byteArrayOf(4, 5, 6),
                ),
            )

            directionTamper[0] = !directionTamper[0]
            assertFalse(
                mesh.verify(
                    QpIntegrityTree.MerkleProof(
                        proof.leafIndex,
                        proof.leafDigest,
                        proof.siblings,
                        directionTamper,
                        proof.root,
                    ),
                    "two".encodeToByteArray(),
                    byteArrayOf(4, 5, 6),
                ),
            )
        } finally {
            siblingTamper.forEach { it.fill(0) }
            rootTamper.fill(0)
            digestTamper.fill(0)
        }

        assertFailsWith<IllegalArgumentException> {
            QpIntegrityTree.build(
                listOf(
                    QpIntegrityTree.Leaf("duplicate".encodeToByteArray(), byteArrayOf(1)),
                    QpIntegrityTree.Leaf("duplicate".encodeToByteArray(), byteArrayOf(2)),
                ),
            )
        }

        val rootWithOriginalPayload = QpIntegrityTree.build(
            listOf(QpIntegrityTree.Leaf("leaf".encodeToByteArray(), ByteArray(32) { it.toByte() })),
        ).root
        val rootWithChangedPayload = QpIntegrityTree.build(
            listOf(
                QpIntegrityTree.Leaf(
                    "leaf".encodeToByteArray(),
                    ByteArray(32) { index -> if (index == 12) 0x7E else index.toByte() },
                ),
            ),
        ).root
        try {
            assertFalse(rootWithOriginalPayload.contentEquals(rootWithChangedPayload))
        } finally {
            rootWithOriginalPayload.fill(0)
            rootWithChangedPayload.fill(0)
        }
    }

    @Test
    fun canonical_artifact_hash_zeros_only_valid_root_shard_ranges() {
        val artifact = ByteArray(64) { index -> index.toByte() }
        val ranges = listOf(10..15, 30..33)
        val baseline = QpIntegrityTree.artifactCanonicalHash(artifact, ranges)
        val changedInsideRanges = artifact.copyOf().also {
            it[10] = 0x4A
            it[15] = 0x4B
            it[30] = 0x4C
            it[33] = 0x4D
        }
        val changedOutsideRanges = artifact.copyOf().also { it[34] = 0x4E }
        val insideHash = QpIntegrityTree.artifactCanonicalHash(changedInsideRanges, ranges)
        val outsideHash = QpIntegrityTree.artifactCanonicalHash(changedOutsideRanges, ranges)
        try {
            assertContentEquals(baseline, insideHash)
            assertFalse(baseline.contentEquals(outsideHash))
        } finally {
            artifact.fill(0)
            changedInsideRanges.fill(0)
            changedOutsideRanges.fill(0)
            baseline.fill(0)
            insideHash.fill(0)
            outsideHash.fill(0)
        }

        assertFailsWith<IllegalArgumentException> {
            QpIntegrityTree.artifactCanonicalHash(ByteArray(8), listOf(-1..1))
        }
        assertFailsWith<IllegalArgumentException> {
            QpIntegrityTree.artifactCanonicalHash(ByteArray(8), listOf(7..8))
        }
        assertFailsWith<IllegalArgumentException> {
            QpIntegrityTree.artifactCanonicalHash(ByteArray(8), listOf(1..4, 4..6))
        }
    }

    @Test
    fun page_size_policy_covers_every_high_value_family() {
        QpResourceKind.entries.forEach { kind ->
            assertTrue(QpPageSizePolicy.DEFAULT.allowedSizes(kind).isNotEmpty())
            assertTrue(QpPageSizePolicy.DEFAULT.allowedSizes(kind).all { it > 0 })
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
