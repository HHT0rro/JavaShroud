package io.github.hht0rro.javashroud.transforms.protection.aken

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays
import java.util.Base64

/**
 * Merkle integrity mesh for encrypted AKEN pages and native chunks.
 *
 * Leaf hashes always cover the complete supplied payload. Artifact canonical
 * hashing is deliberately separate: only that operation may zero approved root
 * shard ranges to break the self-reference created when a commitment is written
 * back into its own artifact.
 */
class AkenIntegrityMesh private constructor(
    private val proofs: Map<String, MerkleProof>,
    root: ByteArray,
    val leafCount: Int,
) {
    private val rootValue: ByteArray = root.copyOf()

    /** Defensive-copy Merkle root view. */
    val root: ByteArray
        get() = rootValue.copyOf()

    /** Input leaf with defensive-copy identity and payload views. */
    class Leaf(identity: ByteArray, payload: ByteArray) {
        private val identityValue: ByteArray = identity.copyOf()
        private val payloadValue: ByteArray = payload.copyOf()

        init {
            require(identityValue.isNotEmpty()) { "AKEN integrity leaf identity must not be empty" }
        }

        val identity: ByteArray
            get() = identityValue.copyOf()

        val payload: ByteArray
            get() = payloadValue.copyOf()

        internal fun copyIdentityForBuild(): ByteArray = identityValue.copyOf()

        internal fun copyPayloadForBuild(): ByteArray = payloadValue.copyOf()
    }

    /** Defensive-copy Merkle proof for exactly one logical leaf. */
    class MerkleProof(
        val leafIndex: Int,
        leafDigest: ByteArray,
        siblings: List<ByteArray>,
        siblingIsLeft: List<Boolean>,
        root: ByteArray,
    ) {
        private val leafDigestValue: ByteArray = leafDigest.copyOf()
        private val siblingValues: List<ByteArray> = siblings.map { it.copyOf() }
        private val siblingIsLeftValue: List<Boolean> = siblingIsLeft.toList()
        private val rootValue: ByteArray = root.copyOf()

        init {
            require(leafIndex >= 0) { "AKEN Merkle proof leaf index must be non-negative" }
            require(leafDigestValue.size == HASH_SIZE) { "AKEN Merkle leaf digest has an invalid length" }
            require(siblingValues.size == siblingIsLeftValue.size) { "AKEN Merkle proof path is malformed" }
            require(siblingValues.all { it.size == HASH_SIZE }) { "AKEN Merkle sibling has an invalid length" }
            require(rootValue.size == HASH_SIZE) { "AKEN Merkle root has an invalid length" }
        }

        val leafDigest: ByteArray
            get() = leafDigestValue.copyOf()

        val siblings: List<ByteArray>
            get() = siblingValues.map { it.copyOf() }

        val siblingIsLeft: List<Boolean>
            get() = siblingIsLeftValue.toList()

        val root: ByteArray
            get() = rootValue.copyOf()

        internal fun copyForStorage(): MerkleProof = MerkleProof(
            leafIndex = leafIndex,
            leafDigest = leafDigestValue,
            siblings = siblingValues,
            siblingIsLeft = siblingIsLeftValue,
            root = rootValue,
        )

        internal fun copyLeafDigestForVerification(): ByteArray = leafDigestValue.copyOf()

        internal fun copySiblingsForVerification(): List<ByteArray> = siblingValues.map { it.copyOf() }

        internal fun copyRootForVerification(): ByteArray = rootValue.copyOf()
    }

    fun proofFor(identity: ByteArray): MerkleProof? {
        if (identity.isEmpty()) return null
        return proofs[identityKey(identity)]?.copyForStorage()
    }

    fun pathFor(identity: ByteArray): MerkleProof? = proofFor(identity)

    fun verify(identity: ByteArray, payload: ByteArray): Boolean {
        val proof = proofFor(identity) ?: return false
        return verify(proof, identity, payload)
    }

    fun verify(proof: MerkleProof, identity: ByteArray, payload: ByteArray): Boolean {
        if (identity.isEmpty()) return false
        var calculatedLeaf: ByteArray? = null
        var proofLeaf: ByteArray? = null
        var proofRoot: ByteArray? = null
        var current: ByteArray? = null
        var siblings: List<ByteArray>? = null
        try {
            calculatedLeaf = leafDigest(identity, payload)
            proofLeaf = proof.copyLeafDigestForVerification()
            if (!MessageDigest.isEqual(calculatedLeaf, proofLeaf)) return false

            val siblingPath = proof.copySiblingsForVerification()
            siblings = siblingPath
            val directions = proof.siblingIsLeft
            if (siblingPath.size != directions.size) return false
            current = calculatedLeaf
            calculatedLeaf = null
            for (index in siblingPath.indices) {
                val currentDigest = current ?: return false
                val next = if (directions[index]) {
                    node(siblingPath[index], currentDigest)
                } else {
                    node(currentDigest, siblingPath[index])
                }
                Arrays.fill(currentDigest, 0)
                current = next
            }
            proofRoot = proof.copyRootForVerification()
            val finalDigest = current ?: return false
            val expectedRoot = proofRoot ?: return false
            return MessageDigest.isEqual(finalDigest, expectedRoot) && MessageDigest.isEqual(finalDigest, rootValue)
        } finally {
            calculatedLeaf?.fill(0)
            proofLeaf?.fill(0)
            proofRoot?.fill(0)
            current?.fill(0)
            siblings?.forEach { Arrays.fill(it, 0) }
        }
    }

    companion object {
        private const val HASH_SIZE = 32
        private val LEAF_DOMAIN = "AKEN-v4-integrity-leaf".toByteArray(StandardCharsets.US_ASCII)
        private val NODE_DOMAIN = "AKEN-v4-integrity-node".toByteArray(StandardCharsets.US_ASCII)
        private val CANONICAL_DOMAIN = "AKEN-v4-artifact-canonical".toByteArray(StandardCharsets.US_ASCII)

        fun build(leaves: List<Leaf>): AkenIntegrityMesh {
            require(leaves.isNotEmpty()) { "AKEN integrity mesh requires at least one leaf" }

            val identityKeys = HashSet<String>()
            val firstLevel = ArrayList<ByteArray>(leaves.size)
            val levels = ArrayList<List<ByteArray>>()
            try {
                leaves.forEach { leaf ->
                    val identity = leaf.copyIdentityForBuild()
                    val payload = leaf.copyPayloadForBuild()
                    try {
                        require(identity.isNotEmpty()) { "AKEN integrity leaf identity must not be empty" }
                        require(identityKeys.add(identityKey(identity))) {
                            "AKEN integrity mesh contains a duplicate leaf identity"
                        }
                        firstLevel += leafDigest(identity, payload)
                    } finally {
                        Arrays.fill(identity, 0)
                        Arrays.fill(payload, 0)
                    }
                }
                levels += firstLevel
                while (levels.last().size > 1) {
                    val previous = levels.last()
                    val next = ArrayList<ByteArray>((previous.size + 1) / 2)
                    var index = 0
                    while (index < previous.size) {
                        val right = previous.getOrElse(index + 1) { previous[index] }
                        next += node(previous[index], right)
                        index += 2
                    }
                    levels += next
                }

                val root = levels.last().single()
                val proofMap = LinkedHashMap<String, MerkleProof>(leaves.size)
                leaves.indices.forEach { leafIndex ->
                    val siblings = ArrayList<ByteArray>()
                    val siblingIsLeft = ArrayList<Boolean>()
                    var index = leafIndex
                    for (levelIndex in 0 until levels.lastIndex) {
                        val level = levels[levelIndex]
                        val siblingIndex = if (index % 2 == 0) index + 1 else index - 1
                        siblings += level.getOrElse(siblingIndex) { level[index] }.copyOf()
                        siblingIsLeft += siblingIndex < index
                        index /= 2
                    }
                    val identity = leaves[leafIndex].copyIdentityForBuild()
                    try {
                        proofMap[identityKey(identity)] = MerkleProof(
                            leafIndex = leafIndex,
                            leafDigest = firstLevel[leafIndex],
                            siblings = siblings,
                            siblingIsLeft = siblingIsLeft,
                            root = root,
                        )
                    } finally {
                        Arrays.fill(identity, 0)
                        siblings.forEach { Arrays.fill(it, 0) }
                    }
                }
                return AkenIntegrityMesh(proofMap, root, leaves.size)
            } finally {
                levels.forEach { level -> level.forEach { Arrays.fill(it, 0) } }
            }
        }

        /**
         * Canonical artifact commitment with only approved root-shard ranges
         * zeroed. This operation is intentionally independent from leaf hashing.
         */
        fun artifactCanonicalHash(artifact: ByteArray, rootShardRanges: List<IntRange>): ByteArray {
            val ranges = normalizeRanges(artifact.size, rootShardRanges)
            val canonical = artifact.copyOf()
            try {
                ranges.forEach { range -> Arrays.fill(canonical, range.first, range.last + 1, 0) }
                return framedDigest(CANONICAL_DOMAIN, canonical)
            } finally {
                Arrays.fill(canonical, 0)
            }
        }

        /** Compatibility name for callers that explicitly provide shard ranges. */
        fun canonicalHash(artifact: ByteArray, rootShardRanges: List<IntRange>): ByteArray =
            artifactCanonicalHash(artifact, rootShardRanges)

        private fun leafDigest(identity: ByteArray, payload: ByteArray): ByteArray =
            framedDigest(LEAF_DOMAIN, identity, payload)

        private fun node(left: ByteArray, right: ByteArray): ByteArray =
            framedDigest(NODE_DOMAIN, left, right)

        private fun framedDigest(domain: ByteArray, vararg fields: ByteArray): ByteArray {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(domain)
            fields.forEach { field ->
                updateInt(digest, field.size)
                digest.update(field)
            }
            return digest.digest()
        }

        private fun updateInt(digest: MessageDigest, value: Int) {
            digest.update((value ushr 24).toByte())
            digest.update((value ushr 16).toByte())
            digest.update((value ushr 8).toByte())
            digest.update(value.toByte())
        }

        private fun identityKey(identity: ByteArray): String =
            Base64.getUrlEncoder().withoutPadding().encodeToString(identity)

        private fun normalizeRanges(artifactSize: Int, rootShardRanges: List<IntRange>): List<IntRange> {
            val sorted = rootShardRanges.sortedBy { it.first }
            var previous: IntRange? = null
            sorted.forEach { range ->
                require(range.first >= 0 && range.last >= range.first) {
                    "AKEN root shard range must be non-negative and ordered"
                }
                require(range.first < artifactSize && range.last < artifactSize) {
                    "AKEN root shard range is outside the artifact"
                }
                val prior = previous
                require(prior == null || prior.last < range.first) {
                    "AKEN root shard ranges must not overlap"
                }
                previous = range
            }
            return sorted
        }
    }
}
