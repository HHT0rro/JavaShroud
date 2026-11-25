package io.github.hht0rro.javashroud.bytecode

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.tree.ClassNode
import java.security.MessageDigest

/**
 * Member shuffle transform.
 *
 * Randomizes the order of fields and methods in a class to break
 * positional assumptions made by decompilers and static analysis tools.
 * Uses ASM Tree API for reliable member reordering.
 *
 * Design inspired by obfuscator-master ShuffleMembersTransformer (MIT),
 * re-implemented as JavaShroud-native Kotlin.
 */
fun shuffleClassMembers(classBytes: ByteArray, buildEntropy: ByteArray, classIdentity: String): ByteArray {
    val classNode = ClassNode()
    val reader = ClassReader(classBytes)
    reader.accept(classNode, 0)

    if (classNode.fields.size <= 1 && classNode.methods.size <= 1) {
        return classBytes
    }

    val shuffledFields = buildLocalPermutation(
        values = classNode.fields,
        buildEntropy = buildEntropy,
        domain = "field",
        scopeIdentity = classIdentity,
        identity = { field -> "${field.name}:${field.desc}" },
    ).toMutableList()
    val shuffledMethods = buildLocalPermutation(
        values = classNode.methods,
        buildEntropy = buildEntropy,
        domain = "method",
        scopeIdentity = classIdentity,
        identity = { method -> "${method.name}${method.desc}" },
    ).toMutableList()

    classNode.fields = shuffledFields
    classNode.methods = shuffledMethods

    val writer = ClassWriter(reader, 0)
    classNode.accept(writer)
    return writer.toByteArray()
}

internal fun <T> buildLocalPermutation(
    values: List<T>,
    buildEntropy: ByteArray,
    domain: String,
    scopeIdentity: String,
    identity: (T) -> String,
): List<T> {
    if (values.size <= 1) return values.toList()
    val originalFirstIdentity = identity(values.first())
    val shuffled = values.sortedBy(identity).toMutableList()
    fisherYates(shuffled, BuildEntropyStream(buildEntropy, domain, scopeIdentity))
    if (identity(shuffled.first()) == originalFirstIdentity) {
        val swapIndex = 1 + BuildEntropyStream(buildEntropy, "$domain-prefix-guard", scopeIdentity)
            .nextInt(shuffled.size - 1)
        val value = shuffled[0]
        shuffled[0] = shuffled[swapIndex]
        shuffled[swapIndex] = value
    }
    return shuffled
}

private fun <T> fisherYates(values: MutableList<T>, entropy: BuildEntropyStream) {
    for (index in values.lastIndex downTo 1) {
        val swapIndex = entropy.nextInt(index + 1)
        if (swapIndex != index) {
            val value = values[index]
            values[index] = values[swapIndex]
            values[swapIndex] = value
        }
    }
}

private class BuildEntropyStream(buildEntropy: ByteArray, domain: String, identity: String) {
    private val seed = MessageDigest.getInstance("SHA-256").run {
        update("javashroud-member-shuffle-v1".toByteArray(Charsets.US_ASCII))
        update(0)
        update(buildEntropy)
        update(0)
        update(domain.toByteArray(Charsets.US_ASCII))
        update(0)
        digest(identity.toByteArray(Charsets.UTF_8))
    }
    private var counter = 0L

    fun nextInt(bound: Int): Int {
        require(bound > 0) { "shuffle bound must be positive" }
        val limit = (1L shl 32) - ((1L shl 32) % bound.toLong())
        while (true) {
            val block = MessageDigest.getInstance("SHA-256").run {
                update(seed)
                digest(longBytes(counter++))
            }
            val value = ((block[0].toLong() and 0xFFL) shl 24) or
                ((block[1].toLong() and 0xFFL) shl 16) or
                ((block[2].toLong() and 0xFFL) shl 8) or
                (block[3].toLong() and 0xFFL)
            if (value < limit) return (value % bound).toInt()
        }
    }
}

private fun longBytes(value: Long): ByteArray = ByteArray(Long.SIZE_BYTES) { index ->
    ((value ushr ((Long.SIZE_BYTES - 1 - index) * 8)) and 0xFF).toByte()
}
