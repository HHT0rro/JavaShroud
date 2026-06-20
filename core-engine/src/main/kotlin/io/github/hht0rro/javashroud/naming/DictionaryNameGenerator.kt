package io.github.hht0rro.javashroud.naming

import java.util.Random

/**
 * Configuration for rename operations, extracted from pass params.
 */
data class RenameConfig(
    val dictionaryStyle: String = "sequential",
    val seed: Long? = null,
    val preservePackageDepth: Int = 0,
    val shufflePackageSegmentCount: Boolean = true,
    val collisionPolicy: String = "append-index",
    val dictionaryFile: String = "",
)

/**
 * Generates names according to the specified dictionary style.
 *
 * Supports: iiliii, ooO0oO, nnmnmnm, sequential, unicode-confusable, custom-file.
 * Uses seed for deterministic replay when provided.
 */
internal class NameGenerator(
    private val config: RenameConfig,
    prefix: String = "",
) {
    private val rng = if (config.seed != null) Random(config.seed!!) else Random()
    private val customDictionary = loadCustomDictionary(config.dictionaryFile)
    private val collisionTracker = mutableSetOf<String>()
    private var counter = 0

    fun generateSimpleName(prefix: String): String {
        val baseName = when (config.dictionaryStyle) {
            "iiliii" -> generateIiliiiName()
            "ooO0oO" -> generateOoO0oOName()
            "nnmnmnm" -> generateNnmnmnmName()
            "sequential" -> generateSequentialName(prefix)
            "unicode-confusable" -> generateUnicodeConfusableName()
            "custom-file" -> generateCustomFileName()
            else -> generateSequentialName(prefix)
        }
        return applyCollisionPolicy(baseName)
    }

    fun generatePackageSegment(): String {
        return when (config.dictionaryStyle) {
            "iiliii" -> generateIiliiiName().lowercase()
            "ooO0oO" -> generateOoO0oOName().lowercase()
            "nnmnmnm" -> generateNnmnmnmName().lowercase()
            "sequential" -> "p${counter++.toString().padStart(4, '0')}"
            "unicode-confusable" -> generateUnicodeConfusableName().lowercase()
            "custom-file" -> generateCustomFileName().lowercase()
            else -> "p${counter++.toString().padStart(4, '0')}"
        }.let { applyCollisionPolicy(it) }
    }

    /**
     * iiliii: names composed of 'i' and 'l' characters, visually confusable.
     * Example outputs: "iliii", "lliil", "iiill"
     */
    private fun generateIiliiiName(): String {
        val len = 4 + rng.nextInt(4) // 4-7 chars
        return buildString {
            repeat(len) {
                append(if (rng.nextBoolean()) 'i' else 'l')
            }
        }
    }

    /**
     * ooO0oO: names composed of 'o', 'O', '0' characters, visually confusable.
     * Example outputs: "oO0o", "O0oO0", "ooOoO0"
     */
    private fun generateOoO0oOName(): String {
        val chars = charArrayOf('o', 'O', '0')
        val len = 4 + rng.nextInt(4)
        return buildString {
            repeat(len) {
                append(chars[rng.nextInt(chars.size)])
            }
        }
    }

    /**
     * nnmnmnm: names composed of 'n' and 'm' characters, visually confusable.
     * Example outputs: "nmnm", "nnmnmn", "mnnmn"
     */
    private fun generateNnmnmnmName(): String {
        val len = 4 + rng.nextInt(4)
        return buildString {
            repeat(len) {
                append(if (rng.nextBoolean()) 'n' else 'm')
            }
        }
    }

    /**
     * sequential: traditional C0000/m0000 style names.
     */
    private fun generateSequentialName(prefix: String): String {
        val idx = counter++
        return "${prefix}${idx.toString().padStart(4, '0')}"
    }

    /**
     * unicode-confusable: uses Unicode characters that look similar to ASCII.
     * Uses Cyrillic, Greek, and other lookalike characters.
     * Example: 'a' -> 'а' (Cyrillic), 'c' -> 'с' (Cyrillic), 'e' -> 'е' (Cyrillic)
     */
    private fun generateUnicodeConfusableName(): String {
        // Unicode confusable character sets
        val confusableSets = listOf(
            charArrayOf('a', '\u0430'), // Latin a / Cyrillic а
            charArrayOf('c', '\u0441'), // Latin c / Cyrillic с
            charArrayOf('e', '\u0435'), // Latin e / Cyrillic е
            charArrayOf('o', '\u043E'), // Latin o / Cyrillic о
            charArrayOf('p', '\u0440'), // Latin p / Cyrillic р
            charArrayOf('x', '\u0445'), // Latin x / Cyrillic х
            charArrayOf('s', '\u0455'), // Latin s / Cyrillic ѕ
            charArrayOf('i', '\u0456'), // Latin i / Cyrillic і
            charArrayOf('j', '\u0458'), // Latin j / Cyrillic ј
            charArrayOf('h', '\u04BB'), // Latin h / Cyrillic һ
        )
        val len = 3 + rng.nextInt(5) // 3-7 chars
        return buildString {
            repeat(len) {
                val set = confusableSets[rng.nextInt(confusableSets.size)]
                append(set[rng.nextInt(set.size)])
            }
        }
    }

    /**
     * custom-file: loads names from a dictionary file, cycling through them.
     */
    private fun generateCustomFileName(): String {
        if (customDictionary.isNotEmpty()) {
            return customDictionary[counter++ % customDictionary.size]
        }
        // Fallback to sequential if no dictionary loaded
        return generateSequentialName("")
    }

    private fun applyCollisionPolicy(name: String): String {
        return when (config.collisionPolicy) {
            "append-index" -> {
                var candidate = name
                var suffix = 0
                while (collisionTracker.contains(candidate)) {
                    suffix++
                    candidate = "${name}_$suffix"
                }
                collisionTracker.add(candidate)
                candidate
            }
            "rehash" -> {
                var candidate = name
                while (collisionTracker.contains(candidate)) {
                    candidate = generateRehashName()
                }
                collisionTracker.add(candidate)
                candidate
            }
            "fail" -> {
                if (collisionTracker.contains(name)) {
                    throw IllegalStateException("Rename collision detected: '$name' (collisionPolicy=fail)")
                }
                collisionTracker.add(name)
                name
            }
            else -> {
                collisionTracker.add(name)
                name
            }
        }
    }

    private fun generateRehashName(): String {
        val len = 6 + rng.nextInt(6)
        return buildString {
            repeat(len) {
                val c = 'a' + rng.nextInt(26)
                append(if (rng.nextBoolean()) c else c.uppercaseChar())
            }
        }
    }

    companion object {
        fun loadCustomDictionary(path: String): List<String> {
            if (path.isBlank()) return emptyList()
            return try {
                java.io.File(path).readLines()
                    .map { it.trim() }
                    .filter { it.isNotBlank() && !it.startsWith("#") }
            } catch (e: Exception) {
                emptyList()
            }
        }
    }
}

/**
 * Build a rename config from pass params map.
 */
fun buildRenameConfig(params: Map<String, Any>): RenameConfig {
    val supportedDictionaryStyles = setOf("iiliii", "ooO0oO", "nnmnmnm", "sequential", "unicode-confusable", "custom-file")
    val dictionaryStyle = (params["dictionaryStyle"] as? String) ?: "sequential"
    require(dictionaryStyle in supportedDictionaryStyles) {
        "rename dictionaryStyle '$dictionaryStyle' is not supported; supported values: ${supportedDictionaryStyles.joinToString(", ")}"
    }

    val supportedCollisionPolicies = setOf("append-index", "rehash", "fail")
    val collisionPolicy = (params["collisionPolicy"] as? String) ?: "append-index"
    require(collisionPolicy in supportedCollisionPolicies) {
        "rename collisionPolicy '$collisionPolicy' is not supported; supported values: ${supportedCollisionPolicies.joinToString(", ")}"
    }

    return RenameConfig(
        dictionaryStyle = dictionaryStyle,
        seed = (params["seed"] as? Int)?.toLong() ?: (params["seed"] as? Long),
        preservePackageDepth = (params["preservePackageDepth"] as? Int) ?: 0,
        shufflePackageSegmentCount = (params["shufflePackageSegmentCount"] as? Boolean) ?: true,
        collisionPolicy = collisionPolicy,
        dictionaryFile = (params["dictionaryFile"] as? String) ?: "",
    )
}
