package io.github.hht0rro.javashroud.transforms.protection

/**
 * Utility for generating opaque identifiers that replace original class/method
 * names in helper dispatch strings. This prevents original package names, class
 * names, and method names from leaking into the output bytecode as string literals.
 *
 * The generated identifiers are deterministic (same input always produces the same
 * output) so that helper runtime dispatch remains consistent, but they cannot be
 * reversed to recover the original names.
 */
object ObfuscatedIdentifierUtil {

    /**
     * Generate an opaque token from a class internal name.
     * e.g. "com/scorpionhermit/C0001" -> "c_a3f7b2e1"
     */
    fun classToken(internalName: String): String {
        val hash = fnv1a32(internalName)
        return "c_${hash.toFixedHexLower(8)}"
    }

    /**
     * Generate an opaque token from a method name + descriptor pair.
     * e.g. "doWork" + "()V" -> "m_7c2e9a14"
     */
    fun methodToken(methodName: String, descriptor: String): String {
        val hash = fnv1a32("$methodName#$descriptor")
        return "m_${hash.toFixedHexLower(8)}"
    }

    /**
     * Generate an opaque token from a combined class+method+descriptor key.
     * Used for transforms that need a single dispatch key.
     */
    fun combinedToken(className: String, methodName: String, descriptor: String): String {
        val hash = fnv1a32("$className/$methodName#$descriptor")
        return "x_${hash.toFixedHexLower(8)}"
    }

    private fun fnv1a32(input: String): Int {
        var hash = 0x811c9dc5.toInt()
        for (ch in input) {
            hash = hash xor (ch.code and 0xFF)
            hash = (hash.toLong() * 0x01000193).toInt()
        }
        return hash
    }
}
