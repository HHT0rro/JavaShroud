package io.github.hht0rro.javashroud.transforms.protection.aken

import java.security.SecureRandom

/** Randomized AKEN v4 target page sizes for each protected resource family. */
class AkenPageSizePolicy private constructor(
    sizesByKind: Map<AkenResourceKind, IntArray>,
) {
    private val sizes = sizesByKind.mapValues { (_, values) -> values.copyOf() }

    init {
        require(sizes.keys.containsAll(AkenResourceKind.entries)) {
            "AKEN page size policy must cover every resource kind"
        }
        require(sizes.values.all { values -> values.isNotEmpty() && values.all { it > 0 } }) {
            "AKEN page sizes must be positive"
        }
    }

    fun allowedSizes(kind: AkenResourceKind): List<Int> = sizes.getValue(kind).toList()

    fun choose(kind: AkenResourceKind, random: SecureRandom = SecureRandom()): Int {
        val values = sizes.getValue(kind)
        return values[random.nextInt(values.size)]
    }

    companion object {
        @JvmField
        val DEFAULT: AkenPageSizePolicy = AkenPageSizePolicy(
            mapOf(
                AkenResourceKind.Vbc4Method to intArrayOf(512, 768, 1024, 1536, 2048),
                AkenResourceKind.StringPage to intArrayOf(128, 192, 256, 384, 512),
                AkenResourceKind.EncryptedClassPage to intArrayOf(512, 1024, 1536, 2048),
                AkenResourceKind.NativeChunk to intArrayOf(1024, 1536, 2048, 3072),
            ),
        )
    }
}
