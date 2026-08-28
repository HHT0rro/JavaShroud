package io.github.hht0rro.javashroud.transforms.protection.qp

import java.security.SecureRandom

/** Randomized AKEN v4 target page sizes for each protected resource family. */
class QpPageSizePolicy private constructor(
    sizesByKind: Map<QpResourceKind, IntArray>,
) {
    private val sizes = sizesByKind.mapValues { (_, values) -> values.copyOf() }

    init {
        require(sizes.keys.containsAll(QpResourceKind.entries)) {
            "AKEN page size policy must cover every resource kind"
        }
        require(sizes.values.all { values -> values.isNotEmpty() && values.all { it > 0 } }) {
            "AKEN page sizes must be positive"
        }
    }

    fun allowedSizes(kind: QpResourceKind): List<Int> = sizes.getValue(kind).toList()

    fun choose(kind: QpResourceKind, random: SecureRandom = SecureRandom()): Int {
        val values = sizes.getValue(kind)
        return values[random.nextInt(values.size)]
    }

    companion object {
        @JvmField
        val DEFAULT: QpPageSizePolicy = QpPageSizePolicy(
            mapOf(
                QpResourceKind.QpMethod to intArrayOf(512, 768, 1024, 1536, 2048),
                QpResourceKind.StringPage to intArrayOf(128, 192, 256, 384, 512),
                QpResourceKind.EncryptedClassPage to intArrayOf(512, 1024, 1536, 2048),
                QpResourceKind.NativeChunk to intArrayOf(1024, 1536, 2048, 3072),
            ),
        )
    }
}
