package io.github.hht0rro.javashroud.transforms.protection.qp

/** High-value page families protected by the AKEN v4 build plan. */
enum class QpResourceKind(
    val id: Int,
    val logicalName: String,
) {
    QpMethod(1, "qp-method"),
    StringPage(2, "string-page"),
    EncryptedClassPage(3, "encrypted-class-page"),
    NativeChunk(4, "native-chunk"),
    ;

    companion object {
        fun fromId(id: Int): QpResourceKind? = entries.firstOrNull { it.id == id }
    }
}
