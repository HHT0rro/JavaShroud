package io.github.hht0rro.javashroud.transforms.protection.aken

/** High-value page families protected by the AKEN v4 build plan. */
enum class AkenResourceKind(
    val id: Int,
    val logicalName: String,
) {
    Vbc4Method(1, "vbc4-method"),
    StringPage(2, "string-page"),
    EncryptedClassPage(3, "encrypted-class-page"),
    NativeChunk(4, "native-chunk"),
    ;

    companion object {
        fun fromId(id: Int): AkenResourceKind? = entries.firstOrNull { it.id == id }
    }
}
