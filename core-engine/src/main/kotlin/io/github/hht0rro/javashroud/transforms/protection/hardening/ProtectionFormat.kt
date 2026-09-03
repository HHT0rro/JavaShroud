package io.github.hht0rro.javashroud.transforms.protection.hardening

/** Current protected-artifact format. Forbidden output signatures fail closed at the release gate. */
internal object ProtectionFormat {
    /** Current protected-artifact wire format. Older formats are retired. */
    const val CURRENT: Int = 3
    val CURRENT_LABEL: String = CURRENT.toString()
    const val DEBUG_MAP_VERSION: Int = 3
    const val DEBUG_MAP_MAGIC = "JSDM"
    const val RETIRED_FRAME_MAGIC_HEX = "4a535231"
    const val RETIRED_DIRECTORY_PREVIOUS_MAGIC_HEX = "4a535231444952"
    const val RETIRED_DIRECTORY_MAGIC_HEX = "4a535232444952"
    const val RETIRED_TOKEN_MAGIC_HEX = "49544b31"
    const val RETIRED_RESOURCE_MAGIC_HEX = "4a535250"
    const val RETIRED_VM_PREVIOUS_MAGIC_HEX = "56424334"
    const val RETIRED_VM_MAGIC_HEX = "56424335"
    const val RETIRED_BOOT_MATERIAL_MAGIC_HEX = "4a53424d"
    const val RETIRED_TOKEN_AAD_DOMAIN_HEX = "4a5349544b414144"
    const val RETIRED_TOKEN_KEY_DOMAIN_HEX = "4a5349544b4b4446"

    private val FORBIDDEN_RELEASE_RESOURCE_BASENAMES: Set<String> = setOf(
        "boot.dat",
        "kek.dat",
        "vm.catalog",
        "dek.bin",
    )

    private val FORBIDDEN_RELEASE_RENAME_INDEX_BASENAMES: Set<String> = setOf(
        "method-renames.idx",
        "field-renames.idx",
    )

    /**
     * These are release-gate rejection signatures only.  Current-format stages
     * never remove, relocate, or otherwise clean up a matching input entry.
     */
    fun isForbiddenReleaseResourcePath(entryName: String): Boolean {
        val normalized = entryName.replace('\\', '/').lowercase(java.util.Locale.ROOT)
        if (normalized == "meta-inf/jsrt" || normalized.startsWith("meta-inf/jsrt/")) {
            return true
        }
        val basename = normalized.substringAfterLast('/')
        return basename in FORBIDDEN_RELEASE_RESOURCE_BASENAMES ||
            basename in FORBIDDEN_RELEASE_RENAME_INDEX_BASENAMES
    }

    fun isForbiddenReleaseRenameIndexPath(entryName: String): Boolean =
        entryName.replace('\\', '/').lowercase(java.util.Locale.ROOT).substringAfterLast('/') in
            FORBIDDEN_RELEASE_RENAME_INDEX_BASENAMES

    val FORBIDDEN_RELEASE_MAGIC_HEX: List<String> = listOf(
        "626f6f742e646174",
        "6b656b2e646174",
        "766d2e636174616c6f67",
        "4a534331",
        "4a535031",
        RETIRED_BOOT_MATERIAL_MAGIC_HEX,
        "4a53424b",
        "4a53424d31",
        "4a53424b31",
        "414b454e2d52312f4576616c372f7631",
        "4a6176615368726f75642f414b454e2d52312f4576616c7561746f7253686172652f7631",
        RETIRED_DIRECTORY_PREVIOUS_MAGIC_HEX,
        RETIRED_DIRECTORY_MAGIC_HEX,
        RETIRED_FRAME_MAGIC_HEX,
        RETIRED_VM_PREVIOUS_MAGIC_HEX,
        RETIRED_VM_MAGIC_HEX,
        RETIRED_TOKEN_MAGIC_HEX,
        RETIRED_RESOURCE_MAGIC_HEX,
        RETIRED_TOKEN_AAD_DOMAIN_HEX,
        RETIRED_TOKEN_KEY_DOMAIN_HEX,
    )
}
