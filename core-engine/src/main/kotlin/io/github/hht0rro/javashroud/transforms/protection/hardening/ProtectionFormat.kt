package io.github.hht0rro.javashroud.transforms.protection.hardening

/** Current protected-artifact format. Forbidden output signatures fail closed at the release gate. */
internal object ProtectionFormat {
    /** Current protected-artifact wire format. Older formats are retired. */
    const val CURRENT: Int = 3
    val CURRENT_LABEL: String = CURRENT.toString()
    const val DEBUG_MAP_VERSION: Int = 3
    const val DEBUG_MAP_MAGIC = "JSDM"
    const val RETIRED_FRAME_MAGIC_HEX = "4a535231"
    const val RETIRED_DIRECTORY_MAGIC_HEX = "4a535232444952"
    const val RETIRED_TOKEN_MAGIC_HEX = "49544b31"
    const val RETIRED_RESOURCE_MAGIC_HEX = "4a535250"
    const val RETIRED_VM_MAGIC_HEX = "56424335"

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

    val FORBIDDEN_RELEASE_MAGICS: List<String> = listOf(
        "boot.dat",
        "kek.dat",
        "vm.catalog",
        "JSC1",
        "JSP1",
        "JSBM",
        "JSBK",
        "JSBM1",
        "JSBK1",
        "AKEN-R1/Eval7/v1",
        "JavaShroud/AKEN-R1/EvaluatorShare/v1",
        "JSR1DIR",
        "JSR2DIR",
        "JSR1",
        "VBC4",
        "VBC5",
        "ITK1",
        "JSRP",
        "JSITKAAD",
        "JSITKKDF",
    )
}
