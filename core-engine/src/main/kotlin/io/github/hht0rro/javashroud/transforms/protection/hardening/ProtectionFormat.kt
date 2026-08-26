package io.github.hht0rro.javashroud.transforms.protection.hardening

/** Current protected-artifact format. Forbidden output signatures fail closed at the release gate. */
internal object ProtectionFormat {
    const val CURRENT = "AKEN-R2"
    const val DEBUG_MAP_VERSION: Int = 3
    const val INDY_TOKEN_MAGIC = "ITK1"
    const val DEBUG_MAP_MAGIC = "JSDM"

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
        val basename = entryName.substringAfterLast('/')
        return basename in FORBIDDEN_RELEASE_RESOURCE_BASENAMES ||
            basename in FORBIDDEN_RELEASE_RENAME_INDEX_BASENAMES
    }

    fun isForbiddenReleaseRenameIndexPath(entryName: String): Boolean =
        entryName.substringAfterLast('/') in FORBIDDEN_RELEASE_RENAME_INDEX_BASENAMES

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
        "VBC4",
    )
}
