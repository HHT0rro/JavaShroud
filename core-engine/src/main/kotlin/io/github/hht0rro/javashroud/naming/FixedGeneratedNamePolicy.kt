package io.github.hht0rro.javashroud.naming

/**
 * Names under this generated package shape were emitted by a retired generator.
 * They are never valid output names in the current protected-artifact format.
 */
internal val fixedGeneratedInternalNamePattern = Regex("^r/[0-9]+/")
internal val fixedGeneratedDottedNamePattern = Regex("^r\\.[0-9]+\\.")

// Existing generators also emitted a two-hex shard between the `r` root and
// the class hash (for example `r/1c/C0123...`).  It is the same retired fixed
// namespace and must be rejected by both the relocation stage and release
// artifact scan, even though the public prohibition is commonly written as
// `r.<digits>`.
internal val fixedGeneratedShardDottedNamePattern =
    Regex("^r\\.[0-9a-fA-F]{2}\\.C[0-9a-fA-F]{8,}(?:\\.|\\$|$)")
internal val fixedGeneratedShardInternalNamePattern =
    Regex("^r/[0-9a-fA-F]{2}/C[0-9a-fA-F]{8,}(?:/|\\$|$)")

internal fun isFixedGeneratedInternalName(internalName: String): Boolean =
    fixedGeneratedInternalNamePattern.containsMatchIn(internalName) ||
        fixedGeneratedShardInternalNamePattern.containsMatchIn(internalName)

internal fun isFixedGeneratedDottedName(binaryName: String): Boolean =
    fixedGeneratedDottedNamePattern.containsMatchIn(binaryName) ||
        fixedGeneratedShardDottedNamePattern.containsMatchIn(binaryName)

internal fun isFixedGeneratedClassEntryPath(entryName: String): Boolean =
    entryName.endsWith(".class") && isFixedGeneratedInternalName(entryName.removeSuffix(".class"))

/**
 * Reserve the top-level segment that could otherwise combine with a numeric
 * generated segment to recreate the retired [r/<number>/] namespace.
 */
internal fun isReservedGeneratedPackageSegment(segment: String): Boolean = segment == "r"
