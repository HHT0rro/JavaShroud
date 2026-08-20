# JavaShroud Repository Rules

## Compatibility Policy

This repository has one current protected-artifact format. Future changes do not preserve compatibility with older JavaShroud artifacts, protocol revisions, Native ABIs, boot material, catalogs, evaluator graphs, or shell layouts.

Do not restore or add compatibility paths for `boot.dat`, `kek.dat`, JSBM, JSBK, legacy catalogs, Java VM fallbacks, legacy evaluator fragments, seed/FNV envelopes, or version-downgrade handling. Old artifacts may fail closed.

Protocol changes must update every serializer, parser, Native bridge, generated include, test fixture, and documentation in the same change. Tests target the current format only and must not require an old version to succeed. Authentication, digest, length, magic, and structural checks remain mandatory; failure must be fail-closed.

## Scope

These rules apply to the JavaShroud protected artifact and Native runtime formats. They do not remove Java classfile compatibility requirements, Gradle/plugin versions, desktop application versions, or release metadata unless a task explicitly requests those changes.

## Working Tree

Preserve unrelated user changes. Do not use `git reset`, `git clean`, destructive checkout, or broad rewrites that overwrite unrelated files.
