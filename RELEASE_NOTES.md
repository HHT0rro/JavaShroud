# JavaShroud v0.11

This release advances the public line to `0.11` and presents the former “Native Max” work under the clearer **Native hardening** name.

## Highlights

- Adds authenticated outer-stub packing for the complete inner Native kernel.
- Binds Native payloads to VMBC resources, bootstrap metadata, resource paths, dispatcher profiles, and artifact identity.
- Hardens Windows PE64 and Linux ELF64 in-memory loader validation across sections, relocations, symbols, imports, initializers, and executable entrypoints.
- Extends Mach-O metadata, rebase / bind, export, and initializer validation while retaining fail-closed behavior at the current macOS execution boundary.
- Expands runtime and reverse-evidence gates for payload, header, profile, bootstrap-index, resource-path, and manifest-mesh tampering.
- Streamlines the Chinese and English READMEs around capabilities, VMBC / NBVM, Native hardening, compatibility, and build usage.

## Release Validation

The tag-triggered GitHub Actions workflow rebuilds the engine, Native components, frontend bundle, and Wails Windows package before publishing `javashroud-windows-amd64.zip`.
