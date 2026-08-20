# JavaShroud Technical Deep Dive

This document records the key mechanisms of the current JavaShroud implementation: the pass pipeline, the VMBC / NBVM protocol, the Native packing protocol, the security model, and the configuration reference. All symbol names and paths are taken from the repository; an evidence index is attached at the end.

<a href="TECHNICAL.md">简体中文</a> · <strong>English</strong>

## Pass Pipeline

The engine registers 26 passes (`buildEngineSchemaPayload`). The default pipeline contains only `strip-compile-debug-info`; every other pass must be enabled explicitly in the config, and opt-in passes additionally require `allowOptInPasses = true`.

| Pass ID | Category | Stability | Default | Opt-in | Dependencies / constraints |
| --- | --- | --- | --- | --- | --- |
| `strip-compile-debug-info` | Metadata | stable | yes | no | Default pipeline member |
| `member-shuffle` | Metadata | stable | yes | no | |
| `rename-classes` | Renaming | stable | yes | yes | |
| `rename-packages` | Renaming | stable | yes | yes | |
| `rename-methods` | Renaming | stable | yes | yes | |
| `rename-fields` | Renaming | stable | yes | yes | |
| `string-encryption` | Encryption | experimental | no | yes | Requires `jni-microkernel-loader` |
| `field-string-encryption` | Encryption | experimental | no | yes | |
| `integer-constant-obfuscation` | Obfuscation | experimental | no | yes | |
| `static-init-perturbation` | Obfuscation | experimental | no | yes | |
| `anti-decompiler-structure` | Obfuscation | experimental | no | yes | |
| `invoke-dynamic-indirection` | Obfuscation | experimental | no | yes | |
| `control-flow-obfuscation` | Obfuscation | experimental | no | yes | |
| `control-flow-flattening` | Obfuscation | experimental | no | yes | |
| `reference-proxy` | Obfuscation | experimental | no | yes | |
| `condy-constant-indirection` | Obfuscation | experimental | no | yes | |
| `member-hide` | Hiding | experimental | no | yes | |
| `callsite-rotation-protection` | RuntimeDefense | experimental | no | yes | |
| `anti-symbolic-execution` | RuntimeDefense | experimental | no | yes | |
| `exception-semantic-virtualization` | RuntimeDefense | experimental | no | yes | |
| `environment-bound-keys` | RuntimeDefense | experimental | no | no | Requires `jni-microkernel-loader` |
| `class-encryption-loader` | LoaderProtection | experimental | no | no | Requires `jni-microkernel-loader` |
| `method-body-delayed-decryption` | LoaderProtection | experimental | no | no | Requires `jni-microkernel-loader` |
| `anti-instrumentation` | NativeKernel | experimental | no | no | Requires `jni-microkernel-loader` |
| `anti-dump-protection` | NativeKernel | experimental | no | no | Requires `jni-microkernel-loader`; HotSpot JVM only |
| `jni-microkernel-loader` | NativeKernel | experimental | no | no | Windows x64 / Linux x64 / macOS x64 / arm64 |
| `method-virtualization` | VmProtection | experimental | no | no | Requires `jni-microkernel-loader`; Java 11+ target runtime |

Validation order at config load (`loadValidatedConfig` -> `validateConfig`):

1. After dependency normalization, `requiredPassIds` and `requiresAnyPassIds` are checked; missing dependencies fail the load.
2. Hard conflict pairs are rejected unconditionally (`allowIncomplete` is parsed and passed into compatibility validation, but the current implementation does not change hard-conflict rejection).
3. Soft (redundant) conflict pairs require `allowRedundantPasses = true`.
4. Opt-in passes require `allowOptInPasses = true`; with `format = "javashroud-workbench"` this defaults to true.
5. Passes requested by annotation directives (such as `@ShroudEncrypt`) require `allowAnnotationPasses = true`.

Frequently used parameter keys (run `-schema` for the full parameter schema):

| Pass | Parameter keys |
| --- | --- |
| `method-virtualization` | `seed`, `methodSelection` (`safe` / `critical-auto` / `critical-plus` / `all-compatible`), `strictVirtualization`, `maxInstructions`, `maxBroadVirtualizedMethods` |
| `jni-microkernel-loader` | `kernelComponents`, `targetPlatform`, `diversifiedVirtualization`, `nativeRecompilation`, `nativeProtectionLevel`, `nativePackingLevel` (`off` / `standard` / `max` / `max-hardening`; all four levels use the AKEN v4 resource-level evaluator), `seed` |
| `string-encryption` | `scope` (`all-strings` / `annotated` / `length-threshold`), `lengthThreshold`, `seed` |
| `anti-instrumentation` | `detectionLevel`, `response`, `seed` |
| `anti-dump-protection` | `protectionLevel` |

## VMBC / NBVM Protocol

### VBC4 Bytecode and Metadata

`VmBytecodeSerializer` lowers JVM bytecode into VBC4. Each virtualized method produces one `vbc4-meta-v2` metadata record (`Vbc4EntryMetadata`) with the fields, in order: entry token (u64 hex), return type tag, method-local profile, method identity (256-bit lowercase hex), owner identity (256-bit lowercase hex), argument tag vector, resource path, static flag, native VM profile id, and dispatch profile tag.

Fixed VBC4 invariants (cannot be disabled via parameters, see `VmProtectionCapabilityBuilder.kt`):

- State-bound encoding and handler morphing are always on; strength is fixed at max with no low-strength compatibility profile.
- Build-time interpreter diversity is always on; execution is native-only with no Java VM fallback.
- JNI call targets are resolved through per-artifact / per-method tokens; no plaintext symbols travel on the hot path.
- The native dispatcher executes register IR; stack opcodes are accepted only as compatibility input.
- The serializer folds super-operators with a per-method structural seed and includes them in the authenticated state.
- The session integrity digest participates in seed unwrap, block-key, and constant-pool key derivation.
- Native root material is derived on demand with a short lifetime and wiped after use.

Constant-pool strings are stored sealed (`VBC4_CP_SEALED_STRING_TYPE = 0x06`), with key / IV / tag derived from separate HMAC domain constants.

### JSRP Envelope Format

JSRP (magic `0x4A 0x53 0x52 0x50`, version 7) is the uniform protected-resource envelope, encoded and decoded by `RuntimeResourceCodec`. Four resource kinds exist: VM bytecode (1), Native library (2), manifest (3), and Native index (4).

Binary layout:

| Section | Size | Description |
| --- | --- | --- |
| magic + version | 5 bytes | `JSRP` + `0x07` |
| nonce | 16 bytes | Random per resource |
| metadata length / MAC length / partition id | 2 bytes LE each | 27-byte header in total |
| metadata ciphertext | 96 bytes | AES-CTR; plaintext holds kind, layer count (1..7), variant (0..127), compression flag, plain length, body length, key id, seed, plaintext / stored SHA-256, partition id |
| body ciphertext | variable | AES-CTR; content is zstd-compressed by default (stored raw when compression does not help) |
| tag | 32 bytes | HMAC-SHA256 over header + metadata + body with domain separator `jsrp-auth-v3` + nonce |
| trailing byte | 1 byte | MAC length, re-checked on decode |

Key derivation: the AES key and IV are the first 16 bytes of `HMAC-SHA256(partitionKey, "jsrp-aes-key" / "jsrp-aes-iv", nonce, kind, variant, layers)`; the key id in metadata is the first 4 bytes of `HMAC(partitionKey, "jsrp-key-id-v3", nonce)`. The partition table `RuntimeKeyPartitions` is generated per build by a CSPRNG, selects a partition by resource identity, and includes one anchor slot.

Decode order: check magic / version -> length and partition-id bounds -> constant-time tag comparison -> decrypt metadata and verify its inner partition id and field ranges -> decrypt body and verify the stored hash -> zstd-decompress and verify the plaintext hash. Any failure returns null and the caller fails closed.

### Runtime Entry

Dispatcher stubs call the `executeVmResource` overload family on `JniMicrokernelHelper` (Object / void / int / int-int / int-void shapes). When the Native kernel is not ready they throw `SecurityException`; there is no Java-side VM fallback. The JNI entry point is `js_vm_execute_resource` (`js_vm_core.c` / `js_vm_resource.c`), and `js_vm_core.c` implements virtual instruction dispatch.

## Native Packing Protocol

### Shell-Kernel Structure

`NativeKernelShellPacker` / `NativeKernelPacker` produce the outer `js_kernel_<platform>` stub; the complete inner kernel is sealed inside the shell as an authenticated, encoded payload. The load chain (`JniMicrokernelHelper`):

1. Resolve the platform suffix and use the artifact-specific locator to find the requested Native chunk; the artifact exposes no enumerable global high-value directory.
2. Authenticate and map only the requested Native chunk, write it to a temporary directory (candidates include `~/.javashroud/native`), and `System.load` the required outer stub.
3. `nativeInit` initialization (retried once on return code 2).
4. Every high-value page access verifies its handle, call-site proof, Merkle path, and artifact canonical commitment; a mismatch fails closed immediately.
5. ABI self-check: `nativeGetBootToken` is XOR-compared against the local mirror value, catching wholesale library replacement (for example Frida `Interceptor.replace`); failure sets `nativeSelfCheckFailed` and all later execution is rejected.

`JNI_OnLoad` verifies the header, section digest, layout and dispatcher profile, payload binding, chunk tags, and payload MAC in sequence; any failure rejects execution.

### AKEN v4 Page Protocol

Each high-value resource page has an independent random DEK, AES-GCM page envelope, and bound AAD. All four `nativePackingLevel` values use AKEN v4; the level changes only Native shell and payload packing strength, not the resource-level decryption architecture.

A runtime necessarily contains executable decryption semantics, so the fixed documentation wording is **artifact-only static cost hardening**, not artifact-only cryptographic-secret isolation. A failed page access, locator lookup, or integrity proof fails closed; startup requires no external runtime key, environment variable, or sidecar key file.

### Platform Loader Boundaries

| Platform | Validation coverage |
| --- | --- |
| Windows x64 | PE64 in-memory mapping: sections, relocations, imports / exports, TLS, `DllMain`, `JNI_OnLoad`, ABI table |
| Linux x64 | Anonymous-memory ELF64 loader: `PT_LOAD` / `PT_DYNAMIC`, hash, symbols, RELA / PLT, initializers, entrypoint |
| macOS x64 / arm64 | Mach-O metadata, rebase / bind, export trie, initializers; unsupported anonymous execution mapping fails closed |

Native sources live under `core-engine/src/main/native/`: `js_kernel.c` (JNI entry and shell), `js_vm_core.c` / `js_vm_core.h` (VM core and instruction dispatch), `js_vm_resource.c` (resource authentication and parsing).

## Security Model

- Kerckhoffs-oriented: strength comes from per-artifact CSPRNG material, structural diversity (layout, opcode dialects, dispatcher profiles), and the Java / Native execution boundary, not from implementation secrecy.
- Binding graph: VMBC resources <-> bootstrap index <-> resource paths <-> manifest <-> shell commitments; transplanting any link across artifacts breaks the authentication chain.
- Fail-closed list:
  - Build time: under `strictVirtualization`, a method with VBC4-unsupported bytecode or beyond `maxInstructions` fails the build; a missing or malformed KEK fails the build.
  - Load time: missing / malformed KEK or GCM authentication failure; boot-token ABI self-check failure; shell binding commitment not consumed; missing sealed index or bindings.
  - Runtime: JSRP tag / hash mismatch; tampered resource paths or profiles.
- After Native installation, `max-hardening` decodes runtime resources through `nativeDecodeRuntimeResource`; Java retains only short-lived load/preload copies and wipes them on failure, exceptions, repeated loads, and unload cleanup.
- Non-goals: the artifact is self-contained and carries all material needed to run; the project does not claim absolute irreversibility. The goal is to raise the cost of one-off analysis and cross-sample bulk reuse.

## Configuration Reference

Configuration files are TOML (parsed with jackson-dataformat-toml), mapping to `ObfuscationConfig`:

| Field | Type | Description |
| --- | --- | --- |
| `inputJarPath` / `outputJarPath` | string, required | May sit at the root or under an `[input]` table |
| `[[passes]]` | array, required | Each entry has `id`, `enabled` (boolean), and an optional `params` table |
| `[ruleSet]` / `rules` | array | Rules as `[[ruleSet.rules]]` inside `[ruleSet]`, or top-level `[[rules]]` |
| `allowOptInPasses` | boolean | Allow opt-in passes; defaults to true with `format = "javashroud-workbench"` |
| `allowRedundantPasses` | boolean | Allow soft-conflict (redundant) pass pairs together |
| `allowAnnotationPasses` | boolean | Allow annotation directives to enable passes |
| `allowIncomplete` | boolean | Parsed and passed into compatibility validation; hard conflicts are still rejected unconditionally |
| `format` | string | `javashroud-workbench` marks a desktop-produced config |

Rule syntax: `target = "class <pattern>"`, optionally followed by `#member` or `#member:descriptor` to narrow to members; the engine currently consumes the actions `obfuscate` (explicitly include) and `exclude` (skip; an explicit obfuscate match wins). Class patterns support `*` (single level) and `**` (multi level) wildcards.

Complete example enabling VMBC and Native packing:

```toml
format = "javashroud-workbench"
inputJarPath = "app.jar"
outputJarPath = "app-obf.jar"
allowOptInPasses = true

[[passes]]
id = "rename-classes"
enabled = true

[[passes]]
id = "control-flow-flattening"
enabled = true

[[passes]]
id = "string-encryption"
enabled = true
params = { scope = "all-strings" }

[[passes]]
id = "jni-microkernel-loader"
enabled = true
params = { nativePackingLevel = "max" }

[[passes]]
id = "method-virtualization"
enabled = true
params = { methodSelection = "critical-plus", strictVirtualization = true }

[ruleSet]
[[ruleSet.rules]]
target = "class com.example.**"
action = "obfuscate"

[[ruleSet.rules]]
target = "class com.example.api.**"
action = "exclude"
```


The strongest profile is explicit; ordinary `max` is not implicitly upgraded:

```toml
[[passes]]
id = "jni-microkernel-loader"
enabled = true
params = { nativeProtectionLevel = "aggressive", nativePackingLevel = "max-hardening", targetPlatform = "windows-x64" }

[[passes]]
id = "method-virtualization"
enabled = true
params = { methodSelection = "all-compatible", strictVirtualization = true }
```

AKEN v4 artifacts remain offline, self-contained, and directly runnable with `java -jar`; they introduce no external runtime key, environment-variable, or sidecar-key-file contract.

All four `nativePackingLevel` levels only change Native shell and payload packing strength; high-value VM, string, class, and Native pages use page-specific evaluators uniformly. The security wording is **artifact-only static cost hardening**: a self-contained runtime necessarily contains executable decryption semantics, but it has no directly extractable static root key that opens every high-value resource in one step.

## Evidence Index

| Symbol | Location |
| --- | --- |
| Pass registry and default pipeline | `core-engine/src/main/kotlin/io/github/hht0rro/javashroud/capabilities/` (`SchemaCapabilities.kt`, the `*CapabilityBuilder.kt` files) |
| Config model and validation | `.../model/config/ConfigModels.kt`, `.../config/ConfigDecodeSupport.kt`, `.../config/ConfigLoadSupport.kt`, `.../config/ConfigRedundantPassSupport.kt`, `.../config/PassConfigDecodeSupport.kt` |
| Rule parsing | `.../analysis/RuleMatching.kt`, `.../analysis/RuleTargeting.kt` |
| VBC4 serialization | `.../transforms/protection/VmBytecodeSerializer.kt` |
| JSRP codec | `.../transforms/protection/RuntimeResourceCodec.kt` |
| Key partitions | `.../transforms/protection/RuntimeKeyPartitions.kt` |
| zstd codec | `.../transforms/protection/Vbc4ZstdCodec.kt` |
| Dispatcher profile | `.../transforms/protection/DispatcherProfile.kt` |
| VM resource catalog | `.../transforms/protection/RuntimeVmCatalog.kt` |
| Shell packing | `.../transforms/protection/NativeKernelShellPacker.kt`, `.../transforms/protection/NativeKernelPacker.kt` |
| Runtime JNI helper | `core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java` |
| Native VM and shell | `core-engine/src/main/native/js_kernel.c`, `js_vm_core.c`, `js_vm_core.h`, `js_vm_resource.c` |
