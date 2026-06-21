<p align="center">
  <img src="assets/logo.png" width="132" alt="JavaShroud Logo" />
</p>

<h1 align="center">JavaShroud</h1>

<p align="center">
  <strong>A Java obfuscation, virtualization, and native hardening toolchain</strong>
</p>

<p align="center">
  <img alt="License" src="https://img.shields.io/badge/license-GPL--3.0-blue" />
  <img alt="Engine" src="https://img.shields.io/badge/engine-Dev--0.7.0-2f6fed" />
  <img alt="VBC" src="https://img.shields.io/badge/VBC-4.52-5b6ee1" />
  <img alt="JDK" src="https://img.shields.io/badge/JDK-21%2B-orange" />
  <img alt="Desktop" src="https://img.shields.io/badge/desktop-Wails%20%2B%20Vue-42b883" />
</p>

<p align="center">
  <a href="README.md">简体中文</a> · <strong>English</strong>
</p>

## Positioning

JavaShroud is a Java obfuscation and hardening project built around bytecode transformation, method virtualization, a native microkernel, and a desktop workflow. It includes conventional Java obfuscation capabilities such as renaming, string protection, control-flow transformation, and metadata cleanup, while also providing a VMBC / NBVM (native bytecode VM) execution path for high-value methods.

The project follows a Kerckhoffs-oriented design philosophy: protection strength should not rely on the permanent secrecy of the implementation. It should instead come from per-artifact key material, structural diversity, runtime authentication, context binding, and the execution boundary between Java and Native code.

JavaShroud protects self-contained deliverables. Key material, runtime logic, and protected code must eventually ship with the artifact, so it cannot fully match the security model of online services, HSM-backed designs, or external authorization systems. The practical goal is not to claim irreversibility; it is to reduce the value of a universal deobfuscation template and raise the cost of targeted recovery, batch analysis, and automated reuse.

## VMBC And Native Execution

In JavaShroud, VMBC / NBVM refers to one code path: `method-virtualization` converts selected Java methods into VBC4 / VMBC resources, `JniMicrokernelHelper.executeVmResource` enters the native dispatcher, and execution continues in the native bytecode VM path represented by `js_vm_execute_resource`. In this repository, NBVM is shorthand for that native bytecode VM execution path rather than a separate subproject.

The core value of this path is that the original method body leaves the ordinary Java bytecode form. Key semantics are moved into an execution protocol constrained by authenticated resources, entry tokens, opcode dialects, constant-pool handling, block dispatch, and native runtime state.

Implemented mechanisms include:

| Layer | Mechanism | Purpose |
| --- | --- | --- |
| Method virtualization | VBC4-only, native-only, strict virtualization, entry token, dispatcher stub | Prevents the original method body from remaining as directly decompilable Java bytecode |
| VMBC encoding | Opcode aliases, super-operator folding, block split / coalesce, exception masking | Reduces stable one-to-one recovery of opcodes, control flow, and exception edges |
| Resource protection | JSRP envelope, AES/CTR, HMAC, nonce, zstd section, decoy / slice / opaque path | Raises the cost of offline enumeration, extraction, and replay of VMBC resources |
| Keys and state | Per-build / per-method material, state-bound seed unwrap, runtime resource key, layout digest | Prevents the public algorithm from directly becoming a cross-sample unpacking script |
| Native runtime | JNI microkernel, native VM parser / executor, register IR, lazy CP decrypt, resident masking, wipe | Shortens plaintext windows and moves the analysis surface across JVM and Native boundaries |
| Runtime defense | Anti-instrumentation, anti-dump, anti-JVMTI / agent checks, trampoline checks, integrity gates | Adds friction against common hooks, instrumentation, dumps, and replacement loading |

### VMBC / NBVM Detailed Flow

The flow below is split into build time and runtime. The relevant validation gates include method eligibility, resource envelope authentication, VBC4 program structure, native ABI integrity, runtime instrumentation/debug signals, and final cleanup of sensitive state.

```mermaid
flowchart LR
  subgraph BUILD_EN["Build time: method to VMBC resource"]
    E4["Eligibility check: constructors / clinit / abstract / native / invokedynamic / size limit"]
    E5["MethodBodyCapture records ASM events"]
    E6["Lowering: opcode aliases, super-operators, block planning, exception masking"]
    E7["Binding material: entryToken, resourcePath, clean entry integrity, jarLayoutDigest"]
    E8["VBC4 packaging: nonce, keyId, wrappedSeed, CP / block encryption, HMAC, padding"]
    E9["JSRP envelope: magic/version/kind/layers/variant, AES/CTR, HMAC"]
    E10["Resource camouflage: opaque path, slice manifest, decoy resources"]
    E11["Replace with native dispatcher stub"]
    EF["Build-time fail-closed: strict selected method is incompatible"]
  end

  subgraph RUN_EN["Runtime: dispatcher to native VM"]
    N1["JniMicrokernelHelper.executeVmResource"]
    N2["Native microkernel: load state, sealed ABI marker, boot token, self-check"]
    N3["JSRP decode: magic/version/length/HMAC validation, decrypt/decompress"]
    N4["js_vm_parse_program: VBC4 version, flags, keyId, wrappedSeed, block token, HMAC"]
    N5["Guard gate: anti-debug, anti-instrumentation, anti-JVMTI, trampoline, trace signal"]
    N6["js_vm_execute_resource: register IR, lazy CP decrypt, resident masking, dispatch drift"]
    N7["Return result and wipe buffers, CP plain values, locals, stack, program state"]
    NF["Runtime fail-closed: native / ABI / resource / program / policy validation failure"]
  end

  E4 -->|"compatible"| E5 --> E6 --> E7 --> E8 --> E9 --> E10 --> E11 --> N1
  E4 -->|"strict but incompatible"| EF
  N1 --> N2 --> N3 --> N4 --> N5 --> N6 --> N7
  N2 -->|"fail"| NF
  N3 -->|"fail"| NF
  N4 -->|"fail"| NF
  N5 -->|"refuse"| NF
```

These capabilities have clear boundaries: `method-virtualization` only protects selected and compatible methods. Methods that are not virtualized remain ordinary bytecode-obfuscation targets. A self-contained artifact still contains the material required for execution, so a sufficiently privileged and targeted reverse-engineering effort can continue layer by layer. JavaShroud focuses on engineering cost increase, not absolute resistance to analysis.

## Compared With JNIC / Native Obfuscation

Traditional JNIC or Native obfuscation usually converts Java methods into C/C++ code and calls the resulting native functions through JNI. Its primary protection boundary is migration from Java to Native: less logic is exposed in the Java layer, and the attacker must analyze local libraries, symbols, exported functions, and machine code.

JavaShroud's VMBC path is closer to a virtual execution model. The Native layer is not merely a container for translated method functions; it participates in resource authentication, VMBC parsing, instruction dispatch, state binding, and runtime validation. Even after entering the Native layer, the attacker faces a protocol spanning Java stubs, VMBC resources, the JNI microkernel, and native VM state, rather than a single native function that maps directly back to the original Java method.

| Dimension | JNIC / Native obfuscation | JavaShroud VMBC / NBVM path |
| --- | --- | --- |
| Core idea | Move Java methods into Native functions | Convert method semantics into VMBC resources executed by a native VM |
| Main analysis target | JNI bridge, exported functions, machine code, symbol recovery | Dispatcher stub, resource envelope, virtual instructions, interpreter state, Native boundary |
| Risk after open sourcing | Fixed conversion templates and JNI shapes may be pattern-matched | Implementation can be studied, but each artifact still requires material/layout/runtime adaptation |
| Dynamic observation challenge | Hook JNI or native function parameters / return values | Recover VM state, instruction semantics, key derivation, and dispatch path together |
| Engineering tradeoff | Suitable for moving a small set of key methods to Native code | Suitable for systematic virtualization and diversified protection of high-value Java logic |

The two approaches are not mutually exclusive. JavaShroud adds a VM protocol and artifact-specific instantiation layer over the Native boundary, making Native code part of the execution model rather than only a place to hide translated code.

## General Capabilities

Beyond the VMBC / native VM path, JavaShroud currently exposes 26 executable pass bindings:

| Module | Representative capabilities |
| --- | --- |
| Metadata | Compile debug info, line number, local variable, and source metadata cleanup |
| Renaming | Class, package, method, and field renaming |
| Encryption | String encryption and field string encryption |
| Obfuscation | Integer constant obfuscation, static initializer perturbation, anti-decompiler structure, invokedynamic indirection, control-flow obfuscation, reference proxy, control-flow flattening, condy constant indirection |
| Loader protection | Class encryption loader and method body delayed decryption |
| Runtime defense | Callsite rotation, environment-bound keys, anti-symbolic execution, exception semantic virtualization |
| Native kernel | Anti-instrumentation, anti-dump, JNI microkernel loader |

The default pipeline stays conservative. High-risk capabilities are disabled by default and must be selected explicitly in rules. Strong protection passes can affect compatibility, performance, and debugging, so they should be applied to authorized protection scenarios and carefully selected classes or methods.

## Technology Stack

| Layer | Technology |
| --- | --- |
| Core engine | Kotlin 2.1, JDK 21, ASM 9.9, Jackson TOML, Gradle |
| Native runtime | C11, JNI, Zig / MSVC toolchain, vendored zstd decompression sources |
| Desktop host | Go, Wails v2, WebView2 |
| Frontend | Vue 3, Vite, TypeScript, Naive UI, lucide-vue-next, xterm, Tailwind CSS |
| Tests | Kotlin test / JUnit Platform, Go test, frontend parser check scripts |

## Common Commands

### Core Engine

```powershell
# Build the core engine JAR
.\gradlew.bat :core-engine:jar

# Run core engine tests
.\gradlew.bat :core-engine:test

# Inspect the engine schema
java -jar build\core-engine\libs\obfuscator-engine.jar -schema

# Process a JAR with a config file; use the actual CLI schema as the authority
java -jar build\core-engine\libs\obfuscator-engine.jar -config path\to\config.toml
```

### Desktop Frontend

```powershell
# Install frontend dependencies
corepack yarn --cwd desktop-app\frontend install --immutable

# Build the Vue / Vite frontend
corepack yarn --cwd desktop-app\frontend build

# Run frontend parser checks
corepack yarn --cwd desktop-app\frontend check:capabilities
corepack yarn --cwd desktop-app\frontend check:events
```

### Desktop Host

```powershell
# Validate Go / Wails-side code
Set-Location desktop-app
go build ./...
go test ./...

# Build with Wails; requires the Wails CLI to be installed
wails build
```

### Windows Release

```powershell
# Full release entrypoint
.\build-release.bat
```

The full release script builds the engine JAR, the GraalVM native engine, the frontend bundle, and the Wails desktop application. Release acceptance should be based on the expected artifacts, such as `build\release\javashroud-windows-amd64\javashroud.exe`, existing and running successfully, not only on individual Gradle, Yarn, or Go commands returning success.

## Repository Layout

```text
.
├─ core-engine/                 # Kotlin/Java core obfuscation engine
│  ├─ src/main/kotlin/          # passes, schema, artifact handling, VMBC, runtime resources
│  ├─ src/main/java/            # runtime helpers, including JNI microkernel and protection helpers
│  ├─ src/main/native/          # C/JNI native runtime, VM executor, anti-debug, vendored zstd sources
│  └─ src/test/kotlin/          # engine, pass, VMBC, native, and regression tests
├─ desktop-app/                 # Wails desktop host
│  ├─ frontend/                 # Vue 3 + Vite + TypeScript frontend
│  ├─ *.go                      # Go/Wails backend, engine process bridge, event bridge
│  └─ wails.json                # Wails configuration
├─ gradle/                      # Gradle wrapper
├─ assets/                      # README and release presentation assets
├─ build-release.bat            # Windows release entrypoint
├─ LICENSE                      # GPLv3 license text
├─ THIRD_PARTY_NOTICES.md       # Third-party notices
└─ SECURITY.md                  # Security and authorized-use notes
```

## License And Third-Party Components

This repository includes the GNU General Public License Version 3 text in `LICENSE`; the repository license should be treated according to that file. Use, modification, and redistribution of this project or derivative works must comply with GPLv3 requirements, including source availability, preservation of copyright notices, and compatible licensing of derivative works.

The project also depends on or vendors third-party components. In particular, `core-engine/src/main/native/zstd/` vendors Zstandard decompression sources, and `THIRD_PARTY_NOTICES.md` / `NOTICE` state that JavaShroud uses the BSD-style license option for those vendored files. ASM, Jackson, Kotlin, Gradle, JUnit, Wails, Vue, Vite, TypeScript, Naive UI, lucide, xterm, and Go dependencies remain under their respective upstream licenses. Binary or source redistribution should preserve the corresponding copyright notices, license texts, and notices.

## Acknowledgements

JavaShroud's design and implementation were informed by many open-source obfuscation, virtualization, and native protection projects. Without the engineering experience accumulated by these projects, JavaShroud would not have its current direction.

- [Open-MyJ2c](https://github.com/MyJ2c/Open-MyJ2c)
- [native-obfuscator](https://github.com/radioegor146/native-obfuscator)
- [native-obfuscator-plus](https://github.com/Araykal/native-obfuscator-plus)
- [skidfuscator-java-obfuscator](https://github.com/skidfuscatordev/skidfuscator-java-obfuscator)
- [Tigress_protection](https://github.com/JonathanSalwan/Tigress_protection)
- code-encryptor-master
- jar-obfuscator-main
- obfuscator-master