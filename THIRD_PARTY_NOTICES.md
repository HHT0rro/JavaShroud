# Third-Party Notices

Zstandard decompression is provided by the Rust crate `ruzstd` (BSD-style / GPLv2 dual license). JavaShroud uses the crate through Cargo and does not vendor C Zstandard sources.

## Zstandard / ruzstd

- Copyright: Meta Platforms, Inc. and affiliates; ruzstd authors.
- Source: https://github.com/facebook/zstd and https://crates.io/crates/ruzstd
- License: BSD-style license or GPLv2, at your option. JavaShroud uses the BSD-style license option.

## R8 / D8 (APK dex compiler)

The APK packing mode compiles Java bytecode to dex with Google's R8 tool via its
D8 command-line entry point. R8 is resolved from Google Maven as
`com.android.tools:r8:8.7.18` (17,650,417 bytes,
SHA-256 `58366f77067207c39a17d469de7b05701d2877212a9c55201bcb0af43e59e903`) and
linked into the engine distribution; the build asserts that pinned digest before
packaging. A build-tools 34.0.0 `d8.jar` may be used as a development fallback
when its own pinned digest matches.

- Copyright: Google LLC and R8 contributors.
- Source: https://maven.google.com/com/android/tools/r8/8.7.18 and https://r8.googlesource.com/r8
- License: Apache License 2.0 or BSD 3-Clause, at your option (see the LICENSE
  file inside the R8 jar). Both are compatible with this repository's GPL-3.0.

## apksig (APK signing and verification)

APK v1/v2 signing and fail-closed signature verification use Google's apksig
library, resolved from Google Maven as
`com.android.tools.build:apksig:8.5.2` (496,313 bytes,
SHA-256 `c4f6fdf2148490296f422a7eb37647ea11d1c3b02f1f2349c33ce257f3c29b1f`; the
build asserts this digest before packaging).

- Copyright: Google LLC.
- Source: https://maven.google.com/com.android/tools/build/apksig/8.5.2 and https://android.googlesource.com/platform/tools/apksig
- License: Apache License 2.0. Compatible with this repository's GPL-3.0.

## dex2jar / dex-tools (vendored binary distribution)

The APK mode converts dex back to Java classfiles with the dex-tools
command-line closure from the dex2jar project. The jars of the
`de.femtopedia.dex2jar:dex-tools:2.4.28` dependency closure are vendored into
the engine as resources under `META-INF/apk-tools/dex2jar/`, covered by a
build-generated `SHA-256SUMS` manifest that the runtime verifies on every
extraction (mismatch deletes the extraction and fails closed).

- Copyright: dex2jar contributors (Bob Pan and others; maintained fork by
  ThexXTURBOXx / femtopedia).
- Source: https://github.com/ThexXTURBOXx/dex2jar and Maven Central
  `de.femtopedia.dex2jar:dex-tools:2.4.28`
- License: Apache License 2.0. Compatible with this repository's GPL-3.0.

JavaShroud compiles a source-derived `DexFix` repair from the fixed 2.4.28
source archive into `javashroud-dex2jar-fixes.jar`. The modified source is in
`core-engine/src/apk-tools-fixes/java/com/googlecode/d2j/dex/DexFix.java`.
It preserves the existing static-field fixes and repairs classfile UTF8
splitting, temporary-register allocation, incoming parameters and interned
string identity. The repair JAR is covered by the same SHA-256SUMS manifest
and precedes the upstream jars on the converter process classpath.

The same source-derived JAR also supplies the one-line common-superclass
correction required by the converter's frame-computation path. JavaShroud
passes `--compute-frames` so large generated control-flow graphs fail closed
with valid verifier frames instead of producing partial class output.

## Apache Commons Compress

APK archive fidelity (raw-entry re-packing, metadata preservation) uses Apache
Commons Compress, resolved as `org.apache.commons:commons-compress:1.28.0`.

- Copyright: The Apache Software Foundation.
- Source: https://commons.apache.org/proper/commons-compress/
- License: Apache License 2.0. Compatible with this repository's GPL-3.0.
