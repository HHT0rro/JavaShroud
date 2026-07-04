# JavaShroud v0.9.2-dev

This development release bumps the engine version to `0.9.2-dev` and the VBC capability version to `4.55`.

- Adds guarded native VM support for engine-generated `ConstantDynamic` LDC values from `condy-constant-indirection`.
- Keeps `method-virtualization` strict `all-compatible` coverage intact for max-method virtualization instead of skipping condy-bearing methods.
- Preserves fail-closed behavior for unknown `ConstantDynamic` bootstrap shapes.
- Validates the previously failing real-JAR pair/max slice for `demo.jar` under `E:\XiangMu\TestJar`.

GitHub Releases are published by `.github/workflows/release.yml` from `v*` tags. Use `v0.9.2-dev` for this release line; bare tags such as `0.9.2-dev` are not release workflow triggers.

## Verification

```powershell
.\gradlew :core-engine:test --tests io.github.hht0rro.javashroud.MethodVirtualizationThresholdTest --no-build-cache --stacktrace
.\gradlew :core-engine:test --fail-fast --no-build-cache --stacktrace
python scripts\real_jar_matrix.py --engine build\core-engine\libs\obfuscator-engine-0.9.2-dev.jar --fixtures E:\XiangMu\TestJar\demo.jar --mode pair --include-native --combo-param-profiles max --limit 8 --offset 140 --work-dir build\real-jar-matrix-v092-pair-max-140-148-demo --run-timeout 60 --run-attempts 2 --obfuscate-timeout 300 --ignore-testjar-pool-flake
```

The matrix slice includes `pair-condy-constant-indirection__method-virtualization-params-max`, which previously failed during obfuscation with unsupported `org.objectweb.asm.ConstantDynamic` LDC input.

## Prior Line

`v0.9.1-dev` preserved the prior sealed VM ABI when fullconfig processed older VBC4-sealed artifacts while keeping fresh inputs on the current VBC4 max-strength/native-only path.
