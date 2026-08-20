# JavaShroud Native Runtime Benchmark Report — 2026-08-19

本报告记录当前工作树在 Windows x64 上的可复现实验结果。报告只保留脱敏计时、能力位、计数器和 output digest；不记录 key、nonce、DEK、page plaintext、descriptor secret、原始资源路径或完整异常 payload。

## 执行环境

- 日期：2026-08-19
- 平台：Windows x64
- 编译器：Zig C compiler (`zig cc`)
- Java headers：`E:\java\jdk-21.0.4\include` 和 `include\win32`
- Native fixture：`core-engine/src/test/native/native_runtime_benchmark.c`
- 样本：100；warmup：2；计时单位：ns；percentile：nearest-rank
- 当前 hardware 日志：`C:\WINDOWS\TEMP\javashroud-native-runtime-benchmark-current-hardware-100.log`
- 当前 software 日志：`C:\WINDOWS\TEMP\javashroud-native-runtime-benchmark-current-software-100.log`
- 硬件 capability：`hardware_aes=1`、`hardware_ghash=1`

## Hardware / software differential

同一 fixture、同一输入和同一输出 digest 分别使用默认 hardware dispatch 与编译期 `JS_CRYPTO_FORCE_SOFTWARE=1` 路径运行。软件路径是同协议 reference baseline，不是旧协议或 fallback artifact。

| Phase | Hardware p50 | Hardware p95 | Hardware p99 | Hardware max | Software p50 | Software p95 | Software p99 | Software max | Speedup (p95) | Output digest |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `ghash-aad-authenticated-page-1m` | 9,173,900 | 13,627,900 | 14,500,800 | 15,220,500 | 125,362,300 | 149,704,100 | 162,279,500 | 162,425,800 | 10.98x | `12d5341457011b7f` |

Hardware result and software result produced the same output digest. The historical schema-2 runners reported `phase_status=pass`, `benchmark_result status=pass`, and `security_gate status=pass` for the measured crypto fixture. Under schema 3 this is phase-level crypto evidence only: a global `pass` additionally requires a valid counter baseline, an explicit differential record, and complete real production coverage.

### Current 4-lane AES-CTR/GCM hot-path differential

The current `js_crypto.c` implementation batches counter-mode payload blocks in
fixed four-lane stack scratch while retaining one operation-local AES schedule.
The authenticated GCM order, GHASH/tag verification, constant-time compare,
artifact binding, and failure wipe are unchanged. A standalone schema-3
Windows x64 run after that change used 100 samples and 16 warmup iterations:

| Phase | Hardware p95 | Software p95 | Speedup (p95) | Output digest |
| --- | ---: | ---: | ---: | --- |
| `gcm-aad-authenticated-page-1m` | 9,543,200 ns | 108,876,000 ns | 11.42x | `12d5341457011b7f` |
| `ctr-128-1m` | 1,166,400 ns | 26,353,900 ns | 22.59x | `19abdc0a2655d4ab` |
| `ctr-256-1m` | 961,700 ns | 39,125,300 ns | 40.68x | `08977865eb38373b` |

Hardware and software outputs matched per phase. The combined hardware run
reported `hardware_crypto_path=28400`, `aes_block_count=27956400`,
`ghash_block_count=6990400`, `auth_check_count=27800`,
`tag_check_count=27800`, `length_check_count=1300`,
`structure_check_count=800`, and `wipe_count=24013300`; the software run
reported the same security-check counters with `software_crypto_path=28400`
and `wipe_count=44979300`. Both runs reported zero fallback/legacy hits, zero
wipe failures, zero plaintext persistence, and zero skipped security checks.
The standalone runner correctly retained `coverage_status=incomplete` and
`security_gate=baseline-missing`; these measurements are phase-level
performance evidence, not full-plan acceptance.

A second 1,000-sample profile was also run from the same binaries:

| Samples | Hardware p50 | Hardware p95 | Software p50 | Software p95 | Output digest | Security gate |
| ---: | ---: | ---: | ---: | ---: | --- | --- |
| 1,000 | 9,427,800 ns | 14,937,500 ns | 127,822,600 ns | 165,504,000 ns | `246d46e98e53d30d` | pass / pass |

The 1,000-sample logs are `C:\WINDOWS\TEMP\javashroud-native-runtime-benchmark-current-hardware-1000.log` and `C:\WINDOWS\TEMP\javashroud-native-runtime-benchmark-current-software-1000.log`. The standalone crypto runner has no 10,000- or 100,000-sample log in this section; dedicated production AKEN page-open profiles at those sample counts are documented below. No percentile is extrapolated, and this standalone section makes no 100,000-sample hardware/software differential claim.

## Crypto KAT and rejection differential

The production crypto KAT probe was rerun after correcting the partial-GCM
fixture lengths. It covers AES-128/AES-256 block known-answer vectors,
GCM empty/AAD/partial-input vectors, CTR block-boundary vectors, wrong
key/nonce/AAD/tag rejection, truncation, output wiping, and default-versus-
forced-software dispatch. Both dispatch modes authenticated the valid vectors,
rejected all invalid variants, and produced the same de-identified output
digest:

```text
crypto-kat differential hardware crypto_kat_security_probe status=pass hardware_crypto_path=39 software_crypto_path=0 hardware_available=1 ghash_hardware_available=1 aes_block_count=841 ghash_block_count=31 auth_failure_count=5 wipe_count=1042 security_checks_skipped=0 fallback_count=0 legacy_path_hits=0 plaintext_persistence_bytes=0 output_digest=4d69803cb36d54d1
crypto-kat differential software crypto_kat_security_probe status=pass hardware_crypto_path=0 software_crypto_path=39 hardware_available=0 ghash_hardware_available=0 aes_block_count=841 ghash_block_count=31 auth_failure_count=5 wipe_count=1190 security_checks_skipped=0 fallback_count=0 legacy_path_hits=0 plaintext_persistence_bytes=0 output_digest=4d69803cb36d54d1
crypto-kat differential capability-disabled crypto_kat_security_probe status=pass hardware_crypto_path=0 software_crypto_path=39 hardware_available=0 ghash_hardware_available=0 aes_block_count=841 ghash_block_count=31 auth_failure_count=5 wipe_count=1190 security_checks_skipped=0 fallback_count=0 legacy_path_hits=0 plaintext_persistence_bytes=0 output_digest=4d69803cb36d54d1
```

JUnit evidence: `build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.NativeRuntimeCryptoKatTest.xml`, timestamp `2026-08-19T19:23:41`, one test, zero failures/errors/skips, elapsed `186.645s`. The lane compiles the crypto-only native fixture and runs default hardware dispatch, forced software dispatch, and a capability-disabled build; all three outputs are byte-for-byte digest-identical, while the disabled build reports `hardware_available=0` and `ghash_hardware_available=0`. This closes the capability-disabled subset in addition to KAT/rejection and same-input hardware/software differential; unsupported-CPU, chunk reorder/duplication, cross-artifact replay, and full large-payload matrix remain open.

An independent fixture-local replay performed the same three compile/run variants
outside the Gradle test worker, using isolated Zig caches while the shared native
Gradle lane was still active. All variants exited `0` and reproduced the same
digest and security counters (`output_digest=4d69803cb36d54d1`,
`auth_failure_count=5`, `security_checks_skipped=0`, `fallback_count=0`,
`legacy_path_hits=0`, `plaintext_persistence_bytes=0`); hardware dispatch
reported `hardware_available=1` and `ghash_hardware_available=1`, while the
forced-software and capability-disabled variants reported both as `0`. This is
corroborating evidence only and does not expand the accepted-artifact coverage
or close the remaining unsupported-CPU/replay/large-payload gaps.

## Native shell payload decode production profile

The shell crypto production fixture now exercises the current-format native
shell payload decode path with complete authentication before the decode
result is accepted. The profile reports only sanitized counters and a digest:

```text
phase=shell-payload-decode phase_mode=production phase_status=pass fixture_scope=current-format-native-shell-payload timing_unit=ns samples=100 warmup=16 p50=546500 p95=563600 p99=585200 max=595800 hardware_crypto_path=500 software_crypto_path=0 aes_block_count=25700 ghash_block_count=0 auth_check_count=500 auth_failure_count=0 tag_check_count=500 length_check_count=100 structure_check_count=100 wipe_count=29000 wipe_failure_count=0 plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0 exception_count=0 security_checks_skipped=0 loader_path=not-measured output_digest=0307e95776cc76f9
```

JUnit evidence: `build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.JsShellCryptoGcmTest.xml`, timestamp `2026-08-19T17:49:21`, one test, zero failures/errors/skips, elapsed `3.869s`. This closes the authenticated shell decode subset only; chunk reorder/duplication, payload-commitment tamper, inner-image loader/mapping lifecycle, and the full accepted-artifact shell attack matrix remain open. `loader_path=not-measured` is intentional and is not treated as loader acceptance.

### Hardware run security counters

```text
hardware_crypto_path=28400
software_crypto_path=0
auth_check_count=500
auth_failure_count=0
tag_check_count=500
length_check_count=1000
structure_check_count=500
wipe_failure_count=0
plaintext_persistence_bytes=0
fallback_count=0
legacy_path_hits=0
security_checks_skipped=0
exception_count=0
```

### Software-reference run security counters

```text
hardware_crypto_path=0
software_crypto_path=28400
auth_check_count=500
auth_failure_count=0
tag_check_count=500
length_check_count=1000
structure_check_count=500
wipe_failure_count=0
plaintext_persistence_bytes=0
fallback_count=0
legacy_path_hits=0
security_checks_skipped=0
exception_count=0
```

## Standalone benchmark coverage

The historical standalone output below was produced by schema 2 before the benchmark gate was tightened. It remains useful crypto microbenchmark evidence, but it is **not** a full-plan acceptance result because it used synthetic crypto/page/shell/resource/JNI adapters and unsupported VM/zstd adapters. Schema 3 reclassifies those phases and prevents a global `pass` while any required production phase is synthetic or unsupported:

```text
phase=resource-alias-lookup phase_mode=synthetic-fixture phase_status=pass
phase=resource-commitment-lookup phase_mode=synthetic-fixture phase_status=pass
phase=jni-method-class-lookup phase_mode=synthetic-fixture phase_status=pass
phase=zstd-context-reuse phase_mode=integration-adapter phase_status=unsupported reason=requires-zstd-integration-build
phase=vm-prepared-execution phase_mode=integration-adapter phase_status=unsupported reason=requires-live-jni-session
phase=vm-nested-execution phase_mode=integration-adapter phase_status=unsupported reason=requires-live-jni-session
coverage_status=incomplete
coverage_gate status=coverage-incomplete
security_gate status=pass
benchmark_result status=coverage-incomplete
```

The explicit `coverage_status=incomplete` is intentional: it prevents a standalone fixture from being mistaken for live JNI/VM/AKEN integration evidence. A schema 3 report also requires a valid de-identified counter baseline and a same-profile hardware/software output-digest differential before its security gate can report `pass`; the coverage gate remains independent and keeps this standalone run out of full acceptance.

## Zstd integration-adapter run

The benchmark was also compiled with `JS_RUNTIME_BENCH_ZSTD=1` and the repository decoder sources (`ZSTD_createDCtx`, `ZSTD_DCtx_reset`, `ZSTD_decompressDCtx`, `ZSTD_freeDCtx`). The synthetic zstd fixture phase passed; it does not close the remaining required production coverage:

```text
phase=zstd-context-reuse phase_mode=synthetic-fixture phase_status=pass
decompress_context_reuse_count=2
wipe_failure_count=0
plaintext_persistence_bytes=0
coverage_gate status=coverage-incomplete
security_gate status=pass
benchmark_result status=coverage-incomplete
```

## Production Zstd session-context evidence

The same full-native benchmark was then rebuilt with `JS_RUNTIME_BENCH_RESOURCE_RUNTIME=1` and the current-only `JS_AKEN_TYPED_ONLY_RUNTIME=1` profile. The benchmark calls `js_vbc4_zstd_decompress_owned` from `js_vm_resource.c`, rather than constructing a local `ZSTD_DCtx`. Its per-thread context is reset on session close, and the malformed-frame check runs after the reset to verify output wiping and current-generation binding.

Direct Windows x64 evidence (`100` samples, `16` warmup iterations, isolated fixture copy; compile exit `0`, run exit `0`):

```text
phase=zstd-context-reuse phase_mode=production phase_status=pass samples=100 warmup=16
p50=2200ns p95=2300ns p99=4100ns max=4100ns
decompress_context_reuse_count=100 structure_check_count=100 length_check_count=100 wipe_count=100
allocation_count=0 exception_count=0 fallback_count=0 legacy_path_hits=0
wipe_failure_count=0 plaintext_persistence_bytes=0 security_checks_skipped=0
zstd_lifecycle phase_mode=production status=pass
post_reset_reuse_count=0 failure_reuse_count=1 failure_wipe_delta=1
fallback_count=0 legacy_path_hits=0 wipe_failure_count=0 plaintext_persistence_bytes=0
security_checks_skipped=0 exception_count=0
```

This closes the production per-thread Zstd context reuse, generation reset, malformed-decode wipe, and bounded decoder-workspace capacity-reuse subset. The updated decoder uses a fixed 256 KiB maximum workspace derived from `ZSTD_estimateDCtxSize()`, binds it to the current session generation, wipes/releases it on reset and thread destruction, and never stores caller plaintext in the workspace. Direct Windows x64 evidence for the expanded probe was `COMPILE_EXIT=0`, `RUN_EXIT=0`, `generation_before=2 generation_after=3 reuse=6 wipes=14 workspace_capacity=95968`. The Kotlin regression lane also passed after the update (XML timestamp `2026-08-19T13:14:18`, one test, zero failures/errors/skips).

A serialized Gradle rerun of the same production lane completed after the shared
test-output lock was released. XML timestamp `2026-08-19T18:27:53`, one test,
zero failures/errors/skips, elapsed `631.503s`. This independently reconfirms
the current native context compile/run path and malformed-frame partial-output
wipe gate; it does not expand the accepted-artifact matrix.

## Production resource-index subset evidence

The focused Kotlin lane `NativeRuntimeResourceProductionBenchmarkTest.production_resource_benchmark_uses_native_immutable_indexes_and_current_jsrp_verifier` compiles `runtime_resource_production_benchmark_probe.c` against the complete current native source set with `JS_RUNTIME_BENCH_RESOURCE_RUNTIME=1`. It invokes the production `js_vm_resource.c` alias index and current JSRP commitment verifier; it does not use the standalone synthetic hash table and it does not claim attached-JVM resource-open coverage.

The first required 100-sample profile with 16 non-measured warmup iterations completed successfully (`BUILD SUCCESSFUL`, one test, zero failures/errors/skips). The production phase evidence was:

```text
phase=resource-alias-lookup phase_mode=production phase_status=pass samples=100 warmup=16
resource_index_hit_count=100
allocation_count=0 exception_count=0 fallback_count=0 legacy_path_hits=0
wipe_failure_count=0 plaintext_persistence_bytes=0 security_checks_skipped=0

phase=resource-commitment-lookup phase_mode=production phase_status=pass samples=100 warmup=16
resource_index_hit_count=100 structure_check_count=100 length_check_count=100 digest_check_count=100 wipe_count=200
allocation_count=0 exception_count=0 fallback_count=0 legacy_path_hits=0
wipe_failure_count=0 plaintext_persistence_bytes=0 security_checks_skipped=0
```

This closes the immutable resource-index, current-format commitment-verification, and production Zstd context lifecycle subsets. The focused Kotlin lane passed with XML timestamp `2026-08-19T16:41:18` (one test, zero failures/errors/skips). The overall benchmark remains `coverage-incomplete` until the remaining accepted-artifact and shell/VM matrix gates are satisfied.

### Resource/Zstd required sample matrix

A later serialized Gradle lane completed the required `100`/`1,000`/`10,000`/
`100,000` sample profiles against the same current native source set. JUnit
XML timestamp `2026-08-19T19:17:35`, one test, zero failures/errors/skips,
elapsed `204.47s`. The phase-level p95 values were:

| Samples | Alias p95 | Commitment p95 | Zstd context p95 | Alias hits | Commitment digest/length/structure checks | Zstd reuse | Output digests |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 100 | 400 ns | 6,600 ns | 2,300 ns | 100 | 100 / 100 / 100 | 100 | `8467b825703f4316` / `f34e68066c094b84` / `9a083743804af552` |
| 1,000 | 400 ns | 10,100 ns | 2,600 ns | 1,000 | 1,000 / 1,000 / 1,000 | 1,000 | `56cbeb80c3b8db90` / `e444dd3e3799dd24` / `5ab8eda16ce76156` |
| 10,000 | 400 ns | 7,400 ns | 5,000 ns | 10,000 | 10,000 / 10,000 / 10,000 | 10,000 | `9a953c56385505aa` / `a3c9321194e0c3e3` / `7a53e7972b1af353` |
| 100,000 | 500 ns | 11,100 ns | 4,500 ns | 100,000 | 100,000 / 100,000 / 100,000 | 100,000 | `688a011085e3ce90` / `4770c339a636e645` / `db304d84e6545064` |

The commitment phase reported `wipe_count=2*samples`; the Zstd phase reported
`wipe_count=samples`, `decompress_context_reuse_count=samples`, and
`post_reset_reuse_count=0`, `failure_reuse_count=1`, `failure_wipe_delta=1`
for every profile. All profiles reported zero allocations, exceptions,
fallback/legacy hits, wipe failures, plaintext persistence, and skipped
security checks. The generation-replay line remained unchanged for each
profile: stale alias/commitment/index hits were zero and replacement indexes
were reinstalled and reauthenticated. This closes the required resource and
Zstd sample-count subset, but not attached-JVM resource opening, concurrent
resource opening, or accepted-artifact resource lanes.

### Resource cache generation replay evidence

The production resource probe now exercises stale alias/commitment replay across explicit session-generation resets. An isolated Windows x64 fixture copy compiled the complete current native source set with `COMPILE_EXIT=0` and ran the first required profile with `RUN_EXIT=0`; no artifact key, nonce, or plaintext is emitted. The added lifecycle line was:

```text
resource_cache_lifecycle phase_name=resource-cache-generation phase_mode=production status=pass generation_before=11 generation_installed=13 generation_after_reset=14 generation_reinstalled=16 stale_alias_reused=0 stale_alias_identity_resolution=1 stale_commitment_reused=0 stale_resource_index_hit_count=0 replacement_resource_index_hit_count=2 replacement_structure_check_count=1 replacement_length_check_count=1 replacement_digest_check_count=1 fallback_count=0 legacy_path_hits=0 wipe_failure_count=0 plaintext_persistence_bytes=0 security_checks_skipped=0 exception_count=0
```

The check proves that reset retires the prior alias route and commitment index (zero stale hits and no old sealed-route reuse), while a replacement generation must reinstall and reauthenticate both indexes before they resolve. The existing resource alias, commitment, and Zstd phase counters remained unchanged; the overall report stays `coverage-incomplete`, and attached-JVM resource opening is still not claimed.

## Attached-JVM JNI cache production evidence

`NativeRuntimeJniCacheProductionBenchmarkTest.production_jni_cache_benchmark_binds_cache_hits_to_real_jvm_loader_and_generation` starts a disposable JDK 21 VM through `JNI_CreateJavaVM`, initializes the production cache, validates a real bootstrap owner and system `ClassLoader`, rejects a non-loader receiver, verifies cache reconstruction after mismatch cleanup, invalidates the resource/session generation, and measures repeated loader validation. The probe reports only counters, timings, and a digest.

Direct Windows x64 probe output (`100` samples, `16` warmup iterations) was:

```text
phase=jni-method-class-lookup phase_mode=production phase_status=pass
p50=4100ns p95=4200ns p99=4200ns max=4300ns
jni_cache_hit_count=100 jni_abi_check_count=100 wipe_count=100
exception_count=0 fallback_count=0 legacy_path_hits=0 wipe_failure_count=0
plaintext_persistence_bytes=0 security_checks_skipped=0
output_digest=bcb30807586e0d8f
COMPILE_EXIT=0 RUN_EXIT=0
```

The production cache mismatch path was tightened so a cache cleared after a loader mismatch is reconstructed only through a complete current JNI lookup and exact loader binding; it never reuses stale global references or takes an ABI fallback. The Gradle lane passed with XML timestamp `2026-08-19T13:06:05` (one test, zero failures/errors/skips).

### Attached-JVM JNI cache profile matrix

The production JNI cache fixture was extended to the complete required sample
matrix in one compile-once Gradle lane.  The authoritative JUnit XML
`build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.NativeRuntimeJniCacheProductionBenchmarkTest.xml`
reports `tests=1`, `skipped=0`, `failures=0`, `errors=0`, timestamp
`2026-08-19T20:26:16`, and elapsed `195.848s`.  Each profile starts a real JDK
21 VM through `JNI_CreateJavaVM`, exercises bootstrap-to-managed loader binding,
rejects a non-loader receiver, rebuilds after mismatch and generation reset, and
then measures repeated production validation.

| Samples | p50 | p95 | p99 | max | cache hits | JNI-ABI checks | wipe count | output digest |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 100 | 3,400 ns | 3,500 ns | 3,500 ns | 3,600 ns | 100 | 100 | 100 | `bcb30807586e0d8f` |
| 1,000 | 3,600 ns | 6,100 ns | 9,600 ns | 51,100 ns | 1,000 | 1,000 | 1,000 | `12927ccd90b75736` |
| 10,000 | 3,600 ns | 3,800 ns | 6,000 ns | 21,600 ns | 10,000 | 10,000 | 10,000 | `a8b9f92d1397ca60` |
| 100,000 | 3,600 ns | 6,600 ns | 8,200 ns | 94,000 ns | 100,000 | 100,000 | 100,000 | `134f60ef7f9b30cf` |

All four profiles reported `phase_mode=production` and `phase_status=pass`,
`cpu_hardware_aes=1`, `cpu_hardware_ghash=1`, cache hits and JNI-ABI checks at
least equal to the measured sample count, and zero allocation/exception/native-
exception/fallback/legacy/wipe-failure/plaintext-persistence/security-skip
counters.  The cache lookup phase does not perform cryptographic work, so its
AES/GHASH/authentication counters remain zero by design; loader, generation,
class-binding, ABI, and session checks are still performed before each hit.
This closes the required attached-JVM JNI cache profile subset only; the full
accepted-artifact JNI/reflection matrix and cross-artifact replay coverage remain
open, so `coverage_status=incomplete` is unchanged.

## AKEN authenticated page-open production evidence

The real single-page JNI harness now has a `bench:SAMPLES:WARMUP` mode that repeats the same production-bound `executeAkenVmPage` path after the one-shot semantic/authentication assertion. The fixture-only diagnostics registration exposes a 26-field de-identified counter vector; no key, nonce, descriptor, path, plaintext, or exception payload is returned. The benchmark enforces production mode, nonzero authentication/digest/tag/length/structure/JNI-ABI/wipe deltas, zero auth failures, exceptions, fallback/legacy hits, wipe failures, plaintext persistence, and skipped security checks.

The focused lane

```text
production_single_page_vbc4_executes_and_authenticates_through_real_jni()
```

passed with the latest JUnit XML timestamp `2026-08-19T15:59:44`, one test,
zero failures/errors/skips, and runtime `145.368s`. The default benchmark
profile is `100` samples with `16` warmup iterations;
`JS_AKEN_PAGE_OPEN_BENCH_SAMPLES` and `JS_AKEN_PAGE_OPEN_BENCH_WARMUP` select
the larger required profiles. The multi-page AKEN lane remains a separate
long-running compile/integration blocker and is not inferred from this
single-page result.

### AKEN single-page required sample matrix

The same production-bound single-page harness was run with the required
`100`/`1,000`/`10,000`/`100,000` measured samples and `16` warmup iterations.
The captured JUnit XML was timestamped `2026-08-19T15:59:44`; all four
profiles reported `phase_status=pass`. Timings are nanoseconds and use the
same authenticated page, output digest check, and security-counter gate as
the focused lane.

| Samples | p50 | p95 | p99 | max | hardware path | frame reuse | auth checks | wipe count | output digest |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| 100 | 592,000 | 706,200 | 810,200 | 862,200 | 100 | 100 | 2,600 | 156,300 | `8a9e39e4def404ed` |
| 1,000 | 443,700 | 567,000 | 668,900 | 3,006,800 | 1,000 | 1,000 | 26,000 | 1,563,000 | `36c4b862c73a760b` |
| 10,000 | 448,500 | 597,900 | 739,400 | 3,845,000 | 10,000 | 10,000 | 260,000 | 15,630,000 | `d3e2c7a8c4b6c7d6` |
| 100,000 | 443,300 | 554,600 | 737,300 | 3,188,900 | 100,000 | 100,000 | 2,600,000 | 156,300,000 | `84a5cc34c5893937` |

Every profile used `hardware_crypto_path=samples`,
`software_crypto_path=0`, `vm_heap_fallback_count=0`,
`auth_failure_count=0`, `wipe_failure_count=0`, `fallback_count=0`,
`legacy_path_hits=0`, `exception_count=0`,
`security_checks_skipped=0`, and `plaintext_persistence_bytes=0`. The
corresponding digest, tag, length, structure, JNI-ABI, and total wipe counters
scaled with the sample count; no security check was removed for the matrix
run. This closes the required single-page AKEN sample-count coverage, but it
does not imply multi-page AKEN, prepared-VM, shell-loader, or real-artifact
matrix acceptance.

### AKEN multi-page production page-open probe

The multi-page lane was extended with the same sanitized `bench:SAMPLES:WARMUP`
entrypoint after its one-shot authenticated execution. The fixture partitions
one current-format VBC4 method into multiple pages, emits one generated locator
include for the complete container, and repeatedly enters page zero through the
real JNI bridge; sibling-page traversal remains inside the production native
page-open path. No protocol, ABI, authentication, binding, or wipe behavior was
changed. The JUnit system-out contains only the phase line and de-identified
latency/counter fields.

The focused lane

```text
production_multi_page_vbc4_assembles_executes_and_authenticates_through_real_jni()
```

passed with JUnit XML timestamp `2026-08-19T16:54:33`, one test,
zero failures/errors/skips, and runtime `96.955s`. The narrow production
profile used `100` samples and `16` warmup iterations:

```text
phase=aken-page-open phase_mode=production phase_status=pass timing_unit=ns samples=100 warmup=16 p50=22425600 p95=27508200 p99=31077600 max=35048800 hardware_crypto_path=800 software_crypto_path=0 aes_block_count=279200 ghash_block_count=301600 vm_frame_reuse_count=100 vm_heap_fallback_count=0 resource_index_hit_count=0 decompress_context_reuse_count=0 jni_cache_hit_count=3300 auth_check_count=20800 auth_failure_count=0 digest_check_count=13600 tag_check_count=800 length_check_count=13100 structure_check_count=12300 jni_abi_check_count=3400 wipe_count=9514600 wipe_failure_count=0 plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0 exception_count=0 security_checks_skipped=0 output_digest=8a9e39e4def404ed
```

The `hardware_crypto_path=800`, `tag_check_count=800`, and
`auth_check_count=20800` deltas reflect repeated authenticated traversal of the
multi-page container rather than a synthetic single-page adapter. All security
gates remained closed successfully: authentication failures, wipe failures,
fallbacks, legacy hits, exceptions, skipped checks, and plaintext persistence
were all zero. Evidence is retained in:

```text
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml
build/multi-page-aken-bench-2026-08-19.log
```

This closes only the multi-page single-profile production probe. The required
multi-page `100`/`1,000`/`10,000`/`100,000` matrix, shell loader/mapped-image
production probe, accepted-artifact matrix, and real-JAR readiness lanes remain
open; overall coverage therefore stays `coverage-incomplete`.

The latest serialized multi-page lane provides a stronger bounded result but is
not an acceptance pass: its JUnit XML
`build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml`
reports `tests=8`, `skipped=0`, `failures=1`, `errors=0`, timestamp
`2026-08-19T19:31:32`, and elapsed `3198.664s`.  The production multi-page
profiles at `100` and `1,000` samples passed with the expected authentication,
digest, tag, length, structure, JNI-ABI, wipe, and zero-fallback counters; the
`10,000` profile timed out at the fixture's 120-second execution bound before a
phase line was emitted.  The timeout is retained as a real performance/integration
blocker rather than converted to a pass, and the required multi-page matrix
therefore remains incomplete.

### Native shell payload decode production probe

The focused shell lane now benchmarks the production `js_shell_decode_payload_chunks`
implementation against a current-format `NativeKernelShellPacker.MaxPayloadBundle`
with authenticated per-chunk tags, current stream-key derivation, nonce, and
binding tag. The benchmark copies the sealed payload into wipe-on-use scratch,
performs warmup, measures repeated authenticated decode, verifies the recovered
payload digest, wipes every decoded buffer, and prints only sanitized timings and
runtime security counters. It does not map or execute the inner image; the
loader/mapped-image lifecycle is explicitly reported as `loader_path=not-measured`.
No shell protocol, payload framing, or authentication behavior was changed.

The focused lane

```text
native_shell_payload_decode_production_profile_reports_sanitized_phase()
```

passed with JUnit XML timestamp `2026-08-19T17:49:21`, one test,
zero failures/errors/skips, and runtime `3.869s`. The narrow production profile
used `100` samples and `16` warmup iterations:

```text
phase=shell-payload-decode phase_mode=production phase_status=pass fixture_scope=current-format-native-shell-payload timing_unit=ns samples=100 warmup=16 p50=546500 p95=563600 p99=585200 max=595800 hardware_crypto_path=500 software_crypto_path=0 aes_block_count=25700 ghash_block_count=0 auth_check_count=500 auth_failure_count=0 tag_check_count=500 length_check_count=100 structure_check_count=100 wipe_count=29000 wipe_failure_count=0 plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0 exception_count=0 security_checks_skipped=0 loader_path=not-measured output_digest=0307e95776cc76f9
```

The native decode profile reported `hardware_crypto_path=500`,
`auth_check_count=500`, and `tag_check_count=500` for the five authenticated
chunks per sample. `auth_failure_count`, `wipe_failure_count`,
`plaintext_persistence_bytes`, `fallback_count`, `legacy_path_hits`,
`exception_count`, and `security_checks_skipped` were all zero. Evidence is
retained in:

```text
E:/XiangMu/JavaShroud-public/build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.JsShellCryptoGcmTest.xml
E:/XiangMu/JavaShroud-public/build/shell-payload-decode-bench-2026-08-19.log
```

This closes the current-format native shell chunk-decode production subset only.
The verified shell metadata parser, inner-image loader/mapping/relocation path,
full shell hot-path matrix, accepted-artifact matrix, and real-JAR readiness
lanes remain coverage-incomplete.

### Native shell payload decode profile matrix

The shell payload production fixture now supports a matrix mode through
`JS_SHELL_PAYLOAD_BENCH_MATRIX=1`.  In one serialized compile/run lane it
compiled the current native crypto/shell sources once per measured profile and
executed the same authenticated current-format payload for `100`, `1,000`,
`10,000`, and `100,000` samples, each with `16` warmup iterations.  The
authoritative JUnit XML
`build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.JsShellCryptoGcmTest.xml`
reports `tests=1`, `skipped=0`, `failures=0`, `errors=0`, timestamp
`2026-08-19T20:52:51`, and elapsed `69.606s`.

| Samples | p50 | p95 | p99 | max | auth/tag checks | hardware path | wipe count | output digest |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 100 | 468,200 ns | 499,400 ns | 561,500 ns | 598,000 ns | 300 | 300 | 20,600 | `0307e95776cc76f9` |
| 1,000 | 486,400 ns | 646,600 ns | 794,300 ns | 938,200 ns | 3,000 | 3,000 | 206,000 | `c62ac153bae60d3b` |
| 10,000 | 482,500 ns | 710,300 ns | 886,800 ns | 2,787,300 ns | 30,000 | 30,000 | 2,060,000 | `04ecb85982ec5bb8` |
| 100,000 | 469,800 ns | 712,600 ns | 858,200 ns | 8,795,400 ns | 300,000 | 300,000 | 20,600,000 | `d5234e6b5c46279b` |

Every profile reported `phase_mode=production`, `phase_status=pass`,
`auth_failure_count=0`, `wipe_failure_count=0`,
`plaintext_persistence_bytes=0`, `fallback_count=0`, `legacy_path_hits=0`,
`exception_count=0`, and `security_checks_skipped=0`.  `loader_path=not-measured`
remains explicit: this matrix closes authenticated shell chunk decoding only;
inner-image mapping/relocation, loader hot-path reuse, shell tamper/reorder/
duplication, accepted-artifact coverage, and readiness remain open.

## VM frame evidence

The live execution-frame lifecycle is covered separately by:

```text
NativeVmExecutionFrameTest.native_execution_frame_arena_covers_tls_fls_and_forced_bounded_pool
```

That test passed for both the normal OS TLS/FLS path and the forced bounded-pool path, including nested depth checks, frame reuse, wipe-on-release, thread-exit destructor cleanup, and owner isolation.

## Prepared VM execution production benchmark

The attached-JVM production fixture now exercises the production
`js_vm_execute_prepared_program_int_int` entrypoint with a session-bound
resident program. It copies resident instruction state into private execution
state and records only de-identified phase metrics. The benchmark test prints
one sanitized phase line per profile into the JUnit `system-out` section so the
sample matrix remains auditable after the temporary native probe directory is
removed.

Command:

```powershell
$env:JAVA_HOME='E:\java\jdk-21.0.4'
$env:JS_VM_PREPARED_EXEC_BENCH_MATRIX='1'
.\gradlew.bat :core-engine:test `
  --no-daemon --no-configuration-cache --max-workers=1 --console=plain `
  --tests 'io.github.hht0rro.javashroud.NativeRuntimeVmPreparedExecutionBenchmarkTest'
```

Latest JUnit evidence after adding an attached-JVM nested and recursive
prepared-program re-entry check:

```text
TEST-io.github.hht0rro.javashroud.NativeRuntimeVmPreparedExecutionBenchmarkTest.xml
timestamp=2026-08-19T16:11:12
tests=1 skipped=0 failures=0 errors=0 time=471.075s
phase_mode=attached-jvm-production-entrypoint
fixture_scope=session-bound-resident-program
nested_frame_depth=8
nested_execution=pass
recursive_execution=pass
```

### Prepared execution sample matrix

| Samples | p50 | p95 | p99 | max | frame reuse | wipe count | output digest |
|---:|---:|---:|---:|---:|---:|---:|---|
| 100 | 113700 ns | 120100 ns | 175700 ns | 186800 ns | 100 | 5,300 | `00754a46981011ba` |

The latest targeted run used the bounded default 100-sample profile after the
fixture gained explicit nested and recursive re-entry checks. The earlier
100/1,000/10,000/100,000 matrix remains valid for the same prepared entrypoint
before that additional lifecycle assertion; the new run is recorded separately
to avoid mixing incomparable harness versions.

The final Kotlin rerun also includes the attached-JVM threaded phase and the
new thread-isolation assertions:

```text
TEST-io.github.hht0rro.javashroud.NativeRuntimeVmPreparedExecutionBenchmarkTest.xml
timestamp=2026-08-19T17:38:40
tests=1 skipped=0 failures=0 errors=0 time=159.029s
phase_status=pass
nested_execution=pass
recursive_execution=pass
threaded_execution=pass
thread_count=4
thread_iterations=32
thread_frame_reuse_count=124
thread_heap_fallback_count=0
thread_wipe_count=6840
samples=100
warmup=16
p50=125500ns
p95=172600ns
p99=251600ns
max=251900ns
vm_frame_reuse_count=100
vm_heap_fallback_count=0
allocation_count=0
exception_count=0
native_exception_count=0
fallback_count=0
legacy_path_hits=0
wipe_failure_count=0
plaintext_persistence_bytes=0
security_checks_skipped=0
output_digest=02c16df59d494c4b
```

The direct attached-JVM probe also retained passing 1,000/10,000/100,000
sample profiles with `thread_frame_reuse_count=124`, zero heap fallback,
zero wipe failures, zero exceptions, zero security skips, and zero plaintext
persistence. The latest exception-enabled executable was rebuilt after
switching the synthetic constant-pool entry to the current authenticated
sealed-string format and rerun for the full 100/1,000/10,000/100,000 matrix;
the de-identified timing and security fields were:

```text
100 samples: p50=127000ns p95=170300ns p99=173500ns max=184000ns output_digest=02c16df59d494c4b
1000 samples: p50=236500ns p95=286500ns p99=347100ns max=715800ns output_digest=a5379d9535e2897b
10000 samples: p50=131000ns p95=415700ns p99=859600ns max=3629900ns output_digest=25354bddf07d9ac4
100000 samples: p50=133200ns p95=269900ns p99=433900ns max=10644700ns output_digest=6b62938b5cb5e18d
exception_execution=pass exception_catch=typed exception_result=42
threaded_execution=pass thread_count=4 thread_iterations=32
thread_frame_reuse_count=124 thread_heap_fallback_count=0 thread_wipe_count=6840
vm_frame_reuse_count=100/1000/10000/100000 vm_heap_fallback_count=0 allocation_count=0
exception_count=0 native_exception_count=0 fallback_count=0 legacy_path_hits=0
wipe_failure_count=0 plaintext_persistence_bytes=0 security_checks_skipped=0
```

This closes the production frame/TLS-FLS/threaded subset and the authenticated
typed exception-table subset, while the full virtualized lambda/invoke-dynamic
and broader exception-semantic matrix remains open.

The prepared probe now additionally exercises a current-format authenticated
typed exception-table entry. The resident program executes a synthetic
`IDIV` fault, catches the virtualized `ArithmeticException` through the
authenticated `[0,3)->handler 4` entry and its sealed-string catch type, pops
the throwable, and returns `42`. The direct Windows x64 attached-JVM profiles
passed with:

```text
exception_execution=pass exception_catch=typed exception_result=42
100 samples: p50=127000ns p95=170300ns p99=173500ns max=184000ns
1000 samples: p50=236500ns p95=286500ns p99=347100ns max=715800ns
10000 samples: p50=131000ns p95=415700ns p99=859600ns max=3629900ns
100000 samples: p50=133200ns p95=269900ns p99=433900ns max=10644700ns
threaded_execution=pass thread_frame_reuse_count=124 thread_heap_fallback_count=0
fallback_count=0 legacy_path_hits=0 wipe_failure_count=0 plaintext_persistence_bytes=0 security_checks_skipped=0
```

The typed-catch variant now uses a sealed-string constant-pool entry with the
same build-key derivation, AES-CTR material, HMAC tag, and outer VBC4 entry
envelope as production serialization. This closes the typed-catch fixture
gap, but it does not claim full lambda/invoke-dynamic or broader
exception-semantic coverage.

The earlier formal Gradle rerun after the fixture change was blocked by the
shared `build/core-engine/test-results/test/binary/output.bin` lock. A later
serialized lane completed after the lock was released and produced a current
JUnit XML result:

```text
TEST-io.github.hht0rro.javashroud.NativeRuntimeVmPreparedExecutionBenchmarkTest.xml
timestamp=2026-08-19T19:13:57
tests=1 skipped=0 failures=0 errors=0 time=139.32s
```

The direct v2 executable logs remain retained under
`build/vm-prepared-thread-probe-direct/run-typedcatch-v2-{100,1000,10000,100000}.log`;
the formal result strengthens the evidence for this attached-JVM subset but
does not upgrade the report's `coverage_status=incomplete` gate.

The current formal Gradle system-out reports the following required sample
profiles from the same session-bound resident program:

```text
100 samples: p50=119100ns p95=128000ns p99=157200ns max=162700ns vm_frame_reuse_count=100 wipe_count=5300 output_digest=02c16df59d494c4b
1000 samples: p50=112800ns p95=118400ns p99=159400ns max=217200ns vm_frame_reuse_count=1000 wipe_count=53000 output_digest=a5379d9535e2897b
10000 samples: p50=110500ns p95=149300ns p99=188500ns max=319900ns vm_frame_reuse_count=10000 wipe_count=530000 output_digest=25354bddf07d9ac9
100000 samples: p50=108400ns p95=137800ns p99=214200ns max=2287800ns vm_frame_reuse_count=100000 wipe_count=5300000 output_digest=6b62938b5cb5e18d
nested_execution=pass recursive_execution=pass exception_execution=pass exception_catch=typed exception_result=42
threaded_execution=pass thread_count=4 thread_iterations=32 thread_frame_reuse_count=124 thread_heap_fallback_count=0 thread_wipe_count=6840
allocation_count=0 exception_count=0 native_exception_count=0 fallback_count=0 legacy_path_hits=0 wipe_failure_count=0 plaintext_persistence_bytes=0 security_checks_skipped=0
```

All four formal profiles reported `phase_status=pass`, zero frame heap
fallbacks, zero allocation count, zero exception/native-exception count, zero
fallback/legacy hits, zero wipe failures, zero plaintext persistence, and zero
security skips. The typed exception-table, nested/recursive, threaded, and
frame-reuse claims are therefore current formal Gradle evidence; lambda,
invoke-dynamic, broader exception semantics, and accepted-artifact VM lanes
remain open.

A local parser re-read all four retained logs and verified `phase_status=pass`,
`exception_catch=typed`, `exception_result=42`, zero fallback/legacy/wipe/
plaintext/security-skip counters, and 16-hex output digests without any
forbidden key/nonce/DEK/plaintext fields.

All four profiles reported `phase_status=pass`, `cpu_hardware_aes=1`, and
`cpu_hardware_ghash=1`. The fixture does not open an AKEN page, so its
operation-local crypto and authentication counters are expected to remain
zero; this is not used as evidence that page authentication was skipped.
Every profile reported zero `vm_heap_fallback_count`, `allocation_count`,
`exception_count`, `native_exception_count`, `fallback_count`,
`legacy_path_hits`, `wipe_failure_count`,
`plaintext_persistence_bytes`, and `security_checks_skipped`. The benchmark
validates bounded nested and native-recursive frame lifecycle plus depth-
overflow handling, but it does not yet claim full recursive virtualized-method,
lambda, invoke-dynamic, or exception-semantic coverage.

## Native loader validated-metadata evidence

The ELF loader now derives and caches the validated symbol-table count only
within one `js_shell_load_inner_image` call, then resolves `JNI_OnLoad`,
`JNI_OnUnload`, and `js_native_abi_table_v1` in one bounds-checked pass. The
PE loader keeps its current per-load validated image plan, import-module cache,
required-export index, relocation cursor, and mapping metadata. The resolved
addresses remain subject to the existing undefined-symbol, string-table,
executable-range, architecture, section/segment, relocation-target, W^X,
native-digest, ABI, route, artifact-binding, and final-commitment checks.

`NativePeLoaderAlignmentTest` passed on `2026-08-19T14:22:31` with three tests,
zero skips/failures/errors. Direct Zig compilation of the modified ELF loader
for `x86_64-linux-gnu` and the Windows PE loader for `x86_64-windows-gnu`
completed with exit code `0`. The cache is stack-local and is never reused
across artifacts, sessions, threads, or mapped images.

## Native build evidence

The modular native build completed for all declared targets:

```text
js_kernel_linux-x64.so
js_kernel_macos-arm64.dylib
js_kernel_macos-x64.dylib
js_kernel_windows-x64.dll
js_kernel_windows-x64.pdb
```

## Acceptance status

- Crypto hardware/software differential: **pass** for the measured 1 MiB authenticated page and CTR phases and the production KAT/rejection probe; hardware, forced-software, and capability-disabled builds produced the expected identical digests and retained the required failure/wipe counters.
- Native shell payload decode: **production subset pass** for the authenticated current-format payload profile; the inner-image loader/mapping lifecycle and shell tamper matrix remain unmeasured.
- Security gate counters: **pass**; no auth failure, fallback, legacy path, wipe failure, plaintext persistence, skipped security check, or exception was observed.
- Prepared VM execution: **production fixture pass** for the attached-JVM sample matrix (100/1,000/10,000/100,000), nested/recursive/threaded frame isolation, and the authenticated typed exception-table subset; full recursive virtualized methods, lambda/invoke-dynamic, and broader exception-semantic breadth remain open.
- Resource immutable-index/commitment/Zstd subset: **production probe pass** for the required 100/1,000/10,000/100,000 profiles, with generation replay and failure-wipe counters retained; attached-JVM resource opening, concurrent resource opening, and accepted-artifact resource lanes remain open.
- Full real-artifact AKEN/JNI matrix and the two requested external JAR readiness lanes require their dedicated integration environment and are not inferred from this standalone report.


## Real-artifact smoke evidence

The two plan-specified JARs were present and were run in the current workspace as direct baseline smoke lanes; this is not a claim that every native/VM capability matrix lane has been accepted.

### `E:\XiangMu\SimpleFiveInARow-master\JavaObfuscatorTest-main\bench\bin\TEST.jar`

- Java 21.0.4 direct run exit code: `0`.
- Tests 1.1–1.7 and 2.1–2.7 reported `PASS`; test 2.8 (`Sec`) reported `ERROR` in the fixture baseline.
- `Calc` completed (`35ms` in the captured run).
- This existing `Sec ERROR` is retained as a baseline compatibility observation and is not attributed to the native runtime optimization.

### `E:\speedfix\SimpleFiveInARow.jar`

- Java 21.0.4 UI smoke reached all 14 diagnostics without a reported failure.
- Diagnostics 1–13 reported `PASS`; SecurityManager compatibility (14/14) reported `SKIPPED`.
- Captured readiness markers: `setVisible(true)` at approximately `1751ms`; background diagnostics completed at approximately `1925ms`; render check completed at approximately `2347ms`.
- The measured readiness is above the plan target of `1500ms`, so the target is recorded as not yet met rather than being inferred as passed.

The full requested matrix (default/native/VM combinations, random order, source rebuild, prebuilt JAR, Pool deterministic lane, and SecurityManager compatibility lane) remains an integration follow-up.

## Real-artifact acceptance matrix — 2026-08-19

本节记录当前工作树对计划指定真实语料的实际命令证据。所有 lane 使用本地输入 JAR；结果按 `pass`、`timeout`、`config-validation-blocked`、`aken-vbc4-format-blocked` 或 `nonzero` 分类。没有把未生成 artifact 或运行失败标记为通过。

### Inputs and engine artifacts

| Item | Evidence |
| --- | --- |
| Engine used for matrix | `E:\XiangMu\JavaShroud-public\build\core-engine\libs\obfuscator-engine-0.12.jar` |
| Source rebuild | `gradlew.bat :core-engine:jar --no-daemon --rerun-tasks` → `BUILD SUCCESSFUL` on 2026-08-19; resulting JAR SHA-256 prefix `9C4B298D826A52BB` |
| Prebuilt copy | `C:\Windows\Temp\javashroud-real-artifact-acceptance-20260819\prebuilt-obfuscator-engine-0.12.jar`; copied before source rebuild, SHA-256 prefix `4531976B22E74931` |
| Fixture A | `E:\speedfix\SimpleFiveInARow.jar`; direct baseline process was bounded at 8 s (reported exit `124`) because the UI remains alive; diagnostics 1–14 completed, `setVisible(true)` and render markers were observed |
| Fixture B | `E:\XiangMu\SimpleFiveInARow-master\JavaObfuscatorTest-main\bench\bin\TEST.jar`; direct baseline exit `0`; `Sec ERROR` is baseline; `Pool PASS`; `Calc` marker observed |

### Direct baseline smoke

| Fixture | Lane | Exit | Classification | Wall time (s) | Markers |
| --- | --- | ---: | --- | ---: | --- |
| `SimpleFiveInARow.jar` | direct baseline | 124 | timeout | 9.323 | `SecurityManager … SKIPPED`; diagnostics 14/14 failed=false; `setVisible(true)`; render marker observed |
| `SimpleFiveInARow.jar` | direct baseline | 124 | timeout | 9.692 | `SecurityManager … SKIPPED`; diagnostics 14/14 failed=false; `setVisible(true)`; render marker observed |
| `TEST.jar` | direct baseline | 0 | pass | 2.658 | `Calc`; `Sec ERROR`; `Pool PASS` |
| `TEST.jar` | direct baseline | 0 | pass | 3.021 | `Calc`; `Sec ERROR`; `Pool PASS` |

### Obfuscation/runtime lanes

| Fixture | Lane | Obfuscation exit | Obfuscation classification/detail | Artifact | Runtime exit | Runtime classification | Obfuscation seconds |
| --- | --- | ---: | --- | --- | ---: | --- | ---: |
| `SimpleFiveInARow.jar` | `default-invalid-empty-config` | 1 | config-validation-blocked: passes must be an array, path=C:\\WINDOWS\\TEMP\\javashroud-real-artifact-acceptance-20260819\\SimpleFiveInARow\\default\\config.toml | not-created | — | — | 1.725 |
| `SimpleFiveInARow.jar` | `native` | 1 | config-validation-blocked: missing companion passes: jni-microkernel-loader requires any of [anti-dump-protection, anti-instrumentation, anti-symbolic-execution, callsite-rotation-protection, class-encryption-loader, environment-bound-keys, exception-semantic-virtualization, method-body-delayed-decryption, method-virtualization, string-encryption], path=C:\\WINDOWS\\TEMP\\javashroud-real-artifact-acceptance-20260819\\SimpleFiveInARow\\native\\config.toml | not-created | — | — | 0.603 |
| `SimpleFiveInARow.jar` | `vm` | 1 | aken-vbc4-format-blocked: AKEN VBC4 block planner expected VBC4 magic | not-created | — | — | 10.971 |
| `SimpleFiveInARow.jar` | `string` | 0 | pass; runtime timeout after 8s (UI remains alive) | created | 124 | timeout | 6.44 |
| `SimpleFiveInARow.jar` | `loader` | 1 | config-validation-blocked: missing companion passes: jni-microkernel-loader requires any of [anti-dump-protection, anti-instrumentation, anti-symbolic-execution, callsite-rotation-protection, class-encryption-loader, environment-bound-keys, exception-semantic-virtualization, method-body-delayed-decryption, method-virtualization, string-encryption], path=C:\\WINDOWS\\TEMP\\javashroud-real-artifact-acceptance-20260819\\SimpleFiveInARow\\loader\\config.toml | not-created | — | — | 0.86 |
| `SimpleFiveInARow.jar` | `resource` | 0 | pass; runtime ExceptionInInitializerError | created | 1 | nonzero | 115.837 |
| `SimpleFiveInARow.jar` | `reflection` | 0 | pass; runtime timeout after 8s (UI remains alive) | created | 124 | timeout | 7.045 |
| `SimpleFiveInARow.jar` | `exception` | 0 | pass; runtime timeout after 8s (UI remains alive) | created | 124 | timeout | 6.686 |
| `SimpleFiveInARow.jar` | `native-vm` | 1 | aken-vbc4-format-blocked: AKEN VBC4 block planner expected VBC4 magic | not-created | — | — | 7.668 |
| `SimpleFiveInARow.jar` | `native-string` | 0 | pass; runtime ExceptionInInitializerError | created | 1 | nonzero | 104.057 |
| `SimpleFiveInARow.jar` | `random` | 0 | pass; runtime timeout after 8s (UI remains alive) | created | 124 | timeout | 8.631 |
| `TEST.jar` | `default-invalid-empty-config` | 1 | config-validation-blocked: passes must be an array, path=C:\\WINDOWS\\TEMP\\javashroud-real-artifact-acceptance-20260819\\TEST\\default\\config.toml | not-created | — | — | 3.58 |
| `TEST.jar` | `native` | 1 | config-validation-blocked: missing companion passes: jni-microkernel-loader requires any of [anti-dump-protection, anti-instrumentation, anti-symbolic-execution, callsite-rotation-protection, class-encryption-loader, environment-bound-keys, exception-semantic-virtualization, method-body-delayed-decryption, method-virtualization, string-encryption], path=C:\\WINDOWS\\TEMP\\javashroud-real-artifact-acceptance-20260819\\TEST\\native\\config.toml | not-created | — | — | 0.946 |
| `TEST.jar` | `vm` | 124 | timeout: >180s engine timeout | not-created | — | — | 180.067 |
| `TEST.jar` | `string` | 0 | pass | created | 0 | pass | 17.917 |
| `TEST.jar` | `loader` | 1 | config-validation-blocked: missing companion passes: jni-microkernel-loader requires any of [anti-dump-protection, anti-instrumentation, anti-symbolic-execution, callsite-rotation-protection, class-encryption-loader, environment-bound-keys, exception-semantic-virtualization, method-body-delayed-decryption, method-virtualization, string-encryption], path=C:\\WINDOWS\\TEMP\\javashroud-real-artifact-acceptance-20260819\\TEST\\loader\\config.toml | not-created | — | — | 1.491 |
| `TEST.jar` | `resource` | 124 | timeout: >180s engine timeout | not-created | — | — | 180.038 |
| `TEST.jar` | `reflection` | 0 | pass | created | 0 | pass | 12.047 |
| `TEST.jar` | `exception` | 0 | pass | created | 0 | pass | 4.4 |
| `TEST.jar` | `native-vm` | 124 | timeout: >180s engine timeout | not-created | — | — | 180.117 |
| `TEST.jar` | `native-string` | 124 | timeout: >180s engine timeout | not-created | — | — | 180.102 |
| `TEST.jar` | `random` | 0 | pass | created | 0 | pass | 13.706 |

### Corrected default-pipeline and prebuilt lanes

The first ad-hoc `default` rows above intentionally retain the harness mistake (`passes` omitted/empty) and are not runtime evidence. A valid default-pipeline lane was then run with the schema's declared `strip-compile-debug-info` pass:

| Fixture / engine | Obfuscation | Artifact | Runtime | Markers / result | Digest prefix |
| --- | --- | --- | --- | --- | --- |
| `SimpleFiveInARow.jar` / source-rebuilt engine | exit `0`, `10.639s` | created, `82,869` bytes | bounded exit `124` at 12s; `SecurityManager`/14-of-14, `setVisible(true)`, and render markers observed | UI remained alive; no failure marker observed in bounded window | `4b1747403aa2ffab` |
| `SimpleFiveInARow.jar` / prebuilt engine copy | exit `0`, `15.353s` | created, `82,869` bytes | bounded exit `124` at 12s; `SecurityManager`/14-of-14, `setVisible(true)`, and render markers observed | UI remained alive; no failure marker observed in bounded window | `404062f2256b8084` |
| `TEST.jar` / source-rebuilt engine | exit `0`, `5.190s` | created, `21,926` bytes | three bounded runs exited `0` (`2.603s`, `2.576s`, `2.582s`) | `Sec ERROR`, `Calc`; **`Pool PASS` once and `Pool FAIL` twice**; nondeterministic generated-lane difference from direct baseline | `820d0322c1bad6f1` |
| `TEST.jar` / prebuilt engine copy | exit `0`, `6.493s` | created, `21,926` bytes | two runs exit `0` (`2.562s`, `2.572s`) | `Sec ERROR`, `Calc`, `Pool PASS` on both runs | `393edd82770d5888` |

Commands used for the corrected lanes:

```powershell
java -jar build/core-engine/libs/obfuscator-engine-0.12.jar -config <strip-compile-debug-info-config.toml>
java -jar C:\Windows\Temp\javashroud-real-artifact-acceptance-20260819\prebuilt-obfuscator-engine-0.12.jar -config <strip-compile-debug-info-config.toml>
java -jar <generated-output.jar>
```

The source-rebuilt `TEST.jar` default-pipeline output's `Pool PASS`/`Pool FAIL` variation is retained as a real semantic-regression/flakiness signal; it is not normalized away or counted as acceptance. The prebuilt-engine lane is separately recorded and does not imply native fallback or protocol compatibility.

### Current-engine real-JAR follow-up lanes

After rebuilding `build/core-engine/libs/obfuscator-engine.jar`, the same
schema-driven harness was rerun against both plan-specified inputs with one
runtime attempt per generated artifact. These runs use the current
`strip-compile-debug-info` default pipeline, the current invoke-dynamic
profiles, and a valid native/string pair (`jni-microkernel-loader` plus
`string-encryption`); they do not use a prebuilt native artifact or a legacy
protocol path.

| Fixtures | Lane | Cases | Result | Evidence directory |
| --- | --- | ---: | --- | --- |
| `SimpleFiveInARow.jar`, `TEST.jar` | `default-pipeline` | 2 | `PASS` / runtime exit `0` | `build/real-jar-matrix-20260819-default` |
| `SimpleFiveInARow.jar`, `TEST.jar` | `single-invoke-dynamic-indirection` (`default`, `min`, `max`) | 6 | all `PASS` / runtime exit `0` | `build/real-jar-matrix-20260819-indy` |
| `SimpleFiveInARow.jar`, `TEST.jar` | `pair-jni-microkernel-loader__string-encryption` | 2 | all `PASS` / runtime exit `0` | `build/real-jar-matrix-20260819-native-string` |

The exact harness summaries were:

```text
default-pipeline: cases=1 failures=0 xfail_validation=0
SimpleFiveInARow.jar: obfuscation 3.7s, output 82869 bytes, sha256-prefix=54a7971d3100b4a7
TEST.jar: obfuscation 3.6s, output 21926 bytes, sha256-prefix=63c3ea507ffcd048

single-invoke-dynamic-indirection: cases=3 failures=0 xfail_validation=0
SimpleFiveInARow.jar: default/min/max all PASS; output sha256-prefixes=043709a988a74aa3,846caf437215f4a8,fba4ca4efb17fd87
TEST.jar: default/min/max all PASS; output sha256-prefixes=b475c50bfcb32d7d,9feac3efd62b9a97,8c56f4faa9b706fb

pair-jni-microkernel-loader__string-encryption: cases=1 failures=0 xfail_validation=0
SimpleFiveInARow.jar: obfuscation 127.1s, runtime exit 0, output 3674887 bytes, sha256-prefix=5f7068e41fd48ace
TEST.jar: obfuscation 122.4s, runtime exit 0, output 1778459 bytes, sha256-prefix=66373551bfa87ca8
```

The `TEST.jar` observations were run with the harness's explicit
`--ignore-testjar-pool-flake` option. This only suppresses the known
nondeterministic Pool line; all other normalized output, exit-code and
artifact checks remain active. The native/string pair is a real current
native recompilation lane and is evidence for that pair only; it does not
close the full native, VM, loader, resource, shell, or readiness matrix.

### Lane interpretation and exact blockers

- The initial `default-invalid-empty-config` rows are harness probes: the ad-hoc config omitted/left `passes` empty and the engine rejected it. The valid default-pipeline result is recorded separately below using `strip-compile-debug-info`; the probe rows are not runtime pass/fail claims.
- `native` and `loader` are blocked by current config validation: `jni-microkernel-loader requires any of [...]` companion passes. No legacy fallback or prebuilt native fallback was attempted.
- `vm` and `native-vm` for `SimpleFiveInARow.jar` reached the current AKEN planner and failed closed with `AKEN VBC4 block planner expected VBC4 magic`; no output artifact was created.
- `TEST.jar` `vm`, `resource`, `native-vm`, and `native-string` exceeded the 180-second obfuscation timeout. They are not accepted; no output artifact was used for those timeout lanes.
- `SimpleFiveInARow.jar` `resource` and `native-string` produced output JARs but failed closed at runtime with `ExceptionInInitializerError` caused by `SecurityException: AKEN native chunk route is unavailable`; these are nonzero runtime results, not passes.
- `SimpleFiveInARow.jar` string/reflection/exception/random outputs reached the UI diagnostic marker but did not exit within the 8-second process window because the GUI stays alive; they remain `runtime timeout`, not readiness acceptance.
- `TEST.jar` string/reflection/exception/random runtime lanes exited `0` and retained baseline markers (`Sec ERROR`, `Pool PASS`, `Calc`). These are the only complete runtime pass rows in this matrix.
- Generated output digest prefixes (for reproducibility only): `SimpleFiveInARow.jar`: string `e614c05a732689b2`, resource `3d049c96560d803c`, reflection `e3ff88196e9e9ad0`, exception `d52bd8179a0a8e60`, native-string `60dd45362988b12e`, random `3601093ad8daefc9`; `TEST.jar`: string `3c2c8948ae6bbc55`, reflection `a973f531f36f2fed`, exception `d7a9bd271373d44d`, random `0efb2f9888d4f6de`. These digests identify generated bytes only and do not imply runtime acceptance.
- `Pool deterministic lane`: direct TEST baseline had `Pool PASS` in both captured attempts. No separate generated lane was labeled deterministic because the current lane helper does not expose a deterministic pool switch; this is recorded as coverage gap rather than inferred pass.
- `SecurityManager compatibility`: SimpleFiveInARow direct baseline reached `SecurityManager ... SKIPPED`; no separate transformed acceptance pass was claimed.
- `native single`, `VM single`, `native + VM`, `native + string`, `loader`, `resource`, and AKEN page-open claims remain security-blocked or integration-blocked where the current planner/route state prevents a valid artifact.

### Raw matrix evidence

- Structured result file: `C:\Windows\Temp\javashroud-real-artifact-acceptance-20260819\results.json` (26 records: 4 direct baseline observations and 22 transformation/runtime lane records).
- Corrected default-pipeline and prebuilt-engine evidence: `C:\Windows\Temp\javashroud-real-artifact-acceptance-20260819\corrected-default-prebuilt-results.json` (4 records; SHA-256 prefix `3cfd4f8959a22734`).
- Per-lane configs and generated outputs: `C:\Windows\Temp\javashroud-real-artifact-acceptance-20260819\<fixture>\<lane>\`.
- Raw logs are retained outside the repository; this report stores only exit codes, timing, markers, classification, and short output digests.

### Commands

```powershell
java -jar build/core-engine/libs/obfuscator-engine-0.12.jar -config <lane-config.toml>
java -jar <generated-lane-output.jar>
.\gradlew.bat :core-engine:jar --no-daemon --rerun-tasks
```

### Acceptance conclusion

`coverage_status=incomplete`. The matrix is useful evidence of current artifact behavior and exact blockers, but it does not satisfy the full plan acceptance gate. No legacy protocol, ABI fallback, prebuilt native fallback, or authentication bypass was used.

### Production malformed-frame partial-output wipe evidence

The production Zstd context fixture now covers a malformed current-format frame
whose first RLE block writes output before the truncated second block is
rejected.  The isolated Gradle lane completed with the following JUnit XML
evidence:

```text
TEST-io.github.hht0rro.javashroud.NativeRuntimeZstdContextTest.xml
tests=1 skipped=0 failures=0 errors=0
timestamp=2026-08-19T18:27:53
time=631.503s
```

The test asserts both compile and run exit `0`, requires the production probe
banner `Zstd production context probe: PASS`, and requires
`execution.output.contains("partial_output_wipe=1")`.  The Kotlin harness
captures the probe stream, so the JUnit XML `system-out` is empty; the
`partial_output_wipe=1` assertion is the authoritative marker-presence
evidence rather than a copied raw stdout line.  The same probe also verifies
same-generation Zstd context reuse, generation invalidation on session reset,
bounded workspace reuse, and failure cleanup counters.  No key, nonce, DEK,
page plaintext, decoder state, or sensitive path is recorded.

```text
compile_exit=0
run_exit=0
partial_output_wipe=1
fallback_count=0
legacy_path_hits=0
wipe_failure_count=0
plaintext_persistence_bytes=0
security_checks_skipped=0
coverage_status=incomplete
```

This evidence closes the production malformed-frame partial-output wipe case
for the Zstd context lane only; the complete runtime/security/performance plan
remains incomplete and the goal stays active.

### Production resource-index profile matrix

The production resource benchmark was extended to run all required sample
profiles in one compile-once fixture: `100`, `1,000`, `10,000`, and `100,000`
measured samples, each with `16` excluded warmup iterations.  The focused
Gradle lane completed with `tests=1`, `skipped=0`, `failures=0`, `errors=0`,
JUnit timestamp `2026-08-19T19:17:35`, and testcase time `204.47s`.
The test assertions also require `compile_exit=0` for the isolated full-native
fixture and `run_exit=0` for each of the four profile executions.

The profile output is production-bound (`phase_mode=production`,
`phase_status=pass`) for alias lookup, commitment lookup, and Zstd context
reuse.  Latency values are nanoseconds and are reported as p50/p95/p99/max:

```text
samples=100
  alias        p50=300  p95=400   p99=500   max=600
  commitment   p50=6500 p95=6600  p99=6600  max=6800
  zstd         p50=2300 p95=2300  p99=2400  max=2400
  index_hits(alias/commitment)=100/100 zstd_reuse=100

samples=1000
  alias        p50=400  p95=400   p99=400   max=600
  commitment   p50=7400 p95=10100 p99=12300 max=21900
  zstd         p50=2500 p95=2600  p99=3800  max=15300
  index_hits(alias/commitment)=1000/1000 zstd_reuse=1000

samples=10000
  alias        p50=400  p95=400   p99=500   max=6000
  commitment   p50=7000 p95=7400  p99=10800 max=34300
  zstd         p50=2900 p95=5000  p99=5800  max=60500
  index_hits(alias/commitment)=10000/10000 zstd_reuse=10000

samples=100000
  alias        p50=400  p95=500   p99=600   max=10800
  commitment   p50=7400 p95=11100 p99=12800 max=71100
  zstd         p50=2600 p95=4500  p99=5100  max=258800
  index_hits(alias/commitment)=100000/100000 zstd_reuse=100000
```

Across all four profiles, the commitment phase retained exactly one structure,
length, and digest check per sample and two wipes per sample; the Zstd phase
retained one structure, length, and wipe per sample.  Every profile reported
`allocation_count=0`, `exception_count=0`, `native_exception_count=0`,
`auth_failure_count=0`, `wipe_failure_count=0`, `fallback_count=0`,
`legacy_path_hits=0`, `plaintext_persistence_bytes=0`, and
`security_checks_skipped=0`.  Each profile also repeated the generation replay
lifecycle: stale alias/commitment/index reuse stayed zero, replacement index
hits stayed at least two, and replacement structure/length/digest checks all
remained present.

This closes the required production resource alias/commitment/Zstd sample-count
profiles.  It does not close the full accepted-artifact, VM, shell, loader,
hardware differential, or readiness matrix; `coverage_status=incomplete` and
the active goal remain unchanged.

### Production AKEN authenticated page-open profile matrix

The retained AKEN page-open production fixture completed the same required
`100`, `1,000`, `10,000`, and `100,000` measured-sample profiles with `16`
warmup iterations.  The JUnit fixture reported one test with zero skipped,
failure, or error cases.  These profiles exercise authenticated current-format
page opening through the native page locator and preserve the production
binding, digest, tag, length, structure, and JNI-ABI checks.

```text
samples=100
  p50=592000   p95=706200  p99=810200  max=862200
  hardware_crypto_path=100 auth_check_count=2600 digest_check_count=1700
  tag_check_count=100 length_check_count=2000 structure_check_count=1900
  jni_abi_check_count=600 wipe_count=156300

samples=1000
  p50=443700   p95=567000  p99=668900  max=3006800
  hardware_crypto_path=1000 auth_check_count=26000 digest_check_count=17000
  tag_check_count=1000 length_check_count=20000 structure_check_count=19000
  jni_abi_check_count=6000 wipe_count=1563000

samples=10000
  p50=448500   p95=597900  p99=739400  max=3845000
  hardware_crypto_path=10000 auth_check_count=260000 digest_check_count=170000
  tag_check_count=10000 length_check_count=200000 structure_check_count=190000
  jni_abi_check_count=60000 wipe_count=15630000

samples=100000
  p50=443300   p95=554600  p99=737300  max=3188900
  hardware_crypto_path=100000 auth_check_count=2600000 digest_check_count=1700000
  tag_check_count=100000 length_check_count=2000000 structure_check_count=1900000
  jni_abi_check_count=600000 wipe_count=156300000
```

All four profiles reported `phase_status=pass`, `software_crypto_path=0`,
`auth_failure_count=0`, `vm_heap_fallback_count=0`, `wipe_failure_count=0`,
`fallback_count=0`, `legacy_path_hits=0`, `plaintext_persistence_bytes=0`,
`exception_count=0`, and `security_checks_skipped=0`.  The output digests were
`8a9e39e4def404ed`, `36c4b862c73a760b`, `d3e2c7a8c4b6c7d6`, and
`84a5cc34c5893937` respectively.  The retained raw profile log is
`build/core-engine/test-results/test/aken-page-open-matrix-2026-08-20.log`.

This closes the required production AKEN page-open sample-count subset.  It
does not establish the Windows hardware-vs-software AKEN differential, the
2x-before/after page-open gate, cross-artifact page swap/replay coverage, or
the two accepted-artifact readiness lanes; therefore
`coverage_status=incomplete` remains mandatory.

### Latest formal AKEN/JNI matrix result and timeout boundary

The serialized formal Gradle lane
`AkenNativePageLocatorResolverNativeTest` completed its current production
matrix with `tests=8`, `skipped=0`, `errors=0`, and `failures=1`.  The failing
case was the multi-page attached-JVM benchmark at `bench:10000:16`, which
reached the explicit 120-second child-process timeout and failed closed.  No
successful output from that timed-out child was accepted as a runnable result.

The same JUnit `system-out` retained passing **single-page** current-format
AKEN page-open profiles for `100`, `1,000`, `10,000`, and `100,000` samples.
The multi-page profile passed only `100` and `1,000` before its `10,000`
sample child timed out; the latest single-page production profile values were:

```text
samples=100
  p50=753300   p95=1159300  p99=1734300  max=1918700
samples=1000
  p50=592200   p95=825800   p99=1031200  max=3915300
samples=10000
  p50=461300   p95=647800   p99=853300   max=3116100
samples=100000
  p50=494700   p95=709700   p99=928100   max=4547100
```

Each retained profile reported `phase_status=pass`, hardware crypto path,
zero authentication failures, zero heap fallback, zero fallback/legacy hits,
zero wipe failures, zero plaintext persistence, zero exceptions, and zero
security skips.  The formal XML is retained at
`build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml`,
and the corresponding profile log is
`build/core-engine/test-results/test/aken-page-open-matrix-2026-08-19-multi-page-attempt.log`.

Because the same formal lane contains one timeout failure, this evidence is a
partial production/security result rather than a green AKEN acceptance lane.
The multi-page 10,000-sample timeout, complete hardware/software differential,
2x before/after performance gate, cross-artifact replay/swap cases, and full
accepted-artifact readiness matrix remain open; `coverage_status=incomplete`
and the active goal remain unchanged.


### AKEN multi-page production matrix attempt (2026-08-19)

A serial Gradle lane was run with the required page-open matrix environment:

```powershell
$env:JS_AKEN_PAGE_OPEN_BENCH_MATRIX='1'
$env:JS_AKEN_PAGE_OPEN_BENCH_WARMUP='16'
.\gradlew.bat :core-engine:test `
  --tests io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest `
  --no-daemon --no-configuration-cache --max-workers=1 --console=plain
```

JUnit evidence: `build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml`.
The lane completed after `3198.664s` (`timestamp=2026-08-19T19:31:32`) with
`tests=8`, `skipped=0`, `failures=1`, and `errors=0`.  The failure is a
bounded fixture-process timeout in the multi-page profile at `samples=10,000`:
`process timed out after 120s`; the `100,000` multi-page profile was therefore
not reached.  This is recorded as a blocker, not as a pass.

The two completed **multi-page** production-bound profiles emitted the following
sanitized phase data (latency unit: ns):

```text
samples=100  phase_status=pass
  p50=22048200 p95=25362900 p99=27834100 max=29418100
  hardware_crypto_path=800 software_crypto_path=0
  auth_check_count=20800 digest_check_count=13600 tag_check_count=800
  length_check_count=13100 structure_check_count=12300 jni_abi_check_count=3400
  wipe_count=9495800 auth_failure_count=0 wipe_failure_count=0
  plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0
  exception_count=0 security_checks_skipped=0
  output_digest=8a9e39e4def404ed

samples=1000 phase_status=pass
  p50=22669100 p95=27996900 p99=32303700 max=44906700
  hardware_crypto_path=8000 software_crypto_path=0
  auth_check_count=208000 digest_check_count=136000 tag_check_count=8000
  length_check_count=131000 structure_check_count=123000 jni_abi_check_count=34000
  wipe_count=94958000 auth_failure_count=0 wipe_failure_count=0
  plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0
  exception_count=0 security_checks_skipped=0
  output_digest=36c4b862c73a760b

samples=10000 phase_status=blocked
  reason=fixture_process_timeout_after_120s
  multi_page_profile=not_completed

samples=100000 phase_status=not_reached
```

For completeness, the same JUnit XML also contains the companion **single-page**
production-bound profiles, all with `phase_status=pass`:

```text
samples=100   p50=753300  p95=1159300 p99=1734300 max=1918700
samples=1000  p50=592200  p95=825800  p99=1031200 max=3915300
samples=10000 p50=461300  p95=647800  p99=853300  max=3116100
samples=100000 p50=494700 p95=709700  p99=928100  max=4547100
```

The phase counters for every completed profile retained non-zero auth, digest,
tag, length, structure, JNI-ABI, and wipe checks, while
`auth_failure_count=0`, `wipe_failure_count=0`, `plaintext_persistence_bytes=0`,
`fallback_count=0`, `legacy_path_hits=0`, `exception_count=0`, and
`security_checks_skipped=0`.  A later targeted 10,000-sample invocation was
attempted but Gradle failed before test execution because the shared
`output.bin` remained locked; it produced no additional accepted result and no
shared output was removed.  The extracted phase-only log is retained at
`build/core-engine/test-results/test/aken-page-open-matrix-2026-08-19-multi-page-attempt.log`.

Because the multi-page `10,000` profile timed out and the `100,000` profile was
not reached, this evidence does not close the complete AKEN matrix or the full
accepted-artifact/security/performance matrix.  Keep `coverage_status=incomplete`
and the active goal unchanged.

## Native shell chunk reorder/duplication fail-closed evidence

The focused `NativeKernelShellPackerTest` lane now includes
`aken_v4_chunk_reorder_and_duplication_fail_closed_before_inner_decode`. The
test constructs a current-format multi-chunk native payload, reverses chunk order,
and duplicates bytes across a chunk boundary. Both mutations return no decoded
inner payload because the authenticated payload commitment fails before inner-image
decode. The test also wipes the synthetic buffers after each assertion.

JUnit evidence:

```text
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.NativeKernelShellPackerTest.xml
tests=15 skipped=0 failures=0 errors=0
case=aken_v4_chunk_reorder_and_duplication_fail_closed_before_inner_decode
```

This closes the shell chunk reorder/duplication subset only. Payload-commitment
tamper coverage beyond this fixture, authenticated inner-image loader/mapping,
and the accepted-artifact shell attack matrix remain open; `coverage_status`
therefore remains `incomplete`.

### Native C shell attack-matrix fixture (2026-08-19)

An independent fixture-local C harness was compiled against the current
`js_crypto.c` and `js_shell_crypto.c` sources with Zig 0.16.0 on Windows x64.
The fixture builds a three-chunk current-format stream through the shared shell
KDF/HMAC/AES-CTR helpers, then exercises the native decoder directly. The
harness verifies a valid decode plus wrong-final-tag, chunk reorder, chunk
duplication, cross-artifact binding replay, cross-session nonce replay, and
extra-tag length/structure rejection. Every rejected path checks that the
caller buffer is zeroed and that no security counter is skipped.

Sanitized output:

```text
valid status=pass digest=242218f6959774b6 auth=3 wipe=173
attack_matrix status=pass chunk_count=3 digest=242218f6959774b6 auth_failures=1 wipe_failures=0 plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0 security_checks_skipped=0
```

The fixture source, executable, and compile/run log are retained at:

```text
build/shell-crypto-attack-matrix-20260819/shell_crypto_attack_matrix.c
build/shell-crypto-attack-matrix-20260819/shell_crypto_attack_matrix.exe
build/shell-crypto-attack-matrix-20260819/compile-and-run.log
```

This closes an additional native shell decoder attack subset and validates the
new framing/length rejection wipe. It does not close authenticated inner-image
loader/mapping, accepted-artifact shell coverage, or the complete crypto
unsupported-CPU and large-page matrix; `coverage_status=incomplete` remains
mandatory.

### Current isolated Resource/Zstd/JNI refresh (2026-08-19)

To avoid treating the shared Gradle `test-results/test/binary/output.bin` lock as
a runtime failure, the production probes were also run with isolated Gradle
test-result directories.  The Resource matrix completed on the current worktree
with `tests=1`, `skipped=0`, `failures=0`, `errors=0`, timestamp
`2026-08-19T21:28:37`, and the Zstd context regression completed in the isolated
directory with `tests=1`, `skipped=0`, `failures=0`, `errors=0`, timestamp
`2026-08-19T21:41:50`.  The attached-JVM JNI cache four-profile lane was then
rerun with the same isolation approach and completed with:

```text
tests=1 skipped=0 failures=0 errors=0
timestamp=2026-08-19T22:03:53
time=99.854s
phase_mode=production
phase_status=pass
```

Authoritative isolated JNI XML:

```text
build/core-engine/test-results-jni-isolated/xml/TEST-io.github.hht0rro.javashroud.NativeRuntimeJniCacheProductionBenchmarkTest.xml
```

The isolated runs only changed Gradle result destinations; they did not change
the runtime protocol, native ABI, authentication, generation, loader, or wipe
logic.  The accepted-artifact JNI/resource/reflection matrix and full readiness
matrix remain open, so `coverage_status=incomplete` remains mandatory.

### Attached-JVM JNI cache serialized profile matrix (2026-08-19)

The isolated JNI cache lane was rerun after the resource/catalog serialization
and completed all required sample profiles against a real disposable JDK 21
VM.  The probe retained loader identity, artifact/session generation, class
binding, ABI, and session checks on every cache hit; no secret or plaintext
material was emitted.

```text
NativeRuntimeJniCacheProductionBenchmarkTest
tests=1 skipped=0 failures=0 errors=0
timestamp=2026-08-19T21:48:15 time=390.912s
samples=100/1000/10000/100000 warmup=16
phase_status=pass for all profiles
jni_cache_hit_count=100/1000/10000/100000
jni_abi_check_count=100/1000/10000/100000
allocation_count=0 exception_count=0 native_exception_count=0
fallback_count=0 legacy_path_hits=0 wipe_failure_count=0
plaintext_persistence_bytes=0 security_checks_skipped=0
```

Evidence:

```text
build/core-engine/test-results-isolated/xml/TEST-io.github.hht0rro.javashroud.NativeRuntimeJniCacheProductionBenchmarkTest.xml
```

The matrix strengthens the attached-JVM JNI cache generation/loader-binding
subset.  It does not close full accepted-artifact reflection/JNI coverage,
concurrent resource opening, cross-artifact cache replay, or the remaining
native loader and security attack cases; `coverage_status=incomplete` remains
mandatory.

### Focused native shell decoder regression after multi-chunk fixture correction (2026-08-19)

The focused JUnit lane
`JsShellCryptoGcmTest.native_chunk_decoder_authenticates_and_wipes_rejected_payload`
initially rejected its own vector because the selected production chunk profile
could be `3072` bytes while the `4097`-byte fixture contained only one complete
pair of chunks.  The fixture now uses `8193` pseudo-random bytes, which guarantees
two complete chunks for every current profile (`1024`/`1536`/`2048`/`3072`) without
changing the current shell format or decoder.

The rerun completed successfully:

```text
command=.\gradlew.bat :core-engine:test --no-daemon --no-configuration-cache --max-workers=1 --console=plain --tests io.github.hht0rro.javashroud.JsShellCryptoGcmTest.native_chunk_decoder_authenticates_and_wipes_rejected_payload
tests=1 skipped=0 failures=0 errors=0
timestamp=2026-08-19T21:15:54 time=6.663s
```

The native harness assertions cover valid decode, wrong final tag, chunk
reordering, duplicated chunk bytes/tags, cross-artifact binding replay,
cross-session nonce replay, and extra-tag structure/length rejection. Each
rejected path requires a wiped caller buffer and zero skipped-security,
fallback, legacy, wipe-failure, exception, and plaintext-persistence counters.
This closes the focused shell decoder regression subset only; authenticated
inner-image loader/mapping and the accepted-artifact shell attack matrix remain
open, so `coverage_status=incomplete` remains mandatory.

### Serialized VM/Zstd rerun after resource-format writer settled (2026-08-19)

The VM and Zstd validation lanes were rerun serially after the concurrent
resource-format writer/build activity had stopped.  The earlier transient
`invalid partition 8448` observation did not reproduce in the serialized lane;
the current-format resource/catalog path completed and the nested VM artifact
assertion passed.

```text
NestedVmExecutionTest.high_value_nested_vm_method_preserves_runtime_result_in_transformed_jar
tests=1 skipped=0 failures=0 errors=0
timestamp=2026-08-19T21:44:32 time=164.741s
engine_passes=2 transformedClasses=2 transformedMembers=2
native_vm_dispatcher_assertion=pass
transformed_runtime_result=42
```

Evidence:

```text
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.NestedVmExecutionTest.xml
```

The isolated production Zstd context lane also completed without failures:

```text
NativeRuntimeZstdContextTest.production_zstd_context_reuses_only_current_session_and_wipes_failed_output()
tests=1 skipped=0 failures=0 errors=0
timestamp=2026-08-19T21:41:50 time=329.340s
```

Evidence:

```text
build/core-engine/test-results-isolated/xml/TEST-io.github.hht0rro.javashroud.NativeRuntimeZstdContextTest.xml
```

These serialized reruns strengthen the nested VM and current-session Zstd
subsets, but they do not close the complete lambda/invoke-dynamic runtime
matrix, accepted-artifact VM/resource lanes, native loader lifecycle, or the
remaining security attack matrix.  `coverage_status=incomplete` remains
mandatory.

### Canonical JSRP resource/catalog lane (2026-08-19)

The resource-format audit found a transient mixed-header observation while a
concurrent writer was changing the local resource codec.  The authoritative
current protected-artifact format remains the existing partitioned JSRP v7
envelope required by the native and Java verifiers; no JSRP redesign or legacy
fallback was introduced.  The serialized focused lane was then rerun against
that canonical format.

```text
RuntimeResourceCodecTest      tests=9 skipped=0 failures=0 errors=0
RuntimeResourcePartitionTest  tests=5 skipped=0 failures=0 errors=0
RuntimeVmCatalogTest           tests=5 skipped=0 failures=0 errors=0
timestamp=2026-08-19T22:03:43
```

Evidence:

```text
build/resource-catalog-focused-20260819.log
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.RuntimeResourceCodecTest.xml
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.RuntimeResourcePartitionTest.xml
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.RuntimeVmCatalogTest.xml
```

The lane covers authenticated JSRP v7 round-trip, header/body/tag tamper
rejection, build-local resource-key binding, partition spread and foreign
partition rejection, duplicate resource path rejection, catalog directory
coverage, Merkle-root checks, root HMAC authentication, and catalog method
identity tamper rejection.  This strengthens the resource/catalog subset but
does not close concurrent resource opening, accepted-artifact resource lanes,
stale JNI/resource cache attacks, or the full security/performance matrix;
`coverage_status=incomplete` remains mandatory.

### Current-format resource writer synchronization and VM fixture refresh (2026-08-19)

The first serialized Nested VM attempt observed `invalid partition 8448` while
another writer was changing a temporary resource-header layout.  That value is
the expected signature of mixing a 27-byte JSRP v7 writer with a 26-byte reader;
it was not accepted as a protocol change.  The authoritative current format
remains the existing JSRP v7 envelope, with the partition field at bytes
`25..26`, and the focused resource/catalog lane passed after the writer/build
state settled.  No compatibility branch, legacy fallback, or JSRP redesign was
introduced.

The nested-VM fixture now also supplies an explicit current rule for
`e2e/NestedVmRoot#verifyLicense:()I` instead of relying on an empty rule set,
and its dispatcher assertion recognizes the current AKEN page dispatcher
descriptor rather than depending on a randomized dead-code shadow call.

Focused verification:

```text
RuntimeResourceCodecTest.runtime_resource_codec_roundtrips_and_rejects_tampering
BUILD SUCCESSFUL

NestedVmExecutionTest.high_value_nested_vm_method_preserves_runtime_result_in_transformed_jar
tests=1 skipped=0 failures=0 errors=0
timestamp=2026-08-19T21:56:35
engine_passes=2 transformedClasses=2 transformedMembers=2
matchedRules=1 matchedClasses=1 matchedMembers=1
native_vm_dispatcher_assertion=pass
transformed_runtime_result=42
```

The serialized fixture refresh preserves current JSRP/AKEN authentication,
length, structure, digest, binding, generation and wipe checks.  It does not close accepted
artifact readiness, native loader mapping/lifecycle, hardware/software
differential, or the complete attack matrix; `coverage_status=incomplete`
remains mandatory.

### Focused lambda/invoke-dynamic transformation evidence (2026-08-19)

The focused transformation/remap lane passed all nine tests:

```text
LambdaRecipeFidelityTest=5/5
InvokeDynamicBootstrapRemapTest=4/4
failures=0 errors=0 skipped=0
```

This validates current lambda recipe shapes, method-handle/bootstrap remapping,
serializable `altMetafactory` markers, mutable-callsite remapping and the
class-loader boundary skip.  It is focused transformation evidence only, not
complete accepted-artifact VM runtime acceptance.

### Resource index and Zstd context serialized production matrix (2026-08-19)

The production resource benchmark was rerun against the canonical current JSRP
verifier with one serialized compile-once lane.  All required sample profiles
completed for alias lookup, commitment lookup, Zstd context reuse, and
generation-bound cache replacement.

```text
NativeRuntimeResourceProductionBenchmarkTest
tests=1 skipped=0 failures=0 errors=0
timestamp=2026-08-19T22:09:40 time=150.952s
profiles=100/1000/10000/100000 warmup=16
phase_status=pass for all profiles
resource_index_hit_count=100/1000/10000/100000
decompress_context_reuse_count=100/1000/10000/100000
stale_resource_index_hit_count=0
replacement_resource_index_hit_count=2 per profile
post_reset_reuse_count=0
failure_reuse_count=1
failure_wipe_delta=1
allocation_count=0 exception_count=0 native_exception_count=0
fallback_count=0 legacy_path_hits=0 wipe_failure_count=0
plaintext_persistence_bytes=0 security_checks_skipped=0
```

The commitment phase retained one digest, length, and structure check per
sample, and two wipes per sample; the Zstd phase retained one length and
structure check and one wipe per sample.  Generation reset retired stale alias
and commitment indexes before replacement reinstallation.

Evidence:

```text
build/resource-production-serialized-20260819.log
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.NativeRuntimeResourceProductionBenchmarkTest.xml
```

This closes the serialized resource-index/Zstd/context-generation subset only;
concurrent resource opening, accepted-artifact resource opening, complete
cross-artifact replay and the remaining native loader/security/performance
gates stay open, so `coverage_status=incomplete` remains mandatory.

### AKEN page-open hardware/software differential (2026-08-19)

The real-JNI multi-page AKEN fixture now builds two copies of the same
current-format artifact and locator include: the default runtime dispatch and
an isolated build with `JS_CRYPTO_FORCE_SOFTWARE=1`.  Both copies execute the
same authenticated page-open benchmark (`samples=100`, `warmup=16`).

```text
phase=aken-page-open-differential phase_mode=production phase_status=pass
samples=100 hardware_crypto_path=600 software_crypto_path=600
output_digest=8a9e39e4def404ed

default/hardware path:
hardware_crypto_path=600 software_crypto_path=0
aes_block_count=277800 ghash_block_count=294800
auth_check_count=15600 digest_check_count=10200 tag_check_count=600
length_check_count=9900 structure_check_count=9300 jni_abi_check_count=2600
wipe_count=9428800 wipe_failure_count=0
plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0
security_checks_skipped=0 output_digest=8a9e39e4def404ed

forced/software path:
hardware_crypto_path=0 software_crypto_path=600
aes_block_count=277800 ghash_block_count=294800
auth_check_count=15600 digest_check_count=10200 tag_check_count=600
length_check_count=9900 structure_check_count=9300 jni_abi_check_count=2600
wipe_count=9411800 wipe_failure_count=0
plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0
security_checks_skipped=0 output_digest=8a9e39e4def404ed
```

The differential asserts identical authenticated output and exact AES/GHASH,
authentication, digest, tag, length, structure and JNI ABI counters.  Wipe
counts are required to be positive for both implementations rather than
being required to match exactly, because the intrinsic and software scratch
implementations legitimately clear different fixed-size temporary regions;
both report zero wipe failures and zero plaintext persistence.

Evidence:

```text
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml
```

The focused production multi-page test passed with `tests=1`,
`failures=0`, `errors=0`, and the forced-software library also completed the
authenticated result path.  This closes the AKEN page-open differential
subset only; the complete 10,000/100,000 multi-page matrix, accepted-artifact
loader/resource lanes, and remaining security attack matrix remain open, so
`coverage_status=incomplete` remains mandatory.

### Cross-language JSRP v7 parser parity (2026-08-19)

The Java helper parser was audited against the canonical Kotlin writer and
native C decoder.  The narrow patch removes the remaining Java-side JSRR/26-byte
interpretation without adding a compatibility branch: all three paths now
recognize only JSRP version 7, use a 27-byte header, read the nonce at bytes
`5..20`, read metadata/MAC/partition fields at offsets `21/23/25`, and use
`jsrp-auth-v3`.

Static cross-language contract lane:

```text
lane=resource-cross-language-jsrp-v7-parity
checks=12 pass
failure_count=0
java_no_jsrr=pass
coverage=parser/static-cross-language-focused
```

Evidence:

```text
build/resource-cross-language-parity-20260819.log
```

An independent Java 8-source-compatible harness compiled the current
`JniMicrokernelHelper.java` with `javac` and exercised the actual public
`decodeRuntimeResourceEnvelope` path using a deterministic AES-CTR/HMAC JSRP v7
envelope.  The valid envelope decoded to the original plaintext; wrong version,
JSRR magic, tag tamper, and partition tamper all failed closed.

```text
lane=java-helper-jsrp-v7-runtime-parity
javac_exit=0
java_exit=0
valid_decode=pass
wrong_version=fail_closed
wrong_magic_jsrr=fail_closed
tampered_tag=fail_closed
tampered_partition=fail_closed
encoded_length=185
```

Evidence:

```text
build/resource-cross-language-java-helper-parity-20260819.log
```

This is focused parser/bridge evidence only.  It does not prove accepted-artifact
resource opening, concurrent resource access, cross-artifact replay resistance,
full native-resource ABI coverage, or the complete security/performance matrix;
`coverage_status=incomplete` remains mandatory.

### Canonical JSRP resource/catalog serialized rerun (2026-08-19)

After the Java helper parser was aligned to the canonical JSRP v7 wire format,
the serialized focused lane was rerun against the current worktree.

```text
RuntimeResourceCodecTest tests=9 skipped=0 failures=0 errors=0
RuntimeResourcePartitionTest tests=5 skipped=0 failures=0 errors=0
RuntimeVmCatalogTest tests=5 skipped=0 failures=0 errors=0
timestamp=2026-08-19T22:46:21
```

Evidence:

```text
build/resource-catalog-focused-rerun-20260819.log
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.RuntimeResourceCodecTest.xml
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.RuntimeResourcePartitionTest.xml
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.RuntimeVmCatalogTest.xml
```

The rerun covers current JSRP v7 authenticated round-trip, header/body/tag
tamper rejection, build-local resource-key binding, partition spread and
foreign-partition rejection, duplicate resource path rejection, catalog
directory coverage, Merkle-root/root-HMAC verification, and method-identity
tamper rejection.  It is still a focused serialized resource/catalog lane;
concurrent/accepted-artifact resource opening, stale-cache attacks, and the
remaining security/performance gates remain open, so
`coverage_status=incomplete` remains mandatory.


### AKEN multi-page 10,000-sample production benchmark (2026-08-19)

The same real-JNI multi-page current-format AKEN fixture completed the
10,000-sample page-open profile after the bounded timeout override was made
usable for a single selected profile.  `pageOpenBenchmarkTimeoutSeconds()` now
honors `JS_AKEN_PAGE_OPEN_BENCH_TIMEOUT_SECONDS` when supplied, without
requiring the complete 100/1,000/10,000/100,000 matrix switch.  No runtime
security check or authentication step was skipped.

The focused lane used `JS_AKEN_PAGE_OPEN_BENCH_SAMPLES=10000`,
`JS_AKEN_PAGE_OPEN_DIFFERENTIAL_SAMPLES=100`, `JS_AKEN_PAGE_OPEN_BENCH_WARMUP=16`,
and `JS_AKEN_PAGE_OPEN_BENCH_TIMEOUT_SECONDS=1800`.

```text
phase=aken-page-open phase_mode=production phase_status=pass
samples=10000 warmup=16 p50=21018300 p95=26048800
p99=30775700 max=49747800
hardware_crypto_path=40000 software_crypto_path=0
aes_block_count=27670000 ghash_block_count=28800000
vm_frame_reuse_count=10000 vm_heap_fallback_count=0
jni_cache_hit_count=170000 auth_check_count=1040000
digest_check_count=680000 tag_check_count=40000
length_check_count=670000 structure_check_count=630000
jni_abi_check_count=180000 wipe_count=935860000
wipe_failure_count=0 plaintext_persistence_bytes=0
fallback_count=0 legacy_path_hits=0 exception_count=0
security_checks_skipped=0 output_digest=d3e2c7a8c4b6c7d6
```

The same run also retained the 100-sample hardware/software differential:
`output_digest=8a9e39e4def404ed`, with exact AES/GHASH/authentication/digest/tag/
length/structure/JNI ABI counters and zero wipe failures, plaintext
persistence, fallback, legacy hits, exceptions and skipped checks.

JUnit evidence:

```text
build/core-engine/test-results-aken-10k2/xml/TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml
```

The XML reports `tests=1`, `failures=0`, `errors=0`, timestamp
`2026-08-19T22:46:27`, and elapsed time `422.625s`.  This closes the current
10,000-sample multi-page AKEN benchmark subset only; the 100,000-sample
profile, accepted-artifact loader/resource lanes, readiness targets and the
remaining attack matrix remain open, so `coverage_status=incomplete` remains
mandatory.

### Native crypto KAT, page-size and dispatch differential (2026-08-19)

A standalone Windows x64 Zig build exercised the current `js_crypto.c`
implementation without sharing Gradle output.  The fixture contains six
AES-GCM known-answer vectors (AES-128/256 empty, zero-block and AAD/partial
inputs) plus 4 KiB, 64 KiB and 1 MiB authenticated payloads.  It also covers
AES-128/256 CTR known-answer vectors, CTR boundary sizes through 4,097 bytes,
wrong key/nonce/AAD/tag, truncation, null output and a `SIZE_MAX` length
overflow probe.

All three dispatch builds passed:

```text
hardware build:           compile=0 run=0
software forced build:    compile=0 run=0
capability-disabled build: compile=0 run=0

output_digest (all paths): 8ca501101587507730ca4168eb2a97ad0aa09905ecf362aa87bc34793bcab6ff
fixture_records=9
fixture_sha256=AD1625AED485BFCB45CFDC2F4509A516EE3CF90C10A259D5D498BA4E30A07C20
```

Hardware path:

```text
aes_hardware_available=1 ghash_hardware_available=1
hardware_crypto_path=161 software_crypto_path=0
aes_block_count=72114 ghash_block_count=69917
auth_check_count=16 auth_failure_count=5 tag_check_count=13
length_check_count=31 structure_check_count=16
wipe_count=211499 wipe_failure_count=0
plaintext_persistence_bytes=0 security_checks_skipped=0
fail_count=0
```

Forced software and capability-disabled paths both reported:

```text
aes_hardware_available=0 ghash_hardware_available=0
hardware_crypto_path=0 software_crypto_path=161
aes_block_count=72114 ghash_block_count=69917
auth_check_count=16 auth_failure_count=5 tag_check_count=13
length_check_count=31 structure_check_count=16
wipe_count=213034 wipe_failure_count=0
plaintext_persistence_bytes=0 security_checks_skipped=0
fail_count=0
```

The differential output digest, AES/GHASH block counts and authentication
results are identical across the hardware, forced-software and
capability-disabled builds.  The overflow probe completed without a crash and
without touching the bounded output buffer.

During this validation, the GCM failure cleanup was tightened: `wipe_len` is
now populated only after ciphertext length and block-count bounds pass.  This
prevents a malformed `SIZE_MAX` ciphertext length from causing cleanup to wipe
an untrusted, effectively unbounded range while retaining full output wiping
for validated-length authentication failures.

Evidence:

```text
build/crypto-kat-differential-20260819.log
```

This is focused native crypto evidence, not the complete 100/1,000/10,000/100,000
production benchmark or accepted-artifact matrix.  Throughput gates, full
Windows CPU coverage, cross-artifact replay, shell/loader integration and the
remaining security matrix stay open; `coverage_status=incomplete` remains
mandatory.

### Shell crypto focused regression after native AES/GHASH changes (2026-08-19)

The current shell crypto regression suite was rerun after the native GCM
schedule and length-overflow cleanup changes.

```text
JsShellCryptoGcmTest tests=3 skipped=0 failures=0 errors=0
timestamp=2026-08-19T23:06:59
time=11.802s
BUILD SUCCESSFUL
```

Evidence:

```text
build/crypto-shell-focused-rerun-20260819.log
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.JsShellCryptoGcmTest.xml
```

This confirms the shell payload/chunk authenticated path remains compatible
with the shared native crypto implementation; it does not close the full
accepted-artifact shell-loader matrix or the remaining performance gates.
`coverage_status=incomplete` remains mandatory.

### Production resource cross-artifact replay and collision guard rerun (2026-08-19)

The production resource probe now installs two distinct current-format artifact
entries in one immutable JSRP index and exercises both artifact-specific
commitments and aliases.  It accepts each artifact's own authenticated bytes,
rejects both raw-byte swaps across artifact paths, and rejects alias/route
collisions rather than retaining an ambiguous binding.  The fixture reports
only booleans, counters, and phase digests; artifact bytes are wiped during
cleanup.

```text
NativeRuntimeResourceProductionBenchmarkTest
 tests=1 skipped=0 failures=0 errors=0
 timestamp=2026-08-19T23:02:20 time=199.152s
 profiles=100/1000/10000/100000 warmup=16
 cross_artifact_a_match=1
 cross_artifact_b_match=1
 cross_artifact_swap_rejected=1
 cross_artifact_alias_collision_rejected=1
 fallback_count=0 legacy_path_hits=0 wipe_failure_count=0
 plaintext_persistence_bytes=0 security_checks_skipped=0 exception_count=0
```

The same rerun retained the existing production alias-index,
commitment-index, JSRP structure/length/digest checks, Zstd context reuse, and
generation-reset assertions for every required sample profile.  Evidence:

```text
build/resource-production-cross-artifact-rerun-20260819.log
build/core-engine/test-results-resource-cross-artifact-rerun/xml/TEST-io.github.hht0rro.javashroud.NativeRuntimeResourceProductionBenchmarkTest.xml
```

This closes the focused native resource cross-artifact replay/collision subset;
it does not prove accepted-artifact concurrent opening, stale JNI cache replay,
native loader lifecycle, or the complete security/performance matrix.
`coverage_status=incomplete` remains mandatory.

### Native shell inner-image loader production benchmark (2026-08-19)

Added a platform-native loader fixture and benchmark:

```text
E:\XiangMu\JavaShroud-public\core-engine\src\test\kotlin\io\github\hht0rro\javashroud\NativeShellLoaderProductionBenchmarkTest.kt
E:\XiangMu\JavaShroud-public\core-engine\src\test\native\shell_loader_fixture_image.c
E:\XiangMu\JavaShroud-public\core-engine\src\test\native\shell_loader_production_benchmark_probe.c
```

The fixture compiles a small current native image with the required JNI and
ABI exports, invokes the real platform loader (`js_shell_loader_pe.c` on
Windows x64 or `js_shell_loader_elf.c` on Linux x64), validates the immutable
mapping metadata and code bounds, unloads every image, and rejects a tampered
image.  The shell stub remains responsible for AEAD/commitment authentication
before this loader entrypoint; this lane measures the already-authenticated
loader/mapping lifecycle and does not expose payload bytes in its output.

```text
phase=shell-loader phase_mode=production phase_status=pass timing_unit=ns
samples=100 warmup=16 p50=93800 p95=116200 p99=122800 max=129400
load_count=100 unload_count=100 mapping_unit_count=7
tamper_rejection_count=1 failure_count=0
length_check_count=1 structure_check_count=1 jni_abi_check_count=1
wipe_failure_count=0 plaintext_persistence_bytes=0
fallback_count=0 legacy_path_hits=0 security_checks_skipped=0
output_digest=94dbb2ebc8e940e4
```

JUnit evidence:

```text
E:\XiangMu\JavaShroud-public\build\core-engine\test-results-shell-loader\xml\TEST-io.github.hht0rro.javashroud.NativeShellLoaderProductionBenchmarkTest.xml
```

The XML reports `tests=1`, `failures=0`, `errors=0`, timestamp
`2026-08-19T23:14:26`, and elapsed time `451.76s`.  This closes the focused
platform loader mapping/lifecycle subset; the full authenticated shell
accepted-artifact lane, cross-platform Mach-O production run, loader attack
matrix, and readiness gates remain open, so `coverage_status=incomplete`
remains mandatory.

### Accepted-artifact real-JAR smoke matrix (2026-08-19)

The current engine JAR and current `scripts/real_jar_matrix.py` were rerun
against both required real fixtures.  The three-case slice covers the
default pipeline plus two single-pass profiles (`default` and `min`) for each
fixture.  Both fixtures completed baseline execution, obfuscation, output
creation, and runtime observation checks without configuration-validation
rejection or runtime mismatch.

```text
fixtures=2 cases_per_fixture=3 total_cases=6 failures=0 xfail_validation=0
SimpleFiveInARow.jar baseline_rc=0
  default-pipeline sha=1e6063dc4c8e5d0e
  single-anti-decompiler-structure-default sha=f7f212f4557e0c73
  single-anti-decompiler-structure-min sha=69f261cb2feaa5ca
TEST.jar baseline_rc=0
  default-pipeline sha=861dc0f1e5039ea7
  single-anti-decompiler-structure-default sha=8f586bdec9475f71
  single-anti-decompiler-structure-min sha=88c80e262e61980
```

Evidence:

```text
build/real-jar-acceptance-smoke-20260819.log
build/real-jar-acceptance-smoke-20260819/
```

This smoke slice confirms that the current default pipeline and selected
single-pass configurations are accepted by the current TOML parser and
runtime for both real artifacts.  It does not close the full native/VM,
resource/JNI, shell/loader, source-rebuild, prebuilt, Pool deterministic,
SecurityManager, readiness, or attack matrices; `coverage_status=incomplete`
remains mandatory.

### Accepted-artifact native/JNI pair smoke (2026-08-20)

The real-JAR matrix then exercised a valid native/JNI combination using the
required companion pass `anti-dump-protection` together with
`jni-microkernel-loader`.  The earlier single-pass JNI case was intentionally
rejected by the current companion-pass validator; this accepted pair was run
after that fail-closed validation check.

```text
SimpleFiveInARow.jar
  case=pair-anti-dump-protection__jni-microkernel-loader
  baseline_rc=0 failures=0 xfail_validation=0
  obfuscate_seconds=105.9 output_sha=94f217c231ca76d0

TEST.jar
  case=pair-anti-dump-protection__jni-microkernel-loader
  baseline_rc=0 failures=0 xfail_validation=0
  obfuscate_seconds=288.5 output_sha=6f312b8fb7029ea9
```

Evidence:

```text
build/real-jar-native-jni-pair-smoke-20260819.log
build/real-jar-native-jni-pair-testjar-20260820.log
build/real-jar-native-jni-pair-smoke-20260819/
build/real-jar-native-jni-pair-testjar-20260820/
```

Both accepted artifacts completed baseline execution, native/JNI obfuscation,
output creation, and runtime observation checks.  This is still a one-case
per-fixture native/JNI acceptance slice; it does not prove the full native
single, VM, native+VM, native+resource, native+reflection, native+exception,
loader lifecycle, readiness, or security-attack matrices, so
`coverage_status=incomplete` remains mandatory.

### NativeHelperHardeningTest current-runtime assertion alignment (2026-08-20)

The hardening test expectations were updated narrowly to match the current
AKEN/native-runtime architecture without restoring any retired protocol or
fallback path:

- VM runtime-session verification is asserted before execution-frame acquire;
- mutable resident instructions are copied into the reusable private frame
  arena (`js_vm_execution_frame_reserve_insns` + `memcpy`), then wiped;
- `loadKernel` is asserted to enter `loadAkenNativeKernel`, which performs the
  authenticated bundled-native load and typed AKEN ABI probe;
- the current VBC4 build-key domain is asserted as `v2`, while method/session
  domains remain `v1`;
- current JSRP version validation is asserted through
  `hasRuntimeResourceHeader` and the `raw[4]` version check.

Isolated verification:

```text
NativeHelperHardeningTest tests=62 skipped=0 failures=0 errors=0
timestamp=2026-08-20T00:10:14
time=1.042s
BUILD SUCCESSFUL
```

Evidence:

```text
build/native-helper-hardening-rerun-20260820.log
build/core-engine/test-results-native-helper-hardening-20260820/xml/TEST-io.github.hht0rro.javashroud.NativeHelperHardeningTest.xml
```

No production protocol, authentication, ABI, or fail-closed implementation
was weakened; `coverage_status=incomplete` remains mandatory.

### Runtime-focused production benchmark matrix (2026-08-19)

An isolated runtime-focused Gradle run covered the current crypto, shell, VM,
resource, JNI, zstd, loader, nested-execution, and catalog lanes. All 11
selected test classes passed with no skipped cases or errors:

```text
ConfigCodecTest tests=28 failures=0 errors=0
AkenNativeLocatorTest tests=2 failures=0 errors=0
JsShellCryptoGcmTest tests=3 failures=0 errors=0
NativeRuntimeCryptoKatTest tests=1 failures=0 errors=0
NativeRuntimeJniCacheProductionBenchmarkTest tests=1 failures=0 errors=0
NativeRuntimeResourceProductionBenchmarkTest tests=1 failures=0 errors=0
NativeRuntimeVmPreparedExecutionBenchmarkTest tests=1 failures=0 errors=0
NativeRuntimeZstdContextTest tests=1 failures=0 errors=0
NativeShellLoaderProductionBenchmarkTest tests=1 failures=0 errors=0
NativeVmExecutionFrameTest tests=1 failures=0 errors=0
NestedVmExecutionTest tests=1 failures=0 errors=0
```

The production resource and JNI profiles exercised `100`, `1,000`, `10,000`
and `100,000` samples with warmup `16`. Representative security counters
remained zero for fallback, legacy paths, wipe failures, plaintext
persistence, and skipped checks. The resource lane reported alias/commitment
index hits and zstd context reuse at every profile. The VM prepared lane
reported nested depth `8`, recursive/exception/threaded execution pass,
`vm_frame_reuse_count=100`, `vm_heap_fallback_count=0`, and
`plaintext_persistence_bytes=0` for its default `100`-sample profile.

Representative output digests and timing evidence are retained in the isolated
JUnit XML.

Evidence:

```text
C:\WINDOWS\TEMP\javashroud-runtime-focused-20260819.log
build/core-engine/test-results-runtime-focused-20260819/xml/
```

This closes the focused runtime benchmark subset. It does not by itself close
the complete accepted-artifact matrix, all 100,000-sample AKEN/VM production
profiles, readiness p95 gates, or the full tamper/crash attack matrix;
`coverage_status=incomplete` remains mandatory.

### AKEN multi-page 100,000-sample production benchmark (2026-08-19 evidence)

The complete selected 100,000-sample multi-page AKEN profile also completed
through the real JNI page-open path.  The run kept the 100-sample hardware/
software differential before the large profile and used the bounded single-
profile timeout override (`JS_AKEN_PAGE_OPEN_BENCH_TIMEOUT_SECONDS=3600`).

```text
phase=aken-page-open phase_mode=production phase_status=pass
samples=100000 warmup=16 p50=24149700 p95=57015500
p99=76113400 max=243837900
hardware_crypto_path=400000 software_crypto_path=0
aes_block_count=278200000 ghash_block_count=289500000
vm_frame_reuse_count=100000 vm_heap_fallback_count=0
jni_cache_hit_count=1700000 auth_check_count=10400000
digest_check_count=6800000 tag_check_count=400000
length_check_count=6700000 structure_check_count=6300000
jni_abi_check_count=1800000 wipe_count=9399300000
wipe_failure_count=0 plaintext_persistence_bytes=0
fallback_count=0 legacy_path_hits=0 exception_count=0
security_checks_skipped=0 output_digest=84a5cc34c5893937
```

The paired 100-sample differential in the same run remained passing with
`output_digest=8a9e39e4def404ed`; the default path reported
`hardware_crypto_path=400/software_crypto_path=0`, while the forced software
path reported `hardware_crypto_path=0/software_crypto_path=400`, with matching
AES/GHASH/authentication/digest/tag/length/structure/JNI ABI counters and zero
wipe failures, plaintext persistence, fallback, legacy hits, exceptions or
skipped checks.

JUnit evidence:

```text
E:\XiangMu\JavaShroud-public\build\core-engine\test-results-aken-100k\xml\TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml
```

The XML reports `tests=1`, `failures=0`, `errors=0`, timestamp
`2026-08-19T23:26:48`, and elapsed time `3301.01s` (`55m32s`).  This closes the
current multi-page AKEN 100/1,000/10,000/100,000 sample-profile subset.  The
full accepted-artifact shell/resource/loader matrix, readiness targets and
complete security attack matrix remain open, so `coverage_status=incomplete`
remains mandatory.


### Real SimpleFiveInARow CP deferred-decode diagnosis and program-bound fix (2026-08-20)

The untouched user-supplied sample `E:\javashroud-product-video\SimpleFiveInARow-shrouded.jar`
was executed read-only.  Its sanitized native telemetry reached sealed constant-pool
stage 7 after decrypt/plain parsing but reported `cp_auth=0` (the inner tag check
failed); no legacy route or authentication skip was observed.  The extracted DLL
was inspected without replacing the JAR.  The failure was traced to deferred CP
identity/decode work reading a scoped layout digest after AKEN preparation had
cleared that scope, even though the authenticated `js_vm_program` already carried
its session-bound layout digest.

The fix is deliberately narrow: `js_vm_decode_cp_entry`, method identity, and owner
identity now derive the temporary build key from the bound program session digest when
`session_layout_digest_bound` is set, while the pre-bind parse path still uses the
current scoped digest.  Keys remain operation-local and are wiped; no key, DEK,
nonce, plaintext, or fallback path is cached.

Focused regression evidence:

```text
build/core-engine/test-results-vm-cp0-program-key-20260820/xml/TEST-io.github.hht0rro.javashroud.NativeRuntimeVmPreparedExecutionBenchmarkTest.xml
```

The XML reports `tests=1`, `failures=0`, `errors=0`, timestamp
`2026-08-20T13:31:10`, and elapsed `121.211s`.  The CP[0] invoke-static fixture
returned `7` after the scoped digest was cleared and emitted
`invoke_static_cp0_session_layout_bound=1`; ciphertext, tag, nonce, length, and type
mutations all failed closed.  The same run reported nested/recursive/threaded
execution pass, `vm_frame_reuse_count=100`, `fallback_count=0`,
`legacy_path_hits=0`, `wipe_failure_count=0`, `plaintext_persistence_bytes=0`, and
`security_checks_skipped=0`.

A newly materialized local fixture artifact (built from `E:\speedfix\SimpleFiveInARow.jar`)
was then run without modifying either source JAR.  Artifact evidence is
`build/cp-program-key-fix-vm-pair-20260820/SimpleFiveInARow-obf.build-evidence.json`;
the recorded native entry, size, SHA-256, layout commitment, and pre-seal inner digest
were independently compared with the JAR entry.  The runtime was intentionally
bounded and terminated after the UI remained healthy; the UTF-8-safe log
`build/cp-program-key-fix-vm-pair-20260820/runtime.log` reached the UI readiness
markers at `+6314ms` and contained no `cp_stage`, `SecurityException`,
`ExceptionInInitializerError`, or `native VM` failure.  This is startup-semantic
recovery evidence, not the plan's `<=1500ms` readiness acceptance.

The original untouched sample remains a separate pre-fix diagnostic and was not
rewritten, injected, or repackaged.  Real accepted-artifact coverage and the complete
performance/security matrix therefore remain `coverage_status=incomplete`.

### AKEN multi-page 100,000-sample differential wrapper status (2026-08-20)

The dedicated 100,000-sample run completed both real-JNI hardware and forced-software
page-open profiles inside the test worker.  The binary evidence is retained at
`build/core-engine/test-results-aken-100k-diff1/binary/output.bin` and records matching
output digest `84a5cc34c5893937` for both paths, identical AES/GHASH/authentication/
digest/tag/length/structure/JNI ABI counters, and zero auth failures, wipe failures,
plaintext persistence, fallback, legacy hits, exceptions, or skipped checks.  Hardware
reported `hardware_crypto_path=1100000`; forced software reported
`software_crypto_path=1100000`.

The Gradle/JUnit wrapper did not produce XML after the long run and exited with
`Cannot read the array length because "<local3>" is null` during test reporting.  A
bounded rerun with 100 differential/benchmark samples completed normally:

```text
build/core-engine/test-results-aken-bounded-diagnostic-20260820/xml/TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml
```

That XML reports `tests=1`, `failures=0`, `errors=0`, timestamp
`2026-08-20T13:52:25`, and elapsed `433.53s`, including the same differential and
fail-closed tamper sequence.  The 100,000-sample result is consequently recorded as
runtime differential evidence with wrapper completion `incomplete`, not as a complete
JUnit acceptance pass.  No native security logic was relaxed and no null guard was
added based only on the reporting failure.

### Native shell loader benchmark refresh (2026-08-20)

After adding the explicit authentication boundary marker, the focused loader
lane was rerun.  The probe now reports `auth_boundary=preverified` so the
zero AEAD counters are not mistaken for skipped authentication: the shell
stub authenticates before invoking the loader, while this fixture validates
only the already-authenticated mapping lifecycle and loader-side tamper
rejection.

```text
phase=shell-loader phase_mode=production phase_status=pass timing_unit=ns
samples=100 warmup=16 p50=260000 p95=563700 p99=891000 max=1684200
auth_boundary=preverified load_count=100 unload_count=100 mapping_unit_count=7
tamper_rejection_count=1 failure_count=0
length_check_count=1 structure_check_count=1 jni_abi_check_count=1
wipe_failure_count=0 plaintext_persistence_bytes=0
fallback_count=0 legacy_path_hits=0 security_checks_skipped=0
output_digest=79a00d15e7416559
```

Latest JUnit evidence:

```text
E:\XiangMu\JavaShroud-public\build\core-engine\test-results-shell-loader2\xml\TEST-io.github.hht0rro.javashroud.NativeShellLoaderProductionBenchmarkTest.xml
```

The XML reports `tests=1`, `failures=0`, `errors=0`, timestamp
`2026-08-20T00:25:17`, and elapsed time `229.768s`.

### VM prepared execution complete sample matrix refresh (2026-08-20)

The attached-JVM production prepared-entrypoint benchmark was rerun with the
plan-required matrix switch (`JS_VM_PREPARED_EXEC_BENCH_MATRIX=1`).  It compiled
the current native sources once and executed the production frame/TLS harness at
100, 1,000, 10,000 and 100,000 samples, with 16 warmup iterations per profile.
All four profiles passed with nested depth 8, recursive execution, typed
exception handling (`ArithmeticException`, result 42), four-thread execution,
zero heap fallback, zero allocation count, zero native exceptions, zero fallback
or legacy hits, zero wipe failures, zero plaintext persistence, and zero skipped
security checks.

Evidence:

```text
build/core-engine/test-results-vm-prepared-matrix-20260820/xml/TEST-io.github.hht0rro.javashroud.NativeRuntimeVmPreparedExecutionBenchmarkTest.xml
```

Representative matrix output:

```text
samples=100    p50=407800ns p95=1090100ns p99=2751900ns max=4758500ns   vm_frame_reuse_count=100    wipe_count=5300
samples=1000   p50=262000ns p95=456500ns  p99=850300ns  max=2387400ns   vm_frame_reuse_count=1000   wipe_count=53000
samples=10000  p50=236500ns p95=512800ns  p99=1147100ns max=6379700ns   vm_frame_reuse_count=10000  wipe_count=530000
samples=100000 p50=281000ns p95=632200ns  p99=1546400ns max=64239600ns  vm_frame_reuse_count=100000 wipe_count=5300000
```

The XML reports `tests=1`, `skipped=0`, `failures=0`, `errors=0`, timestamp
`2026-08-20T00:45:56`, and elapsed time `275.222s`.  This closes the prepared
entrypoint sample-size requirement; it does not close the real protected
artifact VM lane, lambda/invoke-dynamic breadth, or the complete attack matrix.
`coverage_status=incomplete` remains mandatory.

### VM prepared CP[0] `INVOKESTATIC` current-format fixture (2026-08-20)

The prepared-entrypoint probe also exercises an isolated current-format
constant-pool fixture whose CP index `0` is an authenticated sealed-string
entry.  The production `VM_INVOKESTATIC` resolver/JNI method path decodes the
entry and returns the primitive result `7`; the sanitized decode markers are
`decode_stage=9` and `decode_auth=1`.  Five private mutations—ciphertext, tag,
nonce, stored length, and type—each fail closed.  The fixture emits no key,
nonce, method reference, or plaintext.

```text
invoke_static_cp0=pass invoke_static_cp0_index=0 invoke_static_cp0_type=sealed invoke_static_cp0_result=7 invoke_static_cp0_decode_stage=9 invoke_static_cp0_decode_auth=1
invoke_static_cp0_tamper_cipher=fail-closed invoke_static_cp0_tamper_tag=fail-closed invoke_static_cp0_tamper_nonce=fail-closed invoke_static_cp0_tamper_length=fail-closed invoke_static_cp0_tamper_type=fail-closed
```

Evidence:

```text
build/vm-cp0-diagnostic-20260820.log
```

This is a current-format VM decoder/resolver regression fixture, not a
real-artifact acceptance result.  It does not close the real
`SimpleFiveInARow` native+VM blocker documented below; that lane remains
security-blocked/incomplete pending root-cause correction and rerun, and
`coverage_status=incomplete` remains mandatory.

A subsequent isolated rerun of the same CP[0] production fixture completed with
`tests=1`, `failures=0`, `errors=0`, `skipped=0`, and elapsed `187.677s`.
Evidence:

```text
build/core-engine/test-results-vm-cp0-current-20260820/xml/TEST-io.github.hht0rro.javashroud.NativeRuntimeVmPreparedExecutionBenchmarkTest.xml
```

It reproduced `invoke_static_cp0_session_layout_bound=1`, primitive result `7`,
all five fail-closed mutations, nested/recursive/threaded execution pass,
`vm_frame_reuse_count=100`, `vm_heap_fallback_count=0`, `fallback_count=0`,
`legacy_path_hits=0`, `wipe_failure_count=0`, `plaintext_persistence_bytes=0`,
and `security_checks_skipped=0`.  This is a repeatability check for the narrow
program-bound-digest fix, not a claim that the accepted-artifact matrix is closed.

### Real TEST.jar native-string runtime acceptance refresh (2026-08-20)

A valid current-format native/string lane was generated for the plan-specified
`TEST.jar` fixture using `jni-microkernel-loader` plus `string-encryption`.
The engine completed successfully (`passes=2`, transformedClasses=63,
transformedMembers=63) and emitted:

```text
build/real-jar-accepted-20260820/TEST/native-string/TEST-native-string.jar
```

The generated JAR executed to completion with exit code 0.  Runtime markers
matched the direct baseline semantics: Basics 1.1-1.7 PASS, Reflection 2.1-2.7
PASS, baseline `Test 2.8: Sec ERROR`, and `Calc` completed (`302ms` in this
run), followed by `Tests r Finished`.  No stderr output was emitted.

This is an accepted native/string real-artifact case only.  It does not imply
native-only, VM, native+VM, loader, resource, reflection/exception breadth,
readiness p95, deterministic Pool, SecurityManager compatibility, or full
security attack-matrix closure.  Those remain open and `coverage_status=incomplete`
remains mandatory.

### Real SimpleFiveInARow native+VM diagnostic (2026-08-20)

The current valid companion pair (`anti-dump-protection` plus
`method-virtualization`) generated an output JAR, but the protected VM runtime
failed closed during startup:

```text
ExceptionInInitializerError
SecurityException: native VM execution failed for entry=31fc298e46c0263a
pc=0 opcode=178 sp=0 raw=87 mask=229 epoch=0 cached=0
insns=117 step=-1 limit=-1 detail=resolve opcode=178 cp=0 cp_count=53
cp_type=-1 cp_strlen=-1 meta_cp=50 reg_insns=0 exec_insns=117 ref=absent
```

Evidence:

```text
build/real-jar-vm-pair-diagnostic-20260820/SimpleFiveInARow/001-pair-anti-dump-protection__method-virtualization/obfuscated.txt
build/real-jar-vm-pair-diagnostic-20260820/SimpleFiveInARow/001-pair-anti-dump-protection__method-virtualization/SimpleFiveInARow-obf.jar
```

This is recorded as a real-artifact VM integration blocker, not as a pass and
not as a reason to weaken constant-pool authentication or add a fallback path.
The native+VM lane remains security-blocked/incomplete pending root-cause
correction and rerun.

### AKEN multi-page hardware/software differential refresh (2026-08-20)

The current-format multi-page AKEN page-open fixture completed a dedicated
10,000-sample hardware/software differential on Windows x64.  Hardware and
forced-software libraries used the same generated artifact, locator include,
page bytes, route, binding, and JNI harness.  Both paths authenticated and
executed the page, and the differential compared output digest plus AES/GHASH,
authentication, digest, tag, length, structure, and JNI ABI counters.

Evidence:

```text
build/core-engine/test-results-aken-10k-diff4/xml/TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml
```

JUnit result: `tests=1`, `failures=0`, `errors=0`, elapsed `678.174s`.

Sanitized differential evidence:

```text
phase=aken-page-open-differential phase_mode=production phase_status=pass samples=10000 hardware_crypto_path=70000 software_crypto_path=70000 output_digest=d3e2c7a8c4b6c7d6
```

Hardware path:

```text
phase=aken-page-open phase_mode=production phase_status=pass samples=10000 warmup=16 p50=21800900 p95=25912400 p99=29365300 max=44368500 hardware_crypto_path=70000 software_crypto_path=0 aes_block_count=27850000 ghash_block_count=29800000 auth_check_count=1820000 digest_check_count=1190000 tag_check_count=70000 length_check_count=1150000 structure_check_count=1080000 jni_abi_check_count=300000 wipe_failure_count=0 plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0 exception_count=0 security_checks_skipped=0 output_digest=d3e2c7a8c4b6c7d6
```

Forced software path:

```text
phase=aken-page-open phase_mode=production phase_status=pass samples=10000 warmup=16 p50=24220500 p95=29168500 p99=34005700 max=64112900 hardware_crypto_path=0 software_crypto_path=70000 aes_block_count=27850000 ghash_block_count=29800000 auth_check_count=1820000 digest_check_count=1190000 tag_check_count=70000 length_check_count=1150000 structure_check_count=1080000 jni_abi_check_count=300000 wipe_failure_count=0 plaintext_persistence_bytes=0 fallback_count=0 legacy_path_hits=0 exception_count=0 security_checks_skipped=0 output_digest=d3e2c7a8c4b6c7d6
```

Both paths reported identical output digest and security-check counters, with
positive wipe counts (hardware/software scratch ranges may differ), no wipe
failures, no plaintext persistence, no fallback, no legacy path hits, and no
skipped checks.  The 100,000-sample differential remains open; therefore
`coverage_status=incomplete` is retained.

An additional bounded rerun was started with the same current source and
`JS_AKEN_PAGE_OPEN_BENCH_SAMPLES=100`, `JS_AKEN_PAGE_OPEN_DIFFERENTIAL_SAMPLES=100`,
and warmup `1`.  The Gradle wrapper was terminated after the external 15-minute
command bound without producing JUnit XML or phase output; no pass/fail result is
claimed for that attempt.  This timeout is separate from the earlier bounded XML
pass and does not change the retained 100,000-sample wrapper-incomplete status.

### AKEN benchmark phase-line diagnostics hardening (2026-08-20)

The multi-page AKEN benchmark fixture now uses a shared
`requireSingleAkenPhaseLine` helper for the single-page profile, the
hardware/software differential, and the multi-page profile.  The helper requires
exactly one sanitized `phase=aken-page-open` line and reports only bounded
metadata (`phase-line-count`, child `exit_code`, and `output_chars`) when a
fixture times out or emits duplicate phase lines.  It does not copy child
stdout, routes, handles, proofs, plaintext, paths, or full exception payloads
into persistent diagnostics, and it does not alter native authentication,
tag/digest/length/structure checks, or fallback behavior.

Validation after the fixture-only edit:

```text
.\\gradlew.bat :core-engine:compileTestKotlin --rerun-tasks --console=plain --no-daemon
BUILD SUCCESSFUL in 56s
5 actionable tasks: 5 executed
```

A full 100-sample attached-JNI rerun was also attempted with
`JS_AKEN_PAGE_OPEN_BENCH_SAMPLES=100`,
`JS_AKEN_PAGE_OPEN_DIFFERENTIAL_SAMPLES=100`, and warmup `1`.  The external
15-minute command bound expired before the test worker emitted JUnit XML or a
persistent phase line; the attempt is recorded as `incomplete/timeout`, not as
a native differential failure or pass.  The previously completed bounded XML
pass and the 10,000-sample differential evidence remain the authoritative
completed results, while the 100,000-sample JUnit wrapper and full performance
matrix remain open.

### Resource commitment duplicate-path validation (2026-08-20)

The production resource benchmark fixture now exercises the immutable JSRP
commitment index with a duplicate-path manifest before installing the valid
two-artifact manifest. The duplicate registration is required to fail closed;
the fixture then confirms that valid entries still resolve, cross-artifact
raw-byte swaps are rejected, and the generation reset retires both indexes.
This is fixture/test-only and does not alter the current resource protocol,
authentication, digest, length, structure, wipe, or fallback logic.

Source validation:

```text
.\\gradlew.bat :core-engine:compileTestKotlin --console=plain --no-daemon
BUILD SUCCESSFUL in 11s
```

An isolated production probe was compiled from the current native source set
with Zig 0.16.0 and executed for a bounded 100-sample profile. Sanitized
output included:

Evidence:

```text
build/core-engine/test-results-resource-duplicate-path-20260820/run-100.log
```

```text
resource_cache_lifecycle phase_name=resource-cache-generation phase_mode=production status=pass generation_before=13 generation_installed=15 generation_after_reset=16 generation_reinstalled=18 stale_alias_reused=0 stale_alias_identity_resolution=1 stale_commitment_reused=0 stale_resource_index_hit_count=0 replacement_resource_index_hit_count=2 replacement_structure_check_count=1 replacement_length_check_count=1 replacement_digest_check_count=1 cross_artifact_a_match=1 cross_artifact_b_match=1 cross_artifact_swap_rejected=1 cross_artifact_alias_collision_rejected=1 duplicate_commitment_path_rejected=1 fallback_count=0 legacy_path_hits=0 wipe_failure_count=0 plaintext_persistence_bytes=0 security_checks_skipped=0 exception_count=0
```

The same probe passed the resource alias, commitment, and Zstd phases; the
100-sample Zstd phase reported `decompress_context_reuse_count=100`, while the
lifecycle check reported `post_reset_reuse_count=0`, `failure_reuse_count=1`,
and `failure_wipe_delta=1`. This is bounded fixture evidence only; the full
accepted-artifact matrix and 100,000-sample wrapper remain open.

### AKEN capability-gated hardware/software differential refresh (2026-08-20)

The attached-JVM multi-page AKEN fixture now reports two de-identified,
self-tested dispatch flags in each production page-open phase:
`cpu_hardware_aes` and `cpu_hardware_ghash`.  The fixture requires the
effective AES dispatch counter to agree with the capability probe: a hardware
AES capability must produce a positive `hardware_crypto_path`, while an
unsupported or forced-software lane must produce a positive
`software_crypto_path`.  The forced-software build reports both capability
flags as zero; no CPU identity or sensitive runtime state is emitted.

Validation:

```text
cmd /c "gradlew.bat -Djavashroud.isolatedRun=aken-capability-gated :core-engine:test --tests io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.production_multi_page_vbc4_assembles_executes_and_authenticates_through_real_jni --no-daemon --console=plain"
BUILD SUCCESSFUL in 5m 34s
tests=1 failures=0 errors=0 skipped=0
```

JUnit evidence: `build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.aken.AkenNativePageLocatorResolverNativeTest.xml`.

Sanitized differential evidence:

```text
phase=aken-page-open-differential phase_mode=production phase_status=pass samples=100 cpu_hardware_aes=1 cpu_hardware_ghash=1 hardware_crypto_path=700 software_crypto_path=700 output_digest=8a9e39e4def404ed
```

The hardware and forced-software page-open profiles both retained identical
AES/GHASH/authentication/digest/tag/length/structure/JNI-ABI counters and the
same output digest.  The hardware profile reported
`cpu_hardware_aes=1 cpu_hardware_ghash=1 hardware_crypto_path=700
software_crypto_path=0`; the forced-software profile reported
`cpu_hardware_aes=0 cpu_hardware_ghash=0 hardware_crypto_path=0
software_crypto_path=700`.  Both profiles reported zero auth failures, wipe
failures, plaintext persistence, fallback, legacy-path hits, exceptions, and
skipped security checks.  The middle-page tamper route remained fail-closed.
This closes the capability-gated bounded differential subset only; the full
accepted-artifact matrix and 100,000-sample wrapper remain open.

### Native runtime 14-phase hardware/software differential refresh (2026-08-20)

`NativeRuntimeMultiPageDifferentialTest` was tightened as a fixture-only gate;
no native implementation, protocol, ABI, authentication, binding, or fallback
behavior changed.  It compiles the same `native_runtime_benchmark.c` fixture
once with default capability-gated dispatch and once with
`JS_CRYPTO_FORCE_SOFTWARE=1`, then executes one measured sample with zero
warmup in each process.  The bounded comparison now covers all 14 crypto/shell
phases exposed by that runner:

```text
aes-gcm-128-kat, aes-gcm-256-kat
ghash-aad-authenticated-page-{4k,64k,1m}
aes-ctr-{128,256}-{4k,64k,1m}
shell-payload-decode-{4k,64k,1m}
```

For every phase, the gate requires an identical de-identified output digest
and exact equality for the protocol/security decision counters:
`auth_check_count`, `auth_failure_count`, `digest_check_count`,
`tag_check_count`, `length_check_count`, `structure_check_count`,
`jni_abi_check_count`, `wipe_failure_count`,
`plaintext_persistence_bytes`, `fallback_count`, `legacy_path_hits`,
`exception_count`, `native_exception_count`, and
`security_checks_skipped`.  `wipe_count` remains required to be positive on
both paths but is intentionally not compared exactly, because hardware and
software internals may use different transient scratch layouts while retaining
the same mandatory wipe behavior.  Each phase also requires zero failures,
fallbacks, legacy hits, skipped checks, exceptions, and plaintext persistence;
the GCM phases require positive GHASH/auth/tag/length/structure coverage, and
the shell phases require positive authenticated chunk/tag/length/structure
coverage.

The benchmark's `hardware_crypto_path` counts AES schedule dispatch rather
than individual GHASH multiplications.  GHASH acceleration is therefore
observed through its self-tested `hardware_ghash` capability flag while the
GCM phases prove protocol-identical GHASH work through their equal
`ghash_block_count`; the fixture deliberately does not mislabel the AES
schedule counter as a GHASH-path counter.

Focused validation:

```text
.\gradlew.bat :core-engine:test --tests io.github.hht0rro.javashroud.NativeRuntimeMultiPageDifferentialTest --no-daemon --console=plain -x :core-engine:jar
BUILD SUCCESSFUL in 32s
tests=1 failures=0 errors=0 skipped=0
```

The focused run excluded only the lock-affected `:core-engine:jar` packaging
task; it is test-fixture evidence and not a replacement for a full packaged-JAR
build.  JUnit evidence:

```text
build/core-engine/test-results/test/TEST-io.github.hht0rro.javashroud.NativeRuntimeMultiPageDifferentialTest.xml
```

The XML is timestamped `2026-08-20T23:05:30`, reports elapsed `15.065s`, and
contains the following sanitized summary:

```text
multi-page-differential capability_hardware_aes=1 capability_hardware_ghash=1 hardware_ctr_schedule_count=6 software_ctr_schedule_count=6 gcm_ghash_blocks=69904 phase_count=14
```

This closes the bounded 14-phase crypto/shell differential fixture gap only.
It does not claim AKEN production page-open, shell mapped-image/loader,
accepted-artifact, full sample-matrix, or real-JAR readiness acceptance; those
remaining lanes stay `coverage-incomplete` until their own security gates and
tests pass.
