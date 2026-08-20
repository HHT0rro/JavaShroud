# Native Runtime Benchmark 报告模板

本模板对应 `core-engine/src/test/native/native_runtime_benchmark.c`，用于阶段 A 的运行时基线、优化后复测和安全门禁记录。报告仅保留计时、计数器、能力位和输出摘要；不得粘贴 key、nonce、DEK、page plaintext、descriptor secret、原始资源路径或完整异常 payload。

## Fixture 范围

| 阶段 | Fixture phase | 覆盖内容 |
| --- | --- | --- |
| AES-GCM-128 | `aes-gcm-128-kat` | 公共 NIST known-answer vector 的认证解密 |
| AES-GCM-256 | `aes-gcm-256-kat` | 公共 NIST known-answer vector 的认证解密 |
| GHASH/AAD page open | `ghash-aad-authenticated-page-4k/64k/1m` | 带 AAD 的 AES-128-GCM crypto-only synthetic fixture；保留 ciphertext/tag 和调用所需的合成公开元数据，不保留 plaintext；未建立 AKEN locator/descriptor/proof/route/bound-plan session，因此不得作为生产 AKEN page open 证据 |
| AES-CTR | `aes-ctr-{128,256}-{4k,64k,1m}` | AES-128/AES-256 CTR 的 4 KiB、64 KiB、1 MiB payload |
| Native shell | `shell-payload-decode-{4k,64k,1m}` | crypto-only synthetic chunk HMAC 验证、CTR decode 和 wipe-on-use scratch；未建立已验证 inner-image mapping/loader lifecycle，因此不得作为生产 shell-loader 证据 |
| Resource alias/commitment | `resource-alias-lookup`, `resource-commitment-lookup` | 默认是有界 synthetic index fixture；在定义 `JS_RUNTIME_BENCH_RESOURCE_RUNTIME` 并链接生产 `js_vm_resource.c`（及其 full native dependency set）时，改为调用生产 immutable alias index、JSRP commitment install 和 `js_vm_commitment_matches`，phase 行标记为 `phase_mode=production`；仍只保留脱敏计数和 digest，不输出资源内容 |
| JNI method/class | `jni-method-class-lookup` | loader/class/method/generation/ABI identity 的 synthetic cache-hit 检查；无 JVM 时不伪装成 JNI 集成结果 |
| VM prepared/nested | `vm-prepared-execution`, `vm-nested-execution` | standalone benchmark 明确输出 `phase_status=unsupported`；真实 frame/TLS/FLS 证据来自 `vm_execution_frame_probe.c` 和 native integration lane |
| zstd context | `zstd-context-reuse` | 默认 standalone 构建输出 `unsupported`；定义 `JS_RUNTIME_BENCH_ZSTD` 时运行 synthetic per-run `ZSTD_DCtx` fixture；定义 `JS_RUNTIME_BENCH_RESOURCE_RUNTIME` 并链接完整生产 runtime 时，改为调用 `js_vbc4_zstd_decompress_owned`，验证同 generation context reuse、`js_vm_call_gate_reset` 后首个 decode 不误记 reuse、以及失败 decode 的 owned-output wipe |

该独立 fixture 不解析生产 AKEN page/JSRP 记录，也不把 synthetic resource/JNI lookup 当作生产 catalog/ABI 证据。VM prepared/nested phase 在没有 attached JVM、artifact/session binding 时必须报告 `phase_status=unsupported`；真实 execution-frame 生命周期由 `vm_execution_frame_probe.c` 和 native integration harness 记录。zstd phase 只有在显式 `JS_RUNTIME_BENCH_ZSTD` 全量链接时才运行，否则同样报告 `unsupported`。它仍以生产 `js_aes_gcm_decrypt`、`js_aes_ctr_xor` 和 `js_shell_decode_payload_chunks` 作为被测路径。

当使用 `JS_RUNTIME_BENCH_RESOURCE_RUNTIME` 时，resource 两个 phase 不再走本文件中的 synthetic hash table：fixture 会先通过 `js_vm_commitments_install` 安装一个当前格式、带 SHA-256 commitment 的 JSRP index，并通过 `js_vm_resource_alias_register` 建立一条有界 alias。测量区分别调用 `js_vm_resource_alias_resolve_copy` 和 `js_vm_commitment_matches`；setup、reset 和 phase 结束都经过生产 session/index 生命周期清理。该 adapter 只关闭 Resource/JNI 计划中的 **immutable index + commitment verification** 子覆盖，不能替代 attached-JVM resource open、AKEN route binding、JNI class/method cache re-authentication 或 VM execution coverage；其余未覆盖 phase 仍必须使总结果保持 `coverage-incomplete`。

`NativeRuntimeResourceProductionBenchmarkTest.kt` 是该 production-resource 子覆盖的可重复验证入口。它会复制当前 native 源树，启用 `JS_RUNTIME_BENCH_RESOURCE_RUNTIME` 并以完整 native dependency set 编译 `runtime_resource_production_benchmark_probe.c`；随后断言 alias、commitment 和 zstd phase 均为 `phase_mode=production`，production index hit、JSRP structure/length/digest/wipe 计数和同 generation zstd context reuse 均出现。probe 还在 `js_vm_call_gate_reset` 后验证下一次 `js_vbc4_zstd_decompress_owned` 不会把旧 decoder 记为 reuse，并验证错误 zstd frame 触发 owned output wipe；allocation、异常、fallback、legacy、plaintext persistence 和 security-skip 计数保持为零。该 focused probe 不替代 attached-JVM resource open、AKEN page bound-plan、JNI cache re-authentication 或完整 artifact/session coverage，也不改变整体 coverage gate 的 `coverage-incomplete` 语义。

## 运行方式

`JS_RUNTIME_BENCH_MAIN` 生成独立可执行文件后：

```text
native_runtime_benchmark 100 16
native_runtime_benchmark 1000 16
native_runtime_benchmark 10000 16
native_runtime_benchmark 100000 16
native_runtime_benchmark --matrix 16
native_runtime_benchmark 100 16 --baseline baseline-security.txt
```

- 第二个数是 warmup 次数；`0` 允许用于极小 smoke run。
- `--matrix` 依次执行固定样本集 `100,1000,10000,100000`；因为每个样本集包含 1 MiB GCM/CTR/shell 阶段，完整矩阵应在专用性能机器上执行。
- 单阶段数据在 warmup 后重置计数器，`warmup_excluded=1` 表示 phase 的计数与延迟只包含已记录 samples。
- 仅用于完整 gate 评估的运行必须传入 `--baseline FILE`，或由嵌入式调用方使用 `js_runtime_benchmark_run_with_security_baseline(...)` 显式传入 `js_crypto_runtime_metrics` counter floor 和同 profile differential digest。旧的无 baseline API 仍可采样，但总结果会是 `security-blocked`，不会构成验收通过。

### 脱敏 baseline 文件格式

`--baseline` 文件只允许 `key=value` 计数器和 digest；不得包含路径、key、nonce、DEK、page plaintext、descriptor 或异常内容。空行和 `#` 注释允许；重复、未知、缺失或 malformed 字段会使 baseline 无效并 fail closed：

```text
auth_check_count=...
digest_check_count=...
tag_check_count=...
length_check_count=...
structure_check_count=...
jni_abi_check_count=...
wipe_count=...
differential_output_digest=0123456789abcdef
```

`differential_output_digest` 必须来自相同 build、相同 sample/warmup/profile 和相同 fixture 输入的 software-reference run。硬件路径上的缺失或 mismatch 均会被报告为 `security-blocked`。CLI 的 `--differential-output-digest HEX` 只能补充已经有效的 baseline record，不能替代 required counter floor。

## 每次运行必须归档的输出

```text
suite=... samples=... warmup=... sample_profiles=100,1000,10000,100000
capability hardware_aes=... hardware_ghash=...
phase=... timing_unit=ns percentile=nearest-rank samples=... p50=... p95=... p99=... max=...
phase=... phase_mode=production|synthetic-fixture|integration-adapter phase_status=pass|unsupported ...
metrics hardware_crypto_path=... software_crypto_path=... aes_block_count=... ghash_block_count=...
baseline_security status=valid|invalid|missing ...
coverage_gate status=pass|coverage-incomplete ...
security_gate status=pass|security-blocked ...
benchmark_result status=pass|coverage-incomplete|security-blocked
```

每个 `phase` 行还必须包含：

- `output_digest`；
- `allocation_count`、`allocation_bytes`、`exception_count`；
- `hardware_crypto_path`、`software_crypto_path`；
- `aes_block_count`、`ghash_block_count`；
- `vm_frame_reuse_count`、`vm_heap_fallback_count`、`resource_index_hit_count`、`decompress_context_reuse_count`、`jni_cache_hit_count`；
- `auth_check_count`、`auth_failure_count`、`digest_check_count`、`tag_check_count`；
- `length_check_count`、`structure_check_count`、`jni_abi_check_count`；
- `wipe_count`、`wipe_failure_count`、`plaintext_persistence_bytes`；
- `fallback_count`、`legacy_path_hits`、`security_checks_skipped`。

输出摘要是确定性的 sampled digest，仅用于检查同一 fixture 输入的结果一致性；它不包含计时值，因此可用于硬件/软件路径差分比较。

`coverage_status=incomplete` 表示本次 runner 存在明确的 synthetic 或 unsupported required production phase；它不是成功的 VM/JNI/AKEN 运行时声明。只要 `required_production_nonproduction_phase_count != 0`，总结果必须为 `benchmark_result status=coverage-incomplete`（安全问题优先时为 `security-blocked`），不得输出 `pass`。`benchmark_result=status=pass` 只有在全部 required production phase 均为真实 production coverage、baseline 有效且所有安全门禁通过时才允许。

`baseline_security` 必须由脱敏的同 profile baseline 提供，至少包含 `auth_check_count`、`digest_check_count`、`tag_check_count`、`length_check_count`、`structure_check_count`、`jni_abi_check_count` 和 `wipe_count`；实际值低于任一 baseline 时为 `security-blocked`。硬件路径必须提供同 profile software-reference 的 `differential_output_digest`，缺失或不一致同样为 `security-blocked`。

## Before / After 记录

| CPU / OS | Build | Samples | AES capability | PCLMUL capability | Phase | p50 ns | p95 ns | p99 ns | max ns | Output digest | Notes |
| --- | --- | ---: | --- | --- | --- | ---: | ---: | ---: | ---: | --- | --- |
|  | baseline | 100 |  |  |  |  |  |  |  |  |  |
|  | optimized | 100 |  |  |  |  |  |  |  |  |  |
|  | baseline | 1000 |  |  |  |  |  |  |  |  |  |
|  | optimized | 1000 |  |  |  |  |  |  |  |  |  |
|  | baseline | 10000 |  |  |  |  |  |  |  |  |  |
|  | optimized | 10000 |  |  |  |  |  |  |  |  |  |
|  | baseline | 100000 |  |  |  |  |  |  |  |  |  |
|  | optimized | 100000 |  |  |  |  |  |  |  |  |  |

## 安全门禁

以下任一项不满足时，报告状态为 `security-blocked`，性能数值不参与验收：

```text
auth_check_count < corresponding baseline
digest_check_count < corresponding baseline
tag_check_count < corresponding baseline
length_check_count < corresponding baseline
structure_check_count < corresponding baseline
jni_abi_check_count < corresponding baseline
wipe_count < corresponding baseline
baseline_security status != valid
hardware path without differential_output_digest
hardware/software differential_status != match
security_checks_skipped != 0
fallback_count != 0
legacy_path_hits != 0
wipe_failure_count != 0
plaintext_persistence_bytes != 0
auth_failure_count != 0
exception_count != 0
output_digest mismatch for equivalent hardware/software run
coverage_gate status != pass
benchmark_result != pass
```

`hardware_ghash` 是 CPU capability/self-test 的报告字段；只有 phase 中实际 `hardware_crypto_path` / `software_crypto_path` 计数可以说明已执行的 AES dispatch。GHASH 实现路径应由对应 native crypto 证据和 differential test 共同确认，不能仅根据 capability 位推断。
