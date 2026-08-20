# JavaShroud Native 运行时极限性能实施计划

## 1. 范围和固定决策

### 保留内容

- 保留当前工作树中的 Kotlin、Java、C、测试、桌面端和文档改动；
- 保留已有的 native 编译、打包、AKEN、shell、ABI、协议和安全强化改动；
- 不执行 `git reset`、`git clean`、破坏性 checkout 或批量覆盖；
- 不撤回 `NativeRecompilationTransforms.kt`、`js_crypto.c`、`js_vm_core.c` 等已有差异；
- 不新增 Rust workspace、Rust crate、Rust backend 或 Rust FFI。

### 本轮新增内容

本轮新增优化只针对最终构建产物的运行时性能：

- native AES-GCM/CTR、GHASH、AKEN page authenticated open；
- VM instruction dispatch、VM execution frame、locals/stack/operand scratch；
- JNI method/class lookup、resource alias/commitment lookup；
- zstd decompression context、native shell decode/loader hot path；
- Windows x64 AES-NI/PCLMUL 硬件加速。

### 明确不做的事项

- 不把编译期优化作为验收目标；
- 不重新设计 AKEN v4、JSRP、Native/JNI ABI；
- 不减少认证、完整性、结构、长度、tag、digest、binding 或 verifier 检查；
- 不引入旧 artifact/protocol fallback；
- 不使用 prebuilt native fallback；
- 不缓存密钥、DEK、nonce、page plaintext 或未经认证的 native/resource bytes。

## 2. 阶段 A：运行时基线和可观测性

新增 native benchmark fixture，覆盖 AES-128-GCM、AES-256-GCM、AES-CTR、GHASH/AAD、4 KB/64 KB/1 MB page、AKEN page open、repeated resource open、VM prepared program repeated execution、nested VM execution、JNI method/class lookup、zstd decode 和 shell payload decode。

每个 benchmark 执行 warmup，并对 100、1,000、10,000、100,000 次样本记录 p50/p95/p99/max、CPU capability、hardware/software path、allocation count、auth check count、wipe count、exception count 和 output digest。

脱敏指标结构：

```text
NativeRuntimeMetrics
CryptoRuntimeMetrics
VmRuntimeMetrics
ResourceRuntimeMetrics
RuntimeSecurityCounters
```

只记录硬件/软件路径、AES/GHASH block 数、frame/context/cache 命中数、认证/失败/wipe/fallback/legacy 计数、阶段延迟统计和 plaintext persistence 字节数；禁止记录 key、nonce、DEK、page plaintext、原始路径、源码、descriptor secret 或完整异常 payload。

优化前后固定并比较：

```text
auth_check_count
digest_check_count
tag_check_count
length_check_count
structure_check_count
jni_abi_check_count
wipe_count
fallback_count
legacy_path_hits
plaintext_persistence_bytes
```

验收要求：安全检查数量不低于 baseline，security skips、fallback、legacy path、wipe failures 和 plaintext persistence 均为零。

## 3. 阶段 B：AES-GCM/CTR 和 GHASH

涉及 `js_crypto.c/.h`、`js_shell_crypto.c/.h`。

- 每次 GCM/CTR operation 只展开一次 key，使用 `js_aes_schedule`；H、J0、tag mask 和 counter block 共用 schedule；
- operation、异常、认证失败和 session invalidation 都 wipe；schedule 不跨 artifact/page/thread/session 保存；
- Windows x64 运行时 CPUID 检测 AES-NI、PCLMULQDQ，使用一次性线程安全的 immutable dispatch；硬件不可用、自测失败或 capability/fn-pointer 错误时走同协议 software path；
- 硬件和软件路径保持相同 key length、nonce、AAD、ciphertext、tag、length block、constant-time compare、failure wipe 和 artifact binding；
- software GHASH 使用 constant-time、固定访问模式、固定 stack scratch，不使用 secret-indexed table，不减少 GHASH block；
- shell payload decode、chunk tag、payload commitment、nonce/AAD 和 inner image authentication 复用相同 schedule/dispatch；完整认证前不得映射或执行 inner image。

## 4. 阶段 C：VM execution frame

涉及 `js_vm_core.c/.h`、`js_vm_internal.h`。

```c
typedef struct {
    js_vm_insn *insns;
    js_vm_value *locals;
    js_vm_value *stack;
    jint *operand_scratch;
    size_t insn_capacity;
    size_t locals_capacity;
    size_t stack_capacity;
    size_t operand_capacity;
    unsigned int generation;
    unsigned int depth;
    unsigned int active;
} js_vm_execution_frame;
```

- 重复使用已分配 frame、locals、stack 和 operand buffer；resident instruction state 仍复制到 private execution state；不得直接执行共享 resident mutable instruction array；
- Windows x64 使用 FLS 或验证过的 thread-id frame map；Linux/macOS 使用 pthread TLS destructor；线程退出时 wipe，frame 不跨线程复用；TLS/FLS 失败时使用受锁保护的 bounded pool，争用时等待或 fail-closed；
- 支持 nested VM、recursive virtualized call、lambda、invoke-dynamic、异常语义和 method re-entry；固定 depth 上限，超限 fail-closed，不覆盖外层 frame；
- 进入执行前验证 session/layout generation、获取并校验 frame 容量、复制 resident state、初始化 locals/stack/operand、推入 active program；退出时清理 JNI 引用、wipe VM values/operand/instruction mutable fields、清除 owner/generation 并归还 frame；所有异常、取消、JNI exception、allocation/loader failure 走统一清理路径；
- 允许 immutable opcode metadata、operand width、handler category、constant-pool classification、hot opcode hint、primitive return fast path 和预分配小 operand buffer；不得跳过 bounds、epoch、rotation、exception table、session/JNI exception 或 resident-state copy。

## 5. 阶段 D：Resource、JNI 和 zstd 热路径

涉及 `js_vm_resource.c`、`js_jni_runtime.c`、`js_vm_symbol.c`。

- 为当前 artifact/session 建立 immutable alias/commitment/resource-kind/logical-identity/page/route/layout-generation index；alias/hash/route 重复直接 fail-closed；index 不跨 artifact 复用且不含 plaintext、DEK、nonce；首次使用和 cache restore 仍重新认证 binding；
- zstd context 按线程/会话复用，使用 bounded scratch、capacity reuse 和 generation check；session close 时 wipe/release；认证前不得暴露解压明文，失败后不得保留 partial plaintext；
- JNI cache 仅缓存 `jclass` global reference、`jmethodID`、`jfieldID`、loader identity 和 artifact/session generation；每次使用前检查 loader、generation、class binding、ABI 和 session，mismatch 时清除并重新解析/认证，失败 fail-closed。

## 6. 阶段 E：native loader

只复用已经验证的 segment metadata、relocation batch、import/export lookup index、section address calculation、loader string parsing 和 immutable mapping metadata。

每次执行仍验证 architecture、section/segment bounds、relocation target bounds、import/export、W^X、JNI symbol、native digest、resource route、artifact binding 和 final commitment；tag/auth 前不得映射 inner image，不得复用其他 artifact/session image 或旧 function pointer，不得使用旧 shell/prebuilt fallback。

## 7. 测试和验收矩阵

### Crypto

保留并新增 AES-128/256 KAT、GCM empty/partial/AAD/large、CTR boundary、software/hardware differential、capability-disabled/unsupported、wrong key/nonce/AAD/tag、truncation、length overflow、chunk reorder/duplication 和 cross-artifact replay。

### VM

覆盖 100,000 次单线程、多线程、nested、recursive、lambda/invoke-dynamic、exception、session invalidation、generation mismatch、capacity growth、depth overflow、TLS/FLS init failure、thread-exit cleanup、allocation failure、cancellation/crash injection、forced software/hardware dispatch。

### Resource/JNI

覆盖 alias/commitment collision、repeated/concurrent resource open、cross-artifact replay、stale generation/loader、zstd failure、plain length overflow、partial-output wipe、JNI exception、invalid cache 和 cache-hit re-authentication。

### 真实语料和攻击矩阵

对 `E:\speedfix\SimpleFiveInARow.jar` 与 `E:\XiangMu\SimpleFiveInARow-master\JavaObfuscatorTest-main\bench\bin\TEST.jar` 运行 default、native、VM、native+VM、string、loader、resource、reflection、exception、random order、source rebuild、prebuilt JAR、Pool deterministic lane 和 SecurityManager compatibility lane；并执行 class/native/shell/descriptor/route/layout/AAD/nonce/tag/length tamper、duplicate/reorder、cross-artifact swap、stale frame/cache、CPU capability spoof、crash injection。

所有攻击 case 必须 fail-closed、无 partial runnable artifact、无异常吞咽、无 plaintext residue、无 legacy/ABI fallback。

## 8. 性能门禁

安全失败、auth checks 低于 baseline、security checks skipped、fallback/legacy/wipe failure/plaintext persistence 非零、hardware/software differential 不一致、ABI 不一致、新增 VerifyError/LinkageError/BootstrapMethodError/native crash 时直接标记 `security-blocked`。

Windows x64 目标：AES-GCM/CTR 至少 3x 软件 baseline、AKEN page open p95 至少 2x、VM 高频 execution p95 至少 2x、resource repeated-open p95 至少 1.5x；SimpleFiveInARow readiness 与 JavaObfuscatorTest startup marker p95 <= 1500 ms，Calc 结果计数保持 30000。

非硬件平台自动使用 software path，不出现 illegal instruction/native loader error，语义等价且相对 baseline 不超过 10% 回归，安全检查数量不下降。

## 9. 实施顺序

1. 固定 baseline 和 runtime benchmark；
2. 加入 runtime metrics；
3. 完成 AES schedule；
4. 完成 Windows x64 AES-NI/PCLMUL；
5. 完成 software/hardware differential；
6. 完成 VM execution frame reuse；
7. 完成 TLS/FLS/线程隔离；
8. 完成 nested/recursive frame 测试；
9. 完成 resource immutable index；
10. 完成 zstd context reuse；
11. 完成 JNI cache generation binding；
12. 完成 native loader validated metadata reuse；
13. 执行安全攻击矩阵；
14. 执行 JavaObfuscatorTest 双轨矩阵；
15. 执行 SimpleFiveInARow readiness；
16. 生成 before/after 性能报告；
17. 安全门禁通过后默认启用硬件路径和 frame reuse；
18. 保留同协议 software path；
19. 记录未覆盖 CPU、平台和 runtime path。

## Goal linkage

This file is incorporated by reference into the active Codex goal for this
thread. Its complete scope, fixed decisions, implementation phases, security
invariants, test matrix, performance gates, and implementation order are
binding goal text; the active goal must be evaluated against this file rather
than against a shortened summary.

- Authoritative plan file: `E:\XiangMu\JavaShroud-public\docs\native-runtime-extreme-performance-plan.md`
- Active goal thread: `01a016e1-0ba2-7d62-a16c-350682bc6f8d`
- Goal status at linkage time: `active`

```text
Execute and verify the complete JavaShroud Native runtime extreme-performance
plan defined in E:\XiangMu\JavaShroud-public\docs\native-runtime-extreme-performance-plan.md.
Treat that file's full contents as the bound goal text and sole acceptance
source. No separate repository mirror is used; the `docs` path above remains
the sole authoritative plan file.
Preserve unrelated worktree changes, retain all current
artifact/protocol/ABI security checks and fail-closed behavior, and do not
introduce legacy/protocol/ABI/prebuilt fallback, Rust workspace, or Rust FFI.
Keep the goal active until the plan's security gates, builds, tests, and
performance acceptance criteria are all satisfied.
```
