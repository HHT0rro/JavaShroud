# JavaShroud 加固后逆向安全性复核（源码暴露威胁模型 · 第二轮）

> 复核对象：当前工作树（未提交改动，78 文件 +4652/-540 行），对照 `plan/self-decrypt-hardening-plan.md` 的实施情况。
> 基线：`docs/REVERSE_SECURITY_ANALYSIS.md`（第一轮分析）；前提不变：**自解密设计保留，KEK 可离线重放属预期**。
> 方法：13 路并行源码复核（observed/inferred 分级）+ 目标测试集真实执行。
> 测试执行（observed）：Gradle 8.10，`:core-engine:test` 目标子集 **8/8 测试类、16/16 用例全部 PASS**（2026-08-12 运行，含 NativeClassEncryptionRuntimeRegressionTest 真实产物 e2e，61s）。

## 0. 执行摘要

**本轮加固真实落地了 P0 的一半，且落地部分质量高；但两个决定性攻击面未闭合：**

1. **Windows/macOS 动态对抗未实施**（计划 2.2 完全未动）：`js_detect_instrumentation` 仍 Linux-only（`js_vm_core.c:3706-3708`），anti-dump 仍 Windows no-op（`js_antidebug.c:36-41`）。新增的 sensitive-path guard 在 Windows 上只剩 PEB 反调试+trampoline 两条腿——**Frida attach（非调试器、不 patch 入口字节时）在 Windows 上对全部密钥路径仍无检测**。基线"Windows 上 Frida 如入无人之境"的结论未被消除。
2. **Java 层收割路径存活**：`cachedDecodeString` 单点 hook 不变；`jsn_k10` 明文返钥通道 + `MethodBodyDecryptionHelper` 的 JCA 链原样存活；anti-instrumentation 默认 log 且 **refuse 被三个 helper 的 `catch(SecurityException ignored)` 吞掉**（即使手动配 refuse 也无效，新确认的阻断缺陷）；defineClass 仍在 Java 层明文回调。

净效果：攻击者持源码在 **Windows + javaagent/Frida（hook Java 层）** 这一最典型组合下，依然能源源不断收割明文字符串与类。本轮修复主要抬高的是"Linux native 层调试/patch"的成本。

## 1. 判定矩阵（对照基线发现）

| # | 基线发现 / 加固项 | 判定 | 关键证据（当前工作树） |
|---|---|---|---|
| 1 | 类解密主链密钥跨 JNI + JCA 解密 | **FIXED（主链）** | `jsn_k14`（`js_vm_core.c:7031-7093`）HKDF+AES-GCM 全在 native，派生密钥 wipe 不出 native；`ClassEncryptionLoaderHelper` 无 `javax.crypto`；e2e 测试 PASS |
| 2 | └ 残留：`jsn_k10` 明文返钥 + `MethodBodyDecryptionHelper` JCA 链 | **PARTIAL（存活）** | `js_vm_core.c:7025-7026`；`MethodBodyDecryptionHelper.java:54,157-162`；注册项 `DeriveClassEncryptionKey` 仍在（`js_jni_runtime.c:593`） |
| 3 | defineClass Java 层明文回调 | **PARTIAL**（驻留缩短，窗口未消除） | `ClassEncryptionLoaderHelper.java:492-495`（finally 清零为新增缓解） |
| 4 | 密钥路径零检测 → 双层 sensitive-path guard | **FIXED（code-level）** | guard（`js_vm_core.c:3714-3724`）挂于 k7/k10/k14/k15/r21 inner+wrapper 双层；fresh probe（`js_vm_strong_debugger_present_now`）；命中擦除 shares+SecurityException fail-closed |
| 5 | Windows/macOS Frida 扫描、anti-dump | **UNFIXED**（最大未闭合项） | `js_vm_core.c:3706-3708` `#else return 0`；`js_antidebug.c:36-41` 仅 Linux prctl |
| 6 | 字符串明文永久缓存 | **FIXED（缓解）** | off/soft/strong 三档，默认 soft（`StringEncryptionHelper.java:93-95`）；soft 仅内存压力下回收，非消除 |
| 7 | 字符串调用点单点 hook | **UNFIXED** | 调用点形态不变（`bytecode/StringEncryptionTransforms.kt:203`），Java 层 hook 不受 native gate 约束 |
| 8 | shares 常驻 .bss 可扫描重组 | **UNFIXED** | 布局/生命周期零改变（`js_vm_core.c:1818`）；external-file 部署下仍是唯一全量恢复通道 |
| 9 | Java anti-instrumentation（默认 log/clinit 单次/动态 attach） | **UNFIXED + 阻断缺陷** | 默认 log（`NativeKernelTransforms.kt:41,343,521`）；**refuse 被吞**：`AntiJvmTiHelper.java:11`、`AntiInstrumentationHelper.java:15`、`AntiByteBuddyHelper.java:11` catch SecurityException；无周期化、无 attach 痕迹检测 |
| 10 | VBC4 元数据自爆身份（W2） | **FIXED** | `vbc4-meta-v2`：HMAC 身份 + 参数形态串（`VmBytecodeSerializer.kt:72-102`）；native 侧 hash 匹配配套。残留：调用点 CP 引用仍是密封但可重放的重命名后明文+完整描述符 |
| 11 | ISA per-build 随机化 / 通用 devirtualizer 断裂 | **PARTIAL/UNFIXED** | 落地的是语义分割（head+share 双行，max-hardening 门控，`VmBytecodeSerializer.kt:481-519`）+ keyed manifest magic；canonical ISA/dispatch 仍固定公开，一套解码工具通吃所有构建 |
| 12 | 虚拟化覆盖率扩大（默认开/80% 门槛/lambda$ 本体） | **UNFIXED** | `VmProtectionCapabilityBuilder.kt:27` 仍默认关；无覆盖率统计；`lambda$*` 本体仍跳过（`MethodVirtualizationTransforms.kt:2588`） |
| 13 | 基本块重排 + 不透明谓词 | **UNFIXED/PARTIAL（弱）** | 无基本块重排（`EdgeInjectionTransforms.kt:32` 自述）；`__js_flow_state` 恒零字段谓词可被平凡规则静态求解 |
| 14 | W9 MONITOR / W10c lambda / W10d 假异常 | **FIXED**（W10d 残留 decoy 固定前缀 `javashroud/decoy/E` 可机械剔除） | `js_vm_core.c:550-574,6824-6831`；`InvokeDynamicVmSupport.kt:136-161`；`VmBytecodeSerializer.kt:1288-1299` |
| 15 | KEK 自解密结构（三处明文 binding、embedded 明文 hex） | **NA-BY-DESIGN**（按前提保留） | `BootKekSidecar.kt:96`；`EmbeddedHelperDeployment.kt:317`；`NativeKernelShellPacker.kt:366` |
| 16 | 默认配置基线（默认 pipeline 无保护；bootKeyDelivery 默认 external-file） | 维持 + delivery 校验 fail-closed | `SchemaCapabilities.kt:23-25`；`NativeKernelCapabilityBuilder.kt:303-317` |
| 17 | native 残余秘密：`.jsx` lanes | **NA-BY-DESIGN**；`JS_KEY_OBF` **UNFIXED** | `JS_KEY_OBF` 全局固定（`js_kernel.c:49-68`）不被自解密前提豁免，可伪造完整性 MAC |

## 2. 新引入问题（本轮新增代码带入）

1. **jvm-resolver 字符串后端（REGRESSION 性质，非默认）**：强引用 `String[]` 缓存 + `.intern()` 进常量池（`EmbeddedStringResolverTransforms.kt:367,557,639`）——比基线 ConcurrentHashMap 更差，且不受 `stringCache` 约束、不受 native guard 保护；des codec 在生成代码中重新引入 `javax.crypto.Cipher` 调用点（`:604-636`）。`strings-*` profile 显式断言不注入 jni-microkernel（`ResolverProfileMatrixTest:106-133`），即该链无任何检测。
2. **全零 binding 静默回退**：`BootKekSidecar.requireArtifactBindingForBuild()` 在 provider 缺失/文件不可读时静默返回 32B 全零 binding（`:57-66`）——anti-replay 语义失效且全部走此路径的构建共享 wrapping key，建议 fail-closed。
3. **可机械剔除的指纹/谓词三件套**：`$_jsr_` resolver 前缀（被 rename 显式排除故稳定存在）、`__js_flow_state` 恒零字段 + 固定三指令模板、`javashroud/decoy/E` decoy 前缀。修复方向一致：随机化命名、谓词依赖运行时态。
4. **硬件绑定静默降级**：`js_env_binding_token_hardware` 在 expected_fingerprint 为空时静默回退 salt-only（`js_vm_core.c:3464-3470`）。
5. **文档误导面**：`TECHNICAL.md:185` 主配置示例采用 `bootKeyDelivery="embedded"`（最弱档）且无相邻警示；embedded 段（:228）无机密性警告。

## 3. 测试有效性结论

- 目标测试集 8/8 类 16/16 用例真实 PASS（observed，本轮执行）。
- 套件整体诚实，但三处**绿灯假象**需在引用时消歧：① `SelfDecryptBoundaryHardeningTest` 只断言 guard 字符串存在 ≠ Windows 有效，且不覆盖 MethodBody JCA 残留链；② `BootKekSidecarTest` 的"无明文 KEK" ≠ KEK 机密（自解密结构内）；③ `EmbeddedBootKeySealingTest` 名为 Sealing 实为路径改名，显式锁定字节不变。
- 计划自定的动态验证项（调试器附着返回垃圾、Frida attach fail-closed、heap dump 命中率、Transformer 捕获、native 内存扫描）**全部无对应测试**；`scripts/max_hardening_case.py` 等红队脚本未接入 CI（计划 4.1 UNFIXED）。

## 4. 下一轮优先级（按攻击者成本排序）

1. **补 Windows/macOS 检测**（计划 2.2）：模块扫描 + anti-dump——否则 guard 在最主要平台上形同虚设。
2. **修 refuse 吞异常**（三个 helper 的 catch）→ 再改默认 refuse → 周期化 → attach 痕迹检测（计划 2.3 的正确顺序）。
3. **收敛 `jsn_k10`/`MethodBodyDecryptionHelper` 残留链**：延迟方法体解密下沉 native 后删除 `DeriveClassEncryptionKey` 注册项。
4. **字符串调用点多样化**或把解密调用点所在方法纳入虚拟化（关联 3.1）。
5. **shares 分散存储 + 惰性拆分**（计划 2.4）：external-file 部署下的最后通道。
6. **小项**：全零 binding 改 fail-closed；decoy/`$_jsr_`/`__js_flow_state` 去固定前缀；TECHNICAL.md 主示例改回 external-file 并补警示；`JS_KEY_OBF` 每构建重写。
7. **CI 红队套件**固化（计划 4.1）+ 动态验证测试补齐。

## 5. 证明边界

- 除目标测试集真实执行外，全部结论为静态源码审查（observed 级为主）；guard 在 Windows 的无效性为代码级推断（`#else return 0` 为 observed），无误报率/attach 场景动态证据。
- 测试通过仅证明功能与断言成立，安全属性（密钥不跨 JNI、抗 hook）以源码审查为据。
- 复核范围 = git status 列出的 78 个改动文件 + 新增文件 + 其直接调用链；未重新全量审查未改动文件。
