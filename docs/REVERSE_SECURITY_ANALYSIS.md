# JavaShroud 混淆产物逆向安全性分析（源码暴露威胁模型）

> 前置阅读：`docs/KEY_DECRYPTION_ANALYSIS.md`（key 解密链路详解）。
> 本文回答一个问题：**攻击者同时拥有混淆器完整源码（本仓库即公开）和混淆产物时，哪些防线还成立，哪些形同虚设。**
> 结论分级：【可行】= 攻击者可稳定达成还原目标；【部分可行】= 需特定条件（注明）；【不可行】= 该路径在密码学/设计上成立。

## 0. 执行摘要

**总判定：在当前实现下，除"external-file 交付且 sidecar 文件不泄露"这一种部署形态外，混淆产物的全部加密层均可被还原。**

三条决定性事实：

1. **Boot KEK 的两种产物内/随包交付方式都是自解密的**。max-hardening 的 JSBK sidecar 把 artifactBinding 明文写在 sidecar 内（`BootKekSidecar.kt:96`），而包裹密钥 = `HMAC(binding, domain‖salt)`，salt 也在 sidecar 内——KEK 对持产物者零秘密。非 hardened 更糟：embedded 交付直接写明文 hex KEK 进 jar（`EmbeddedHelperDeployment.kt:316-317`）。
2. **所有密钥和明文最终必须跨 JNI 边界进入 JVM**（defineClass、String 使用），边界上的 Java 方法（`nativeDeriveClassEncryptionKey`、`cachedDecodeString`、`decryptClassBytes`）是无检测、可重复的稳定 hook 点。
3. **native 层的全部加固只覆盖"方法虚拟化执行"这一条链**。字符串解密（`jsn_r21`）、类密钥派生（`jsn_k10`）、boot 安装（`jsn_k7`）函数体内没有任何 anti-debug/instrumentation 检测调用。

---

## 1. 威胁模型与基线

- 攻击者持有：混淆器完整源码 + 产物 jar + 产物 native 库（+ 可选：sidecar 文件、对运行进程的动态分析能力）。
- 默认配置基线：不显式配置时 pipeline 只含 `strip-compile-debug-info`（`SchemaCapabilities.kt:23-25`），**所有加密/虚拟化/密钥 pass 全部默认关闭**（`EncryptionCapabilityBuilder.kt:18`、`NativeKernelCapabilityBuilder.kt:200` 等，risk=high 强制 opt-in）。默认构建等同未保护，以下分析均针对显式启用了全部保护的产物。
- seed 参数不构成弱点：nativeSeed/masterKey/BootKEK 均强制掺入 SecureRandom 熵（`Vbc4BuildContext.kt:255-257,302-311`；`EngineCliRunSupport.kt:57,62`），知道 seed+源码也无法复现密钥——【不可行】，此项设计正确。

## 2. 静态攻击面（纯离线，不运行产物）

### 2.1 KEK 交付模式判定矩阵（核心）

| 交付模式 | 判定 | 证据 |
|---|---|---|
| embedded + 非 hardened (v2) | 【可行】 | `META-INF/.r/kek.dat` 为裸 hex KEK（`EmbeddedHelperDeployment.kt:303-318`），AAD 为固定常量（`BootMaterialEnvelope.kt:80`） |
| embedded + max-hardening (v3) | 【可行】 | JSBK sidecar 自解密（见下） |
| external-file + sidecar 随包分发 | 【可行】 | max 档 sidecar 是明文 hex（`EngineCliRunSupport.kt:64-66,75`）；max-hardening 档 JSBK 同样自解密 |
| external-file + sidecar 离线保管 | 【不可行】 | KEK 为 CSPRNG，jar 内仅有 AES-GCM 密文 |
| env 变量（仅 v2 可用） | 【不可行（纯静态）】 | 产物内无 KEK 材料；但与 max-hardening 互斥（`JniMicrokernelHelper.java:1382`） |
| + bootSecretEnvBinding 机器指纹掩码 | 不改变结论 | 掩码密钥为**全零常量**，`mask = HMAC(0-key, "javashroud-boot-env-mask-v1"‖fingerprint)`（`JniMicrokernelHelper.java:1440-1484`）；指纹是任意本地用户可读的 MachineGuid/machine-id（`js_machine_id.c:37-69`），期望指纹随产物发布（`RuntimeArtifactSealing.kt:792-793`）——可完全离线重放 |

### 2.2 max-hardening 的自解密缺陷（详述）

artifactBinding 由混淆器自己 SecureRandom 生成（`EngineCliRunSupport.kt:62`），**不是外部秘密**，且以明文出现在产物内的三个位置：

1. JSBK sidecar 偏移 10..42（`BootKekSidecar.kt:96`，运行时 `embeddedBinding()` :187-188 直接明文切片读出）；
2. hardened boot.dat 信封头部偏移 6..38（`BootMaterialEnvelope.kt:87-88`）；
3. max-hardening native stub 的 rodata：`static const unsigned char js_shell_boot_sidecar_binding[32]`（`NativeKernelShellPacker.kt:366`）。

KEK 包裹密钥 = `HMAC-SHA256(binding, "JavaShroud/BootKekSidecar/v1/key"‖salt)`（`BootKekSidecar.kt:269-281`），salt 也在 sidecar 明文（偏移 42）。**全部输入皆公开 → 持 jar（embedded）或 jar+sidecar（external-file）即可离线解出 KEK → 解 boot.dat（masterKey/layoutDigest/全部 slot 密钥）→ 按源码 HKDF 链重放，还原全部字符串/类/资源密钥。**

binding 的真实设计目的只是防跨产物重放（`BootKekSidecar.kt:15-21` 注释自述），它从未提供 KEK 机密性。`BootMaterialEnvelope.kt:10-14` 明确假设 "the KEK is deliberately obtained outside the output artifact"——embedded 交付和随包分发 sidecar 都违背了这一假设。docs/TECHNICAL.md:142 也自述"产物自包含运行所需材料，不宣称绝对不可逆"。

### 2.3 native 二进制残余秘密（密钥与密文同盒）

| 目标 | 判定 | 证据 |
|---|---|---|
| `.jsx` 保护段明文代码 | 【可行】无条件 | 密钥以 4 条 lane+mask 编译进产物（`native_secrets.inc:155-174`），重组算法公开，keystream = `SHA256(key‖ctr)`（`js_protected_section.c:70-102` ↔ `NativeProtectedSectionPacker.kt:393-412`）。纯机械操作，熵为零 |
| JNI 抹除字符串（JDK 类/方法名表） | 【可行】无条件 | AES-CTR KEY/IV 为编译期 `static const`（`native_secrets.inc:10-11`）；范围仅限 38 项固定 JDK 名称（`NativeRecompilationTransforms.kt:1011-1014`），价值低，但暴露反调试反射入口 |
| `JS_KEY_OBF` 完整性校验 key | 【可行】无条件 | 全局固定、跨构建不变（无构建期重写逻辑），按源码 `js_kernel.c:56-68` 直接解码；可伪造 native 完整性 MAC、绕过反篡改自校验 |
| shell payload `encryptedSeed` | 【不可行】严格无 KEK 时 | `js_shell_open_seed_envelope` 需 boot_secret 派生（`js_shell_crypto.c:382-398`），stub 内无编译期秘密——这条链的密码学设计本身成立；但 embedded 交付下前提崩塌（同 2.2） |

## 3. 运行时攻击面（动态分析）

| 攻击 | 判定 | 证据与条件 |
|---|---|---|
| dump 明文字符串 CACHE | 【可行】 | `StringEncryptionHelper.java:10` 的 `ConcurrentHashMap` 永久缓存所有已解密 String；反射读取或 heap dump 即得，无时序竞争 |
| hook JNI 边界持续 dump 类密钥 | 【可行】 | `jsn_k10` 经 JNI 明文返回派生密钥（`js_vm_core.c:6999-7000`）；Java 侧 `deriveClassEncryptionKey` 是 public 方法（`JniMicrokernelHelper.java:114`）；亦可直接 hook `javax.crypto.Cipher`（JDK 类，混淆器管不到）。**本模型下最廉价的攻击点** |
| hook 字符串解密链 | 【可行】 | hook `cachedDecodeString`（`StringEncryptionHelper.java:16`）或直接读 CACHE；`jsn_r21` 函数体内无任何检测调用 |
| 提取根密钥 shares | 【可行】 | `js_runtime_resource_key_shares[17][3][32]` 常驻 .bss（`js_vm_core.c:1816`），进程生命周期不清零；持源码知确切布局，进程内存扫描+XOR 即得 anchor/master key，无需抓栈窗口 |
| defineClass 明文拦截 | 【可行】 | 解密全在 Java（`ClassEncryptionLoaderHelper.java:294,341-351`），`defineClass` 时 JVM 以明文回调 ClassFileTransformer（`:480-487`） |
| 加载窗口截取 boot 密钥 | 【部分可行】 | v2 envelope 在 Java 侧解密（`JniMicrokernelHelper.java:1621-1629`），明文 material 经过 JVM 堆；窗口 = `prepareJavaBootMaterialForLoad`→`finally`（`:1870-1885`）。窗口外 `runtimeResourceKeys` 不驻留（finally 无条件清除） |
| native anti-debug 防护 | 【部分可行（可绕过）】 | 检测存在但盲区明确：① anti-trace 只在 VM dispatch 循环触发（`js_vm_core.c:6434-6446`）——只保护被虚拟化的方法；② `jsn_k7/k10/r21` 无检测；③ Frida 扫描仅 Linux 分支，Windows/macOS 恒返回 0（`js_vm_core.c:3687-3706`）；④ anti-dump 在 Windows 为 no-op（`js_antidebug.c:36-41`）；⑤ Java 层 anti-instrumentation 默认 response=log（`NativeKernelTransforms.kt:41`）、只在被保护类 clinit 触发一次、动态 attach 可完全规避 |

## 4. 仍然成立的防线

1. **Boot KEK 离线保管**（external-file + sidecar 不随包、或 env 交付）：静态分析不可行，密钥链收敛于 CSPRNG——Kerckhoffs 设计正确（docs/TECHNICAL.md:135）。
2. **方法虚拟化（vm-diverse）覆盖的方法内部**：唯一有 anti-trace 毒化（错误 seed 产出垃圾明文，`js_vm_core.c:428`）和 trampoline 自检的路径；历史案例表明其仍可被深度逆向（VBC4 资源重组、parser dump、dispatch 表恢复均已达成），但成本显著高于其他链。
3. **密码学原语选择**：AES-GCM/HKDF-HMAC 域分离、先认证后解密、fail-closed——算法层面无弱点；所有失败都出在密钥交付与边界暴露，不在密码学。

## 5. 加固建议（按投入产出排序）

1. **消除自解密 sidecar**：JSBK 的 wrapping key 不得由产物内的 binding 派生。可选：binding 改为外部部署秘密；或 embedded 交付整体标记为"仅便利、无机密性"并从 hardened profile 中移除，强制 external-file。
2. **加固 JNI 边界**：`jsn_k10` 不应把类密钥明文返回 JVM——把 AES-GCM 解密下沉到 native，Java 只接收待 defineClass 的字节；或在 native 内直接调 defineClass。字符串链同理考虑 native 侧直返 String（仍不可避免 JVM 明文，但消除可 hook 的 key 通道）。
3. **把检测挂到密钥路径**：`jsn_k7/k10/r21` 入口调用现有的 `js_vm_strong_debugger_present`/`js_check_trampoline`；Windows 补 Frida 模块扫描与反 dump；Java 层 anti-instrumentation 默认 response 改 refuse，并从 clinit 单次改为周期性检查。
4. **缩短 shares 驻留**：boot 完成后对不用的 slot shares 延迟拆分/按需清除；`runtimeResourceKeys` 的 v2 加载窗口改用 direct ByteBuffer 传递。
5. **明文字符串 CACHE 加限**：提供 no-cache 模式或软引用缓存，降低 heap dump 一次性全量泄露。
6. **文档明示安全边界**：把"embedded/随包 sidecar = 仅防静态小白，不防持源码攻击者"写进 TECHNICAL.md 的 profile 说明，避免用户误判保护强度。

## 6. 证据与证明边界

- 证据类型：全部为**静态源码审查**（4 路并行通读构建端 Kotlin、运行时 Java helper、native C），结论附 文件:行号；未对真实产物做动态验证。
- 标注为【可行】的运行时攻击（第 3 节）属于"路径存在且无防护拦截"的源码级推断，置信度高但未逐一实操复现。
- 历史动态证据（技能案例手册 `javashroud_vbc4_reverse_case.md`）：此前真实产物已实现 VBC4 资源 584/584 重组、native parser dump、四级 dispatch 表恢复——佐证虚拟化链亦非终点。
- 未覆盖：JVM 层 jvm-resolver 字符串后端、桌面端打包含义、zstd 压缩面的侧信道，均为次要路径。
---

## 7. 2026-08-11 — P0 实施后复评、验收目标与证明边界

> 第 2–3 节是 P0 落地前的静态基线。本节记录当前工作树与 CASE 证据：若干最低成本的 JVM/JCA hook 点已收敛，真实 sealed class-decrypt 产物链已通过 verifier 回归；自解密交付的 KEK 边界、跨平台动态对抗和 CASE `0/142` 仍保持原结论。

### 7.1 当前边界变化

| 原攻击面 | 2026-08-11 当前状态 | 复评 |
|---|---|---|
| JNI 返回 class key + Java `Cipher` 解密 | `ClassEncryptionLoaderHelper` 已调用 public `JniMicrokernelHelper.decryptClassBytes(...)`；native `jsn_k14` 在 native 内派生 key 并执行 AES-GCM。 | **已收敛（正常 encrypted-class 主链）**：class key 不再通过该主链返回 Java，helper 的 JCA AES-GCM hook 已移除。`MethodBodyDecryptionHelper` 的另一条延迟 method-body 链仍保留 raw key `byte[]` 与 Java `Cipher`，不应并入该结论。 |
| shell/inner JNI 注册与 ABI | `JS_NATIVE_ABI_TABLE_VERSION=9`；inner ABI 与 shell forwarding table 均包含 `nativeDecryptClassBytes`/`jsw_k14`（`([B[B[B[B[BI)[B`）及 `nativeSealedBindingKey`/`jsw_k15`（`([B)Ljava/lang/String;`）。 | **已覆盖 focused 注册链**：class-decrypt runtime 与 native binding-key regressions 记录 shell/inner 转发；其他平台/profile 仍需回归。 |
| `jsn_k7/k10/r21` 无检测 | `js_vm_sensitive_path_guard` 同时覆盖 inner `jsn_k7/k10/k14/k15/r21` 和 JVM 直接注册 wrapper `jsw_k7/k10/k14/k15/r21`；两层均检查 trampoline、fresh debugger 和当前 instrumentation。 | **已实现 code-level 双层 gate**：不能仅绕过 wrapper 或直接调用 inner 入口来跳过检查，keyed binding identity 同样受 gate 保护；Windows/macOS 动态覆盖和误报尚未证明。 |
| `jsn_k10` JNI 长度边界 | `id_len`、`salt_len` 先分别限幅，再用 `id_len > 4096 - salt_len` 防止 signed `jsize` 相加溢出，最后才转换为 `size_t`。 | **已修复边界条件**：源码回归已锁定；尚未将该旧派生 API 从所有兼容调用链移除。 |
| clearJavaBootMaterial 后的异步 SAM binding | Java `sealedBindingKey` 改调用 `nativeSealedBindingKey(byte[])`；`jsn_k15`/`jsw_k15` 通过 `js_sealed_binding_key` 使用 native resident anchor 生成 keyed identity，shell 通过 `native_sealed_binding_key` / `js_shell_native_sealed_binding_key` 转发。 | **已修复 Java-key-cleanup 兼容性**：`SamInvocationHandler.target()` 与 `readObject()` 的异步重新链接经 `resolveSamLambdaTarget → resolveBoundMethodName → nativeSealedBindingKey` 工作，不再依赖 `clearJavaBootMaterial` 后已擦除的 Java `runtimeResourceKeys`。resident anchor shares 的内存驻留风险仍保持未闭合。 |
| sealed class manifest | `ClassEncryptionLoaderHelper` 对缺失/认证失败/空 manifest 直接 fail-closed；sealed resource 无 authenticated 映射时抛错，仅旧 `__jse/*.enc` 允许 legacy fallback。 | **已收敛**：manifest 不再静默变成空 map，也不再把 sealed path 当作 binary class name。 |
| class plaintext 生命周期 | `SharedDecryptingClassLoader` 在 `defineClass` 返回或抛异常后的 `finally` 中清零 `byte[]`。 | **已缓解，不是消除**：定义/Transformer 窗口内仍可观察明文，native `DefineClass` 尚未实现。 |
| sealed manifest 输出顺序 | `RuntimeArtifactSealing` 在输出前按原始 JAR 顺序预分配所有动态 sealed 名称，再编码 class-encryption manifest；collision 顺序稳定。 | **已修复**：manifest 出现在 encrypted entry 之前时，仍记录最终 sealed path；collision regression exit code `0`。 |
| loader-only 缺少 `META-INF/.r/vm.catalog` | `preloadRuntimeResourcesIntoNative()` 先检查 `hasVmCatalogResource()`；loader-only artifact 无 catalog 时仅跳过 VM preload，不伪造空 catalog，boot/class-decrypt bridge 仍继续。 | **已修复并纳入真实回归**：class-encryption-only fixture 不再因不存在 VM catalog 而把 native 初始化判为失败。 |
| compressed JSRP/native decoder 可选性 | runtime resource decode 优先 native；返回 null 或 `LinkageError` 时回退 Java authenticated decoder，且 Java 路径允许 compressed JSRP 并继续校验 HMAC、partition、metadata/stored/plaintext hash 与 zstd 长度。 | **已收敛为兼容性 fallback**：fallback 不绕过认证；篡改 envelope 仍应 fail-closed。 |
| `StringEncryptionHelper` 永久强缓存 | 当前 `javashroud.stringCache` 默认 `soft`，支持 `off`/`soft`/`strong`。 | **已缓解，不是消除**：heap dump 仍可能取得活跃字符串或尚未回收的 soft entry，真实 dump 命中率尚未测量。 |
| `js_runtime_resource_key_shares` 常驻／可重组 | 本轮未实现 slot 惰性拆分、触发清除、分散存储或 native dump 回归。 | **仍未缓解**。 |

### 7.2 已验证的 focused 与真实 sealed 证据

- `validation/js_crypto_gcm_run.txt`：AES-128/AES-256-GCM 向量、tag tamper reject、拒绝输出清零。
- `validation/native-kernel-windows-compile-post-abi9.txt` 与 `validation/js_kernel_windows-x64-post-abi9.dll`：Windows x64 native ABI 9 编译成功（`EXIT=0`）。
- `validation/manifest-order-resource-rename-plan.json`：`RuntimeArtifactSealingCollisionTest` exit code `0`，并附 `patches/manifest-order-resource-rename-plan.diff`。
- `validation/gradle-p0-focused-suite-post-abi9.log`：通过 evidence-only init script 精确选择六个 P0 test classes，Gradle `BUILD SUCCESSFUL`、exit `0`；JUnit 合计 `20 tests`, `0 failures`, `0 errors`, `0 skipped`。
- 同次真实 sealed fixture：`recovered/native-class-encryption-runtime-post-abi9-focused/output.jar`，大小 `783324` bytes，SHA-256 `6b37b0fd9d4054b109cc0a516f98fbaed8e42ded9759563b35e699f5752ab1f0`；其中 `NativeClassEncryptionRuntimeRegressionTest` 为 `tests=1`, `failures=0`, `errors=0`。
- `NativeClassEncryptionRuntimeRegressionTest.sealed_native_class_decrypt_runs_with_verifier_and_preserves_behavior` 的断言要求真实 sealed JAR 使用 `java -Xverify:all`，退出码 `7`，输出包含 `CLASS_DECRYPT=ok`，且不存在 `VerifyError`、`IllegalAccessError`、`ClassNotFoundException`；该测试已通过。因此“real sealed class-decrypt test passed”是**真实产物行为证据**，不是仅编译或 source-level 断言。
- `validation/gradle-native-binding-key-regression.log`：focused native binding-key regression 以 `BUILD SUCCESSFUL` 结束；`NativeBindingLoadOrderTest` JUnit XML 记录 `tests=6`, `failures=0`, `errors=0`。
- `SelfDecryptBoundaryHardeningTest` 的 source-level 回归覆盖 inner/wrapper 双层 gate、ABI **9**、class-decrypt 与 `nativeSealedBindingKey` descriptor、shell forwarding 和 `jsize` overflow；其证据类型仍与真实 JAR 动态证据分开记录。
- `report/self-decrypt-tamper-validation-abi9-focused-2026-08-11.md` 与 `validation/self-decrypt-tamper-validation-abi9-focused-2026-08-11.json`：同次 focused sealed JAR 的 control 在 `java -Xverify:all` 下 exit `7` 且含 `CLASS_DECRYPT=ok`；source hash 在验证前后保持 `6b37b0fd9d4054b109cc0a516f98fbaed8e42ded9759563b35e699f5752ab1f0`，ciphertext、GCM tag、JSRP body、JSRP HMAC 单字节篡改均 exit `1`、无 marker 并达到各自 authenticated-rejection diagnostic，matrix overall `PASS`。
- `report/max-hardening-case-static-post-abi9-focused/max-hardening-case.{md,json}`：对同次 focused artifact 的只读 CASE 静态盘点未执行 verify/rebuild/pipeline，`command_failure=false`、`errors=[]`；历史恢复矩阵仍为 `complete_recovery_evidence_count=142`，当前 class-only fixture 又缺 method build-evidence，这份报告是恢复基线，不是 `0/142` 成功证据。
- `validation/gradle-native-key-lifecycle-suite-post-binding-bridge.log` 与 `...-timeout.txt`：完整 native lifecycle suite 在 2404 秒后超时，终止仅限对应 Gradle PID tree、source 未改变；不存在 final test summary，故该 suite 仍未验证。

### 7.3 尚未证明的关键结论

下列事项保持未证明，不能从当前源码、focused harness 或单个真实 sealed fixture 推导出来：

- 自解密交付模式下，持有源码和产物的一方仍可离线重放 `KEK → boot.dat → 根密钥` 链；这一本质边界未改变。
- `MethodBodyDecryptionHelper` 的 raw key/JCA method-body 路径尚未收敛。
- native `DefineClass` / `ClassFileTransformer` 零明文捕获尚未实现或以真实 agent/Transformer 实测；defineClass 后清零只缩短驻留。
- Windows/macOS instrumentation attach、模块扫描、anti-dump 和正常环境零误报尚无本轮动态证据，`js_vm_sensitive_path_guard` 的存在不等于两个平台已完成覆盖。
- `js_runtime_resource_key_shares` 驻留收缩、native memory dump 中的可重组 slot 上限尚未验证。
- artifact-only 与动态 CASE 回放下的 `0/142` 高价值恢复矩阵尚未完成；最新只读 CASE static report 记录历史 `complete_recovery_evidence_count=142`，不能与当前 sealed fixture 的 focused evidence 混同。
- 完整 native key-lifecycle suite 在 post-binding-bridge 运行中超时，尚无 final summary；它不计入 passed evidence。

### 7.4 安全结论更新与验收门槛

本轮 P0 使直接 hook class key 或 `ClassEncryptionLoaderHelper` 的 Java AES-GCM 不再是正常 encrypted-class 主链的最低成本路径；manifest/resource 映射顺序与 loader-only 启动阻塞已修复；五个敏感 native 入口及其 JVM wrapper 均受 guard，`clearJavaBootMaterial` 后的异步 SAM binding lookup 也已改由 native resident anchor bridge 支撑；class plaintext 在 defineClass 后会被清零。

但这不等于绝对保密性，也不等于所有 profile、平台或 hook 手段均已阻断。准确定位是：

> **P0 partial / focused evidence passed / real sealed class-decrypt test passed / CASE 0/142 pending**

已完成 ciphertext/GCM tag/JSRP body/JSRP HMAC tamper matrix；下一轮验收按以下顺序推进：nonce/AAD mismatch 与 ABI/profile 回归 → `MethodBodyDecryptionHelper` raw key/JCA 路径 → Windows/macOS attach 与误报基线 → native `DefineClass` 或等价可见性收敛 → `js_runtime_resource_key_shares` 生命周期 → 重新完成 native key-lifecycle suite → artifact-only + dynamic CASE `0/142` 回放。
