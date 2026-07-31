# JavaShroud 技术深挖

本文记录 JavaShroud 当前实现的关键机制：pass 管线、VMBC / NBVM 协议、Native 加壳协议、安全模型与配置参考。所有符号名和路径以仓库代码为准，文末附证据索引。

<strong>简体中文</strong> · <a href="TECHNICAL_EN.md">English</a>

## Pass 管线

引擎注册 26 个 pass（`buildEngineSchemaPayload`）。默认 pipeline 只含 `strip-compile-debug-info`；其余 pass 需在配置中显式启用，带 opt-in 标记的还要求 `allowOptInPasses = true`。

| pass ID | 类别 | stability | 默认启用 | 需 opt-in | 依赖 / 约束 |
| --- | --- | --- | --- | --- | --- |
| `strip-compile-debug-info` | Metadata | stable | 是 | 否 | 默认 pipeline 成员 |
| `member-shuffle` | Metadata | stable | 是 | 否 | |
| `rename-classes` | Renaming | stable | 是 | 是 | |
| `rename-packages` | Renaming | stable | 是 | 是 | |
| `rename-methods` | Renaming | stable | 是 | 是 | |
| `rename-fields` | Renaming | stable | 是 | 是 | |
| `string-encryption` | Encryption | experimental | 否 | 是 | 依赖 `jni-microkernel-loader` |
| `field-string-encryption` | Encryption | experimental | 否 | 是 | |
| `integer-constant-obfuscation` | Obfuscation | experimental | 否 | 是 | |
| `static-init-perturbation` | Obfuscation | experimental | 否 | 是 | |
| `anti-decompiler-structure` | Obfuscation | experimental | 否 | 是 | |
| `invoke-dynamic-indirection` | Obfuscation | experimental | 否 | 是 | |
| `control-flow-obfuscation` | Obfuscation | experimental | 否 | 是 | |
| `control-flow-flattening` | Obfuscation | experimental | 否 | 是 | |
| `reference-proxy` | Obfuscation | experimental | 否 | 是 | |
| `condy-constant-indirection` | Obfuscation | experimental | 否 | 是 | |
| `member-hide` | Hiding | experimental | 否 | 是 | |
| `callsite-rotation-protection` | RuntimeDefense | experimental | 否 | 是 | |
| `anti-symbolic-execution` | RuntimeDefense | experimental | 否 | 是 | |
| `exception-semantic-virtualization` | RuntimeDefense | experimental | 否 | 是 | |
| `environment-bound-keys` | RuntimeDefense | experimental | 否 | 否 | 依赖 `jni-microkernel-loader` |
| `class-encryption-loader` | LoaderProtection | experimental | 否 | 否 | 依赖 `jni-microkernel-loader` |
| `method-body-delayed-decryption` | LoaderProtection | experimental | 否 | 否 | 依赖 `jni-microkernel-loader` |
| `anti-instrumentation` | NativeKernel | experimental | 否 | 否 | 依赖 `jni-microkernel-loader` |
| `anti-dump-protection` | NativeKernel | experimental | 否 | 否 | 依赖 `jni-microkernel-loader`；平台约束 HotSpot JVM |
| `jni-microkernel-loader` | NativeKernel | experimental | 否 | 否 | 平台约束 Windows x64 / Linux x64 / macOS x64 / arm64 |
| `method-virtualization` | VmProtection | experimental | 否 | 否 | 依赖 `jni-microkernel-loader`；目标运行时 Java 11+ |

配置加载时的校验顺序（`loadValidatedConfig` → `validateConfig`）：

1. 依赖归一化后检查 `requiredPassIds` 与 `requiresAnyPassIds`，缺依赖直接报错。
2. 硬冲突 pass 对无条件拒绝（`allowIncomplete` 已解析并传入兼容性校验，但当前实现不改变硬冲突的拒绝行为）。
3. 软冲突（冗余）pass 对需要 `allowRedundantPasses = true`。
4. opt-in pass 需要 `allowOptInPasses = true`；配置 `format = "javashroud-workbench"` 时该项默认为 true。
5. 注解指令（`@ShroudEncrypt` 等）启用 pass 需要 `allowAnnotationPasses = true`。

常用参数键（完整参数 schema 用 `-schema` 查看）：

| pass | 参数键 |
| --- | --- |
| `method-virtualization` | `seed`、`methodSelection`（`safe` / `critical-auto` / `critical-plus` / `all-compatible`）、`strictVirtualization`、`maxInstructions`、`maxBroadVirtualizedMethods` |
| `jni-microkernel-loader` | `kernelComponents`、`targetPlatform`、`diversifiedVirtualization`、`nativeRecompilation`、`nativeProtectionLevel`、`nativePackingLevel`（`off` / `standard` / `max`）、`seed` |
| `string-encryption` | `scope`（`all-strings` / `annotated` / `length-threshold`）、`lengthThreshold`、`seed` |
| `anti-instrumentation` | `detectionLevel`、`response`、`seed` |
| `anti-dump-protection` | `protectionLevel` |

## VMBC / NBVM 协议

### VBC4 字节码与元数据

`VmBytecodeSerializer` 把 JVM 字节码 lowering 为 VBC4。每个被虚拟化的方法生成一条 `vbc4-meta-v2` 元数据（`Vbc4EntryMetadata`），字段依次为：entry token（u64 hex）、返回类型 tag、方法局部 profile、方法身份（256-bit 小写 hex）、属主身份（256-bit 小写 hex）、参数 tag 向量、资源路径、static 标记、native VM profile id、dispatch profile tag。

VBC4 固定不变量（不可通过参数关闭，见 `VmProtectionCapabilityBuilder.kt`）：

- state-bound encoding 与 handler morphing 始终启用；强度固定为 max，无低强度兼容 profile。
- 构建期解释器多样化始终启用，执行只走 native 路径，无 Java VM fallback。
- JNI 调用目标按每产物 / 每方法 token 定位，热路径不传明文符号。
- native dispatcher 以 register IR 为主执行，stack opcode 只作兼容输入。
- serializer 按方法随机结构 seed 折叠 super-operator，并纳入认证状态。
- session integrity digest 参与 seed unwrap、block key 与常量池 key 派生。
- native 根材料按需短生命周期派生，用后擦除。

常量池中的字符串以 sealed 形式存放（`VBC4_CP_SEALED_STRING_TYPE = 0x06`），key / IV / tag 由各自的 HMAC 域分离常量派生。

### JSRP 封装格式

JSRP（magic `0x4A 0x53 0x52 0x50`，版本 7）是统一的受保护资源封装，`RuntimeResourceCodec` 负责编解码。资源分四类：VM 字节码（1）、Native 库（2）、manifest（3）、Native 索引（4）。

二进制布局：

| 区段 | 大小 | 说明 |
| --- | --- | --- |
| magic + version | 5 字节 | `JSRP` + `0x07` |
| nonce | 16 字节 | 每资源随机 |
| metadata 长度 / MAC 长度 / partition id | 各 2 字节 LE | header 共 27 字节 |
| metadata 密文 | 96 字节 | AES-CTR；明文含 kind、层数（1..7）、variant（0..127）、压缩标记、原文长度、body 长度、key id、seed、原文 / 存储 SHA-256、partition id |
| body 密文 | 变长 | AES-CTR；存储内容默认 zstd 压缩（压缩无效时存原文） |
| tag | 32 字节 | HMAC-SHA256，覆盖 header + metadata + body，域分隔常量 `jsrp-auth-v3` + nonce |
| 尾字节 | 1 字节 | MAC 长度回写校验 |

密钥派生：AES key 与 IV 分别取 `HMAC-SHA256(partitionKey, "jsrp-aes-key"/"jsrp-aes-iv", nonce, kind, variant, layers)` 的前 16 字节；metadata 中的 key id 取 `HMAC(partitionKey, "jsrp-key-id-v3", nonce)` 前 4 字节。分区密钥表 `RuntimeKeyPartitions` 在构建期由 CSPRNG 生成，按资源身份选择分区，含一个 anchor 槽。

解码顺序：校验 magic / version → 长度与 partition id 边界 → 常数时间比较 tag → 解 metadata 并核对其内部 partition id 与字段范围 → 解 body 并核对存储哈希 → zstd 解压并核对原文哈希。任一步失败返回 null，由上层 fail-closed。

### 运行时入口

dispatcher stub 调 `JniMicrokernelHelper` 的 `executeVmResource` 系列重载（Object / void / int / int-int / int-void 形态）。Native 未就绪时直接抛 `SecurityException`，不存在 Java 侧 VM fallback。JNI 侧入口为 `js_vm_execute_resource`（`js_vm_core.c` / `js_vm_resource.c`），虚拟指令调度由 `js_vm_core.c` 实现。

## Native 加壳协议

### 外壳-内核结构

`NativeKernelShellPacker` / `NativeKernelPacker` 生成外层 `js_kernel_<platform>` stub，完整 inner kernel 以认证编码 payload 封装在外壳内。加载链（`JniMicrokernelHelper`）：

1. 解析平台后缀，读取 bootstrap 索引 `META-INF/.r/0.dat`（版本 1），得到密封 Native 库清单。
2. 解码密封库资源，写入临时目录（`~/.javashroud/native` 等候选路径），`System.load` 加载外层 stub。
3. `nativeInit` 初始化（返回码 2 时重试一次）。
4. 安装 boot 材料（见下），随后发布密封绑定 `META-INF/.r/bindings.dat`，预加载运行时资源进 native。
5. ABI 自检：调用 `nativeGetBootToken` 与本地镜像值做 XOR 比对，拦截库被整体替换（如 Frida `Interceptor.replace`）的情况；失败置 `nativeSelfCheckFailed`，后续执行全部拒绝。

`JNI_OnLoad` 逐级校验 header、section digest、layout 与 dispatcher profile、payload binding、分块 tag、payload MAC，任何一级失败拒绝执行。

### Boot 材料封装（boot.dat）

产物内只存放 `META-INF/.r/boot.dat`（magic `JSBM`，版本 2，`BootMaterialEnvelope`）。封装方式为 AES-GCM（128-bit tag，12 字节随机 nonce），AAD 为 `javashroud-boot-material-v2`，密钥即 256-bit Boot KEK。

明文布局：版本（1）+ 资源分区数（1）+ 总槽数（1，范围 2..17）+ 平台绑定数（1）+ master key（64）+ JAR layout digest（32）+ 各槽分区密钥（槽数 × 32）+ 平台绑定项（每项 1 字节平台 id + 32 字节非零承诺）。平台 id：`windows-x64=1`、`linux-x64=2`、`macos-x64=3`、`macos-arm64=4`。

JVM 在 `JNI_OnLoad` 期间通过 `nativeInstallBootMaterial` 一次性交付，`nativeIsBootMaterialReady` 确认，并检查外壳确实消费了绑定承诺。KEK 本身从环境变量 `JAVASHROUD_BOOT_SECRET_V1`（64 个十六进制字符）或 `JAVASHROUD_BOOT_SECRET_FILE_V1` 指向的文件（32 原始字节或 64 十六进制字符）读取，缺失、格式错误、GCM 认证失败都 fail-closed。

### 平台 loader 边界

| 平台 | 校验范围 |
| --- | --- |
| Windows x64 | PE64 内存映射：section、relocation、import / export、TLS、`DllMain`、`JNI_OnLoad`、ABI table |
| Linux x64 | 匿名内存 ELF64 loader：`PT_LOAD` / `PT_DYNAMIC`、hash、symbol、RELA / PLT、initializer、入口点 |
| macOS x64 / arm64 | Mach-O metadata、rebase / bind、export trie、initializer；不满足匿名执行映射条件时 fail-closed |

Native 源码位于 `core-engine/src/main/native/`：`js_kernel.c`（JNI 入口与外壳）、`js_vm_core.c` / `js_vm_core.h`（VM 核心与指令调度）、`js_vm_resource.c`（资源认证与解析）。

## 安全模型

- 取向接近 Kerckhoffs 原则：强度来自每产物 CSPRNG 生成的密钥材料、结构差异（布局、opcode 方言、dispatcher profile）和 Java / Native 执行边界，不依赖实现细节保密。
- 绑定图：VMBC 资源 ↔ bootstrap 索引 ↔ 资源路径 ↔ manifest ↔ 外壳承诺，跨产物替换任一环节都会破坏认证链。
- fail-closed 清单：
  - 构建期：`strictVirtualization` 下方法含 VBC4 不支持的字节码或超出 `maxInstructions` 时构建失败；缺 KEK 或格式错误时构建失败。
  - 加载期：KEK 缺失 / 格式错误 / GCM 认证失败；boot token ABI 自检失败；外壳绑定承诺未被消费；密封索引或绑定缺失。
  - 运行期：JSRP tag / 哈希不匹配；资源路径或 profile 被篡改。
- 非目标：产物自包含运行所需材料，不宣称绝对不可逆；目标是提高单次分析和跨样本批量复用的成本。

## 配置参考

配置文件为 TOML（jackson-dataformat-toml 解析），对应 `ObfuscationConfig`：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `inputJarPath` / `outputJarPath` | 字符串，必填 | 可放根级或 `[input]` 节下 |
| `[[passes]]` | 数组，必填 | 每项含 `id`、`enabled`（布尔）、可选 `params` 表 |
| `[ruleSet]` / `rules` | 数组 | 规则表 `[ruleSet]` 内 `[[ruleSet.rules]]`，或根级 `[[rules]]` |
| `allowOptInPasses` | 布尔 | 允许启用 opt-in pass；`format = "javashroud-workbench"` 时默认 true |
| `allowRedundantPasses` | 布尔 | 允许同时启用软冲突（冗余）pass 对 |
| `allowAnnotationPasses` | 布尔 | 允许注解指令启用 pass |
| `allowIncomplete` | 布尔 | 已解析并传入兼容性校验；当前硬冲突仍无条件拒绝 |
| `format` | 字符串 | `javashroud-workbench` 表示桌面端产物配置 |

规则语法：`target = "class <pattern>"`，可追加 `#member` 或 `#member:descriptor` 限定成员；`action` 目前消费 `obfuscate`（显式纳入）与 `exclude`（排除，显式 obfuscate 优先）。类模式支持 `*`（单层）与 `**`（多层）通配。

启用 VMBC 与 Native 加壳的完整示例：

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

构建与运行前设置同一个 KEK：

```powershell
$env:JAVASHROUD_BOOT_SECRET_V1 = "<64 个十六进制字符>"
```

## 证据索引

| 符号 | 位置 |
| --- | --- |
| pass 注册表与默认 pipeline | `core-engine/src/main/kotlin/io/github/hht0rro/javashroud/capabilities/`（`SchemaCapabilities.kt`、各 `*CapabilityBuilder.kt`） |
| 配置模型与校验 | `.../model/config/ConfigModels.kt`、`.../config/ConfigDecodeSupport.kt`、`.../config/ConfigLoadSupport.kt`、`.../config/ConfigRedundantPassSupport.kt`、`.../config/PassConfigDecodeSupport.kt` |
| 规则解析 | `.../analysis/RuleMatching.kt`、`.../analysis/RuleTargeting.kt` |
| VBC4 序列化 | `.../transforms/protection/VmBytecodeSerializer.kt` |
| JSRP 编解码 | `.../transforms/protection/RuntimeResourceCodec.kt` |
| 分区密钥 | `.../transforms/protection/RuntimeKeyPartitions.kt` |
| zstd 编解码 | `.../transforms/protection/Vbc4ZstdCodec.kt` |
| dispatcher profile | `.../transforms/protection/DispatcherProfile.kt` |
| VM 资源目录 | `.../transforms/protection/RuntimeVmCatalog.kt` |
| boot 材料封装 | `.../transforms/protection/BootMaterialEnvelope.kt` |
| 外壳打包 | `.../transforms/protection/NativeKernelShellPacker.kt`、`.../transforms/protection/NativeKernelPacker.kt` |
| 运行时 JNI helper | `core-engine/src/main/java/io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper.java` |
| Native VM 与外壳 | `core-engine/src/main/native/js_kernel.c`、`js_vm_core.c`、`js_vm_core.h`、`js_vm_resource.c` |