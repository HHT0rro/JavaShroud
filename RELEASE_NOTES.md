# JavaShroud v0.21.0-dev

> 开发版更新（2026-08-23）。本版本只支持 current-format artifact、协议与 Native ABI；旧格式、旧协议、旧 Native ABI 和预构建 Native 回退均不再保留。

## Current-format runtime

- AKEN-R1 production Native is Rust-only and supports exactly Windows x64 (`x86_64-pc-windows-gnu`) and Linux x64 (`x86_64-unknown-linux-gnu.2.17`).
- Retired C/Zig build entrypoints, macOS host/target, Mach-O, `.dylib`, and old Native resource paths fail closed; no legacy C ABI or prebuilt Native fallback is retained.
- 统一 JavaShroud 版本来源，移除独立 VBC 版本字段及旧 schema 输出。
- 强化 AKEN v4 Native locator、page descriptor、route、digest、commitment 和 generation 校验。
- 缺失 Native DLL、Native digest mismatch、page tamper、结构截断和跨 session/artifact replay 均保持 fail-closed。
- 保留完整 page authentication；AKEN cache-hit 不跳过当前 page 的认证流程。
- 不恢复 legacy artifact、旧协议、旧 Native ABI、prebuilt Native 或 Java fallback。

## VM performance and lifecycle

- execution frame 使用线程隔离状态，保留有界 frame pool、generation binding 和统一 wipe/归还路径。
- 优化 active execution copy 到 persistent prepared program 的安全复用路径。
- 保持 nested/recursive dispatch depth 上限，超限继续走 fail-closed/受控回退路径。
- 优化重复 VM dispatch、resource index、JNI cache、zstd context 和 Native loader 热路径。
- 修复字段反射字符串按字段 owner 限定改写，避免同名字段跨类污染。

## Security and regression coverage

- 增加 Native parser、AKEN page auth、VM frame、runtime metrics、tamper、protocol label 和 protected artifact 回归测试。
- 增加 missing DLL、digest mismatch、page tamper、partial-output wipe、generation mismatch 和 verifier 相关验证。
- 敏感材料仍不进入持久化 cache：key、DEK、nonce、page plaintext 和 descriptor secret 均不缓存。

## Desktop workbench and release integration

- 更新 capability schema、pass selection、配置解析、版本展示和桌面端状态管理。
- 收紧 release workflow、Native 构建绑定和最终 artifact 校验。

# JavaShroud v0.20.0-dev

> 开发版更新（2026-08-21）。本版本只支持当前受保护 artifact、协议与 Native ABI；旧格式、旧协议、旧 Native ABI 和预构建 Native 回退均不再保留。

## Native 运行时性能
- 引入 operation-local AES schedule：每次 AES-GCM/CTR 操作只展开一次密钥，并在认证成功、失败、异常和会话失效时统一擦除。
- Windows x64 增加运行时 CPU 能力检测与不可变函数指针分发，支持 AES-NI、PCLMULQDQ（可用时使用 VAES/VPCLMULQDQ），不满足能力或自检条件时使用同协议软件路径。
- 优化 GHASH/AAD、CTR counter 批处理和固定大小 scratch；硬件与软件路径保持相同的 nonce、AAD、长度块、tag 比较、artifact binding 和失败擦除语义。
- Native shell crypto 复用同一套 schedule/dispatch，shell payload、chunk tag、payload commitment 和 inner image 在完整认证后才进入后续 loader 流程。

## AKEN、VBC4 与 Native artifact 管线
- 完善当前格式的 typed NativeChunk、AKEN page descriptor、route、layout generation、commitment 和 artifact binding 生产链路，支持多页 Native 资源的认证打开。
- 保留每次打开都必须执行的 digest、tag、长度、结构、路由、布局和最终 commitment 校验；认证前不映射、不暴露、不执行 inner image。
- 补充 CP/row dialect、page frame 和 parser profile 的脱敏诊断字段，遇到截断、代际混用或构建上下文不一致时继续 fail-closed，而不是放宽解析条件。

## VM 执行帧与 dispatch 热路径
- 新增按线程隔离的 execution frame：Windows 使用 FLS，Linux/macOS 使用 pthread TLS，并提供有界、受锁保护的兜底池。frame 绑定 artifact/session generation，不跨线程、跨 artifact 或跨 session 复用。
- 复用 locals、stack、operand scratch 和容量，保留 resident instruction state 到私有执行状态的复制；退出、异常、取消、JNI exception 和分配失败均走统一 wipe/归还路径。
- 支持 nested、recursive、lambda、invoke-dynamic 与 method re-entry，并限制 frame depth；超过上限直接 fail-closed。opcode bounds、epoch、rotation、exception table、session verification 和 JNI exception check 均保持不跳过。
- 增加不可变 opcode metadata、operand width、handler category 与已验证常量池分类缓存，减少临时对象和重复分支，同时不直接执行共享 resident mutable instruction array。

## Resource、JNI、zstd 与 loader 热路径
- 建立 artifact/session 内的 immutable resource index，支持 alias 与 commitment 的近似 O(1) 查找；重复 alias/hash/route、跨 artifact replay 和 generation mismatch 直接拒绝。
- 复用按线程/会话绑定的 zstd 解压上下文与有界 scratch，认证前不暴露明文，解压失败会清除 partial output。
- JNI 缓存加入 loader identity、class binding、ABI 与 artifact/session generation 校验；缓存失配会清除并重新解析、重新认证。
- Native loader 复用已验证的 segment metadata、relocation 批处理、import/export index 和地址计算结果，但每次仍执行架构、边界、W^X、JNI symbol、digest、route、binding 与 final commitment 检查。

## 基准、可观测性与安全回归
- 新增脱敏 `NativeRuntimeMetrics`、`CryptoRuntimeMetrics`、`VmRuntimeMetrics`、`ResourceRuntimeMetrics` 与 `RuntimeSecurityCounters`，只记录路径、阶段耗时、计数器和 output digest，不记录 key、nonce、DEK、page plaintext、descriptor secret 或敏感路径。
- 增加 AES-128/256-GCM、CTR、GHASH/AAD、4 KB/64 KB/1 MB page、AKEN page open、重复 resource open、VM prepared/nested execution、JNI lookup、zstd decode 和 shell payload decode fixture。
- 增加硬件/软件 differential、known-answer、错误 key/nonce/AAD/tag、截断、长度溢出、跨 artifact replay、alias/commitment collision、stale generation、frame depth、JNI exception 和 partial-output wipe 覆盖。
- 安全门禁优先于性能：认证检查数不得下降，`fallback_count`、`legacy_path_hits`、`wipe_failure_count`、`plaintext_persistence_bytes` 和 `security_checks_skipped` 必须为零；不引入旧协议或 prebuilt native fallback。

## Desktop workbench 与发布集成
- 升级桌面端能力/规则/目标选择、配置解析、class tree 虚拟列表和 pass selection 状态管理，改善大型项目的可视化与配置反馈。
- 收紧 embedded engine release integration、Native 构建/打包和证据清单绑定，发布物按最终 artifact 条目记录脱敏哈希与验证结果。

## 验收边界
- 本版本的 benchmark 报告同时标注 phase-level 证据与 coverage 状态；尚未被真实 accepted artifact 矩阵覆盖的路径不会被标记为完整计划验收通过。
- 从旧版本生成的 artifact 不保证可加载；请使用同一构建上下文重新生成 engine、Native image、AKEN pages、routes、bindings 和 commitments。

# JavaShroud v0.12.0

## Native 加固与密钥边界
- 引入 Boot KEK 驱动的加密启动材料（`META-INF/.r/boot.dat`，AES-GCM 认证），运行时密钥不再随产物分发。
- 强化 MAX Native Shell：加密载荷头、分块认证加密、启动完整性校验与敏感缓冲区主动擦除（`PACKER_VERSION = 5`）。
- 外壳绑定期望值只存在于加密 boot.dat 中，由 JVM 在 `JNI_OnLoad` 期间一次性交付，Native 库内不再自带可整体替换的期望值。
- 新增运行时密钥分区（按分片隔离、可擦除）与五级构建安全计划（target → partition → method → profile → page 派生，freeze 后不可变）。
- 字符串加密升级为 AES-CTR，密钥/IV 按构建上下文 + 16 字节类身份域分离派生，杜绝跨类复用密文。

## VMBC 与运行时
- VBC4 元数据升级至 `vbc4-meta-v2`：类型标签向量去标识化、密封字符串常量池项（带 MAC）。
- 新增 CFG 索引编码（按种子派生的模逆映射），指令物理布局与执行顺序解耦；新增诱饵异常表项。
- 新增加密 VM 目录（按分片分散存放、Merkle root 派生目录名、支持重命名映射），降低静态命名与资源映射泄露。
- 修复 Native VM 的 `MONITORENTER` / `MONITOREXIT` 真实 JNI 同步语义（含 NPE / IllegalMonitorStateException）。
- VM 核心增强：按方法身份定位激活程序、运行时会话校验、`ldc` 类型与所属类身份匹配校验。

## 历史 Native 路径（已在 AKEN-R1 退役）
- 旧版本曾通过 Zig 交叉编译 Windows x64、Linux x64、macOS x64 和 macOS ARM64 Native 库。
- 旧 macOS Mach-O 外壳、Linux 专用 C 链接脚本及多平台 Native 资源布局均不属于 AKEN-R1；当前构建对这些路径 fail-closed。
- 历史构建证据中的 `natives[]` 记录不代表当前格式兼容性；AKEN-R1 只接受当前 Rust 资源与 ABI。

## 兼容性与正确性
- Lambda 配方保真度提升，覆盖更多 MethodHandle 调用类型、构造器引用、接口调用及 checked exception。
- 修复大小写不敏感文件系统上的类名冲突问题。
- 嵌入式运行时 helper 以 Java 8 字节码编译，可在最低支持运行时加载；引擎本体保持 Java 21。
- 修复 MAX 加密产物跨构建缓存复用问题（绑定当前 Boot KEK）。
