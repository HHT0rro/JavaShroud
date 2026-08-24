# JavaShroud v0.30.0-dev

> 开发版大更新（2026-08-24）。本版本彻底抛弃 C 语言，Native 内核整体使用 Rust 重写，并引入以随机化 VM 方言与统一防御内核为核心的新一代防护管线。

## Rust-only Native 运行时

- 删除全部 C 语言 Native 内核源码，Native 运行时由 Rust workspace 完整接管（jsrt-vm / jsrt-crypto / jsrt-page / jsrt-ffi / jsrt-shell / jsrt-resource / jsrt-runtime 共 7 个 crate）。
- 新增 Rust 工具链自动 provisioner，Native 一律 zigbuild 构建，CI 同步预置 Rust 工具链。
- AKEN R1：新增打包与 wire format、artifact 目录编解码器、当前页绑定解密器与 Eval7 DEK wrap。
- Catalog sidecar：`System.load` 前抽取认证目录到 `META-INF/jsrt/`，每页携带 handle、locator、PageKey 与 RuntimeBindingDigest。
- Per-artifact Native 重编译：每次构建生成 specialization nonce 并覆写 `specialization.rs`，构建锁以完整 specialization identity 为键。

## 随机化 VM 方言与数据布局

- Per-artifact 指令集方言：以构建材料经 HMAC 扩展，对约 150 个 live opcode 做 Fisher-Yates 洗牌生成 65536 项 encode/decode 表，同一语义指令在不同产物中编号不同。
- 随机化融合超指令（fused opcode）与 dispatch 分发族（0–3），并生成 32 字节 dialect commitment 供跨组件校验。
- 随机数据布局：寄存器行 6 个字段按块种子逐行排列，每个字段再 XOR 独立 mix 掩码（register row envelope）。
- 混合操作数 envelope：操作数字段经 mix word 混淆的备选行编码。
- 嵌套 VM：行内再嵌套一层微指令，带独立 magic、dialect 校验、字段排列与逐槽 mix 掩码。

## OS 级反调试 / 反 VM（统一防御内核）

- 新增 UnifiedDefenseTransforms：os-anti-debug 与 os-anti-vm 合并为同一套 Native 状态机，支持 balanced / hardened 两档 profile 与 1–4 个分布式探针方法注入。
- Rust FFI 真实环境检测：Linux 读 TracerPid 与 javaagent / JAVA_TOOL_OPTIONS 注入检测，Windows 调 IsDebuggerPresent；反 VM 使用 CPUID hypervisor 位 + DMI / cpuinfo 厂商串双证据判定。
- 新增 DefenseKernelRuntimeHelper：7 态防御状态机，全部状态迁移须经认证 JNI，仅产出 32 字节短期认证 share，密钥材料用后即刻清零。

## 强化管线与产物收口

- 新增 hardening 包：当前产物格式定义与 release gate、默认 pass 编排、产物最终化、发布扫描与旧生成名退役 gate。
- invokedynamic 目标改写为不透明 token envelope，classfile 只存 envelope，目标信息短时恢复后即清零。
- Ed25519 签名的版本化 rename/debug 映射，生产 JAR 不含此文件。
- AKEN 路由统一 canonical commitment，page-open / catalog-open / VM dispatch / JNI 路由不匹配即 fail-closed。
- 移除 ClassEncryptionLoader、MethodBodyDelayedDecryption、RuntimeVmCatalog 及一批 legacy helper；capability builders、配置模型（HardenedProtectionProfile）、kernel orchestration 全面重建；命名层新增 FixedGeneratedNamePolicy。
- 测试套件整体更新至当前格式，桌面端 pass catalog 同步；README 已刷新。
