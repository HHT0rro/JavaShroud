# JavaShroud v0.31.0

自 v0.30.0-dev 以来共 120 个提交（35 security、24 perf、14 fix、6 feat 等）。

## 保护协议与运行时加固

- 保护协议全序列化器升级 v5，JSRP 资源格式升级 v8；构建期为每份产物生成 6–16 个资源分区密钥 + 锚密钥、256 位 opcode 方言承诺、页密钥槽位与 native locator 绑定摘要。
- Secret pack 全程密文驻留（AEAD 封装、按当前镜像承诺 reseal），明文只存在于回调与擦除窗口内；自举材料在 `JNI_OnLoad` 内自解封。
- 移除通用 Java 解密回退通道与调试密钥泄漏路径；VM 程序、方言、抛出帧用后擦除。
- 运行时防御：JVMTI/JDWP 存活探测、敌意模块枚举、dump 感知完整性看门狗、JNI 路由数值化。

## NativeShroud 打包 + Xenolith 一等支持

- 新 `nativeshroud` pass：Xenolith 自动打包（`cliPath` + `profile`）、预打包路径（`packedPath`）、交互交接（`JAVASHROUD_PACK_HANDOFF`）三种方式，全部 fail-closed。
- 打包镜像 JSIM 绑定前强制预校验：PE64 DLL、保留 `.jsms`/`.jsmk` 测量段与 JNI 导出；`lazyRegions` 因与 JNI 宿主引导不兼容被具名拒绝。
- 函数级选择透出：`vmExports`、`selectRva`、`selectFunction`、`selectAll`、`strictCoverage`、`allowNativeFallback`、`protectImports`、`strictConstants`、`traceDiverge`。
- 退役 `NativeKernelShellPacker` C 外壳与 `nativePackingLevel`（Mach-O loader、Zig 入口、`.dylib` 一并退役）。
- 桌面端内嵌 Xenolith CLI（`javashroud_embed_xenolith`）并随包附带 `tools\xenolith.exe`；`fetch-xenolith.ps1` 支持构建期自动下载（国内镜像链 + SHA-256 manifest 校验）。

## 桌面工作台重构

- Wails + Vue 工作台布局与交互全面重建：类树虚拟列表与范围导航、流水线面板、终端事件流、命令栏与运行状态栏；配套 16 项前端检查。

## 性能

- VM 会话级缓存（解析程序、页密钥、根密钥材料、JNI class/member ID、entry token）；mhstatic 自调用折叠回 `INVOKESTATIC`；防御探测降频至看门狗节奏；NT 调试端口查询、JVMTI 扫描、模块全扫描移出 VM 热路径。
- 修复 LambdaMetafactory 实现句柄被误虚化导致的回归。

## 兼容性

- 旧产物 fail-closed：旧 boot/kek 材料、JSBM/JSBK、旧 catalog 与评估器、seed/FNV 封套全部退役，不做降级兼容。
- JDK 基线更新为 17+。

## 下载内容

- `javashroud.exe`（内嵌引擎与 Xenolith CLI）
- `engine\obfuscator-engine.exe`
- `tools\xenolith.exe`（GPL-3.0，独立项目）
- `javashroud-annotations-*.jar`
