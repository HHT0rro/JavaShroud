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

## 多平台 Native
- `targetPlatform` 支持 `"all"` 与多平台集合，单次构建产出 Windows x64、Linux x64、macOS x64、macOS ARM64 四份原生库（Zig 交叉编译）。
- 新增 macOS Mach-O 外壳链（导出符号白名单 + fail-closed 校验）与 Linux 专用链接脚本。
- 构建证据报告支持 schema v2 `natives[]`，按最终 JAR 条目 SHA-256 逐项绑定四平台产物；单 PE 场景保持 schema v1 兼容输出。

## 兼容性与正确性
- Lambda 配方保真度提升，覆盖更多 MethodHandle 调用类型、构造器引用、接口调用及 checked exception。
- 修复大小写不敏感文件系统上的类名冲突问题。
- 嵌入式运行时 helper 以 Java 8 字节码编译，可在最低支持运行时加载；引擎本体保持 Java 21。
- 修复 MAX 加密产物跨构建缓存复用问题（绑定当前 Boot KEK）。
