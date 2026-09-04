# JavaShroud v0.40.0-dev
**喜报，来了版大更新。**
>  `v0.40.0-dev` JavaShroud 的保护链路整体换了一套骨架：Native 运行时、Qp VM、JNI bridge、artifact catalog、页面格式、构建流程和测试覆盖一起迁移到 current-format，并在此版本内切断 VMBC 离线解密链。

## Native 秘密包与 VMBC 离线链切断

- 每个 artifact 在混淆期间生成专属 native secret pack：页密钥派生种子只经过分片、随机顺序 XOR 与随机私有函数写入一次性编译的 specialization source；编译结束后 Rust source、临时 workspace、中间产物与 JVM 侧副本全部擦除。
- 最终 JAR、class、catalog 与资源中不再存在可独立 materialize 页 DEK 的 evaluator 材料：`QpEvaluatorPlan`/`QpBoundPlan`/AKE1 fragment 体系整体退役，页 DEK 改为结构化二进制派生（preNativeCommitment + secretSlot + pageIdentity + pageNonce + nativeIdentity，HKDF-SHA256），页帧头 32 字节槽位升级为 key commitment，native 打开页面前先常时校验承诺。
- runtime descriptor 改为带版本字节的 compact locator（route、proof、目标页大小、secret slot）；旧 inline descriptor、旧 evaluator 编码与旧 envelope form 全部 fail-closed。
- native 侧 `SecretPackState` 在 catalog 与 session 认证通过后重组分片；defense probe 违规会立即 revoke 重组材料，protected page 打开统一 fail-closed，无秘密细节外泄。
- VM 方言语义语料改为 per-build specialization 注入（XOR 掩码存储），fused superoperator 语义 id 也随构建材料派生；编译产物中不再存在固定 `LIVE_OPCODES`/`FUSED` 表。
- max-hardening profile 不再读写持久化 native cache；specialization digest 绑定 secret pack commitment，同一输入连续两次构建产生不同 native digest、slot 布局与方言承诺但行为一致。
- 协议版本统一提升：directory format 3→4、name schedule 1→2、frame 2→3、descriptor/envelope 版本重编；release scan 新增 retired evaluator domain 扫描，旧报告脚本面对新产物将在 evaluator 解析/DEK 派生阶段失效。

## Rust Native 运行时

- Native workspace 由 `qp-crypto`、`qp-page`、`qp-vm`、`qp-ffi`、`qp-resource`、`qp-runtime` 和 `qp-shell` 组成，负责加密材料、页面、VM、JNI、资源目录、运行时路由和平台加载。
- Windows 与 Linux target 通过统一的 Gradle/Rust 构建入口生成，打包阶段会检查目标架构、镜像头、资源路径和 release contract。
- Native artifact 的 SHA-256、ABI digest 与 specialization digest 写入运行时绑定；打包后的 DLL/SO 被替换时，catalog 校验不会放行。
- Rust 源码随引擎分发，构建流程可以准备锁定的本地工具链，不要求用户预装 rustup、系统 Zig 或 MinGW。
- Native 资源副本在生成目录、主资源目录和最终 artifact 之间执行一致性校验，避免测试和发布包加载到不同版本的库。

## Qp VM 与当前 wire format

- VM 程序使用当前 Qp wire format：认证 header、状态绑定、加密 constant pool、压缩 section、块级加密、MAC 和认证 padding 都属于同一格式的一部分。
- VM dialect、opcode mask、块布局和部分行字段由构建材料派生；Kotlin serializer 与 Rust parser 通过 dialect commitment 互相确认，拒绝跨构建材料混用。
- 寄存器行支持显式 compact/wide 布局、register-row envelope、mixed-operand envelope、continuation row、semantic split/share 和 folded/super operator。
- folded row 在 serializer 和 Native lowerer 中使用相同的 logical mask cursor；一个 folded group 展开为两个逻辑指令，不会再把后续字段访问解码到错误位置。
- Native-only 解释器链路覆盖实例方法、递归调用、构造器栈形状、option parser、`defineClass`、循环与嵌套 catch、方法注解 metadata、字符串 indy bridge 和并发调用。
- Nested VM 使用独立的当前格式校验、行布局和执行入口，不恢复旧 VM magic，也不回退 Java 解释器。

## Constant Pool 与 metadata

- constant pool 使用 logical-to-physical remap，在重排后的 pool 中仍保持 operand 与实际条目的对应关系。
- META row 继续绑定当前 10-field metadata，包含 entry token、返回类型、方法/owner identity、参数标签、资源路径和运行时 profile 信息。
- serializer 会检查 metadata row 是否在非 identity pool map 下完成 remap；native parser 对 metadata 缺失、重复或越界直接拒绝。
- 字符串常量逐项密封，解密所需材料在使用后清零；异常表和资源 locator 也纳入当前 artifact binding。

## JNI、调用点与方法虚拟化

- Qp bridge 保留公开的 `executeQpVmPage`、`openQpString` 等调用形态，内部请求包含 entry token、packed handle、page index 和 call-site proof。
- JNI 入口会先完成当前格式、native kernel、defense path 和 page request 校验，再进入 VM 或字符串路径；失败不会静默降级到 Java fallback。
- invokedynamic 目标改写为 token envelope，classfile 不直接保存完整的目标描述；恢复、校验和调用都受当前路由 binding 约束。
- 方法选择支持显式成员、all-compatible、critical 和 critical-plus 等现有配置语义，并对 descriptor、synthetic bootstrap 和严格虚拟化边界执行 fail-closed 检查。

## 防御内核与产物扫描

- OS anti-debug 与 OS anti-VM 统一进入 Native 防御状态机，支持 balanced 与 hardened profile。
- QpGuard 通过认证 JNI 管理短期状态 share；防御材料和临时密钥在使用后清零。
- release scan 检查旧路径、旧 magic、旧生成名、固定模板、调试映射、直接 evaluator recovery、残留 key lane、Native binding、诊断输出和平台资源完整性。
- 最终 protected JAR 不应携带旧 catalog、旧 VM helper、临时 `QP_DIAG` 输出或 Java VM fallback 入口。
