# AKEN v4 资源页密钥与解密边界分析

## 1. 安全模型

AKEN v4 的部署契约保持离线、完全自包含和 `java -jar` 可直接启动。产物不依赖用户输入、宿主秘密、设备因子、网络服务、证书或外部密钥文件。

因此它的目标是 **artifact-only static cost hardening**：提高离线静态恢复、跨构建脚本复用和批量资源横向解封的成本；它不声称从完整自足产物中创造一个对持有产物者不可获得的密码学秘密。拥有完整动态执行控制权或可截获运行时明文的攻击者不属于静态恢复门槛。

## 2. 高价值资源页

AKEN 只覆盖高价值范围：VBC4 方法页、字符串页、加密 class 页以及 native shell/handler chunk。普通未保护资源不进入该路径。

每一个高价值页面都有独立随机 DEK。页面之间没有共享根、可枚举的全量槽位表或由一个页面推导另一页面材料的路径。页面以独立 AEAD 记录封装，AAD 绑定：

- artifact canonical commitment；
- 逻辑资源身份与 page index；
- evaluator plan fingerprint；
- codec 与 layout variant。

## 3. AKEN-7 等价密钥求值网络

单页 DEK 被编译为该页专属的 AKEN-7 evaluator graph：三个生成的 Java fragment、三个 native fragment 和一个仅在 native 最小作用域内使用 32-byte key 的 terminal fragment。构建会随机化 fragment 拆分、执行次序、算子族、表排列、常量切分、异常路径、调用图和 handle 编码。

公开绑定材料只承担完整性绑定与抗重打包职责，不被定义为秘密来源。任意一个 evaluator 的语义重构只适用于其绑定的单页，不能作为全包通用解封器。

## 4. 定位与完整性

调用点持有独立 `AkenHandle`，它仅表达当前调用目标。运行时不提供枚举全部 handle、目录、资源或页面密钥的通用接口。

`AkenIntegrityMesh` 对高价值密文页、native payload chunk、关键 helper、关键 bootstrap 形状和逻辑资源映射建立 Merkle commitment。每次高价值访问都验证当前叶子、Merkle path、artifact canonical root 与 call-site proof。canonical hash 对预留 commitment shard 范围归零，以避免自引用哈希循环。

## 5. 运行时边界

高价值页通过按用途划分的 native bridge 访问：VM 页打开并执行、字符串页解码、class 页读取、native chunk 消费。bridge 只接受已绑定的 `AkenHandle`、page index 与 call-site proof；不接受任意资源字节和任意 key metadata。

Java 侧不缓存 DEK、全局根、完整目录或全量页面密钥。页面明文、keystream、fragment state 和拼接缓冲都在 Java `finally` 或 native cleanup 路径清零。字符串返回值和 JVM 已定义 class 的生命周期属于 JVM 语义，不被表述为额外的内存隔离边界。

native 加载、ABI、locator、完整性 proof、fragment 校验或页认证任一失败时，运行时 fail-closed；不存在 Java 纯实现回退。

## 6. 静态恢复门槛

静态恢复需要针对当前构建分别重构 evaluator、locator 和 native graph 的语义。恢复一个页面不会提供其他页面的 DEK、locator 或认证材料。连续构建的 fragment 调用图、native table layout、资源路径语法、页大小序列、handle 编码和 dispatcher signature 应保持变化。

发布前应使用固定 artifact-only 预算执行多样本恢复测试，并同时检查：高价值方法恢复数、可启动 clean recovery artifact、单样本脚本在其他构建上的失效情况以及 JAR/冷启动/首次访问预算。

## 7. 验证清单

- 四种 JNI packing profile 都走资源级 AKEN 路径；
- 扫描产物、native strings、常量池与资源树，确认不存在旧协议、外部交付和通用解码面；
- 篡改密文页、native chunk、helper、locator、Merkle path、call-site proof 或 commitment shard 时，相关访问 fail-closed；
- `java -Xverify:all`、目标应用启动、高价值行为基线和 native target matrix 均通过；
- 性能相对相同 pass 集与 packing profile 的基线进行评估。
