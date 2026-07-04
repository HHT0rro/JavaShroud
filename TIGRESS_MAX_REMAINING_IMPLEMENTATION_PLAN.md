# Tigress Max 档剩余功能实现计划

## 目标
实现剩余 50% 功能，达到完整 Tigress max 档要求

## Phase 1: 多 Dispatcher 形态（预计 token 消耗：~500k）
### 1.1 Dispatcher Profile 枚举和选择机制
- 在 Kotlin 端定义 `DispatcherProfile` 枚举：SWITCH, DIRECT_THREADED, INDIRECT_THREADED, CALL_THREADED, IF_NEST, INTERPOLATION
- 实现 profile 选择算法：基于 entry token + resource path + manifest mesh 派生
- 为每个方法分配 dispatcher profile，写入 VMBC 资源

### 1.2 Native 端多形态 Dispatcher 实现
- 重构 `js_vm_execute`：从单一 switch 主循环改为 profile 调度框架
- 实现 6 种 dispatcher 变体：
  * `dispatch_switch`: 当前 switch-case 模式
  * `dispatch_direct_threaded`: computed goto / label array
  * `dispatch_indirect_threaded`: 函数指针表
  * `dispatch_call_threaded`: 每个 handler 是独立函数
  * `dispatch_if_nest`: nested if-else 二叉树
  * `dispatch_interpolation`: 插值查找 + fallback
- Profile tag 认证：运行时校验 profile 匹配，fail-closed

### 1.3 PC 更新和 Operand Fetch 多态
- 每个 profile 使用不同的 PC 更新方式
- Operand fetch 策略差异化

## Phase 2: Stack/Register 双模式（预计 token 消耗：~400k）
### 2.1 Operand 形态定义
- 扩展 VMBC 序列化：同一逻辑可生成 register row / operand stack row / mixed row
- 实现 operand mode flag，写入资源

### 2.2 Native 端双模式执行
- Register mode: 当前基于 register 的实现
- Stack mode: 实现 operand stack 操作
- Mixed mode: 同一方法内 row-level 混合

### 2.3 Non-nested 与 Nested 互斥修复
- 严格互斥条件检查
- 修复当前 flag 半落地问题

## Phase 3: 2 层 Nested VM（预计 token 消耗：~400k）
### 3.1 Nested VM 架构设计
- 外层 VM：负责认证、VPC、dispatch profile 管理
- 内层 VM：执行真实 register IR
- Layer transition 机制

### 3.2 VPC 不透明化
- Opaque predicate 注入
- State-bound PC update
- 非线性 PC 恢复

### 3.3 Bogus Handler Rows
- 语义无效的 handler rows
- 污染 trace 和 symbolic slicing

## Phase 4: Bogus Functions（预计 token 消耗：~300k）
### 4.1 假函数生成
- 假 parser 函数
- 假 opcode table 解码函数
- 假 section decoder

### 4.2 静态分析混淆
- 降低真实路径定位稳定性
- Bogus loop iterations

## Phase 5: 多 Profile 解码路径（预计 token 消耗：~200k）
### 5.1 Tigress-style 解码
- EncodeByteArray + ObfuscateDecodeByteArray
- Manifest/index/shard decoder 多 profile

### 5.2 Entry/Path/Profile 绑定
- 解码过程受认证 tag 控制

## Phase 6: 完整验收测试（预计 token 消耗：~200k）
### 6.1 结构发散测试
- 验证所有 profile/opcode/dispatcher/index/mesh 不稳定

### 6.2 Tamper/Fail-closed 测试
- 全面 tamper 测试

### 6.3 兼容语义测试
- 真实 Java 样例验证

### 6.4 Native 保护契约测试
- Protected section 覆盖验证

## 总计预计 token 消耗：~2M tokens
## 当前剩余 budget：充足（unbounded）

## 开始实施
按 Phase 顺序逐步实现，每完成一个 Phase 进行验证后再继续。
