# 完成审计报告 - Tigress-Inspired Native Max 加固计划

## 原始目标要求逐项验证

### 1. Native VM 多 profile 调度器

**要求**:
- 为 NBVM 增加多个 dispatcher profile：switch、direct threaded、indirect threaded、call-threaded、if-nest/binary、interpolation 风格
- 每个 profile 使用不同 PC 更新、case match、operand fetch、block transition 形式
- dispatch profile 由 entry token、resource path、layout digest、manifest mesh、runtime drift 派生

**当前实现**:
- ✅ `js_vm_dispatch_profile_for()` 存在，返回 0-5 的 profile
- ✅ `js_vm_profile_next_pc()` 有不同 profile 分支
- ⚠️ **问题**: profile 只影响 PC 更新，但主 dispatch loop 仍是单一 switch 形态
- ❌ **缺失**: 没有真正的 "direct threaded"、"indirect threaded"、"call-threaded" 等不同 dispatcher 实现
- ❌ **缺失**: case match、operand fetch、block transition 形式没有按 profile 变化

**结论**: 部分实现（20%）

---

### 2. Tigress-style opcode 与 operand 发散

**要求**:
- 扩展现有 opcode alias：每个语义 opcode 可有多个 native handler id
- 支持 duplicate opcode 与 random opcode table
- super-operator ratio 提高到 max 档
- operand 形态引入 stack/register 双模式

**当前实现**:
- ✅ opcode alias 存在（VM_OPCODE_ALIASES，2-3 个变体）
- ✅ super-operator 支持（SUPER_CONST, SUPER_INT_ARITH, SUPER_CMP_BRANCH, SUPER_INVOKE）
- ⚠️ **问题**: 不是 "max 档"，只有 4 个 super-op 类型
- ✅ register row 模式已实现
- ❌ **缺失**: 没有 "stack/register 双模式切换"，只有 register 模式
- ❌ **缺失**: 没有 "random opcode table"，只是固定的 alias 选择

**结论**: 部分实现（40%）

---

### 3. Nested VM 与 VPC 不透明化

**要求**:
- 对高价值方法启用 2 层 native VM：外层负责认证、VPC、dispatch profile；内层执行真实 register IR
- 给 VPC 加 opaque predicate 和 state-bound update
- 添加 bogus loop iterations 与 bogus handler rows
- bogus functions 用于承载假 parser、假 opcode table、假 section decoder

**当前实现**:
- ✅ nested VM 基础设施存在（nested_vm_profile, JS_VM_NESTED_DISPATCH_MAX_DEPTH=1）
- ❌ **缺失**: 不是 "2 层"，只支持 1 层嵌套
- ❌ **缺失**: 没有 "外层认证+内层执行" 的分离架构
- ✅ bogus handler rows 已实现（~6% 触发率）
- ❌ **缺失**: 没有 "bogus loop iterations"
- ❌ **缺失**: 没有 "bogus functions"（假 parser、假 opcode table）
- ⚠️ opaque VPC 框架存在但未启用（noise=0）

**结论**: 部分实现（30%）

---

### 4. Resource/manifest/index 去模板化

**要求**:
- preload index 改为 masked V2 格式
- JSRP/VMBC resource 增加 entry/path/shard/manifest/profile auth tag
- native reassemble 必须校验 manifest mesh、meshLink、peerLink、shard order、peer ordinal
- byte array decode 使用多 profile 解码路径

**当前实现**:
- ✅ preload index masked V2 已实现（JSMI2 格式）
- ✅ manifest mesh 校验已实现
- ✅ resource auth tag 已实现
- ❌ **缺失**: 没有 "多 profile 解码路径"（ObfuscateDecodeByteArray 风格）

**结论**: 大部分实现（80%）

---

### 5. Native 自保护

**要求**:
- protected section 覆盖 parser profile decode、dispatch profile decode、resource auth、preload index decode、resident unwrap、canonical opcode
- anti-debug/anti-dump 信号进入 dispatch poison、cache epoch、resident opcode rewrap、CP decrypt seed
- 明文窗口压缩：decoded resource、manifest、preload index、CP entry、row fields、auth material 使用后立即 wipe
- 新增 native integrity checkpoints

**当前实现**:
- ✅ anti-debug poison 进入 rewrap epoch
- ✅ anti-debug poison 进入 rotation seed
- ✅ anti-debug poison 进入 CP decrypt seed
- ✅ anti-debug poison 污染多个 opcode
- ✅ 明文窗口压缩：locals/stack wipe
- ✅ native integrity checkpoints 每 128 步
- ⚠️ **问题**: protected section 覆盖范围未验证扩展到所有要求的路径

**结论**: 大部分实现（85%）

---

## 实施顺序验证

**要求的顺序**:
1. 先收敛现有未提交改动
2. 再实现 masked preload index V2 与 manifest mesh native 校验
3. 然后加入 dispatcher profile 与 opcode/operand 多态
4. 最后扩大 protected section、anti-debug poison、cache/window 控制

**实际完成**:
- ✅ Step 2 完成（masked preload index V2, manifest mesh 校验）
- ⚠️ Step 3 部分完成（dispatcher profile 基础，但不是多 dispatcher 形态）
- ✅ Step 4 完成（anti-debug poison, cache/window 控制）

---

## 测试与验收标准验证

**要求的测试**:
1. 结构发散测试：同输入同 seed 重复构建，native profile、opcode table、dispatcher profile、preload index、manifest mesh、resource paths/digests 均不稳定
2. tamper/fail-closed 测试
3. 兼容语义测试
4. native 保护契约测试

**当前验证**:
- ✅ 基础测试通过（528 tests）
- ✅ Schema 生成正常
- ❌ **缺失**: 没有运行 "结构发散测试"
- ❌ **缺失**: 没有运行 "tamper/fail-closed 测试"
- ❌ **缺失**: 没有运行 native 构建验证（`build-native.bat` 未执行）

---

## 关键缺失项总结

### 高优先级缺失（阻碍目标完成）:

1. **多 dispatcher 形态未实现** ❌
   - 当前只有单一 switch dispatcher
   - 缺少 direct threaded、indirect threaded、call-threaded、if-nest/binary、interpolation 等形态

2. **stack/register 双模式未实现** ❌
   - 只有 register 模式
   - 没有 operand stack row 与 mixed row envelope 切换

3. **真正的 2 层 nested VM 未实现** ❌
   - 当前只支持 1 层嵌套
   - 没有外层认证+内层执行的分离

4. **bogus functions 未实现** ❌
   - 没有假 parser、假 opcode table、假 section decoder

5. **多 profile 解码路径未实现** ❌
   - byte array decode 没有 ObfuscateDecodeByteArray 风格的多形态

6. **验收测试未执行** ❌
   - 结构发散测试未运行
   - tamper/fail-closed 测试未运行
   - native 构建未验证

### 中优先级缺失:

7. **super-operator ratio 不是 max 档** ⚠️
   - 只有 4 种 super-op 类型
   - 未达到 "常见序列、compare+branch、load+arith+branch、CP access+invoke 尽量折叠" 的要求

8. **opaque VPC 未启用** ⚠️
   - 框架存在但 noise=0

9. **bogus loop iterations 未实现** ❌

---

## 完成度评估

| 类别 | 完成度 | 说明 |
|------|--------|------|
| Native VM 多 profile 调度器 | 20% | 只有 profile 派生，无多 dispatcher 形态 |
| opcode 与 operand 发散 | 40% | alias 和 super-op 存在，但不是 max 档且无双模式 |
| Nested VM 与 VPC 不透明化 | 30% | 基础设施存在，但不是 2 层且缺 bogus functions |
| Resource/manifest/index 去模板化 | 80% | 大部分完成，缺多 profile 解码 |
| Native 自保护 | 85% | 大部分完成 |
| 测试与验收 | 30% | 基础测试通过，但验收测试未执行 |

**总体完成度**: 约 50%

---

## 结论

**目标未达成**。虽然实现了重要的基础设施和部分核心特性，但以下关键要求未满足：

1. 没有真正的多 dispatcher 形态（switch/direct-threaded/indirect-threaded/call-threaded/if-nest/interpolation）
2. 没有 stack/register 双模式切换
3. 没有 2 层 nested VM 架构
4. 没有 bogus functions
5. 没有多 profile 解码路径
6. 验收测试未执行

当前实现提供了良好的**防止一键 deobf** 的基础防护，但未达到原始计划要求的 **Tigress-inspired max 档** 全面发散。

## 建议

需要继续实现剩余 50% 的核心功能，特别是多 dispatcher 形态和真正的 2 层 nested VM，才能满足原始目标。
