# 强化的 Goal 声明

## 原始需求
继续实施 Tigress Max 档剩余 45% 工作，从 Phase 1 Task 1 开始

## 强化后的 Goal

/goal 实现 Tigress-Inspired Native Max 加固的 Phase 1 核心功能（多 Dispatcher 形态），包括：(1) 从 js_vm_core.c 提取主循环为 dispatch_switch 函数，(2) 实现 dispatch_indirect_threaded 和 dispatch_if_nest 两个额外 dispatcher，(3) 重构 js_vm_execute 为 dispatcher 选择器，(4) 修改 build-native-kernel.bat 包含新文件，(5) 编译通过并运行测试。成功条件：编译无警告、测试保持 >=528 passed、3 种 dispatcher 可正常工作。验证方式：执行 `.\core-engine\build-native.bat` 成功，执行 `.\gradlew.bat :core-engine:test --tests "*Vm*"` 通过。约束条件：工作目录为 E:\XiangMu\JavaShroud-public，保持现有 VMBC 格式兼容性，默认使用 SWITCH profile 确保向后兼容。如遇到阻塞：在连续 3 次尝试后仍无法提取主循环、或编译持续失败、或测试回退超过 10 个，则停止并报告已尝试的方法、收集的错误信息、具体阻塞点和需要的用户输入（如架构决策或环境配置）。

## Goal 组成部分说明

### 1. 成功条件（Success Condition）
- 提取 dispatch_switch 函数完成
- 实现 2 个额外 dispatcher（indirect_threaded, if_nest）
- js_vm_execute 重构完成
- 构建脚本更新
- 编译无警告
- 测试 >=528 passed
- 3 种 dispatcher 可工作

### 2. 验证表面（Verification Surface）
- `.\core-engine\build-native.bat` 编译成功
- `.\gradlew.bat :core-engine:test --tests "*Vm*"` 测试通过
- 代码可编译且功能正常

### 3. 约束条件（Constraints）
- 工作目录：E:\XiangMu\JavaShroud-public
- 保持 VMBC 格式兼容性
- 默认 SWITCH profile（向后兼容）
- 不修改现有测试预期行为

### 4. 阻塞停止条件（Blocked Stop Condition）
连续 3 次尝试后仍遇到以下情况之一：
- 无法从 js_vm_core.c 提取主循环
- 编译持续失败
- 测试回退超过 10 个

停止时必须提供：
- 已尝试的所有方法
- 收集的错误信息和日志
- 具体阻塞点描述
- 需要的用户输入类型（架构决策/环境配置/等）

## 执行命令

将以下 goal 复制到新的 Codex session：

```
/goal 实现 Tigress-Inspired Native Max 加固的 Phase 1 核心功能（多 Dispatcher 形态），包括：(1) 从 js_vm_core.c 提取主循环为 dispatch_switch 函数，(2) 实现 dispatch_indirect_threaded 和 dispatch_if_nest 两个额外 dispatcher，(3) 重构 js_vm_execute 为 dispatcher 选择器，(4) 修改 build-native-kernel.bat 包含新文件，(5) 编译通过并运行测试。成功条件：编译无警告、测试保持 >=528 passed、3 种 dispatcher 可正常工作。验证方式：执行 `.\core-engine\build-native.bat` 成功，执行 `.\gradlew.bat :core-engine:test --tests "*Vm*"` 通过。约束条件：工作目录为 E:\XiangMu\JavaShroud-public，保持现有 VMBC 格式兼容性，默认使用 SWITCH profile 确保向后兼容。如遇到阻塞：在连续 3 次尝试后仍无法提取主循环、或编译持续失败、或测试回退超过 10 个，则停止并报告已尝试的方法、收集的错误信息、具体阻塞点和需要的用户输入（如架构决策或环境配置）。
```

## 参考文档

执行前请阅读：
- PHASE1_IMPLEMENTATION_CHECKLIST.md - Task 1-6 详细步骤
- TIGRESS_MAX_TECHNICAL_SPEC.md - 代码模板
- COMPLETE_HANDOVER_DOCUMENT.md - 完整上下文

## 预计时间

Phase 1 基础（Task 1-6）：4-6 小时

## 当前状态

- 工作目录：E:\XiangMu\JavaShroud-public
- 完成度：55%
- 代码框架：已就绪
- 文档：17个齐全

---

准备好开始执行！
