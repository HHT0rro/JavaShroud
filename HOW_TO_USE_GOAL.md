# 🎯 如何使用强化的 Goal

## 📋 准备工作

### 1. 确认当前位置
```powershell
Get-Location
# 应显示：E:\XiangMu\JavaShroud-public
```

### 2. 查看强化的 Goal
```powershell
code STRENGTHENED_GOAL_WITH_CONTEXT.md
```

## 🚀 启动新的 Goal Session

### 方法 1：复制完整 Goal（推荐）

1. 打开 `STRENGTHENED_GOAL_WITH_CONTEXT.md`
2. 复制 "执行命令" 部分的完整 goal（从 `/goal` 开始到末尾）
3. 在新的 Codex chat 中粘贴并发送

### 方法 2：使用命令行

```powershell
# 查看 goal 内容
Get-Content STRENGTHENED_GOAL_WITH_CONTEXT.md -Encoding UTF8

# 复制到剪贴板（Windows）
Get-Content STRENGTHENED_GOAL_WITH_CONTEXT.md -Encoding UTF8 | clip
```

## 📚 Goal 包含的内容

✅ **完整上下文**
- 当前状态（55% 完成）
- 已完成工作概述
- 工作目录确认

✅ **6个详细任务**
- Task 1-6 的具体步骤
- 每个任务的预期输出
- 代码示例和模板

✅ **明确的成功条件**
- 编译无警告
- 测试 >=528 passed
- 3 种 dispatcher 可工作

✅ **验证命令**
- `.\core-engine\build-native.bat`
- `.\gradlew.bat :core-engine:test --tests "*Vm*"`

✅ **技术要点**
- 上下文传递
- 错误处理
- PC 管理

✅ **阻塞停止条件**
- 连续 3 次失败的场景
- 必须提供的停止信息

✅ **参考文档列表**
- PHASE1_IMPLEMENTATION_CHECKLIST.md
- TIGRESS_MAX_TECHNICAL_SPEC.md
- COMPLETE_HANDOVER_DOCUMENT.md
- 等

## ⏱️ 预计执行时间

**Phase 1 基础（Task 1-6）**：4-6小时

## 📊 执行后的预期结果

### 成功标志
- [x] dispatch_switch 函数提取完成
- [x] dispatch_indirect_threaded 实现完成
- [x] dispatch_if_nest 实现完成
- [x] js_vm_execute 重构完成
- [x] 构建脚本更新完成
- [x] 编译通过，无警告
- [x] 测试 >=528 passed

### 文件变更
- 修改：`core-engine/src/main/native/js_vm_dispatcher.c`
- 修改：`core-engine/src/main/native/js_vm_core.c`
- 修改：`core-engine/src/main/native/build-native-kernel.bat`

## 🔍 如何检查进度

执行中可以查看：
- 编译日志
- 测试输出
- Git 状态：`git status --short`

## 📞 如果遇到问题

Goal 包含明确的阻塞停止条件，如果连续 3 次尝试后仍无法继续，会自动停止并提供：
- 已尝试的方法
- 错误信息
- 阻塞点描述
- 需要的用户输入

## 🎯 下一步（Goal 完成后）

Phase 1 基础完成后，可以继续：
- Task 7-8（Phase 1 完整）：2-3小时
- Phase 2-6：12-16小时

## 📂 所有交接文档

在 `E:\XiangMu\JavaShroud-public` 目录下：

### 核心文档
- STRENGTHENED_GOAL_WITH_CONTEXT.md ⭐⭐⭐
- COMPLETE_HANDOVER_DOCUMENT.md ⭐⭐⭐
- PHASE1_IMPLEMENTATION_CHECKLIST.md ⭐⭐⭐
- QUICK_REFERENCE.md ⭐⭐

### 技术参考
- TIGRESS_MAX_TECHNICAL_SPEC.md
- TIGRESS_MAX_QUICKSTART.md

### 其他文档（共 18个）
- 规划追踪、历史记录、索引导航等

## ✅ 最终检查清单

开始执行前确认：
- [ ] 当前目录：E:\XiangMu\JavaShroud-public
- [ ] Goal 已复制完整
- [ ] 参考文档可访问
- [ ] 理解成功条件
- [ ] 理解阻塞停止条件

---

## 🎉 准备就绪！

**复制 STRENGTHENED_GOAL_WITH_CONTEXT.md 中的完整 goal 到新的 Codex session，开始执行 Phase 1！**

**预计时间**：4-6小时
**目标**：Phase 1 基础完成
**最终目标**：100% Tigress max 档

---

*创建时间：2026-05-07 上午 2:48*
*工作目录：E:\XiangMu\JavaShroud-public*
*Goal 状态：准备启动*
