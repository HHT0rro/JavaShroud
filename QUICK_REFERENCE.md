# 🚀 快速参考卡片

## 📍 当前状态
- **位置**：`E:\XiangMu\JavaShroud-public`
- **完成度**：55% / 100%
- **Goal**：ACTIVE
- **下一步**：Task 1 - 提取 dispatch_switch

## 🎯 立即开始（3步）

### 1️⃣ 打开文档（30秒）
```powershell
cd E:\XiangMu\JavaShroud-public
code PHASE1_IMPLEMENTATION_CHECKLIST.md
```

### 2️⃣ 打开代码（30秒）
```powershell
code core-engine/src/main/native/js_vm_dispatcher.c
code core-engine/src/main/native/js_vm_core.c
```

### 3️⃣ 开始 Task 1（1-2小时）
- 在 `js_vm_core.c` 找主循环
- 复制到 `js_vm_dispatcher.c` 的 `dispatch_switch`
- 调整参数，编译测试

## 📚 关键文档（按重要性）

| 文档 | 用途 | 重要性 |
|------|------|--------|
| `COMPLETE_HANDOVER_DOCUMENT.md` | 完整交接 | ⭐⭐⭐ |
| `PHASE1_IMPLEMENTATION_CHECKLIST.md` | Task 指南 | ⭐⭐⭐ |
| `TIGRESS_MAX_TECHNICAL_SPEC.md` | 代码模板 | ⭐⭐ |
| `README_IMPLEMENTATION.md` | 文档索引 | ⭐ |

## ✅ Phase 1 待办清单

- [ ] **Task 1**: 提取 dispatch_switch (1-2h)
- [ ] **Task 2**: 实现 dispatch_indirect_threaded (1-2h)
- [ ] **Task 3**: 实现 dispatch_if_nest (1h)
- [ ] **Task 4**: 重构 js_vm_execute (30min)
- [ ] **Task 5**: 修改构建脚本 (15min)
- [ ] **Task 6**: 编译和测试 (30-60min)
- [ ] **Task 7**: Profile 序列化 (1-2h, 可选)
- [ ] **Task 8**: Profile 认证 (1-2h, 可选)

**Phase 1 预计**：6-9小时

## 🔧 常用命令

```powershell
# 编译
.\core-engine\build-native.bat

# 测试
.\gradlew.bat :core-engine:test --tests "*Vm*"

# 完整测试
.\gradlew.bat :core-engine:test --tests "*Vbc4*" --tests "*Vm*"

# 状态
git status --short
```

## 📊 进度追踪

```
已完成：55% ━━━━━━━━━━━
Phase 1： 10% ━━ (待实施)
Phase 2-6：35% ━━━━━━━ (待规划)
```

## ⚡ 验收标准

### Phase 1 完成标志：
- ✅ 3+ dispatcher 实现
- ✅ 编译通过，无警告  
- ✅ 测试保持 >=528 passed
- ✅ Profile 选择生效

## 💡 快速提示

1. **遇到问题**：先查 `PHASE1_IMPLEMENTATION_CHECKLIST.md`
2. **需要代码**：查 `TIGRESS_MAX_TECHNICAL_SPEC.md`
3. **找不到文档**：查 `README_IMPLEMENTATION.md`
4. **完整信息**：查 `COMPLETE_HANDOVER_DOCUMENT.md`

## 🎯 目标

100% Tigress max 档
预计剩余：18-25小时

---

**立即行动**：打开 `PHASE1_IMPLEMENTATION_CHECKLIST.md`，开始 Task 1！
