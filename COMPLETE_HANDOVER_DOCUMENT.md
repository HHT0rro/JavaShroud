# Tigress Max 档实施 - 完整交接文档

## 📋 项目概览

### 目标
实现 100% Tigress max 档 native 加固，防止破一次 native 后形成跨样本一键 deobf

### 当前状态
- **完成度**：55% / 100%
- **位置**：`E:\XiangMu\JavaShroud-public`
- **Goal 状态**：ACTIVE
- **Token 使用**：约 4.03M

---

## ✅ 已完成工作（50% → 55%）

### 1. 核心防护机制（50%，前期完成）
- ✅ Per-artifact/per-method/per-run 发散机制
- ✅ Anti-debug poison 多路径注入
- ✅ Native integrity checkpoints
- ✅ 明文窗口压缩
- ✅ Masked preload index V2
- ✅ Manifest mesh validation
- ✅ Bogus handler rows
- ✅ 528 tests passed

### 2. Phase 1 架构和框架（+5%，本次完成）

#### 2.1 完整文档体系（9个文档）
- ✅ `TIGRESS_MAX_TECHNICAL_SPEC.md` (7.8KB) - 技术规格和代码模板
- ✅ `TIGRESS_MAX_REMAINING_IMPLEMENTATION_PLAN.md` (3.2KB) - 总体计划
- ✅ `PHASE1_IMPLEMENTATION_CHECKLIST.md` (5.5KB) - 逐步实施指南
- ✅ `TIGRESS_MAX_QUICKSTART.md` (3.8KB) - 快速启动
- ✅ `TIGRESS_MAX_PROGRESS_UPDATE.md` (4.0KB) - 进度追踪
- ✅ `TIGRESS_MAX_SESSION_REPORT.md` (3.5KB) - Session 报告
- ✅ `SESSION_FINAL_SUMMARY.md` (4.1KB) - 最终总结
- ✅ `README_IMPLEMENTATION.md` (4.5KB) - 文档索引
- ✅ `TIGRESS_NATIVE_MAX_IMPLEMENTATION_SUMMARY.md` (8.3KB) - 前期总结

#### 2.2 代码框架（3个文件）
- ✅ `core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/DispatcherProfile.kt`
  * 6 种 profile 枚举
  * selectFromAuth() 实现
  * encode/decode 方法

- ✅ `core-engine/src/main/native/js_vm_dispatcher.h`
  * dispatcher_profile_t 枚举
  * dispatcher_fn 函数指针类型
  * 函数声明

- ✅ `core-engine/src/main/native/js_vm_dispatcher.c`
  * js_vm_get_dispatcher() 实现
  * 4 个 dispatcher 框架（占位符）
  * 认证占位符

---

## 🚧 待完成工作（剩余 45%）

### Phase 1: 多 Dispatcher 形态（~10%，6-9小时）

#### Task 1: 提取 dispatch_switch ⭐⭐⭐
**优先级**：P0（最高）
**预计时间**：1-2小时
**状态**：⏸️ 待开始

**目标**：
从 `js_vm_core.c` 提取现有主执行循环为独立的 `dispatch_switch` 函数

**步骤**：
1. 打开 `core-engine/src/main/native/js_vm_core.c`
2. 找到主执行循环（通常包含 `while` + `switch(opcode)`）
3. 识别循环边界（初始化、循环体、退出条件）
4. 复制循环体到 `js_vm_dispatcher.c` 的 `dispatch_switch` 函数
5. 调整参数访问（使用传入的 `ctx`, `program`, `program_size`）
6. 验证语义等价

**预期输出**：
```c
jvalue dispatch_switch(JNIEnv* env, js_vm_context_t* ctx,
                       const uint8_t* program, uint32_t program_size) {
    uint32_t pc = 0;
    while (pc < program_size) {
        uint8_t opcode = program[pc++];
        switch (opcode) {
            case 0x01: /* handler */ break;
            // ... 所有 opcodes
        }
    }
    return result;
}
```

**验证**：
- 编译通过
- 可以被 `js_vm_get_dispatcher(DISPATCHER_SWITCH)` 调用

---

#### Task 2: 实现 dispatch_indirect_threaded ⭐⭐
**优先级**：P0
**预计时间**：1-2小时
**状态**：⏸️ 待开始
**依赖**：Task 1

**目标**：
实现基于函数指针表的 dispatcher

**步骤**：
1. 定义 handler 函数类型：
   ```c
   typedef jvalue (*opcode_handler_t)(JNIEnv*, js_vm_context_t*, const uint8_t**, uint32_t*);
   ```
2. 为每个 opcode 创建独立的 handler 函数
3. 构建函数指针数组
4. 实现 dispatch 循环

**预期输出**：
```c
static opcode_handler_t handlers[256] = {
    handler_load,
    handler_store,
    // ...
};

jvalue dispatch_indirect_threaded(...) {
    uint32_t pc = 0;
    while (pc < program_size) {
        uint8_t opcode = program[pc++];
        handlers[opcode](env, ctx, &program[pc], &pc);
    }
}
```

**验证**：
- 编译通过
- 功能与 dispatch_switch 等价

---

#### Task 3: 实现 dispatch_if_nest ⭐⭐
**优先级**：P0
**预计时间**：1小时
**状态**：⏸️ 待开始
**依赖**：Task 1

**目标**：
实现二叉树 if-else dispatcher

**步骤**：
1. 分析 opcode 分布（0-255）
2. 构建二叉决策树
3. 实现嵌套 if-else 结构

**预期输出**：
```c
jvalue dispatch_if_nest(...) {
    while (pc < program_size) {
        uint8_t op = program[pc++];
        if (op < 128) {
            if (op < 64) {
                if (op < 32) {
                    // 0-31
                } else {
                    // 32-63
                }
            } else {
                // 64-127
            }
        } else {
            // 128-255
        }
    }
}
```

**验证**：
- 编译通过
- 功能等价

---

#### Task 4: 重构 js_vm_execute ⭐⭐⭐
**优先级**：P0
**预计时间**：30分钟
**状态**：⏸️ 待开始
**依赖**：Task 1, 2, 3

**目标**：
将 `js_vm_execute` 改为 dispatcher 选择器

**文件**：`core-engine/src/main/native/js_vm_core.c`

**修改**：
```c
jvalue js_vm_execute(JNIEnv* env, js_vm_context_t* ctx,
                     const uint8_t* program, uint32_t size) {
    // 1. Read dispatcher profile
    dispatcher_profile_t profile = js_vm_read_dispatcher_profile(ctx);
    
    // 2. Verify authentication
    if (!js_vm_verify_dispatcher_auth(ctx, profile)) {
        return fail_closed();
    }
    
    // 3. Get dispatcher function
    dispatcher_fn dispatcher = js_vm_get_dispatcher(profile);
    if (!dispatcher) {
        return fail_closed();
    }
    
    // 4. Execute
    return dispatcher(env, ctx, program, size);
}
```

**验证**：
- 编译通过
- 默认 SWITCH profile 工作正常

---

#### Task 5: 修改构建脚本 ⭐
**优先级**：P0
**预计时间**：15分钟
**状态**：⏸️ 待开始
**依赖**：Task 1-4

**文件**：`core-engine/src/main/native/build-native-kernel.bat`

**修改**：
在编译列表中添加：
```batch
js_vm_dispatcher.c
```

**验证**：
运行 `.\core-engine\build-native.bat` 成功

---

#### Task 6: 编译和测试 ⭐⭐⭐
**优先级**：P0
**预计时间**：30-60分钟
**状态**：⏸️ 待开始
**依赖**：Task 1-5

**命令**：
```powershell
# 1. 编译 native
.\core-engine\build-native.bat

# 2. 运行测试
.\gradlew.bat :core-engine:test --tests "*Vm*"

# 3. 完整测试
.\gradlew.bat :core-engine:test --tests "*Vbc4*" --tests "*Vm*"
```

**预期结果**：
- 编译成功，无警告
- 至少 528 tests passed
- 无新增失败

**问题排查**：
- 编译错误：检查头文件包含和函数签名
- 链接错误：检查 build-native-kernel.bat
- 运行时错误：添加日志输出调试

---

#### Task 7: Profile 序列化（可选）⭐⭐
**优先级**：P1
**预计时间**：1-2小时
**状态**：⏸️ 待开始
**依赖**：Task 6 完成

**目标**：
将 dispatcher profile 序列化到 VMBC 资源

**文件**：
- `core-engine/src/main/kotlin/.../VmBytecodeSerializer.kt`
- `core-engine/src/main/native/js_vm_resource.c`

**步骤**：
1. 在序列化时调用 `DispatcherProfile.selectFromAuth()`
2. 将 profile 写入资源（marker: 0xD1）
3. 修改 `js_vm_read_dispatcher_profile()` 读取

**验证**：
- Profile 正确写入和读取
- 不同构建得到不同 profile（发散测试）

---

#### Task 8: Profile 认证（可选）⭐⭐
**优先级**：P1
**预计时间**：1-2小时
**状态**：⏸️ 待开始
**依赖**：Task 7

**目标**：
实现完整的 profile 认证链

**步骤**：
1. 设计认证 tag 格式
2. 在 Kotlin 端生成 tag
3. 在 Native 端验证 tag
4. 实现 fail-closed 逻辑

**验证**：
- 正确 profile 通过验证
- 错误 profile 被拒绝
- Tamper 测试通过

---

### Phase 2: Stack/Register 双模式（~8%，3-4小时）

**优先级**：P1
**状态**：⏸️ 待开始
**依赖**：Phase 1 完成

**主要任务**：
1. 定义 OperandMode 枚举（REGISTER/STACK/MIXED）
2. 实现 operand stack 操作
3. Native 端双模式执行
4. Non-nested 与 Nested 互斥修复

**参考文档**：`TIGRESS_MAX_TECHNICAL_SPEC.md` - Phase 2 部分

---

### Phase 3: Nested VM 与 VPC 不透明化（~8%，4-5小时）

**优先级**：P1
**状态**：⏸️ 待开始
**依赖**：Phase 2 完成

**主要任务**：
1. 设计 2 层 VM 架构
2. 外层 VM：认证 + dispatch 管理
3. 内层 VM：真实执行
4. VPC opaque predicate
5. Bogus handler rows

**参考文档**：`TIGRESS_MAX_TECHNICAL_SPEC.md` - Phase 3 部分

---

### Phase 4: Bogus Functions（~6%，3-4小时）

**优先级**：P2
**状态**：⏸️ 待开始
**依赖**：Phase 3 完成

**主要任务**：
1. 生成假 parser 函数
2. 假 opcode table
3. 假 section decoder
4. Bogus loop iterations

---

### Phase 5: 多 Profile 解码路径（~5%，2-3小时）

**优先级**：P2
**状态**：⏸️ 待开始
**依赖**：Phase 4 完成

**主要任务**：
1. Tigress EncodeByteArray/ObfuscateDecodeByteArray
2. Manifest/index/shard 多 profile 解码
3. Entry/path/profile 三重绑定

---

### Phase 6: 完整验收测试（~8%，2-3小时）

**优先级**：P0（最终）
**状态**：⏸️ 待开始
**依赖**：Phase 1-5 完成

**测试清单**：
- [ ] 结构发散测试（所有 profile/opcode/index/mesh 不稳定）
- [ ] Tamper/fail-closed 测试（任意篡改必须拒绝）
- [ ] 兼容语义测试（真实 Java 样例输出一致）
- [ ] Native 保护契约测试（protected section 覆盖）

**验证命令**：
```powershell
.\gradlew.bat :core-engine:test --tests "*Vbc4*" --tests "*Vm*" --tests "*RuntimeResourceCodecTest" --tests "*SchemaCapabilitiesTest"
.\core-engine\build-native.bat
.\gradlew.bat :core-engine:shadowJar
```

---

## 📚 关键文档索引

### 立即使用（按优先级）
1. **`PHASE1_IMPLEMENTATION_CHECKLIST.md`** ⭐⭐⭐
   - Task 1-8 详细步骤
   - 预期输出和验证标准
   - 最重要的实施指南

2. **`TIGRESS_MAX_TECHNICAL_SPEC.md`** ⭐⭐
   - 完整技术规格
   - 代码模板和示例
   - Phase 1-6 详细设计

3. **`SESSION_FINAL_SUMMARY.md`** ⭐
   - 本次 session 总结
   - 当前状态快照

4. **`README_IMPLEMENTATION.md`** ⭐
   - 文档导航和索引
   - 快速访问指南

### 规划参考
5. `TIGRESS_MAX_REMAINING_IMPLEMENTATION_PLAN.md`
   - 总体计划和 token 预算

6. `TIGRESS_MAX_PROGRESS_UPDATE.md`
   - 进度追踪和风险点

7. `TIGRESS_MAX_QUICKSTART.md`
   - 快速启动指令

### 历史记录
8. `TIGRESS_NATIVE_MAX_IMPLEMENTATION_SUMMARY.md`
   - 前期 50% 工作总结

9. `TIGRESS_MAX_SESSION_REPORT.md`
   - Session 中间报告

---

## 🔧 技术要点

### Dispatcher 实现注意事项

#### 1. Switch Dispatcher（当前实现）
- 直接提取现有主循环
- 保持原有语义不变
- 最简单，最稳定

#### 2. Indirect Threaded Dispatcher
- 需要 handler 函数指针数组
- 每个 opcode 一个独立函数
- 注意 PC 和参数传递

#### 3. If-nest Dispatcher
- 构建二叉决策树
- 按 opcode 值范围划分
- 注意分支平衡

#### 4. Direct Threaded（GCC only）
- 仅在 `__GNUC__` 定义时编译
- 使用 `&&label` 和 `goto *`
- 最快但依赖 GCC 扩展

#### 5. Call Threaded（高级）
- 预处理 program 为调用序列
- 实现复杂度高
- 可选实现

#### 6. Interpolation（高级）
- 插值搜索 + 线性 fallback
- 适合 opcode 分布不均匀
- 可选实现

### 关键数据结构

```c
// Dispatcher profile 枚举
typedef enum {
    DISPATCHER_SWITCH = 0,
    DISPATCHER_DIRECT_THREADED = 1,
    DISPATCHER_INDIRECT_THREADED = 2,
    DISPATCHER_CALL_THREADED = 3,
    DISPATCHER_IF_NEST = 4,
    DISPATCHER_INTERPOLATION = 5
} dispatcher_profile_t;

// Dispatcher 函数指针类型
typedef jvalue (*dispatcher_fn)(
    JNIEnv* env,
    js_vm_context_t* ctx,
    const uint8_t* program,
    uint32_t program_size
);
```

### 上下文传递
确保所有 dispatcher 正确使用：
- `JNIEnv* env` - JNI 环境
- `js_vm_context_t* ctx` - VM 上下文
- `const uint8_t* program` - 字节码程序
- `uint32_t program_size` - 程序大小

### 错误处理
所有路径都要有 fail-closed 逻辑：
```c
if (error_condition) {
    return fail_closed_result();
}
```

---

## ⚠️ 风险和缓解

### 风险 1: 主循环提取失败
**影响**：无法完成 Task 1
**缓解**：
- 先创建简化版本
- 逐步对齐现有行为
- 保留原有代码作为参考

### 风险 2: 性能回退
**影响**：不同 dispatcher 性能差异大
**缓解**：
- 保留 SWITCH 作为默认
- 性能敏感场景优先使用 SWITCH
- 实测性能差异

### 风险 3: 兼容性问题
**影响**：新代码与现有 VMBC 不兼容
**缓解**：
- 逐步迁移
- 先保持双路径并存
- 充分测试

### 风险 4: 构建失败
**影响**：无法编译或链接
**缓解**：
- 检查头文件包含
- 验证函数签名一致
- 确认构建脚本正确

---

## 🎯 里程碑和验收标准

### Milestone 1: Phase 1 基础（Task 1-6）
**预计时间**：4-6小时
**完成标志**：
- [ ] 至少 3 个 dispatcher 实现
- [ ] 编译通过，无警告
- [ ] 测试套件保持绿色（>=528 passed）
- [ ] 默认 SWITCH profile 正常工作

### Milestone 2: Phase 1 完整（Task 7-8）
**预计时间**：+2-3小时
**完成标志**：
- [ ] Profile 序列化和读取
- [ ] Profile 认证生效
- [ ] 发散测试通过
- [ ] Tamper 测试通过

### Milestone 3: Phase 2-6 完成
**预计时间**：15-20小时
**完成标志**：
- [ ] Stack/Register 双模式
- [ ] Nested VM
- [ ] Bogus functions
- [ ] 多 profile 解码
- [ ] 完整验收测试通过

### 最终验收：100% Tigress max 档
**完成标志**：
- [ ] 所有 Phase 完成
- [ ] 所有测试通过
- [ ] 发散性验证通过
- [ ] Fail-closed 机制生效
- [ ] 性能在可接受范围

---

## 🚀 立即开始指令

### 进入工作目录
```powershell
cd E:\XiangMu\JavaShroud-public
Get-Location  # 确认位置
```

### 打开关键文档
```powershell
code PHASE1_IMPLEMENTATION_CHECKLIST.md
code TIGRESS_MAX_TECHNICAL_SPEC.md
code README_IMPLEMENTATION.md
```

### 打开代码文件
```powershell
code core-engine/src/main/native/js_vm_dispatcher.c
code core-engine/src/main/native/js_vm_core.c
code core-engine/src/main/native/js_vm_dispatcher.h
```

### 开始 Task 1
1. 阅读 `PHASE1_IMPLEMENTATION_CHECKLIST.md` - Task 1 部分
2. 打开 `js_vm_core.c`，找到主执行循环
3. 复制到 `js_vm_dispatcher.c` 的 `dispatch_switch` 函数
4. 调整参数访问
5. 编译测试

---

## 📊 时间预估总表

| Phase | 描述 | 预计时间 | 优先级 | 状态 |
|-------|------|---------|--------|------|
| Phase 1 基础 | Task 1-6 | 4-6h | P0 | ⏸️ |
| Phase 1 完整 | Task 7-8 | 2-3h | P1 | ⏸️ |
| Phase 2 | Stack/Register | 3-4h | P1 | ⏸️ |
| Phase 3 | Nested VM | 4-5h | P1 | ⏸️ |
| Phase 4 | Bogus Functions | 3-4h | P2 | ⏸️ |
| Phase 5 | 多 Profile 解码 | 2-3h | P2 | ⏸️ |
| Phase 6 | 完整验收 | 2-3h | P0 | ⏸️ |
| **总计** | | **20-28h** | | |

---

## 💡 成功的关键

1. **渐进式实施**：先做 3 个基础 dispatcher，再扩展
2. **持续验证**：每完成一个 Task 立即测试
3. **保持兼容**：SWITCH 作为默认和后备
4. **文档优先**：遇到问题先查文档
5. **证据驱动**：用测试结果证明完成度

---

## 📞 支持资源

### 文档位置
`E:\XiangMu\JavaShroud-public\*.md`

### 代码位置
- Kotlin: `core-engine/src/main/kotlin/io/github/hht0rro/javashroud/transforms/protection/`
- Native: `core-engine/src/main/native/`

### 构建命令
```powershell
.\core-engine\build-native.bat
.\gradlew.bat :core-engine:test --tests "*Vm*"
```

### Git 状态
```powershell
git status --short
```

---

## 🎉 准备完毕！

**当前状态**：
- ✅ 架构设计完成
- ✅ 框架代码就绪
- ✅ 实施路径明确
- ✅ 文档齐全完备

**下一步**：
从 Task 1 开始，提取 `dispatch_switch`，启动 Phase 1 核心实现！

**目标**：100% Tigress max 档

**预计剩余**：18-25小时

---

*最后更新：2026-05-07*
*Goal 状态：ACTIVE*
*完成度：55%*
