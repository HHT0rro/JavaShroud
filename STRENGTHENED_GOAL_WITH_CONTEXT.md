# 强化的 Goal（包含完整上下文）

## 执行命令

将以下完整 goal 复制到新的 Codex session：

```
/goal 实现 Tigress-Inspired Native Max 加固的 Phase 1 核心功能（多 Dispatcher 形态）。

## 背景和上下文
当前在 E:\XiangMu\JavaShroud-public，完成度 55%。前期已完成核心防护机制（per-artifact/per-method/per-run 发散、anti-debug poison、integrity checkpoints、masked preload index V2、manifest mesh validation）和 Phase 1 架构框架（DispatcherProfile.kt、js_vm_dispatcher.h、js_vm_dispatcher.c 框架已创建）。

## 目标任务（Phase 1 基础，Task 1-6）

### Task 1: 提取 dispatch_switch（1-2小时）
从 core-engine/src/main/native/js_vm_core.c 找到主执行循环（通常包含 while + switch(opcode)），复制到 js_vm_dispatcher.c 的 dispatch_switch 函数体，调整参数访问使用传入的 ctx、program、program_size。预期输出：
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

### Task 2: 实现 dispatch_indirect_threaded（1-2小时）
定义 handler 函数类型 `typedef jvalue (*opcode_handler_t)(JNIEnv*, js_vm_context_t*, const uint8_t**, uint32_t*);`，为每个 opcode 创建独立 handler 函数，构建函数指针数组 `opcode_handler_t handlers[256]`，实现基于数组的 dispatch 循环。

### Task 3: 实现 dispatch_if_nest（1小时）
构建二叉决策树，使用嵌套 if-else 按 opcode 值范围（0-31, 32-63, 64-127, 128-255）分支选择 handler。

### Task 4: 重构 js_vm_execute（30分钟）
修改 core-engine/src/main/native/js_vm_core.c 中的 js_vm_execute：
```c
jvalue js_vm_execute(JNIEnv* env, js_vm_context_t* ctx,
                     const uint8_t* program, uint32_t size) {
    dispatcher_profile_t profile = js_vm_read_dispatcher_profile(ctx);
    if (!js_vm_verify_dispatcher_auth(ctx, profile)) {
        return fail_closed();
    }
    dispatcher_fn dispatcher = js_vm_get_dispatcher(profile);
    if (!dispatcher) {
        return fail_closed();
    }
    return dispatcher(env, ctx, program, size);
}
```

### Task 5: 修改构建脚本（15分钟）
在 core-engine/src/main/native/build-native-kernel.bat 的编译列表中添加 js_vm_dispatcher.c。

### Task 6: 编译和测试（30-60分钟）
执行 `.\core-engine\build-native.bat`，然后执行 `.\gradlew.bat :core-engine:test --tests "*Vm*"`。

## 成功条件
- 编译通过，无警告
- 测试保持 >=528 passed，无新增失败
- 3 种 dispatcher（SWITCH, INDIRECT_THREADED, IF_NEST）可正常工作
- js_vm_get_dispatcher() 可根据 profile 返回正确的 dispatcher 函数

## 验证方式
1. 执行 `.\core-engine\build-native.bat` 编译成功
2. 执行 `.\gradlew.bat :core-engine:test --tests "*Vm*"` 测试通过
3. 默认 DISPATCHER_SWITCH profile 下功能与原有行为一致

## 约束条件
- 工作目录：E:\XiangMu\JavaShroud-public
- 保持现有 VMBC 格式兼容性
- 默认使用 DISPATCHER_SWITCH profile 确保向后兼容
- 不修改现有测试预期行为
- 提取的循环必须语义等价于原实现

## 技术要点
- 上下文传递：确保所有 dispatcher 正确使用 JNIEnv* env, js_vm_context_t* ctx, const uint8_t* program, uint32_t program_size
- 错误处理：所有路径都要有 fail-closed 逻辑
- PC 管理：不同 dispatcher 的 PC 更新方式可能不同，注意调整
- 当前 js_vm_read_dispatcher_profile() 返回 DISPATCHER_SWITCH，js_vm_verify_dispatcher_auth() 返回 1（通过），这是占位符实现

## 阻塞停止条件
如果连续 3 次尝试后仍遇到以下情况之一，则停止并报告：
- 无法从 js_vm_core.c 定位或提取主执行循环
- 编译持续失败且无法修复
- 测试回退超过 10 个且无法恢复
- handler 函数签名与现有代码不兼容且无法调和

停止时必须提供：
- 已尝试的所有方法和路径
- 收集的完整错误信息和编译/测试日志
- 具体阻塞点的详细描述
- 需要的用户输入类型（如架构决策、环境配置、现有代码结构说明）

## 参考文件（已存在于工作目录）
- PHASE1_IMPLEMENTATION_CHECKLIST.md - Task 1-8 详细步骤和验证标准
- TIGRESS_MAX_TECHNICAL_SPEC.md - 完整技术规格和代码模板
- COMPLETE_HANDOVER_DOCUMENT.md - 完整交接文档和上下文
- js_vm_dispatcher.h - Native 类型定义（已创建）
- js_vm_dispatcher.c - Dispatcher 框架（已创建，函数体待填充）
- DispatcherProfile.kt - Kotlin 端实现（已创建）

预计时间：4-6小时
```

---

## 说明

这个强化的 goal 包含：

### ✅ 完整上下文
- 当前状态和已完成工作
- 工作目录和完成度

### ✅ 详细任务分解
- Task 1-6 的具体步骤
- 每个 Task 的预期输出
- 代码示例和模板

### ✅ 明确的成功条件
- 编译无警告
- 测试 >=528 passed
- 3 种 dispatcher 工作

### ✅ 可验证的表面
- 具体的编译命令
- 具体的测试命令

### ✅ 清晰的约束
- 工作目录
- 兼容性要求
- 默认 profile

### ✅ 技术要点
- 上下文传递
- 错误处理
- PC 管理
- 当前占位符状态

### ✅ 具体的阻塞条件
- 3 次连续失败的具体场景
- 必须提供的信息

### ✅ 参考文档
- 列出所有可用的参考文件

---

将上面的完整 goal 复制到新的 Codex session 即可开始执行！
