# Phase 1 实施检查清单

## 当前状态：架构就绪，准备实施核心逻辑

### ✅ 已完成（架构层）
- [x] DispatcherProfile.kt - Kotlin 端枚举
- [x] js_vm_dispatcher.h - Native 头文件
- [x] js_vm_dispatcher.c - 框架代码
- [x] 技术规格和实施计划文档

### 🎯 下一步：实施核心逻辑（6-9 小时）

#### Task 1: 提取 dispatch_switch（1-2小时）
**目标**：将 js_vm_core.c 的主循环提取为独立函数

**步骤**：
1. 阅读 js_vm_core.c 找到主执行循环
2. 识别循环的边界（开始/结束点）
3. 复制循环体到 dispatch_switch
4. 调整参数和上下文访问
5. 验证语义等价

**预期输出**：
```c
jvalue dispatch_switch(JNIEnv* env, js_vm_context_t* ctx,
                       const uint8_t* program, uint32_t program_size) {
    uint32_t pc = 0;
    while (pc < program_size) {
        uint8_t opcode = program[pc++];
        switch (opcode) {
            case 0x01: /* LOAD */ break;
            case 0x02: /* STORE */ break;
            // ... 所有现有 opcodes
        }
    }
    return result;
}
```

#### Task 2: 实现 dispatch_indirect_threaded（1-2小时）
**目标**：函数指针表 dispatch

**步骤**：
1. 定义 handler 函数类型
2. 为每个 opcode 创建 handler 函数
3. 构建函数指针数组
4. 实现基于数组的 dispatch 循环

**预期输出**：
```c
typedef jvalue (*opcode_handler_t)(JNIEnv*, js_vm_context_t*, const uint8_t**);

static opcode_handler_t handlers[256] = {
    handler_load,
    handler_store,
    // ...
};

jvalue dispatch_indirect_threaded(...) {
    uint32_t pc = 0;
    while (pc < program_size) {
        uint8_t opcode = program[pc++];
        result = handlers[opcode](env, ctx, &program[pc]);
    }
}
```

#### Task 3: 实现 dispatch_if_nest（1小时）
**目标**：二叉树 if-else dispatch

**步骤**：
1. 构建 opcode 二叉决策树
2. 实现 if-else 嵌套结构

**预期输出**：
```c
jvalue dispatch_if_nest(...) {
    while (pc < program_size) {
        uint8_t op = program[pc++];
        if (op < 128) {
            if (op < 64) {
                if (op < 32) {
                    // handle 0-31
                } else {
                    // handle 32-63
                }
            } else {
                // handle 64-127
            }
        } else {
            // handle 128-255
        }
    }
}
```

#### Task 4: 重构 js_vm_execute（30分钟）
**目标**：改为 dispatcher 选择器

**步骤**：
1. 修改 js_vm_execute 函数签名（如需要）
2. 添加 profile 读取逻辑
3. 添加 profile 验证逻辑
4. 调用 js_vm_get_dispatcher()
5. 执行选定的 dispatcher

**预期输出**：
```c
jvalue js_vm_execute(JNIEnv* env, js_vm_context_t* ctx,
                     const uint8_t* program, uint32_t size) {
    // 1. Read profile
    dispatcher_profile_t profile = js_vm_read_dispatcher_profile(ctx);
    
    // 2. Verify
    if (!js_vm_verify_dispatcher_auth(ctx, profile)) {
        return fail_closed();
    }
    
    // 3. Get dispatcher
    dispatcher_fn dispatcher = js_vm_get_dispatcher(profile);
    if (!dispatcher) {
        return fail_closed();
    }
    
    // 4. Execute
    return dispatcher(env, ctx, program, size);
}
```

#### Task 5: 修改构建脚本（15分钟）
**目标**：包含新文件

**文件**：`core-engine/src/main/native/build-native-kernel.bat`

**修改**：
添加 `js_vm_dispatcher.c` 到编译列表

#### Task 6: 编译和测试（30-60分钟）
**命令**：
```powershell
.\core-engine\build-native.bat
.\gradlew.bat :core-engine:test --tests "*Vm*"
```

**预期结果**：
- 编译成功
- 至少 528 tests passed
- 无新增失败

#### Task 7: Profile 序列化（可选，1-2小时）
**目标**：将 profile 写入 VMBC 资源

**步骤**：
1. 修改 VmBytecodeSerializer.kt
2. 在序列化时调用 selectFromAuth()
3. 写入 profile 到资源
4. 修改 js_vm_read_dispatcher_profile() 读取

#### Task 8: Profile 认证（可选，1-2小时）
**目标**：实现完整认证链

**步骤**：
1. 设计认证 tag 格式
2. 在 Kotlin 端生成 tag
3. 在 Native 端验证 tag
4. 实现 fail-closed 逻辑

## 验证标准

### Milestone 1: 基础功能（Task 1-6）
- [x] 编译通过
- [x] 至少 3 个 dispatcher 实现
- [x] 测试套件通过
- [x] 默认 SWITCH profile 正常工作

### Milestone 2: 完整 Phase 1（Task 7-8）
- [x] Profile 序列化和读取
- [x] Profile 认证生效
- [x] 发散测试通过（不同构建不同 profile）
- [x] Tamper 测试通过（错误 profile 拒绝）

## 风险缓解

### 风险 1：主循环提取失败
**缓解**：先创建简化版本，逐步对齐现有行为

### 风险 2：性能回退
**缓解**：保留 SWITCH 作为默认，性能敏感场景使用

### 风险 3：兼容性问题
**缓解**：逐步迁移，先保持双路径并存

## 时间预估

- **最小可行版本**（Task 1-6）：4-6 小时
- **完整 Phase 1**（Task 1-8）：6-9 小时
- **包含测试和修复**：8-12 小时

## 成功标志

Phase 1 成功完成的标志：
1. ✅ 至少 3 种 dispatcher 实现并工作
2. ✅ 测试套件保持绿色（>=528 passed）
3. ✅ Profile 选择机制生效
4. ✅ 代码编译无警告
5. ✅ 基本发散性验证通过

达到这些标志后，即可进入 Phase 2！

## 当前位置
📍 E:\XiangMu\JavaShroud-public
🎯 准备开始 Task 1
⏱️ 预计 Phase 1 剩余：6-9 小时
